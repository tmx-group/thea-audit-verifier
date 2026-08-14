import { createHash } from 'node:crypto';
import { describe, it, expect } from 'vitest';
import {
  verifyChain,
  verifyReceipt,
  recomputeHash,
  isReproducibleRow,
  canVerify,
  type AuditChainRow,
} from '../src/verify';

// ── helpers ───────────────────────────────────────────────────────────────────

const sha256Hex = (t: string) => createHash('sha256').update(t).digest('hex');
const canonical = (o: Record<string, unknown>) => JSON.stringify(o, Object.keys(o).sort());
const GENESIS = '(genesis)';

function buildChain(ws: string, n: number): AuditChainRow[] {
  const rows: AuditChainRow[] = [];
  let prev = GENESIS;
  for (let idx = 0; idx < n; idx++) {
    const payload: Record<string, unknown> = {
      workspace_id: ws, idx, prev_hash: prev,
      query: `q${idx}`,
      route_summary: { cb_missions: idx, atoms_matched: idx + 1 },
      atom_refs: [`cite_${idx}`],
      tier: 'none', latency_ms: 10 + idx,
      ts: `2026-05-31T00:00:${String(idx).padStart(2, '0')}.000Z`,
    };
    const c = canonical(payload);
    const hash = sha256Hex(c + prev);
    rows.push({ ...(payload as unknown as AuditChainRow), hash, canonical: c });
    prev = hash;
  }
  return rows;
}

function buildLegacyChain(ws: string, n: number): AuditChainRow[] {
  return buildChain(ws, n).map(({ canonical: _c, ...rest }) => rest as AuditChainRow);
}

// ── THEA-314 happy path ───────────────────────────────────────────────────────

describe('THEA-314 chain verification', () => {
  it('verifies a valid chain', () => {
    const chain = buildChain('beefycorp', 5);
    const r = verifyChain(chain);
    expect(r.ok).toBe(true);
    expect(r.rows_checked).toBe(5);
    expect(r.legacy_unverifiable).toHaveLength(0);
  });

  it('recomputeHash uses canonical preimage and matches stored hash', () => {
    const chain = buildChain('beefycorp', 5);
    expect(recomputeHash(chain[2])).toBe(chain[2].hash);
  });

  it('isReproducibleRow is true for THEA-314 rows', () => {
    expect(isReproducibleRow(buildChain('ws', 1)[0])).toBe(true);
  });

  it('canVerify is an alias for isReproducibleRow', () => {
    const row = buildChain('ws', 1)[0];
    expect(canVerify(row)).toBe(isReproducibleRow(row));
  });

  it('detects mutated canonical preimage (payload tamper)', () => {
    const chain = buildChain('beefycorp', 5);
    chain[2].canonical = chain[2].canonical!.replace('q2', 'TAMPERED');
    const r = verifyChain(chain);
    expect(r.ok).toBe(false);
    expect(r.breaks.some(b => b.idx === 2 && b.reason === 'hash_mismatch')).toBe(true);
  });

  it('mutating typed query without changing canonical does not break verification', () => {
    const chain = buildChain('beefycorp', 5);
    chain[2].query = 'DIFFERENT';
    expect(verifyChain(chain).ok).toBe(true);
  });

  it('detects broken chain link', () => {
    const chain = buildChain('beefycorp', 5);
    chain[3].prev_hash = 'deadbeef';
    const r = verifyChain(chain);
    expect(r.ok).toBe(false);
    expect(r.breaks.some(b => b.idx === 3 && b.reason === 'broken_link')).toBe(true);
  });

  it('detects deleted row', () => {
    const chain = buildChain('beefycorp', 5).filter(r => r.idx !== 2);
    const r = verifyChain(chain);
    expect(r.ok).toBe(false);
    expect(r.breaks.some(b => b.reason === 'idx_discontinuity' || b.reason === 'broken_link')).toBe(true);
  });

  it('detects silent insert', () => {
    const chain = buildChain('beefycorp', 5);
    const fake: Record<string, unknown> = {
      workspace_id: 'beefycorp', idx: 2, prev_hash: chain[1].hash,
      query: 'INSERTED', route_summary: {}, atom_refs: [], tier: 'none', latency_ms: 1,
      ts: '2026-05-31T00:00:02.500Z',
    };
    chain.push({ ...(fake as unknown as AuditChainRow), canonical: canonical(fake), hash: 'fakehash' });
    expect(verifyChain(chain).ok).toBe(false);
  });
});

// ── Receipts ──────────────────────────────────────────────────────────────────

describe('verifyReceipt', () => {
  it('genuine receipt verifies', () => {
    const chain = buildChain('beefycorp', 5);
    const receipt = { idx: 3, hash: chain[3].hash, prev_hash: chain[3].prev_hash, ts: chain[3].ts! };
    expect(verifyReceipt(receipt, chain).ok).toBe(true);
  });

  it('forged receipt hash fails', () => {
    const chain = buildChain('beefycorp', 5);
    const receipt = { idx: 3, hash: 'notreal', prev_hash: chain[3].prev_hash, ts: chain[3].ts! };
    expect(verifyReceipt(receipt, chain).ok).toBe(false);
  });
});

// ── Cross-cutting guards ──────────────────────────────────────────────────────

describe('cross-cutting guards', () => {
  it('rejects mixed-workspace chain', () => {
    const a = buildChain('a', 2), b = buildChain('b', 2);
    expect(verifyChain([...a, ...b]).ok).toBe(false);
  });

  it('rejects empty chain', () => {
    expect(verifyChain([]).ok).toBe(false);
  });
});

// ── Legacy (pre-THEA-314) rows ────────────────────────────────────────────────

describe('legacy row handling', () => {
  it('chain-link checks pass on legacy chain', () => {
    const chain = buildLegacyChain('beefycorp', 3);
    const r = verifyChain(chain);
    expect(r.ok).toBe(true);
    expect(r.legacy_unverifiable).toHaveLength(3);
  });

  it('isReproducibleRow is false for legacy rows', () => {
    expect(isReproducibleRow(buildLegacyChain('ws', 1)[0])).toBe(false);
  });

  it('recomputeHash returns a hex string for legacy rows', () => {
    expect(typeof recomputeHash(buildLegacyChain('ws', 1)[0])).toBe('string');
  });

  it('detects broken link in legacy chain', () => {
    const chain = buildLegacyChain('beefycorp', 3);
    chain[1].prev_hash = 'forged';
    const r = verifyChain(chain);
    expect(r.ok).toBe(false);
    expect(r.breaks.some(b => b.reason === 'broken_link')).toBe(true);
  });
});

// ── Mixed chain (legacy + THEA-314) ──────────────────────────────────────────

describe('mixed chain (legacy idx 0..2 + canonical idx 3..4)', () => {
  function buildMixed() {
    const legacy = buildLegacyChain('mixed', 3);
    const tail: AuditChainRow[] = [];
    let prev = legacy[2].hash;
    for (let idx = 3; idx < 5; idx++) {
      const payload: Record<string, unknown> = {
        workspace_id: 'mixed', idx, prev_hash: prev,
        query: `c${idx}`, route_summary: {}, atom_refs: [], tier: 'none', latency_ms: 7 + idx,
        ts: `2026-06-27T00:00:${String(idx).padStart(2, '0')}.000Z`,
      };
      const c = canonical(payload);
      const hash = sha256Hex(c + prev);
      tail.push({ ...(payload as unknown as AuditChainRow), hash, canonical: c });
      prev = hash;
    }
    return [...legacy, ...tail];
  }

  it('verifies clean across the legacy→canonical boundary', () => {
    const r = verifyChain(buildMixed());
    expect(r.ok).toBe(true);
    expect(r.rows_checked).toBe(5);
    expect(r.legacy_unverifiable).toEqual([0, 1, 2]);
  });

  it('catches tamper on a canonical row in a mixed chain', () => {
    const mixed = buildMixed();
    mixed[3] = { ...mixed[3], canonical: mixed[3].canonical!.replace('c3', 'TAMPERED') };
    const r = verifyChain(mixed);
    expect(r.ok).toBe(false);
    expect(r.breaks.some(b => b.idx === 3 && b.reason === 'hash_mismatch')).toBe(true);
  });
});

// ── Anchor / slice verification ───────────────────────────────────────────────

describe('anchor (slice verification)', () => {
  it('verifies a slice with a valid anchor', () => {
    const full = buildChain('slice', 6);
    const slice = full.slice(3);
    const anchor = { idx: 3, prev_hash: full[2].hash };
    const r = verifyChain(slice, { anchor });
    expect(r.ok).toBe(true);
    expect(r.rows_checked).toBe(3);
  });

  it('catches broken link at slice start vs anchor', () => {
    const full = buildChain('slice', 6);
    const slice = full.slice(3).map((r, i) => i === 0 ? { ...r, prev_hash: 'forged' } : r);
    const r = verifyChain(slice, { anchor: { idx: 3, prev_hash: full[2].hash } });
    expect(r.ok).toBe(false);
    expect(r.breaks.some(b => b.reason === 'broken_link')).toBe(true);
  });
});

// ── Golden test vectors (SPEC.md §7) ─────────────────────────────────────────
// These are the normative vectors. A correct implementation must reproduce
// the exact hashes below. Any deviation indicates a canonicalisation mismatch.

describe('golden test vectors (SPEC.md §7)', () => {
  // §7.2 Vector 1 — first row (chain_seq 0, genesis, THEA-314)
  const VECTOR_1_CANONICAL =
    '{"acting_role":"default","brain_versions":{},"chain_seq":0,' +
    '"key_id_hash":"91322071511d56d4d5c97421c29843a9e42367e35cf2ed0b4cae6bad61152214",' +
    '"prev_hash":"(genesis)",' +
    '"query_hash":"81e041787e431a4ca43bb36f9612e192230612f13e0d0f518e7f89251527994f",' +
    '"records_routed":null,"request_id":"nonce-20260101-abc",' +
    '"response_hash":"53410b589b036457a1dab51f49e86b614324c138df8229c97eb660f48c1a8a9a",' +
    '"signature":"aabbccdd00000000000000000000000000000000000000000000000000000000",' +
    '"signing_key_version":"hmac-sha256-v1","status":"success",' +
    '"workspace_id":"ws_example_00000001"}';
  const VECTOR_1_HASH = 'f15ed3ee533206747cfc5a934568e846bb62eb9abf8206d7004c8d17d0a77b7f';

  // §7.3 Vector 2 — chain_seq 1, chained from Vector 1
  const VECTOR_2_CANONICAL =
    '{"acting_role":"default","brain_versions":{},"chain_seq":1,' +
    '"key_id_hash":"91322071511d56d4d5c97421c29843a9e42367e35cf2ed0b4cae6bad61152214",' +
    `"prev_hash":"${VECTOR_1_HASH}",` +
    '"query_hash":"d02421d8f8b7083f20af17fb44b48bbf0f4ebdb8741edab81bd1222e3ebc7803",' +
    '"records_routed":1,"request_id":"nonce-20260101-xyz",' +
    '"response_hash":"972f8126d3235fa1678fd63fcb0e0185102328fd44c73ba5af9e0fbe13db187e",' +
    '"signature":"bbccddee00000000000000000000000000000000000000000000000000000000",' +
    '"signing_key_version":"hmac-sha256-v1","status":"success",' +
    '"workspace_id":"ws_example_00000001"}';
  const VECTOR_2_HASH = '5aeb803db54ce5d1d982f1699a4fe87ee4fc68f9c498bf2e186468381dbaebeb';

  const row1: AuditChainRow = {
    workspace_id: 'ws_example_00000001',
    idx: 0,
    prev_hash: GENESIS,
    hash: VECTOR_1_HASH,
    canonical: VECTOR_1_CANONICAL,
  };
  const row2: AuditChainRow = {
    workspace_id: 'ws_example_00000001',
    idx: 1,
    prev_hash: VECTOR_1_HASH,
    hash: VECTOR_2_HASH,
    canonical: VECTOR_2_CANONICAL,
  };

  it('Vector 1: recomputeHash matches spec hash', () => {
    expect(recomputeHash(row1)).toBe(VECTOR_1_HASH);
  });

  it('Vector 2: recomputeHash matches spec hash', () => {
    expect(recomputeHash(row2)).toBe(VECTOR_2_HASH);
  });

  it('Vector 1+2 chain verifies cleanly', () => {
    const r = verifyChain([row1, row2]);
    expect(r.ok).toBe(true);
    expect(r.rows_checked).toBe(2);
    expect(r.head_hash).toBe(VECTOR_2_HASH);
    expect(r.legacy_unverifiable).toHaveLength(0);
  });

  // §7.4 Vector 3 — legacy row (pre-THEA-314, idx 0, ts MUST be Z form)
  const VECTOR_3_HASH = '3a469b96d070939b6daef96e396ad7b4454628a7f89af1902af83987d368b0eb';
  const legacyRow: AuditChainRow = {
    workspace_id: 'ws_example_00000001',
    idx: 0,
    prev_hash: GENESIS,
    hash: VECTOR_3_HASH,
    // no canonical — legacy row
    query: 'what is the total PO value?',
    route_summary: { cb_missions: 1, atoms_matched: 3 },
    atom_refs: ['cite_001', 'cite_002'],
    tier: 'none',
    latency_ms: 87,
    ts: '2026-01-01T00:00:00.000Z',
  };

  it('Vector 3: recomputeHash matches spec hash (legacy typed-column reconstruction)', () => {
    expect(recomputeHash(legacyRow)).toBe(VECTOR_3_HASH);
  });

  it('Vector 3: ts in +00:00 form produces a different hash (Z form required)', () => {
    const wrongTs = { ...legacyRow, ts: '2026-01-01T00:00:00.000+00:00' };
    expect(recomputeHash(wrongTs)).not.toBe(VECTOR_3_HASH);
  });

  it('Vector 3: chain-link checks pass, row is in legacy_unverifiable', () => {
    const r = verifyChain([legacyRow]);
    expect(r.ok).toBe(true);
    expect(r.legacy_unverifiable).toContain(0);
  });
});
