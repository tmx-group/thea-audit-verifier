import { createHash } from 'node:crypto';
import { verifyChain, verifyReceipt, recomputeHash, isReproducibleRow, canVerify } from '../src/verify.js';

let fails = 0;
const ok = (c, m) => { if (!c) { fails++; console.error('FAIL:', m); } };

const GENESIS = '(genesis)';
const sha256Hex = t => createHash('sha256').update(t).digest('hex');
const canonical = o => JSON.stringify(o, Object.keys(o).sort());

// THEA-314 shape — stores the exact hashed preimage as `canonical`. New rows
// (from migration 0014 onwards) carry this; the verifier rehashes it
// verbatim, so timestamptz/jsonb normalisation on the Postgres round-trip
// can't break reproducibility.
function buildChain(ws, n) {
  const rows = [];
  let prev = GENESIS;
  for (let idx = 0; idx < n; idx++) {
    const payload = {
      workspace_id: ws, idx, prev_hash: prev,
      query: `q${idx}`,
      route_summary: { cb_missions: idx, atoms_matched: idx + 1 },
      atom_refs: [`cite_${idx}`],
      tier: 'none', latency_ms: 10 + idx,
      ts: `2026-05-31T00:00:${String(idx).padStart(2, '0')}.000Z`,
    };
    const c = canonical(payload);
    const hash = sha256Hex(c + prev);
    rows.push({ ...payload, hash, canonical: c });
    prev = hash;
  }
  return rows;
}

// Legacy shape (pre-0014). Same payload hashing, but no canonical column —
// what rows written before THEA-314 look like. recomputeHash falls back to
// payload-reconstruction; verifyChain skips the per-row tamper check + lists
// the idx under legacy_unverifiable.
function buildLegacyChain(ws, n) {
  return buildChain(ws, n).map(({ canonical, ...rest }) => rest);
}

// ── THEA-314 happy path ────────────────────────────────────────────────────

{ const chain = buildChain('beefycorp', 5); const r = verifyChain(chain);
  ok(r.ok, `valid chain should verify, breaks: ${JSON.stringify(r.breaks)}`);
  ok(r.rows_checked === 5, 'should check all 5 rows');
  ok(r.legacy_unverifiable.length === 0, 'THEA-314 chain has zero legacy rows');
  ok(recomputeHash(chain[2]) === chain[2].hash, 'recomputeHash uses canonical → matches stored hash');
  ok(isReproducibleRow(chain[2]), 'isReproducibleRow true for THEA-314 row'); }

// THEA-314 — mutating the canonical preimage must be detected. Same effect as
// mutating any payload field, since the hash is sha256(canonical + prev_hash).
{ const chain = buildChain('beefycorp', 5);
  chain[2].canonical = chain[2].canonical.replace('q2', 'TAMPERED');
  const r = verifyChain(chain);
  ok(!r.ok, 'mutated canonical must be detected');
  ok(r.breaks.some(b => b.idx === 2 && b.reason === 'hash_mismatch'), 'flag hash_mismatch at idx 2'); }

// THEA-314 — mutating a typed-column payload field does NOT change hash on
// its own (the verifier rehashes canonical, not the typed columns). The check
// that catches tampering is that an attacker would need to forge canonical to
// match a mutated `query`, and the resulting hash would diverge from stored
// `row.hash` — covered above. Here we just confirm: tampering with `query`
// without touching canonical doesn't break verification (canonical is the
// source of truth).
{ const chain = buildChain('beefycorp', 5); chain[2].query = 'DIFFERENT-BUT-NO-CANONICAL-CHANGE';
  const r = verifyChain(chain);
  ok(r.ok, 'mutating typed query without canonical leaves hash verifiable (canonical is source of truth)'); }

// Chain-link checks unchanged from pre-THEA-314 — still catch broken links,
// deleted rows, silent inserts.
{ const chain = buildChain('beefycorp', 5); chain[3].prev_hash = 'deadbeef'; const r = verifyChain(chain);
  ok(!r.ok, 'broken link must be detected');
  ok(r.breaks.some(b => b.idx === 3 && b.reason === 'broken_link'), 'flag broken_link at idx 3'); }

{ const chain = buildChain('beefycorp', 5).filter(r => r.idx !== 2); const r = verifyChain(chain);
  ok(!r.ok, 'deleted row must be detected');
  ok(r.breaks.some(b => b.reason === 'idx_discontinuity' || b.reason === 'broken_link'), 'flag gap'); }

{ const chain = buildChain('beefycorp', 5);
  // Build a forged insert that links cleanly but with a fake hash.
  const fakePayload = { workspace_id: 'beefycorp', idx: 2, prev_hash: chain[1].hash, query: 'INSERTED',
    route_summary: {}, atom_refs: [], tier: 'none', latency_ms: 1, ts: '2026-05-31T00:00:02.500Z' };
  chain.push({ ...fakePayload, canonical: canonical(fakePayload), hash: 'fakehash' });
  ok(!verifyChain(chain).ok, 'silent insert must be detected'); }

// Receipts.
{ const chain = buildChain('beefycorp', 5);
  const receipt = { idx: 3, hash: chain[3].hash, prev_hash: chain[3].prev_hash, ts: chain[3].ts };
  ok(verifyReceipt(receipt, chain).ok, 'genuine receipt should verify');
  ok(!verifyReceipt({ idx: 3, hash: 'notreal', prev_hash: chain[3].prev_hash, ts: chain[3].ts }, chain).ok, 'forged receipt must fail'); }

// Cross-cutting guards.
{ const a = buildChain('a', 2), b = buildChain('b', 2);
  ok(!verifyChain([...a, ...b]).ok, 'mixed-workspace chain must be rejected');
  ok(!verifyChain([]).ok, 'empty chain must be rejected'); }

// ── Legacy (pre-0014) path ─────────────────────────────────────────────────
// Rows without canonical are LEGACY-UNVERIFIABLE. The chain-link walk still
// runs and stored hashes are accepted as-is; the per-row tamper check is
// skipped and the idx is recorded in result.legacy_unverifiable.

{ const chain = buildLegacyChain('beefycorp', 3); const r = verifyChain(chain);
  ok(r.ok, 'legacy chain still ok on chain-link checks');
  ok(r.legacy_unverifiable.length === 3, 'all 3 legacy rows recorded as unverifiable');
  ok(!isReproducibleRow(chain[0]), 'isReproducibleRow false for legacy row');
  // In the test, payload-reconstruction produces the same hash because we
  // controlled both ends. In production it does NOT, because Postgres
  // normalises the round-trip. The point: recomputeHash returns a string.
  ok(typeof recomputeHash(chain[0]) === 'string', 'legacy recomputeHash returns a hex string'); }

// A legacy row whose hash has been tampered with isn't flagged by the per-row
// check (skipped), but a broken chain link still gets caught.
{ const chain = buildLegacyChain('beefycorp', 3); chain[1].prev_hash = 'forged';
  const r = verifyChain(chain);
  ok(!r.ok, 'legacy chain still detects broken_link');
  ok(r.breaks.some(b => b.reason === 'broken_link'), 'flag broken_link in legacy chain'); }

// ── Mixed chain (legacy idx 0..2 + canonical idx 3..4) ────────────────────
// The post-0015 reality: workspaces that wrote rows before THEA-314 land
// have a tail of legacy rows with canonical = NULL, then everything from
// the day 0015 deployed forward is reproducible. verifyChain must:
//   · chain-walk cleanly across the boundary
//   · skip the legacy ones from the hash check (list them in legacy_unverifiable)
//   · per-row hash-verify the canonical ones
//   · catch tampering with a canonical row's preimage
{ const legacy = buildLegacyChain('mixed', 3);
  // Continue the chain with canonical rows starting at idx 3, prev_hash = legacy tail
  const canonicalTail = [];
  let prev = legacy[legacy.length - 1].hash;
  for (let idx = 3; idx < 5; idx++) {
    const payload = {
      workspace_id: 'mixed', idx, prev_hash: prev,
      query: `c${idx}`,
      route_summary: { atoms_matched: idx },
      atom_refs: [`x${idx}`],
      tier: 'none', latency_ms: 7 + idx,
      ts: `2026-06-27T00:00:${String(idx).padStart(2, '0')}.000Z`,
    };
    const c = canonical(payload);
    const hash = sha256Hex(c + prev);
    canonicalTail.push({ ...payload, hash, canonical: c });
    prev = hash;
  }
  const mixed = [...legacy, ...canonicalTail];
  const r = verifyChain(mixed);
  ok(r.ok, `mixed chain verifies clean, breaks: ${JSON.stringify(r.breaks)}`);
  ok(r.rows_checked === 5, 'all 5 rows walked');
  ok(JSON.stringify(r.legacy_unverifiable) === JSON.stringify([0, 1, 2]), `legacy idx 0..2 flagged, got ${JSON.stringify(r.legacy_unverifiable)}`);

  // Tamper a CANONICAL row's preimage — must be caught (legacy skip doesn't shield it).
  const tampered = [...mixed];
  tampered[3] = { ...tampered[3], canonical: tampered[3].canonical.replace('c3', 'TAMPERED') };
  const r2 = verifyChain(tampered);
  ok(!r2.ok, 'tampered canonical in mixed chain must be caught');
  ok(r2.breaks.some(b => b.idx === 3 && b.reason === 'hash_mismatch'), 'flag hash_mismatch at idx 3 in mixed chain'); }

// ── Anchor (slice verification) ───────────────────────────────────────────
// Smoke reads the last N rows of a long chain; it can't reasonably walk
// from genesis. verifyChain takes opts.anchor = { idx, prev_hash } so slice
// verification works without a false idx_discontinuity at the slice start.
{ const full = buildChain('slice', 6);
  // Slice = idx 3..5; anchor is the head of the preceding row (idx 2)
  const slice = full.slice(3);
  const anchor = { idx: 3, prev_hash: full[2].hash };
  const r = verifyChain(slice, { anchor });
  ok(r.ok, `sliced verify with anchor must pass, breaks: ${JSON.stringify(r.breaks)}`);
  ok(r.rows_checked === 3, 'walked 3 rows in slice');

  // Tampered prev_hash on the slice-start surfaces as broken_link against the anchor.
  const bad = [...slice];
  bad[0] = { ...bad[0], prev_hash: 'forged' };
  const r2 = verifyChain(bad, { anchor });
  ok(!r2.ok, 'slice with broken anchor link is caught');
  ok(r2.breaks.some(b => b.reason === 'broken_link'), 'broken_link reported on slice-start vs anchor'); }

// ── canVerify alias ───────────────────────────────────────────────────────
{ const c = buildChain('a', 1)[0];
  const l = buildLegacyChain('a', 1)[0];
  ok(canVerify(c), 'canVerify true for canonical row');
  ok(!canVerify(l), 'canVerify false for legacy row'); }

// ── Golden test vectors (THEA-221 spec §7) ───────────────────────────────────
// Pin the exact hex values from the specification. Any change to the canonical
// construction, hash algorithm, or key sort order will fail here and must be
// reflected in the spec (and vice-versa). These are the authoritative values a
// third-party implementation must reproduce.

{ // Vector 1 — first row (chain_seq 0, genesis), THEA-314 construction
  const row = {
    workspace_id:        'ws_example_00000001',
    chain_seq:           0,
    prev_hash:           '(genesis)',
    signature:           'aabbccdd00000000000000000000000000000000000000000000000000000000',
    signing_key_version: 'hmac-sha256-v1',
    request_id:          'nonce-20260101-abc',
    key_id_hash:         '91322071511d56d4d5c97421c29843a9e42367e35cf2ed0b4cae6bad61152214',
    acting_role:         'default',
    query_hash:          '81e041787e431a4ca43bb36f9612e192230612f13e0d0f518e7f89251527994f',
    response_hash:       '53410b589b036457a1dab51f49e86b614324c138df8229c97eb660f48c1a8a9a',
    records_routed:      null,
    brain_versions:      { 'brain-core': '0.9.1' },
    status:              'success',
  };
  const c = canonical({ ...row });     // canonical drops brain-core key (not top-level)
  const hash = sha256Hex(c + '(genesis)');
  row.canonical = c;
  row.idx = row.chain_seq;             // verifier uses idx vocabulary
  ok(hash === 'f15ed3ee533206747cfc5a934568e846bb62eb9abf8206d7004c8d17d0a77b7f',
    `golden vector 1 hash mismatch: got ${hash}`);
  ok(recomputeHash({ ...row, hash }) === hash,
    'golden vector 1: recomputeHash must match stored hash');

  // Vector 2 — second row (chain_seq 1, chained from Vector 1)
  const row2 = {
    workspace_id:        'ws_example_00000001',
    chain_seq:           1,
    prev_hash:           'f15ed3ee533206747cfc5a934568e846bb62eb9abf8206d7004c8d17d0a77b7f',
    signature:           'bbccddee00000000000000000000000000000000000000000000000000000000',
    signing_key_version: 'hmac-sha256-v1',
    request_id:          'nonce-20260101-xyz',
    key_id_hash:         '91322071511d56d4d5c97421c29843a9e42367e35cf2ed0b4cae6bad61152214',
    acting_role:         'default',
    query_hash:          'd02421d8f8b7083f20af17fb44b48bbf0f4ebdb8741edab81bd1222e3ebc7803',
    response_hash:       '972f8126d3235fa1678fd63fcb0e0185102328fd44c73ba5af9e0fbe13db187e',
    records_routed:      1,
    brain_versions:      { 'brain-core': '0.9.1' },
    status:              'success',
  };
  const c2 = canonical({ ...row2 });
  const hash2 = sha256Hex(c2 + row2.prev_hash);
  row2.canonical = c2;
  row2.idx = row2.chain_seq;
  ok(hash2 === '5aeb803db54ce5d1d982f1699a4fe87ee4fc68f9c498bf2e186468381dbaebeb',
    `golden vector 2 hash mismatch: got ${hash2}`);
  ok(recomputeHash({ ...row2, hash: hash2 }) === hash2,
    'golden vector 2: recomputeHash must match stored hash');

  // Two-row chain verifies end-to-end
  const chain = [
    { ...row,  hash, idx: 0 },
    { ...row2, hash: hash2, idx: 1 },
  ];
  const r = verifyChain(chain);
  ok(r.ok, `golden vectors 1+2: two-row chain must verify, breaks: ${JSON.stringify(r.breaks)}`);
  ok(r.rows_checked === 2, 'golden vectors 1+2: rows_checked should be 2');
  ok(r.legacy_unverifiable.length === 0, 'golden vectors 1+2: no legacy rows'); }

{ // Vector 3 — legacy row (pre-THEA-314, idx 0, genesis)
  // ts MUST be Z form — using +00:00 would produce a different hash.
  const legacyPayload = {
    workspace_id: 'ws_example_00000001',
    idx:          0,
    prev_hash:    '(genesis)',
    query:        'what is the total PO value?',
    route_summary: { cb_missions: 1, atoms_matched: 3 },
    atom_refs:    ['cite_001', 'cite_002'],
    tier:         'none',
    latency_ms:   87,
    ts:           '2026-01-01T00:00:00.000Z',
  };
  const c = canonical(legacyPayload);   // route_summary nested keys dropped → {}
  const hash = sha256Hex(c + '(genesis)');
  ok(hash === '3a469b96d070939b6daef96e396ad7b4454628a7f89af1902af83987d368b0eb',
    `golden vector 3 (legacy) hash mismatch: got ${hash}`);

  // Confirm that +00:00 form of the same ts produces a different hash.
  const withPlus = canonical({ ...legacyPayload, ts: '2026-01-01T00:00:00.000+00:00' });
  const hashPlus = sha256Hex(withPlus + '(genesis)');
  ok(hash !== hashPlus,
    'golden vector 3: +00:00 form must produce a different hash than Z form'); }

console.log('─'.repeat(60));
console.log(`failures: ${fails}`);
if (fails === 0) { console.log('PASS — verifier rehashes canonical preimage (THEA-314); legacy rows verify on chain-link only; tamper / break / insert / forge detected; golden vectors match spec.'); process.exit(0); }
else { console.error('FAIL'); process.exit(1); }
