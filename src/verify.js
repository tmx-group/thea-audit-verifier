// ════════════════════════════════════════════════════════════════════════════
// @tmx-group/audit-verifier · src/verify.js
// ════════════════════════════════════════════════════════════════════════════
// STANDALONE, open-source audit-chain verifier. Zero dependencies, no network,
// no trust in the API. Give it the rows of a workspace's audit chain and it
// independently:
//   • recomputes each row's hash from its payload (the SAME construction the
//     gateway used: sha256(canonical(payload) + prev_hash))
//   • confirms each row's prev_hash links to the previous row's hash
//   • confirms idx is contiguous and monotonic (no inserted/removed rows)
//   • reports the first break, if any, with the offending idx
//
// This is constraint #4 made independently checkable: anyone can prove an answer
// happened and hasn't been altered, WITHOUT trusting TMX. Publish it; it's the
// trust anchor of the whole sealed-API claim.
//
// HASH CONSTRUCTION (must mirror gateway/src/index.js exactly):
//   payload = { workspace_id, idx, prev_hash, query, route_summary,
//               atom_refs, tier, latency_ms, ts }
//   canonical(payload) = JSON.stringify(payload, TOP-LEVEL keys sorted)
//   hash = sha256Hex( canonical(payload) + prev_hash )
//   genesis prev_hash = '(genesis)'
//
// THEA-314 — Postgres normalises timestamptz + jsonb on the round-trip, so
// re-canonicalising from the typed columns can never reproduce the bytes the
// gateway hashed. New rows (from 0014_audit_chain_canonical onwards) carry
// the exact preimage as `canonical text`; the verifier prefers it when
// present and rehashes verbatim. Rows without `canonical` are LEGACY (pre-0014)
// and treated as legacy-unverifiable rather than producing a false break.
// ════════════════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto';

const GENESIS = '(genesis)';

// Mirror the gateway's canonical(): sort TOP-LEVEL keys only. Nested objects
// (route_summary) are serialised in their stored key order — exactly as the
// gateway did, because gateway canonical() did not deep-sort. If the verifier
// deep-sorted, hashes would diverge. This faithfulness is the whole point.
// Only used for legacy rows (pre-THEA-314); new rows use the stored
// `canonical` column verbatim and bypass this function entirely.
function canonicalLegacy(o) {
  return JSON.stringify(o, Object.keys(o).sort());
}

function sha256Hex(text) {
  return createHash('sha256').update(text).digest('hex');
}

/** Sentinel returned by recomputeHash for rows that predate THEA-314 (no
 *  `canonical` column). Treat as "cannot verify the hash construction" —
 *  chain-link checks (idx contiguity, prev_hash linkage) still run against
 *  the stored hash. */
export const LEGACY_UNVERIFIABLE = Symbol('legacy_unverifiable');

// Recompute the hash for a single row.
//   · If row.canonical is present: rehash that preimage verbatim — the only
//     reproducible path, because Postgres normalises the typed columns on
//     round-trip (THEA-314).
//   · Else: legacy reconstruction from the typed columns. Returns a hex
//     string the chain-walk may compare against row.hash, but on most envs
//     it will NOT match — see LEGACY_UNVERIFIABLE for the explicit signal.
export function recomputeHash(row) {
  if (typeof row.canonical === 'string' && row.canonical.length > 0) {
    return sha256Hex(row.canonical + row.prev_hash);
  }
  // Legacy path (pre-0014). Kept for back-compat / forensic use.
  const payload = {
    workspace_id: row.workspace_id,
    idx: row.idx,
    prev_hash: row.prev_hash,
    query: row.query,
    route_summary: row.route_summary,
    atom_refs: row.atom_refs,
    tier: row.tier,
    latency_ms: row.latency_ms,
    ts: row.ts,
  };
  return sha256Hex(canonicalLegacy(payload) + row.prev_hash);
}

/** True iff the row carries the THEA-314 canonical preimage and can be
 *  hash-verified deterministically. False = pre-0014 row; chain-link checks
 *  still apply but recomputeHash will likely diverge from row.hash. */
export function isReproducibleRow(row) {
  return typeof row.canonical === 'string' && row.canonical.length > 0;
}

/** Alias of isReproducibleRow with a verifier-vocabulary-friendly name —
 *  "can this row be hash-verified?". Use either; same predicate. */
export const canVerify = isReproducibleRow;

// Verify a chain (array of rows for ONE workspace). Rows may be unsorted;
// we sort by idx. Returns a structured report.
//
// Options:
//   opts.stopOnFirstBreak    bool — return on first break (default false).
//   opts.anchor              { idx, prev_hash } — starting point for the walk.
//                              Default: idx 0, prev_hash '(genesis)'. Pass an
//                              anchor when verifying a SLICE of a chain (e.g.
//                              the most recent N rows of a long workspace).
//                              The slice must be contiguous starting at
//                              anchor.idx; the first row's prev_hash must
//                              equal anchor.prev_hash.
//
// THEA-314 — per-row tamper checks (recomputed hash vs stored hash) need the
// stored `canonical` preimage; rows without it are legacy-unverifiable (pre
// 0014) and skipped from the hash check but STILL participate in the chain-
// link walk. result.legacy_unverifiable lists their idx for transparency.
export function verifyChain(rows, opts = {}) {
  const result = {
    ok: true,
    rows_checked: 0,
    workspace_id: rows.length ? rows[0].workspace_id : null,
    breaks: [],          // { idx, reason, expected, got }
    legacy_unverifiable: [],  // idx[] — rows without canonical preimage (pre-THEA-314)
    head_hash: null,
  };
  if (!Array.isArray(rows) || rows.length === 0) {
    result.ok = false;
    result.breaks.push({ idx: null, reason: 'empty_chain' });
    return result;
  }

  // single-workspace guard — mixing workspaces would invalidate the walk
  const wsIds = new Set(rows.map(r => r.workspace_id));
  if (wsIds.size > 1) {
    result.ok = false;
    result.breaks.push({ idx: null, reason: 'multiple_workspaces', got: [...wsIds] });
    return result;
  }

  const sorted = [...rows].sort((a, b) => a.idx - b.idx);
  // Default anchor is genesis (the canonical "verify from the start" mode).
  // Caller may pass an explicit anchor for slice verification.
  const anchor = opts.anchor && typeof opts.anchor.idx === 'number'
    ? { idx: opts.anchor.idx, prev_hash: String(opts.anchor.prev_hash ?? GENESIS) }
    : { idx: 0, prev_hash: GENESIS };
  let expectedPrev = anchor.prev_hash;
  let expectedIdx  = anchor.idx;

  for (const row of sorted) {
    result.rows_checked++;

    // 1. idx must be contiguous & monotonic from 0 (no gaps, no dupes, no reorder)
    if (row.idx !== expectedIdx) {
      result.ok = false;
      result.breaks.push({ idx: row.idx, reason: 'idx_discontinuity', expected: expectedIdx, got: row.idx });
      // continue walking from the row's own idx so we can report further breaks
      expectedIdx = row.idx;
    }

    // 2. prev_hash must link to the previous row's hash (or genesis at idx 0)
    if (row.prev_hash !== expectedPrev) {
      result.ok = false;
      result.breaks.push({ idx: row.idx, reason: 'broken_link', expected: expectedPrev, got: row.prev_hash });
    }

    // 3. recomputed hash must equal the stored hash (detects payload tampering)
    //    Skipped for legacy rows (no canonical preimage) — recorded so callers
    //    know which idx couldn't be hash-verified.
    if (isReproducibleRow(row)) {
      const recomputed = recomputeHash(row);
      if (recomputed !== row.hash) {
        result.ok = false;
        result.breaks.push({ idx: row.idx, reason: 'hash_mismatch', expected: recomputed, got: row.hash });
      }
    } else {
      result.legacy_unverifiable.push(row.idx);
    }

    expectedPrev = row.hash;
    expectedIdx = row.idx + 1;
    result.head_hash = row.hash;

    if (opts.stopOnFirstBreak && !result.ok) break;
  }

  return result;
}

// Verify a single receipt anchor (the {idx, hash, prev_hash, ts} a client gets
// in a sealed response) against the full chain rows — confirms that receipt is
// genuinely IN the chain and the chain up to it verifies.
export function verifyReceipt(receipt, chainRows) {
  const chain = verifyChain(chainRows);
  const inChain = chainRows.some(r => r.idx === receipt.idx && r.hash === receipt.hash);
  return {
    ok: chain.ok && inChain,
    receipt_in_chain: inChain,
    chain_ok: chain.ok,
    breaks: chain.breaks,
  };
}
