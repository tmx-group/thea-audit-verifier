// ════════════════════════════════════════════════════════════════════════════
// @tmx-group/audit-verifier · src/verify.js
// ════════════════════════════════════════════════════════════════════════════
// STANDALONE, open-source audit-chain verifier. Zero dependencies, no network,
// no trust in the API. Give it the rows of a workspace's audit chain and it
// independently:
//   • recomputes each row's hash from its payload (the SAME construction the
//     server used: sha256(canonical(payload) + prev_hash))
//   • confirms each row's prev_hash links to the previous row's hash
//   • confirms idx is contiguous and monotonic (no inserted/removed rows)
//   • reports the first break, if any, with the offending idx
//
// This makes the audit trail independently checkable: anyone can prove an answer
// happened and has not been altered, without trusting the API provider. It is
// the trust anchor of the sealed-API guarantee.
//
// HASH CONSTRUCTION (must mirror the API server's receipt construction exactly):
//   payload = { workspace_id, idx, prev_hash, query, route_summary,
//               atom_refs, tier, latency_ms, ts }
//   canonical(payload) = JSON.stringify(payload, TOP-LEVEL keys sorted)
//   hash = sha256Hex( canonical(payload) + prev_hash )
//   genesis prev_hash = '(genesis)'
// ════════════════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto';

const GENESIS = '(genesis)';

// Mirror the server's canonicalisation: sort TOP-LEVEL keys only. Nested objects
// (route_summary) are serialised in their stored key order — exactly as the
// server did, because its canonicalisation does not deep-sort. If the verifier
// deep-sorted, hashes would diverge. This faithfulness is the whole point.
function canonical(o) {
  return JSON.stringify(o, Object.keys(o).sort());
}

function sha256Hex(text) {
  return createHash('sha256').update(text).digest('hex');
}

// Recompute the hash for a single row from its payload fields.
export function recomputeHash(row) {
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
  return sha256Hex(canonical(payload) + row.prev_hash);
}

// Verify a full chain (array of rows for ONE workspace). Rows may be unsorted;
// we sort by idx. Returns a structured report.
export function verifyChain(rows, opts = {}) {
  const result = {
    ok: true,
    rows_checked: 0,
    workspace_id: rows.length ? rows[0].workspace_id : null,
    breaks: [],          // { idx, reason, expected, got }
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
  let expectedPrev = GENESIS;
  let expectedIdx = 0;

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
    const recomputed = recomputeHash(row);
    if (recomputed !== row.hash) {
      result.ok = false;
      result.breaks.push({ idx: row.idx, reason: 'hash_mismatch', expected: recomputed, got: row.hash });
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
