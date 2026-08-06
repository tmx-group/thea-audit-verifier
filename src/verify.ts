// ════════════════════════════════════════════════════════════════════════════
// @tmx-group/audit-verifier · src/verify.ts
// ════════════════════════════════════════════════════════════════════════════
// Standalone, zero-dependency verifier for Thea API hash-chained audit
// receipts. Give it the rows of a workspace's audit chain and it independently:
//
//   · recomputes each row's hash from its stored canonical preimage (THEA-314)
//     or from typed columns (legacy rows, pre-migration 0014)
//   · confirms each row's prev_hash links to the previous row's hash
//   · confirms idx is contiguous and monotonic (no inserted/removed rows)
//   · confirms all rows belong to a single workspace
//   · reports every break with the offending idx and reason
//
// Receipt format, hash construction, and canonical key order are specified in
// packages/audit-verifier/SPEC.md (thea-api). Implement that spec exactly;
// any divergence here produces hash_mismatch for every valid row.
// ════════════════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto';

const GENESIS = '(genesis)';

// ── Types ────────────────────────────────────────────────────────────────────

/** A single row from the workspace audit chain. */
export interface AuditChainRow {
  workspace_id: string;
  idx: number;
  prev_hash: string;
  hash: string;
  /**
   * Stored canonical preimage (THEA-314, migration 0014+).
   * When present the verifier rehashes this verbatim — Postgres normalisation
   * of jsonb/timestamptz on the round-trip cannot break reproducibility.
   * Absent on legacy rows (pre-0014); those fall back to typed-column reconstruction.
   */
  canonical?: string;
  // Typed columns used for legacy row reconstruction
  query?: string;
  route_summary?: Record<string, unknown>;
  atom_refs?: string[];
  tier?: string;
  latency_ms?: number;
  ts?: string;
}

export interface VerifyBreak {
  idx: number | null;
  reason: string;
  expected?: unknown;
  got?: unknown;
}

export interface VerifyResult {
  ok: boolean;
  rows_checked: number;
  workspace_id: string | null;
  breaks: VerifyBreak[];
  /** Indices of rows without a canonical preimage — chain-link checks ran but per-row hash check was skipped. */
  legacy_unverifiable: number[];
  head_hash: string | null;
}

export interface AuditReceipt {
  idx: number;
  hash: string;
  prev_hash: string;
  ts: string;
}

export interface VerifyAnchor {
  /** The idx of the first row in the slice. */
  idx: number;
  /** The hash of the row immediately before the slice (i.e. row[idx-1].hash). */
  prev_hash: string;
}

export interface VerifyReceiptResult {
  ok: boolean;
  receipt_in_chain: boolean;
  chain_ok: boolean;
  breaks: VerifyBreak[];
}

// ── Internal helpers ──────────────────────────────────────────────────────────

function sha256Hex(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

// Mirror the server's canonicalisation exactly (SPEC.md §3.1):
// sort TOP-LEVEL keys only. The array-replacer form of JSON.stringify drops
// sub-keys of nested objects that are not themselves top-level keys, so
// brain_versions: { 'brain-core': '0.9.1' } → brain_versions: {} in canonical.
function canonical(o: Record<string, unknown>): string {
  return JSON.stringify(o, Object.keys(o).sort());
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * True if this row carries the stored canonical preimage (THEA-314).
 * Only these rows can be independently hash-verified.
 */
export function isReproducibleRow(row: AuditChainRow): boolean {
  return typeof row.canonical === 'string' && row.canonical.length > 0;
}

/** Alias for isReproducibleRow — matches the verifier's published vocabulary. */
export const canVerify = isReproducibleRow;

/**
 * Recompute the SHA-256 hash for a single row.
 *
 * THEA-314 rows: rehash the stored canonical preimage verbatim (SPEC.md §3.3).
 * Legacy rows: reconstruct canonical from typed columns (SPEC.md §6).
 *
 * In production, legacy reconstruction is unreliable because Postgres normalises
 * typed columns on the round-trip (timestamptz → +00:00 vs Z, jsonb key reorder).
 * Use this for reference and testing only; verifyChain() skips the hash check for
 * legacy rows and records them in legacy_unverifiable instead.
 */
export function recomputeHash(row: AuditChainRow): string {
  if (isReproducibleRow(row)) {
    return sha256Hex(row.canonical! + row.prev_hash);
  }
  // Legacy: reconstruct payload from typed columns (SPEC.md §6)
  const payload: Record<string, unknown> = {
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

/**
 * Verify a workspace audit chain (SPEC.md §5, §9).
 *
 * Pass all rows for one workspace, or a contiguous slice with opts.anchor.
 * Rows may arrive in any order — they are sorted by idx internally.
 *
 * @param rows   - Chain rows (full chain or contiguous slice).
 * @param opts   - Optional anchor for slice verification.
 */
export function verifyChain(
  rows: AuditChainRow[],
  opts: { anchor?: VerifyAnchor } = {},
): VerifyResult {
  const result: VerifyResult = {
    ok: true,
    rows_checked: 0,
    workspace_id: rows.length ? rows[0].workspace_id : null,
    breaks: [],
    legacy_unverifiable: [],
    head_hash: null,
  };

  if (!Array.isArray(rows) || rows.length === 0) {
    result.ok = false;
    result.breaks.push({ idx: null, reason: 'empty_chain' });
    return result;
  }

  const wsIds = new Set(rows.map(r => r.workspace_id));
  if (wsIds.size > 1) {
    result.ok = false;
    result.breaks.push({ idx: null, reason: 'multiple_workspaces', got: [...wsIds] });
    return result;
  }

  const sorted = [...rows].sort((a, b) => a.idx - b.idx);
  const anchor = opts.anchor;
  let expectedPrev = anchor ? anchor.prev_hash : GENESIS;
  let expectedIdx  = anchor ? anchor.idx        : 0;

  for (const row of sorted) {
    result.rows_checked++;

    if (row.idx !== expectedIdx) {
      result.ok = false;
      result.breaks.push({ idx: row.idx, reason: 'idx_discontinuity', expected: expectedIdx, got: row.idx });
      expectedIdx = row.idx;
    }

    if (row.prev_hash !== expectedPrev) {
      result.ok = false;
      result.breaks.push({ idx: row.idx, reason: 'broken_link', expected: expectedPrev, got: row.prev_hash });
    }

    if (isReproducibleRow(row)) {
      const recomputed = recomputeHash(row);
      if (recomputed !== row.hash) {
        result.ok = false;
        result.breaks.push({ idx: row.idx, reason: 'hash_mismatch', expected: recomputed, got: row.hash });
      }
    } else {
      result.legacy_unverifiable.push(row.idx);
    }

    expectedPrev   = row.hash;
    expectedIdx    = row.idx + 1;
    result.head_hash = row.hash;
  }

  return result;
}

/**
 * Verify a single receipt anchor against the full chain rows (SPEC.md §5).
 * Confirms the receipt is genuinely in the chain and the chain up to it verifies.
 */
export function verifyReceipt(receipt: AuditReceipt, chainRows: AuditChainRow[]): VerifyReceiptResult {
  const chain = verifyChain(chainRows);
  const inChain = chainRows.some(r => r.idx === receipt.idx && r.hash === receipt.hash);
  return {
    ok: chain.ok && inChain,
    receipt_in_chain: inChain,
    chain_ok: chain.ok,
    breaks: chain.breaks,
  };
}
