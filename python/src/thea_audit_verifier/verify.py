# Standalone, zero-dependency verifier for Thea API hash-chained audit receipts.
#
# Implements the same algorithm as @tmx-group/audit-verifier (TypeScript).
# Receipt format, hash construction, and canonical key order are specified in
# thea-api packages/audit-verifier/SPEC.md. Any divergence produces hash_mismatch
# for every valid row — implement that spec exactly.

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

GENESIS = "(genesis)"


# ── Return types ──────────────────────────────────────────────────────────────

@dataclass
class VerifyBreak:
    idx: int | None
    reason: str
    expected: Any = None
    got: Any = None


@dataclass
class VerifyResult:
    ok: bool
    rows_checked: int
    workspace_id: str | None
    breaks: list[VerifyBreak]
    legacy_unverifiable: list[int]
    head_hash: str | None


@dataclass
class VerifyReceiptResult:
    ok: bool
    receipt_in_chain: bool
    chain_ok: bool
    breaks: list[VerifyBreak]


# ── Internal helpers ──────────────────────────────────────────────────────────

def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical(obj: dict[str, Any]) -> str:
    # Mirror JS: JSON.stringify(obj, Object.keys(obj).sort())
    # The array-replacer form only outputs keys that appear in the top-level key
    # list — nested objects are filtered to those same keys. Python's sort_keys=True
    # sorts all levels and cannot replicate this, so we do it manually.
    top_keys = sorted(obj.keys())
    allowed = set(top_keys)

    def _filter(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: _filter(v) for k, v in value.items() if k in allowed}
        if isinstance(value, list):
            return [_filter(item) for item in value]
        return value

    filtered = {k: _filter(obj[k]) for k in top_keys}
    return json.dumps(filtered, separators=(",", ":"), ensure_ascii=False)


# ── Public API ────────────────────────────────────────────────────────────────

def is_reproducible_row(row: dict[str, Any]) -> bool:
    """True if the row carries a stored canonical preimage (THEA-314 row)."""
    c = row.get("canonical")
    return isinstance(c, str) and len(c) > 0


# Alias — matches the verifier's published vocabulary.
can_verify = is_reproducible_row


def recompute_hash(row: dict[str, Any]) -> str:
    """Recompute the SHA-256 hash for a single row (SPEC.md §3.3, §6)."""
    if is_reproducible_row(row):
        return _sha256_hex(row["canonical"] + row["prev_hash"])

    # Legacy: reconstruct payload from typed columns (SPEC.md §6).
    # Only include keys that are present in the row (absent key == JS undefined → dropped).
    payload: dict[str, Any] = {}
    for key in ("workspace_id", "idx", "prev_hash", "query", "route_summary",
                "atom_refs", "tier", "latency_ms", "ts"):
        if key in row:
            payload[key] = row[key]
    return _sha256_hex(_canonical(payload) + row["prev_hash"])


def verify_chain(
    rows: list[dict[str, Any]],
    *,
    anchor: dict[str, Any] | None = None,
) -> VerifyResult:
    """
    Verify a workspace audit chain (SPEC.md §5, §9).

    Pass all rows for one workspace, or a contiguous slice with anchor.
    Rows may arrive in any order — sorted by idx internally.

    anchor: dict with keys ``idx`` (first row's idx) and ``prev_hash``
            (hash of the row immediately before the slice).
    """
    result = VerifyResult(
        ok=True,
        rows_checked=0,
        workspace_id=rows[0]["workspace_id"] if rows else None,
        breaks=[],
        legacy_unverifiable=[],
        head_hash=None,
    )

    if not rows:
        result.ok = False
        result.breaks.append(VerifyBreak(idx=None, reason="empty_chain"))
        return result

    ws_ids = {r["workspace_id"] for r in rows}
    if len(ws_ids) > 1:
        result.ok = False
        result.breaks.append(VerifyBreak(idx=None, reason="multiple_workspaces", got=sorted(ws_ids)))
        return result

    sorted_rows = sorted(rows, key=lambda r: r["idx"])
    expected_prev = anchor["prev_hash"] if anchor else GENESIS
    expected_idx = anchor["idx"] if anchor else 0

    for row in sorted_rows:
        result.rows_checked += 1

        if row["idx"] != expected_idx:
            result.ok = False
            result.breaks.append(VerifyBreak(
                idx=row["idx"], reason="idx_discontinuity",
                expected=expected_idx, got=row["idx"],
            ))
            expected_idx = row["idx"]

        if row["prev_hash"] != expected_prev:
            result.ok = False
            result.breaks.append(VerifyBreak(
                idx=row["idx"], reason="broken_link",
                expected=expected_prev, got=row["prev_hash"],
            ))

        if is_reproducible_row(row):
            recomputed = recompute_hash(row)
            if recomputed != row["hash"]:
                result.ok = False
                result.breaks.append(VerifyBreak(
                    idx=row["idx"], reason="hash_mismatch",
                    expected=recomputed, got=row["hash"],
                ))
        else:
            result.legacy_unverifiable.append(row["idx"])

        expected_prev = row["hash"]
        expected_idx = row["idx"] + 1
        result.head_hash = row["hash"]

    return result


def verify_receipt(receipt: dict[str, Any], chain_rows: list[dict[str, Any]]) -> VerifyReceiptResult:
    """Verify a single receipt against the full chain rows (SPEC.md §5)."""
    chain = verify_chain(chain_rows)
    in_chain = any(r["idx"] == receipt["idx"] and r["hash"] == receipt["hash"] for r in chain_rows)
    return VerifyReceiptResult(
        ok=chain.ok and in_chain,
        receipt_in_chain=in_chain,
        chain_ok=chain.ok,
        breaks=chain.breaks,
    )
