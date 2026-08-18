import hashlib
import json
import pytest

from thea_audit_verifier import (
    GENESIS,
    verify_chain,
    verify_receipt,
    recompute_hash,
    is_reproducible_row,
    can_verify,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical(obj: dict) -> str:
    """Mirror the JS array-replacer canonical — sorts top-level keys only."""
    top_keys = sorted(obj.keys())
    allowed = set(top_keys)

    def _filter(v):
        if isinstance(v, dict):
            return {k: _filter(val) for k, val in v.items() if k in allowed}
        if isinstance(v, list):
            return [_filter(i) for i in v]
        return v

    filtered = {k: _filter(obj[k]) for k in top_keys}
    return json.dumps(filtered, separators=(",", ":"), ensure_ascii=False)


def build_chain(ws: str, n: int) -> list[dict]:
    rows = []
    prev = GENESIS
    for idx in range(n):
        payload = {
            "workspace_id": ws,
            "idx": idx,
            "prev_hash": prev,
            "query": f"q{idx}",
            "route_summary": {"cb_missions": idx, "atoms_matched": idx + 1},
            "atom_refs": [f"cite_{idx}"],
            "tier": "none",
            "latency_ms": 10 + idx,
            "ts": f"2026-05-31T00:00:{str(idx).zfill(2)}.000Z",
        }
        c = canonical(payload)
        h = sha256_hex(c + prev)
        rows.append({**payload, "hash": h, "canonical": c})
        prev = h
    return rows


def build_legacy_chain(ws: str, n: int) -> list[dict]:
    return [{k: v for k, v in row.items() if k != "canonical"} for row in build_chain(ws, n)]


# ── THEA-314 happy path ───────────────────────────────────────────────────────

class TestThea314Chain:
    def test_verifies_valid_chain(self):
        chain = build_chain("beefycorp", 5)
        r = verify_chain(chain)
        assert r.ok is True
        assert r.rows_checked == 5
        assert r.legacy_unverifiable == []

    def test_recompute_hash_uses_canonical_preimage(self):
        chain = build_chain("beefycorp", 5)
        assert recompute_hash(chain[2]) == chain[2]["hash"]

    def test_is_reproducible_row_true_for_thea314(self):
        assert is_reproducible_row(build_chain("ws", 1)[0]) is True

    def test_can_verify_alias(self):
        row = build_chain("ws", 1)[0]
        assert can_verify(row) == is_reproducible_row(row)

    def test_detects_mutated_canonical(self):
        chain = build_chain("beefycorp", 5)
        chain[2]["canonical"] = chain[2]["canonical"].replace("q2", "TAMPERED")
        r = verify_chain(chain)
        assert r.ok is False
        assert any(b.idx == 2 and b.reason == "hash_mismatch" for b in r.breaks)

    def test_mutating_typed_query_without_changing_canonical_does_not_break(self):
        chain = build_chain("beefycorp", 5)
        chain[2]["query"] = "DIFFERENT"
        assert verify_chain(chain).ok is True

    def test_detects_broken_chain_link(self):
        chain = build_chain("beefycorp", 5)
        chain[3]["prev_hash"] = "deadbeef"
        r = verify_chain(chain)
        assert r.ok is False
        assert any(b.idx == 3 and b.reason == "broken_link" for b in r.breaks)

    def test_detects_deleted_row(self):
        chain = [r for r in build_chain("beefycorp", 5) if r["idx"] != 2]
        r = verify_chain(chain)
        assert r.ok is False
        assert any(b.reason in ("idx_discontinuity", "broken_link") for b in r.breaks)

    def test_detects_silent_insert(self):
        chain = build_chain("beefycorp", 5)
        fake_payload = {
            "workspace_id": "beefycorp", "idx": 2, "prev_hash": chain[1]["hash"],
            "query": "INSERTED", "route_summary": {}, "atom_refs": [], "tier": "none",
            "latency_ms": 1, "ts": "2026-05-31T00:00:02.500Z",
        }
        chain.append({**fake_payload, "canonical": canonical(fake_payload), "hash": "fakehash"})
        assert verify_chain(chain).ok is False


# ── Receipts ──────────────────────────────────────────────────────────────────

class TestVerifyReceipt:
    def test_genuine_receipt_verifies(self):
        chain = build_chain("beefycorp", 5)
        receipt = {"idx": 3, "hash": chain[3]["hash"], "prev_hash": chain[3]["prev_hash"], "ts": chain[3]["ts"]}
        assert verify_receipt(receipt, chain).ok is True

    def test_forged_receipt_hash_fails(self):
        chain = build_chain("beefycorp", 5)
        receipt = {"idx": 3, "hash": "notreal", "prev_hash": chain[3]["prev_hash"], "ts": chain[3]["ts"]}
        assert verify_receipt(receipt, chain).ok is False


# ── Cross-cutting guards ──────────────────────────────────────────────────────

class TestCrossCuttingGuards:
    def test_rejects_mixed_workspace_chain(self):
        a = build_chain("a", 2)
        b = build_chain("b", 2)
        assert verify_chain([*a, *b]).ok is False

    def test_rejects_empty_chain(self):
        assert verify_chain([]).ok is False


# ── Legacy (pre-THEA-314) rows ────────────────────────────────────────────────

class TestLegacyRows:
    def test_chain_link_checks_pass_on_legacy_chain(self):
        chain = build_legacy_chain("beefycorp", 3)
        r = verify_chain(chain)
        assert r.ok is True
        assert len(r.legacy_unverifiable) == 3

    def test_is_reproducible_row_false_for_legacy(self):
        assert is_reproducible_row(build_legacy_chain("ws", 1)[0]) is False

    def test_recompute_hash_returns_hex_string_for_legacy(self):
        assert isinstance(recompute_hash(build_legacy_chain("ws", 1)[0]), str)

    def test_detects_broken_link_in_legacy_chain(self):
        chain = build_legacy_chain("beefycorp", 3)
        chain[1]["prev_hash"] = "forged"
        r = verify_chain(chain)
        assert r.ok is False
        assert any(b.reason == "broken_link" for b in r.breaks)


# ── Mixed chain (legacy + THEA-314) ──────────────────────────────────────────

class TestMixedChain:
    def _build_mixed(self):
        legacy = build_legacy_chain("mixed", 3)
        tail = []
        prev = legacy[2]["hash"]
        for idx in range(3, 5):
            payload = {
                "workspace_id": "mixed", "idx": idx, "prev_hash": prev,
                "query": f"c{idx}", "route_summary": {}, "atom_refs": [],
                "tier": "none", "latency_ms": 7 + idx,
                "ts": f"2026-06-27T00:00:{str(idx).zfill(2)}.000Z",
            }
            c = canonical(payload)
            h = sha256_hex(c + prev)
            tail.append({**payload, "hash": h, "canonical": c})
            prev = h
        return [*legacy, *tail]

    def test_verifies_clean_across_legacy_canonical_boundary(self):
        r = verify_chain(self._build_mixed())
        assert r.ok is True
        assert r.rows_checked == 5
        assert r.legacy_unverifiable == [0, 1, 2]

    def test_catches_tamper_on_canonical_row_in_mixed_chain(self):
        mixed = self._build_mixed()
        mixed[3] = {**mixed[3], "canonical": mixed[3]["canonical"].replace("c3", "TAMPERED")}
        r = verify_chain(mixed)
        assert r.ok is False
        assert any(b.idx == 3 and b.reason == "hash_mismatch" for b in r.breaks)


# ── Anchor / slice verification ───────────────────────────────────────────────

class TestAnchor:
    def test_verifies_slice_with_valid_anchor(self):
        full = build_chain("slice", 6)
        anchor = {"idx": 3, "prev_hash": full[2]["hash"]}
        r = verify_chain(full[3:], anchor=anchor)
        assert r.ok is True
        assert r.rows_checked == 3

    def test_catches_broken_link_at_slice_start_vs_anchor(self):
        full = build_chain("slice", 6)
        sliced = [
            {**r, "prev_hash": "forged"} if i == 0 else r
            for i, r in enumerate(full[3:])
        ]
        r = verify_chain(sliced, anchor={"idx": 3, "prev_hash": full[2]["hash"]})
        assert r.ok is False
        assert any(b.reason == "broken_link" for b in r.breaks)


# ── Golden test vectors (SPEC.md §7) ─────────────────────────────────────────
# These are the normative vectors from the spec. A correct implementation must
# reproduce the exact hashes below — any deviation indicates a canonicalisation
# mismatch with the TypeScript reference implementation.

VECTOR_1_CANONICAL = (
    '{"acting_role":"default","brain_versions":{},"chain_seq":0,'
    '"key_id_hash":"91322071511d56d4d5c97421c29843a9e42367e35cf2ed0b4cae6bad61152214",'
    '"prev_hash":"(genesis)",'
    '"query_hash":"81e041787e431a4ca43bb36f9612e192230612f13e0d0f518e7f89251527994f",'
    '"records_routed":null,"request_id":"nonce-20260101-abc",'
    '"response_hash":"53410b589b036457a1dab51f49e86b614324c138df8229c97eb660f48c1a8a9a",'
    '"signature":"aabbccdd00000000000000000000000000000000000000000000000000000000",'
    '"signing_key_version":"hmac-sha256-v1","status":"success",'
    '"workspace_id":"ws_example_00000001"}'
)
VECTOR_1_HASH = "f15ed3ee533206747cfc5a934568e846bb62eb9abf8206d7004c8d17d0a77b7f"

VECTOR_2_CANONICAL = (
    '{"acting_role":"default","brain_versions":{},"chain_seq":1,'
    '"key_id_hash":"91322071511d56d4d5c97421c29843a9e42367e35cf2ed0b4cae6bad61152214",'
    f'"prev_hash":"{VECTOR_1_HASH}",'
    '"query_hash":"d02421d8f8b7083f20af17fb44b48bbf0f4ebdb8741edab81bd1222e3ebc7803",'
    '"records_routed":1,"request_id":"nonce-20260101-xyz",'
    '"response_hash":"972f8126d3235fa1678fd63fcb0e0185102328fd44c73ba5af9e0fbe13db187e",'
    '"signature":"bbccddee00000000000000000000000000000000000000000000000000000000",'
    '"signing_key_version":"hmac-sha256-v1","status":"success",'
    '"workspace_id":"ws_example_00000001"}'
)
VECTOR_2_HASH = "5aeb803db54ce5d1d982f1699a4fe87ee4fc68f9c498bf2e186468381dbaebeb"

VECTOR_3_HASH = "3a469b96d070939b6daef96e396ad7b4454628a7f89af1902af83987d368b0eb"

ROW_1 = {
    "workspace_id": "ws_example_00000001",
    "idx": 0,
    "prev_hash": GENESIS,
    "hash": VECTOR_1_HASH,
    "canonical": VECTOR_1_CANONICAL,
}
ROW_2 = {
    "workspace_id": "ws_example_00000001",
    "idx": 1,
    "prev_hash": VECTOR_1_HASH,
    "hash": VECTOR_2_HASH,
    "canonical": VECTOR_2_CANONICAL,
}
LEGACY_ROW = {
    "workspace_id": "ws_example_00000001",
    "idx": 0,
    "prev_hash": GENESIS,
    "hash": VECTOR_3_HASH,
    "query": "what is the total PO value?",
    "route_summary": {"cb_missions": 1, "atoms_matched": 3},
    "atom_refs": ["cite_001", "cite_002"],
    "tier": "none",
    "latency_ms": 87,
    "ts": "2026-01-01T00:00:00.000Z",
}


class TestGoldenVectors:
    def test_vector_1_recompute_hash_matches_spec(self):
        assert recompute_hash(ROW_1) == VECTOR_1_HASH

    def test_vector_2_recompute_hash_matches_spec(self):
        assert recompute_hash(ROW_2) == VECTOR_2_HASH

    def test_vector_1_and_2_chain_verifies(self):
        r = verify_chain([ROW_1, ROW_2])
        assert r.ok is True
        assert r.rows_checked == 2
        assert r.head_hash == VECTOR_2_HASH
        assert r.legacy_unverifiable == []

    def test_vector_3_legacy_recompute_matches_spec(self):
        assert recompute_hash(LEGACY_ROW) == VECTOR_3_HASH

    def test_vector_3_wrong_ts_format_produces_different_hash(self):
        wrong_ts_row = {**LEGACY_ROW, "ts": "2026-01-01T00:00:00.000+00:00"}
        assert recompute_hash(wrong_ts_row) != VECTOR_3_HASH

    def test_vector_3_chain_link_passes_row_in_legacy_unverifiable(self):
        r = verify_chain([LEGACY_ROW])
        assert r.ok is True
        assert 0 in r.legacy_unverifiable
