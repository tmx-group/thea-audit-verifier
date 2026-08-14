# Thea Audit-Chain Receipt Format — Specification

Version 1.0 · 2026-08-04

---

## Purpose

Every query sent to the Thea API produces an immutable audit receipt. Receipts form a hash chain: each entry commits to the one before it, so any deletion, insertion, or modification of a row breaks the chain in a way that a third party can detect independently — without trusting TMX.

This document is the specification that both the gateway (which writes the chain) and any verifier (which reads it) must implement byte-for-byte. The reference implementation is `src/verify.js` in this repository.

---

## Definitions

| Term | Meaning |
|---|---|
| `chain_seq` | Monotonically increasing integer, starting at 0. Database column name. |
| `idx` | The same integer in verifier and API vocabulary. `idx == chain_seq`. |
| `prev_hash` | The `hash` of the preceding row; `(genesis)` for the first row. |
| `hash` | SHA-256 of `canonical(payload) + prev_hash` (see §3). |
| `canonical` | The exact JSON preimage string that was hashed (stored in the DB as the `canonical` column from migration 0014 onward). |
| THEA-314 row | Any row written after migration 0014. Has `canonical != NULL`. Hash-verifiable. |
| Legacy row | Any row written before migration 0014. Has `canonical = NULL`. Chain-link checks still run; per-row hash verification is skipped. |

---

## 1. Receipt shape

What the API returns on `GET /v1/receipts` and inside every `POST /v1/query` response:

```
{
  idx:                  integer   // chain_seq; 0-based, contiguous
  hash:                 string    // hex SHA-256 of SHA-256(canonical + prev_hash)
  prev_hash:            string    // previous hash, or "(genesis)"
  ts:                   string    // ISO-8601 UTC, Z suffix, millisecond precision
  request_id:           string?   // the X-Thea-Nonce header value of the request
  signing_key_version:  string?   // describes the hash construction, e.g. "hmac-sha256-v1"
}
```

### `ts` format

`ts` **must** be `YYYY-MM-DDTHH:MM:SS.sssZ` — ISO-8601 UTC with the `Z` suffix and millisecond precision.

Postgres serialises `timestamptz` as `+00:00` (e.g. `2026-06-17T08:31:10.189+00:00`). This is a different byte sequence from `2026-06-17T08:31:10.189Z`. For legacy rows, `ts` is part of the hashed payload (see §6), so the two forms produce **different hashes** — an external auditor pulling rows directly from Postgres would see a hash_mismatch for every legacy row until they normalise the timestamp.

**The audit-read endpoint (`GET /v1/receipts`, `POST /v1/audit/seal`) MUST emit `ts` in Z form, not raw `timestamptz`.** External auditors must not have to massage the timestamp format before verification.

_(Finding: THEA-278 independent verification, 2026-06-17.)_

---

## 2. Row payload fields (THEA-314 / current construction)

The gateway writes every chain row using these fields. The canonical JSON of these fields, concatenated with `prev_hash`, is what gets hashed:

| Field | Type | Source |
|---|---|---|
| `acting_role` | string | Literal `"default"` (role-based access planned but not yet used) |
| `brain_versions` | object | Engine output `brain_versions`; nested keys are dropped by canonical — see §3 |
| `chain_seq` | integer | Auto-incremented from the previous row's `chain_seq + 1`; `0` for the first row |
| `key_id_hash` | string | `SHA-256(key_id)` — the `X-Thea-Key` header value, hashed so the raw key ID is not stored |
| `prev_hash` | string | The `hash` of the previous row, or `(genesis)` for `chain_seq == 0` |
| `query_hash` | string | `SHA-256(rawBody)` — the raw request body bytes |
| `records_routed` | integer \| null | Engine output: number of records touched; `null` if not applicable |
| `request_id` | string | The `X-Thea-Nonce` header value (unique per request, replay-protected) |
| `response_hash` | string | `SHA-256(JSON.stringify(engineOut))` — the engine's full output |
| `signature` | string | The `X-Thea-Signature` header value: the caller's HMAC-SHA256 request signature (see §4) |
| `signing_key_version` | string | Literal `"hmac-sha256-v1"` — identifies the request-auth scheme used |
| `status` | string | `"success"` for a completed query |
| `workspace_id` | string | The workspace that owns this chain entry |

No `ts` field. Timestamps in the current construction come from the database `created_at` column and are not part of the hashed payload.

---

## 3. Hash construction

### 3.1 canonical()

```
canonical(payload) = JSON.stringify(payload, Object.keys(payload).sort())
```

- Top-level keys are sorted alphabetically.
- The array-replacer form of `JSON.stringify` is used. This means nested objects are serialised with only those sub-keys that also appear as top-level keys. In practice, nested objects like `brain_versions` and `route_summary` serialise as `{}` because their sub-keys (`brain-core`, `cb_missions`, …) are not top-level keys.
- No whitespace. No trailing newline.

### 3.2 hash()

```
hash(payload, prev_hash) = SHA-256( canonical(payload) + prev_hash )
```

- String concatenation: the canonical JSON string followed immediately by `prev_hash`.
- Encoded as lowercase hexadecimal (64 characters).
- For the first row (`chain_seq == 0`), `prev_hash` is the literal string `(genesis)`.

### 3.3 Stored preimage (THEA-314)

The exact canonical string is stored in the `canonical` column. The verifier rehashes this verbatim:

```
recomputeHash(row) = SHA-256( row.canonical + row.prev_hash )
```

Postgres normalises `jsonb` and `timestamptz` on the round-trip, which would change the canonical string if it were reconstructed from typed columns. Storing the preimage is what makes per-row tamper detection reproducible outside TMX.

---

## 4. Request signature stored in the chain

The `signature` field in every chain row is the `X-Thea-Signature` header value that the caller sent with the request. Including it in the canonical hash preimage means any tampering with which client signed a request is detectable.

**The verifier does not re-verify the HMAC** — that would require the client's secret, which is not published. The stored signature is tamper-evident (altering it breaks `hash`), but independent HMAC-validity checking is left to the workspace that holds the matching secret.

### HMAC-SHA256 signing scheme (for reference)

Every authenticated request carries four headers:

```
X-Thea-Key        — the API key ID (identifies the workspace)
X-Thea-Timestamp  — Unix epoch seconds, integer string
X-Thea-Nonce      — unique string per request
X-Thea-Signature  — HMAC-SHA256(signing_string, key_secret), lowercase hex
```

Signing string (newline-joined, exact order):

```
{METHOD}\n{path}\n{timestamp}\n{nonce}\n{rawBody}
```

`{METHOD}` is the request's own HTTP method, upper-cased. A signature for `GET` is not valid for `POST` on the same path.

---

## 5. Chain-link rules

A verifier must check every row in the chain:

1. **Contiguity** — `idx` values must be consecutive integers starting from 0 (or from the anchor, for slice verification). A gap or duplicate is a chain break.
2. **Link integrity** — `row.prev_hash` must equal the previous row's `hash` (or the anchor's `prev_hash` for slice start). A mismatch means a row was deleted, replaced, or inserted without re-linking.
3. **Hash integrity** (THEA-314 rows only) — `SHA-256(row.canonical + row.prev_hash)` must equal `row.hash`. A mismatch means the row's content was altered after writing.
4. **Single workspace** — all rows must share the same `workspace_id`. A mixed-workspace input is rejected.

Legacy rows (no `canonical` column) skip check 3 and are listed in `result.legacy_unverifiable`.

### Slice verification

A verifier can check a contiguous slice of a chain without the full history by supplying an anchor:

```
anchor = { idx: N, prev_hash: "<hash of row N-1>" }
```

The first row in the slice must have `idx == N` and `prev_hash == anchor.prev_hash`.

---

## 6. Legacy row construction (pre-THEA-314)

Rows written before migration 0014 have no `canonical` column. Chain-link checks still run against the stored `hash`, but per-row hash verification is unreliable (Postgres normalises the typed columns on round-trip).

For completeness, the original payload fields were:

| Field | Notes |
|---|---|
| `workspace_id` | string |
| `idx` | integer (same as `chain_seq`) |
| `prev_hash` | string |
| `query` | raw query text |
| `route_summary` | object; nested keys dropped by canonical |
| `atom_refs` | array of strings |
| `tier` | string |
| `latency_ms` | integer |
| `ts` | **ISO-8601 Z form required** — see §1 |

---

## 7. Golden test vectors

These vectors are computed from the exact algorithms above. A correct implementation must produce the same hex values.

### 7.1 Inputs used across vectors

```
workspace_id:        "ws_example_00000001"
key_id:              "tk_aabbccddeeff0011"
key_id_hash:         SHA-256("tk_aabbccddeeff0011")
                   = 91322071511d56d4d5c97421c29843a9e42367e35cf2ed0b4cae6bad61152214
```

### 7.2 Vector 1 — first row (chain_seq 0, genesis)

**Request:**
```
rawBody:       {"query":"what is the total PO value?"}
query_hash:    SHA-256(rawBody)
             = 81e041787e431a4ca43bb36f9612e192230612f13e0d0f518e7f89251527994f

engineOut:     {"answer":"The total PO value is $4,821,300.","brain_versions":{"brain-core":"0.9.1"}}
response_hash: SHA-256(JSON.stringify(engineOut))
             = 53410b589b036457a1dab51f49e86b614324c138df8229c97eb660f48c1a8a9a

signature:     aabbccdd00000000000000000000000000000000000000000000000000000000
request_id:    nonce-20260101-abc
```

**Canonical payload (sorted keys, exact string):**
```json
{"acting_role":"default","brain_versions":{},"chain_seq":0,"key_id_hash":"91322071511d56d4d5c97421c29843a9e42367e35cf2ed0b4cae6bad61152214","prev_hash":"(genesis)","query_hash":"81e041787e431a4ca43bb36f9612e192230612f13e0d0f518e7f89251527994f","records_routed":null,"request_id":"nonce-20260101-abc","response_hash":"53410b589b036457a1dab51f49e86b614324c138df8229c97eb660f48c1a8a9a","signature":"aabbccdd00000000000000000000000000000000000000000000000000000000","signing_key_version":"hmac-sha256-v1","status":"success","workspace_id":"ws_example_00000001"}
```

Note: `brain_versions` is `{}` because its sub-key `"brain-core"` is not a top-level payload key (see §3.1).

**Result:**
```
prev_hash:  (genesis)
hash:       f15ed3ee533206747cfc5a934568e846bb62eb9abf8206d7004c8d17d0a77b7f
```

### 7.3 Vector 2 — second row (chain_seq 1, chained from Vector 1)

**Request:**
```
rawBody:       {"execute":"SELECT SUM(amount) FROM purchase_orders"}
query_hash:    d02421d8f8b7083f20af17fb44b48bbf0f4ebdb8741edab81bd1222e3ebc7803

engineOut:     {"records":[{"sum":4821300}],"brain_versions":{"brain-core":"0.9.1"}}
response_hash: 972f8126d3235fa1678fd63fcb0e0185102328fd44c73ba5af9e0fbe13db187e

signature:     bbccddee00000000000000000000000000000000000000000000000000000000
request_id:    nonce-20260101-xyz
records_routed: 1
```

**Canonical payload (exact string):**
```json
{"acting_role":"default","brain_versions":{},"chain_seq":1,"key_id_hash":"91322071511d56d4d5c97421c29843a9e42367e35cf2ed0b4cae6bad61152214","prev_hash":"f15ed3ee533206747cfc5a934568e846bb62eb9abf8206d7004c8d17d0a77b7f","query_hash":"d02421d8f8b7083f20af17fb44b48bbf0f4ebdb8741edab81bd1222e3ebc7803","records_routed":1,"request_id":"nonce-20260101-xyz","response_hash":"972f8126d3235fa1678fd63fcb0e0185102328fd44c73ba5af9e0fbe13db187e","signature":"bbccddee00000000000000000000000000000000000000000000000000000000","signing_key_version":"hmac-sha256-v1","status":"success","workspace_id":"ws_example_00000001"}
```

**Result:**
```
prev_hash:  f15ed3ee533206747cfc5a934568e846bb62eb9abf8206d7004c8d17d0a77b7f
hash:       5aeb803db54ce5d1d982f1699a4fe87ee4fc68f9c498bf2e186468381dbaebeb
```

### 7.4 Vector 3 — legacy row (pre-THEA-314, idx 0)

**Important:** `ts` must be ISO-8601 Z form. Using `+00:00` produces a different hash.

**Payload:**
```json
{
  "workspace_id": "ws_example_00000001",
  "idx": 0,
  "prev_hash": "(genesis)",
  "query": "what is the total PO value?",
  "route_summary": { "cb_missions": 1, "atoms_matched": 3 },
  "atom_refs": ["cite_001", "cite_002"],
  "tier": "none",
  "latency_ms": 87,
  "ts": "2026-01-01T00:00:00.000Z"
}
```

**Canonical payload (exact string):**
```json
{"atom_refs":["cite_001","cite_002"],"idx":0,"latency_ms":87,"prev_hash":"(genesis)","query":"what is the total PO value?","route_summary":{},"tier":"none","ts":"2026-01-01T00:00:00.000Z","workspace_id":"ws_example_00000001"}
```

Note: `route_summary` is `{}` because `cb_missions` and `atoms_matched` are not top-level payload keys (see §3.1).

**Result:**
```
prev_hash:  (genesis)
hash:       3a469b96d070939b6daef96e396ad7b4454628a7f89af1902af83987d368b0eb
```

### 7.5 Request HMAC signing (for reference)

```
algorithm:      HMAC-SHA256
secret:         super-secret-key-example-do-not-use   ← illustrative only
signing string: POST\n/v1/query\n1751328000\nnonce-20260101-abc\n{"query":"what is the total PO value?"}
X-Thea-Signature: 02e09371baa730afc2a99d83b405549a2495e7668a718c0874a79ab3b3ff070f
```

---

## 8. Canonical key order reference

**THEA-314 (current) rows — alphabetical order:**

```
acting_role, brain_versions, chain_seq, key_id_hash, prev_hash,
query_hash, records_routed, request_id, response_hash, signature,
signing_key_version, status, workspace_id
```

**Legacy rows — alphabetical order:**

```
atom_refs, idx, latency_ms, prev_hash, query, route_summary, tier, ts, workspace_id
```

---

## 9. Verification algorithm (normative)

```
function verifyChain(rows, opts = {}):
  sort rows by idx ascending
  anchor = opts.anchor ?? { idx: 0, prev_hash: "(genesis)" }
  expectedIdx = anchor.idx
  expectedPrev = anchor.prev_hash

  for each row in sorted:
    if row.idx != expectedIdx:
      record break: idx_discontinuity
      expectedIdx = row.idx   // continue from actual idx

    if row.prev_hash != expectedPrev:
      record break: broken_link

    if row.canonical is present and non-empty:
      recomputed = SHA-256(row.canonical + row.prev_hash)
      if recomputed != row.hash:
        record break: hash_mismatch
    else:
      record row.idx in legacy_unverifiable

    expectedPrev = row.hash
    expectedIdx = row.idx + 1

  return { ok, rows_checked, workspace_id, breaks, legacy_unverifiable, head_hash }
```

All rows must belong to a single `workspace_id`. Mixed-workspace input must be rejected immediately.

---

## 10. Open items

- **Signature verification.** The `signature` field is stored and included in the hash preimage, providing tamper evidence. Independent HMAC-validity checking (proving the stored signature was valid when written) would require the client's secret. This is not yet supported in the verifier.
- **Role-based entries.** `acting_role` is currently always `"default"`. Role-scoped audit entries are planned (THEA-81).
- **Ed25519 signing.** A future version may add an Ed25519 signature over the chain head, allowing the public key embedded in the verifier package to certify the chain without the client's HMAC secret.
