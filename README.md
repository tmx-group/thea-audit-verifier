# @tmx-group/audit-verifier

Standalone, **zero-dependency** verifier for Thea API hash-chained audit receipts.

Every answer the Thea API returns is recorded as a row in a tamper-evident hash
chain. This package lets **anyone** — you, an auditor, a customer's own
compliance team — independently confirm that an answer happened and has not been
altered, **without trusting TMX or the API**. It runs offline, makes no network
calls, and has no dependencies beyond Node's built-in `crypto`.

## Install

**As a library** (developers integrating verification into their own code):

```bash
npm install @tmx-group/audit-verifier
```

**As a CLI** (compliance teams and auditors verifying a chain file offline):

```bash
npm install -g @tmx-group/audit-verifier
```

Requires Node.js >= 18.

## What it checks

Given the rows of a workspace's audit chain, the verifier:

- **recomputes** each row's hash from its payload, using the exact construction
  the gateway used — `sha256(canonical(payload) + prev_hash)`;
- confirms each row's `prev_hash` links to the previous row's `hash`;
- confirms `idx` is contiguous and monotonic from 0 (no inserted, removed, or
  reordered rows);
- rejects chains that mix more than one `workspace_id`;
- reports **all breaks**, each with the offending `idx` and reason.

## CLI usage

The `audit-verifier` command reads a JSON file containing the chain rows and
reports whether the chain is intact.

### Compliance — plain-text pass/fail

Run this after exporting your workspace's audit chain to `chain.json`:

```bash
audit-verifier verify chain.json
```

```
✓ PASS  workspace ws_acme_00000001  1 847 rows checked
  head: 9f3a1b…
```

Exit code is `0` on pass, `1` on any break.

### Auditor — full break details

Use `--verbose` to see the exact expected vs. actual values for every break:

```bash
audit-verifier verify chain.json --verbose
```

```
✗ FAIL  workspace ws_acme_00000001  1 847 rows checked

  1 break(s):
    row 204: broken_link
      expected: 7e3f9a…
      got:      deadbeef…
```

### Developer — JSON output for scripting

Use `--json` to get the full `VerifyResult` as JSON, suitable for piping to
`jq` or feeding into a CI check:

```bash
audit-verifier verify chain.json --json | jq '.ok'
```

```json
{
  "ok": true,
  "rows_checked": 1847,
  "workspace_id": "ws_acme_00000001",
  "breaks": [],
  "legacy_unverifiable": [],
  "head_hash": "9f3a1b…"
}
```

### Sample chains

The package ships two example files for sanity testing:

```bash
# should exit 0
audit-verifier verify node_modules/@tmx-group/audit-verifier/examples/chain-ok.json

# should exit 1 — row 1 has a tampered prev_hash
audit-verifier verify node_modules/@tmx-group/audit-verifier/examples/chain-broken.json
```

---

## Library usage

```js
import { verifyChain, verifyReceipt } from '@tmx-group/audit-verifier';

// `rows` is the full audit chain for one workspace, each row shaped:
// { workspace_id, idx, prev_hash, hash,
//   canonical? /* THEA-314+ rows: verbatim preimage; pass this if present */,
//   query?, route_summary?, atom_refs?, tier?, latency_ms?, ts? /* legacy only */ }
const result = verifyChain(rows);

if (result.ok) {
  console.log(`verified ${result.rows_checked} rows; head = ${result.head_hash}`);
} else {
  console.error('chain broken:', result.breaks);
  // e.g. [{ idx: 2, reason: 'hash_mismatch', expected: '…', got: '…' }]
}
```

Verify a single sealed-response receipt against the full chain:

```js
import { verifyReceipt } from '@tmx-group/audit-verifier';

// `receipt` is the { idx, hash, prev_hash, ts } anchor returned in a sealed
// response; `chainRows` is the workspace's audit chain.
const r = verifyReceipt(receipt, chainRows);
// { ok, receipt_in_chain, chain_ok, breaks }
```

## API

### `verifyChain(rows, opts?)`

Returns `{ ok, rows_checked, workspace_id, head_hash, breaks, legacy_unverifiable }`.
`breaks` is an array of `{ idx, reason, expected?, got? }`; `reason` is one of
`hash_mismatch`, `broken_link`, `idx_discontinuity`, or `multiple_workspaces`.
`legacy_unverifiable` lists indices of rows without a `canonical` preimage — their
chain links were checked but their per-row hash was not recomputed.

Pass `opts.anchor = { idx, prev_hash }` to verify a contiguous slice rather than a
full chain starting at genesis.

### `verifyReceipt(receipt, chainRows)`

Returns `{ ok, receipt_in_chain, chain_ok, breaks }`. `ok` is true only when the
full chain verifies **and** the receipt is genuinely present in it.

### `recomputeHash(row)`

Returns the hash the gateway would have stored for `row`. Exposed for advanced
checks and testing.

## Hash construction

The verifier mirrors the gateway exactly:

```
payload  = { workspace_id, idx, prev_hash, query, route_summary,
             atom_refs, tier, latency_ms, ts }
canonical = JSON.stringify(payload, TOP-LEVEL keys sorted)
hash      = sha256Hex( canonical + prev_hash )
genesis prev_hash = "(genesis)"
```

Only top-level keys are sorted — nested objects (e.g. `route_summary`) are
serialised in their stored key order, because the gateway's `canonical()` does
not deep-sort. This faithfulness is the whole point: deep-sorting here would make
hashes diverge and defeat verification.

## Tests

```bash
npm test
```

Covers valid chains, payload tampering, broken links, deleted rows, silent
inserts, forged receipts, and mixed-/empty-workspace rejection.

## License

Apache License 2.0 © The TMX Group ("TMX Group Ventures Pte Ltd"). See [LICENSE](./LICENSE)
and [NOTICE](./NOTICE).
