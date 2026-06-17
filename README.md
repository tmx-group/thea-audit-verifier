# @tmx-group/audit-verifier

Standalone, **zero-dependency** verifier for Thea API hash-chained audit receipts.

Every answer the Thea API returns is recorded as a row in a tamper-evident hash
chain. This package lets **anyone** — you, an auditor, a customer's own
compliance team — independently confirm that an answer happened and has not been
altered, **without trusting TMX or the API**. It runs offline, makes no network
calls, and has no dependencies beyond Node's built-in `crypto`.

## Install

```bash
npm install @tmx-group/audit-verifier
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
- reports the **first break**, with the offending `idx` and reason.

## Usage

```js
import { verifyChain, verifyReceipt } from '@tmx-group/audit-verifier';

// `rows` is the full audit chain for one workspace, each row shaped:
// { workspace_id, idx, prev_hash, query, route_summary,
//   atom_refs, tier, latency_ms, ts, hash }
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

Returns `{ ok, rows_checked, head_hash, breaks }`. `breaks` is an array of
`{ idx, reason, expected?, got? }`; `reason` is one of `hash_mismatch`,
`broken_link`, `idx_discontinuity`, or `multiple_workspaces`. Pass
`{ stopOnFirstBreak: true }` to stop walking at the first failure.

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
