import { createHash } from 'node:crypto';
import { verifyChain, verifyReceipt, recomputeHash } from '../src/verify.js';

let fails = 0;
const ok = (c, m) => { if (!c) { fails++; console.error('FAIL:', m); } };

const GENESIS = '(genesis)';
const sha256Hex = t => createHash('sha256').update(t).digest('hex');
const canonical = o => JSON.stringify(o, Object.keys(o).sort());

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
    const hash = sha256Hex(canonical(payload) + prev);
    rows.push({ ...payload, hash });
    prev = hash;
  }
  return rows;
}

{ const chain = buildChain('beefycorp', 5); const r = verifyChain(chain);
  ok(r.ok, `valid chain should verify, breaks: ${JSON.stringify(r.breaks)}`);
  ok(r.rows_checked === 5, 'should check all 5 rows');
  ok(recomputeHash(chain[2]) === chain[2].hash, 'verifier hash must match gateway hash'); }

{ const chain = buildChain('beefycorp', 5); chain[2].query = 'TAMPERED'; const r = verifyChain(chain);
  ok(!r.ok, 'payload tamper must be detected');
  ok(r.breaks.some(b => b.idx === 2 && b.reason === 'hash_mismatch'), 'flag hash_mismatch at idx 2'); }

{ const chain = buildChain('beefycorp', 5); chain[3].prev_hash = 'deadbeef'; const r = verifyChain(chain);
  ok(!r.ok, 'broken link must be detected');
  ok(r.breaks.some(b => b.idx === 3 && b.reason === 'broken_link'), 'flag broken_link at idx 3'); }

{ const chain = buildChain('beefycorp', 5).filter(r => r.idx !== 2); const r = verifyChain(chain);
  ok(!r.ok, 'deleted row must be detected');
  ok(r.breaks.some(b => b.reason === 'idx_discontinuity' || b.reason === 'broken_link'), 'flag gap'); }

{ const chain = buildChain('beefycorp', 5);
  chain.push({ workspace_id: 'beefycorp', idx: 2, prev_hash: chain[1].hash, query: 'INSERTED',
    route_summary: {}, atom_refs: [], tier: 'none', latency_ms: 1, ts: '2026-05-31T00:00:02.500Z', hash: 'fakehash' });
  ok(!verifyChain(chain).ok, 'silent insert must be detected'); }

{ const chain = buildChain('beefycorp', 5);
  const receipt = { idx: 3, hash: chain[3].hash, prev_hash: chain[3].prev_hash, ts: chain[3].ts };
  ok(verifyReceipt(receipt, chain).ok, 'genuine receipt should verify');
  ok(!verifyReceipt({ idx: 3, hash: 'notreal', prev_hash: chain[3].prev_hash, ts: chain[3].ts }, chain).ok, 'forged receipt must fail'); }

{ const a = buildChain('a', 2), b = buildChain('b', 2);
  ok(!verifyChain([...a, ...b]).ok, 'mixed-workspace chain must be rejected');
  ok(!verifyChain([]).ok, 'empty chain must be rejected'); }

console.log('─'.repeat(60));
console.log(`failures: ${fails}`);
if (fails === 0) { console.log('PASS — verifier agrees with gateway hash; detects tamper, broken links, gaps, inserts, forged receipts.'); process.exit(0); }
else { console.error('FAIL'); process.exit(1); }
