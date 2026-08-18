import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { verifyChain, type AuditChainRow } from './verify.js';

// ── Argument parsing ──────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const isJson    = args.includes('--json');
const isVerbose = args.includes('--verbose');
const positional = args.filter(a => !a.startsWith('--'));

function die(msg: string): never {
  process.stderr.write(msg + '\n');
  process.exit(2);
}

if (positional[0] !== 'verify') {
  die('Usage: audit-verifier verify <chain-file.json> [--json] [--verbose]');
}

const filePath = positional[1];
if (!filePath) {
  die('Usage: audit-verifier verify <chain-file.json> [--json] [--verbose]');
}

// ── Load chain ────────────────────────────────────────────────────────────────

let rows: AuditChainRow[];
try {
  const raw = readFileSync(resolve(filePath), 'utf8');
  const parsed: unknown = JSON.parse(raw);
  // Accept a bare array or an object with a `rows` / `chain` key.
  const candidate = Array.isArray(parsed)
    ? parsed
    : (parsed as Record<string, unknown>).rows ?? (parsed as Record<string, unknown>).chain;
  if (!Array.isArray(candidate) || candidate.length === 0) {
    die('chain file must contain a non-empty JSON array of rows (or an object with a "rows" or "chain" key)');
  }
  rows = candidate as AuditChainRow[];
} catch (err) {
  if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
    die(`file not found: ${filePath}`);
  }
  // Re-throw only if it isn't already a process.exit path (i.e. die wasn't called).
  die(`could not read ${filePath}: ${(err as Error).message}`);
}

// ── Verify ────────────────────────────────────────────────────────────────────

const result = verifyChain(rows);

// ── JSON output (developer / scripting) ──────────────────────────────────────

if (isJson) {
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  process.exit(result.ok ? 0 : 1);
}

// ── Human-readable output ─────────────────────────────────────────────────────

const statusMark = result.ok ? '✓ PASS' : '✗ FAIL';
const ws         = result.workspace_id ?? '(unknown)';

process.stdout.write(`${statusMark}  workspace ${ws}  ${result.rows_checked} rows checked\n`);

if (result.legacy_unverifiable.length > 0) {
  process.stdout.write(
    `  ⚠  ${result.legacy_unverifiable.length} legacy row(s) — chain links verified, per-row hash skipped` +
    ` (idx: ${result.legacy_unverifiable.join(', ')})\n`,
  );
}

if (result.head_hash) {
  process.stdout.write(`  head: ${result.head_hash}\n`);
}

if (!result.ok) {
  process.stdout.write(`\n  ${result.breaks.length} break(s):\n`);
  for (const b of result.breaks) {
    const loc = b.idx != null ? `row ${b.idx}` : 'chain';
    process.stdout.write(`    ${loc}: ${b.reason}\n`);
    if (isVerbose) {
      if (b.expected !== undefined) process.stdout.write(`      expected: ${b.expected}\n`);
      if (b.got      !== undefined) process.stdout.write(`      got:      ${b.got}\n`);
    }
  }
  process.exit(1);
}
