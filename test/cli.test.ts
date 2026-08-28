import { execSync, spawnSync } from 'node:child_process';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, it, expect } from 'vitest';

const ROOT     = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CLI      = resolve(ROOT, 'dist/cli.js');
const EXAMPLES = resolve(ROOT, 'examples');

beforeAll(() => {
  execSync('npm run build', { cwd: ROOT, stdio: 'pipe', shell: true });
});

function cli(...args: string[]) {
  return spawnSync('node', [CLI, ...args], { cwd: ROOT, encoding: 'utf8' });
}

// ── Default (compliance) output ───────────────────────────────────────────────

describe('compliance output (default)', () => {
  it('exits 0 and prints PASS on a valid chain', () => {
    const r = cli('verify', resolve(EXAMPLES, 'chain-ok.json'));
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('PASS');
    expect(r.stdout).toContain('2 rows checked');
  });

  it('exits 1 and prints FAIL on a broken chain', () => {
    const r = cli('verify', resolve(EXAMPLES, 'chain-broken.json'));
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('FAIL');
    expect(r.stdout).toContain('broken_link');
  });
});

// ── Auditor output (--verbose) ────────────────────────────────────────────────

describe('auditor output (--verbose)', () => {
  it('shows expected and got on a broken chain', () => {
    const r = cli('verify', resolve(EXAMPLES, 'chain-broken.json'), '--verbose');
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('expected:');
    expect(r.stdout).toContain('got:');
  });
});

// ── Developer output (--json) ─────────────────────────────────────────────────

describe('developer output (--json)', () => {
  it('exits 0 and outputs valid JSON for a clean chain', () => {
    const r = cli('verify', resolve(EXAMPLES, 'chain-ok.json'), '--json');
    expect(r.status).toBe(0);
    const out = JSON.parse(r.stdout);
    expect(out.ok).toBe(true);
    expect(out.rows_checked).toBe(2);
    expect(out.breaks).toHaveLength(0);
    expect(typeof out.head_hash).toBe('string');
  });

  it('exits 1 and outputs ok: false for a broken chain', () => {
    const r = cli('verify', resolve(EXAMPLES, 'chain-broken.json'), '--json');
    expect(r.status).toBe(1);
    const out = JSON.parse(r.stdout);
    expect(out.ok).toBe(false);
    expect(out.breaks.length).toBeGreaterThan(0);
  });
});

// ── Error handling ────────────────────────────────────────────────────────────

describe('error handling', () => {
  it('exits 2 when the file does not exist', () => {
    const r = cli('verify', 'nonexistent-file.json');
    expect(r.status).toBe(2);
  });

  it('exits 2 when no arguments are given', () => {
    const r = cli();
    expect(r.status).toBe(2);
  });
});
