import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const CLI = join(ROOT, 'mac-worker.mjs');
const PASS = 'a long local passphrase 123';
const sh = (args, { env = {}, input } = {}) => {
  const state = env.RING_MAC_STATE_DIR;
  const e = { PATH: process.env.PATH, HOME: process.env.HOME, RING_MAC_STATE_DIR: state, ...env };
  return spawnSync(process.execPath, [CLI, ...args], { env: e, input, encoding: 'utf8' });
};
const fresh = () => join(mkdtempSync(join(tmpdir(), 'ring-mac-cli-')), 'state');

test('CLI keygen via env passphrase prints keyId/publicKeySpki/skeleton only', () => {
  const dir = fresh();
  const r = sh(['keygen', '--owner-ref', 'owner/cli', '--association-revision', '1'], { env: { RING_MAC_STATE_DIR: dir, RING_MAC_KEY_PASSPHRASE: PASS } });
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.deepEqual(Object.keys(out), ['keyId', 'publicKeySpki', 'approvalSkeleton']);
  assert.equal(out.approvalSkeleton.expectedRevision, 0); assert.equal('expiresAt' in out.approvalSkeleton, false);
  assert.equal((r.stdout + r.stderr).includes(PASS), false);
  const again = sh(['keygen', '--owner-ref', 'owner/cli', '--association-revision', '1'], { env: { RING_MAC_STATE_DIR: dir, RING_MAC_KEY_PASSPHRASE: PASS } });
  assert.notEqual(again.status, 0); assert.match(again.stderr, /^ERROR IDENTITY_EXISTS/mu);
  const st = JSON.parse(sh(['status'], { env: { RING_MAC_STATE_DIR: dir } }).stdout);
  assert.equal(st.enrolledIdentity.keyId, out.keyId);
});

test('CLI keygen via piped stdin; passphrase on argv is rejected; missing passphrase fails with ERROR', () => {
  const dir = fresh();
  const ok = sh(['keygen', '--owner-ref', 'owner/cli', '--association-revision', '2'], { env: { RING_MAC_STATE_DIR: dir }, input: PASS + '\n' });
  assert.equal(ok.status, 0, ok.stderr);
  const argv = sh(['keygen', '--owner-ref', 'owner/x', '--association-revision', '1', '--passphrase', PASS], { env: { RING_MAC_STATE_DIR: fresh() } });
  assert.equal(argv.status, 2); assert.match(argv.stderr, /^ERROR USAGE/mu); assert.equal(argv.stderr.includes(PASS), false);
  const none = sh(['keygen', '--owner-ref', 'owner/x', '--association-revision', '1'], { env: { RING_MAC_STATE_DIR: fresh() }, input: '' });
  assert.notEqual(none.status, 0); assert.match(none.stderr, /^ERROR PASSPHRASE_REQUIRED/mu);
});

test('CLI login-url prints only the authorize URL on stdout; run without identity prints ERROR', () => {
  const dir = fresh();
  const r = sh(['login-url'], { env: { RING_MAC_STATE_DIR: dir } });
  assert.equal(r.status, 0, r.stderr);
  const u = new URL(r.stdout.trim());
  assert.equal(u.hostname, 'your-prefix-abcdefghij.auth.us-east-1.amazoncognito.com');
  assert.equal(u.searchParams.get('client_id'), 'replacewithyourappclientid');
  assert.equal(u.searchParams.get('redirect_uri'), 'https://abcdefghij.execute-api.us-east-1.amazonaws.com/staging/auth/callback');
  assert.equal(u.searchParams.get('scope'), 'https://abcdefghij.execute-api.us-east-1.amazonaws.com/staging/mcp/tools.list https://abcdefghij.execute-api.us-east-1.amazonaws.com/staging/mcp/tools.call');
  const run = sh(['run', '--callback-url', 'https://x.invalid/'], { env: { RING_MAC_STATE_DIR: dir, RING_MAC_KEY_PASSPHRASE: PASS } });
  assert.notEqual(run.status, 0); assert.match(run.stderr, /^ERROR NO_IDENTITY_RUN_KEYGEN_FIRST/mu);
});

test('vendored library files match SHA256SUMS and (when present) the canonical src/formal-runtime copies', () => {
  const sums = readFileSync(join(ROOT, 'vendor', 'SHA256SUMS'), 'utf8').trim().split('\n').map(l => l.split(/\s+/u));
  assert.equal(sums.length, 11);
  const canonical = join(ROOT, '..', '..', '..', '..', '..', 'src', 'formal-runtime');
  for (const [sum, name] of sums) {
    const h = f => createHash('sha256').update(readFileSync(f)).digest('hex');
    assert.equal(h(join(ROOT, 'vendor', name)), sum, name);
    if (existsSync(join(canonical, name))) assert.equal(h(join(canonical, name)), sum, 'canonical drift: ' + name);
  }
});
