import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { resolveConfig } from '../src/config.mjs';
import { loginUrl, bootstrap, enroll, ringDemo, accountIdSha256 } from '../src/launcher.mjs';
import { startFakeCloud, HOST, COGNITO_HOST } from './helpers/fake-cloud.mjs';

const cfg = resolveConfig({ apiBase: `https://${HOST}/staging`, cognitoDomain: `https://${COGNITO_HOST}`, clientId: 'abcdefghijklmnopqrstuvwxyz' });
const sha = s => createHash('sha256').update(s).digest('hex');
async function setup() {
  const stateDir = join(mkdtempSync(join(tmpdir(), 'ring-mac-owner-')), 'state');
  const cloud = await startFakeCloud({ enrollment: { publicKeySpki: 'x', ownerRef: 'owner/x', associationRevision: 1 }, audience: cfg.audience });
  const cb = async () => cloud.authorize((await loginUrl({ stateDir, cfg })).url);
  const common = async () => ({ stateDir, cfg, callbackUrl: await cb(), tokenRequest: cloud.reroute, httpsRequest: cloud.reroute });
  const noSecrets = (out) => {
    const dump = [out, ...(existsSync(stateDir) ? readdirSync(stateDir, { recursive: true }) : []).map(f => { try { return readFileSync(join(stateDir, f), 'utf8'); } catch { return ''; } })].join('\n');
    for (const secret of [cloud.state.token, cloud.state.ringToken, 'unused-refresh-token', cloud.state.ringAccountId, 'someone@example.com']) assert.equal(dump.includes(secret), false);
  };
  return { stateDir, cloud, common, noSecrets };
}

test('bootstrap: Bearer=Cognito token, JSON body only {ringAccessToken}, prints status only', async () => {
  const s = await setup();
  try {
    const r = await bootstrap({ ...await s.common(), ringToken: s.cloud.state.ringToken });
    assert.deepEqual(r, { operation: 'owner_bootstrap', httpStatus: 200, status: 'owner_bootstrapped', ok: true });
    const seen = s.cloud.state.seen.at(-1);
    assert.equal(seen.authorization, 'Bearer ' + s.cloud.state.token); assert.equal(seen.contentType, 'application/json');
    assert.deepEqual(JSON.parse(seen.body), { ringAccessToken: s.cloud.state.ringToken });
    s.noSecrets(JSON.stringify(r));
  } finally { await s.cloud.close(); }
});

test('bootstrap/enroll: wrong status and generic errors are reported without echoing bodies', async () => {
  const s = await setup();
  try {
    s.cloud.state.ownerResponse = { status: 403, body: { error: 'owner_exists', detail: 'LEAK ' + s.cloud.state.ringToken } };
    const r = await bootstrap({ ...await s.common(), ringToken: s.cloud.state.ringToken });
    assert.deepEqual(r, { operation: 'owner_bootstrap', httpStatus: 403, status: 'error:owner_exists', ok: false });
    s.cloud.state.ownerResponse = { status: 200, body: { status: 'something_else' } };
    assert.equal((await bootstrap({ ...await s.common(), ringToken: s.cloud.state.ringToken })).ok, false, '200 with unexpected status is not ok');
    s.cloud.state.ownerResponse = { status: 500, body: 'not json at all' };
    const e = await enroll(await s.common());
    assert.deepEqual(e, { operation: 'mac_enroll', httpStatus: 500, status: 'unknown', ok: false });
    s.noSecrets(JSON.stringify([r, e]));
  } finally { await s.cloud.close(); }
});

test('enroll: POST with Bearer and empty body', async () => {
  const s = await setup();
  try {
    const r = await enroll(await s.common());
    assert.equal(r.ok, true); assert.equal(r.httpStatus, 200);
    const seen = s.cloud.state.seen.at(-1);
    assert.equal(seen.url, '/staging/mac/enroll'); assert.equal(seen.method, 'POST');
    assert.equal(seen.authorization, 'Bearer ' + s.cloud.state.token); assert.equal(seen.body, '');
    s.noSecrets(JSON.stringify(r));
  } finally { await s.cloud.close(); }
});

test('bootstrap with a bad callback state or expired token never calls the API', async () => {
  const s = await setup();
  try {
    const c = await s.common(); const n = s.cloud.state.seen.length;
    await assert.rejects(bootstrap({ ...c, callbackUrl: c.callbackUrl.replace(/state=[^&]+/u, 'state=' + 'B'.repeat(43)), ringToken: 'x'.repeat(20) }), /CALLBACK_STATE_MISMATCH/u);
    s.cloud.state.tokenLifetimeSeconds = 1;
    await assert.rejects(enroll(await s.common()), /OAUTH_TOKEN_EXPIRED/u);
    assert.equal(s.cloud.state.seen.length, n);
  } finally { await s.cloud.close(); }
});

test('ring-demo: safe summary with sha256 of account id, empty device list accepted, no leaks', async () => {
  const s = await setup();
  try {
    const r = await ringDemo({ cfg, ringToken: s.cloud.state.ringToken, httpsRequest: s.cloud.reroute });
    assert.equal(r.ok, true); assert.equal(r.me.type, 'user');
    assert.equal(r.me.ringAccountIdSha256, sha(s.cloud.state.ringAccountId)); assert.equal(r.me.accountIdLength, s.cloud.state.ringAccountId.length);
    assert.equal(r.devices.deviceCount, 0); assert.deepEqual(r.devices.devices, []);
    assert.deepEqual(s.cloud.state.seen.map(x => [x.method, x.url]), [['GET', '/v1/users/me'], ['GET', '/v1/devices']]);
    assert.ok(s.cloud.state.seen.every(x => x.authorization === 'Bearer ' + s.cloud.state.ringToken));
    s.cloud.state.devices = [{ type: 'device', id: 'dev-0123456789abcdef', attributes: { status: 'online', capabilities: ['switch', { name: 'motion' }], serial: 'SERIAL-SECRET' } }];
    const d = await ringDemo({ cfg, ringToken: s.cloud.state.ringToken, httpsRequest: s.cloud.reroute });
    assert.equal(d.devices.deviceCount, 1);
    assert.deepEqual(d.devices.devices[0], { id: 'dev-01...(20)', type: 'device', status: 'online', capabilities: ['switch', 'motion'] });
    const text = JSON.stringify([r, d]);
    assert.equal(text.includes('SERIAL-SECRET'), false); assert.equal(text.includes('dev-0123456789abcdef'), false);
    s.noSecrets(text);
    s.cloud.state.ringStatus = 503;
    const bad = await ringDemo({ cfg, ringToken: s.cloud.state.ringToken, httpsRequest: s.cloud.reroute });
    assert.equal(bad.ok, false); assert.equal(bad.me.ringAccountIdSha256, null);
    const unauth = await ringDemo({ cfg, ringToken: 'wrong-token-wrong-token', httpsRequest: s.cloud.reroute });
    assert.equal(unauth.ok, false); assert.equal(JSON.stringify(unauth).includes('secret-detail'), false);
  } finally { await s.cloud.close(); }
});

test('local-sha account-id-sha256 (lib + CLI via stdin); CLI secret prompts refuse argv and missing input', () => {
  assert.equal(accountIdSha256('abc123\n'), sha('abc123'));
  const CLI = join(dirname(dirname(fileURLToPath(import.meta.url))), 'mac-worker.mjs');
  const env = { PATH: process.env.PATH, HOME: process.env.HOME, RING_MAC_STATE_DIR: join(mkdtempSync(join(tmpdir(), 'ring-mac-sha-')), 's') };
  const r = spawnSync(process.execPath, [CLI, 'local-sha', 'account-id-sha256'], { env, input: 'abc123\n', encoding: 'utf8' });
  assert.equal(r.stdout.trim(), sha('abc123'));
  const argv = spawnSync(process.execPath, [CLI, 'ring-demo', '--token', 'x'.repeat(20)], { env, encoding: 'utf8' });
  assert.equal(argv.status, 2); assert.match(argv.stderr, /^ERROR USAGE/mu);
  const none = spawnSync(process.execPath, [CLI, 'ring-demo'], { env, input: '', encoding: 'utf8' });
  assert.notEqual(none.status, 0); assert.match(none.stderr, /^ERROR SECRET_REQUIRED/mu);
});
