import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, statSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolveConfig } from '../src/config.mjs';
import { keygen, loginUrl, run, status } from '../src/launcher.mjs';
import { startFakeCloud, HOST, COGNITO_HOST } from './helpers/fake-cloud.mjs';
import { createMacCommandHttpsClient } from '../vendor/mac-command-https-client.mjs';
import { openMacCommandSigningKey } from '../vendor/mac-command-signing-key.mjs';

const cfg = resolveConfig({ apiBase: `https://${HOST}/staging`, cognitoDomain: `https://${COGNITO_HOST}`, clientId: 'abcdefghijklmnopqrstuvwxyz' });
const PASS = () => Buffer.from('correct horse battery staple');
const OWNER = 'owner/fixture';
const dir = () => join(mkdtempSync(join(tmpdir(), 'ring-mac-launcher-')), 'state');

async function setup(overrides = {}) {
  const stateDir = dir();
  const k = await keygen({ stateDir, cfg, passphrase: PASS(), ownerRef: OWNER, associationRevision: 1 });
  const cloud = await startFakeCloud({ enrollment: { publicKeySpki: overrides.enrolledSpki ?? k.publicKeySpki, ownerRef: OWNER, associationRevision: 1 }, audience: cfg.audience });
  const login = async (sd = stateDir) => cloud.authorize((await loginUrl({ stateDir: sd, cfg })).url);
  const go = async (opts = {}) => run({ stateDir, cfg, passphrase: PASS(), callbackUrl: await login(), tokenRequest: cloud.reroute, httpsRequest: cloud.reroute, ...opts });
  return { stateDir, k, cloud, login, go };
}

test('keygen: key file 0600 in 0700 dir, output has keyId/spki/skeleton, no passphrase; second keygen refused', async () => {
  const stateDir = dir();
  const pass = PASS();
  const r = await keygen({ stateDir, cfg, passphrase: pass, ownerRef: OWNER, associationRevision: 1 });
  assert.match(r.keyId, /^[a-f0-9]{64}$/u);
  assert.deepEqual(Object.keys(r.approvalSkeleton), ['schema', 'ownerRef', 'associationRevision', 'keyId', 'publicKeySpki', 'expectedRevision', 'revision']);
  assert.equal(r.approvalSkeleton.schema, 'ring-mac-enrollment-approval-v1');
  assert.equal(JSON.stringify(r).includes('correct horse'), false);
  const keyFile = join(stateDir, 'keys', 'mac-command-signing-key.pem');
  assert.equal(statSync(keyFile).mode & 0o777, 0o600); assert.equal(statSync(join(stateDir, 'keys')).mode & 0o777, 0o700);
  assert.match(readFileSync(keyFile, 'utf8'), /BEGIN ENCRYPTED PRIVATE KEY/u);
  await assert.rejects(keygen({ stateDir, cfg, passphrase: PASS(), ownerRef: OWNER, associationRevision: 1 }), /IDENTITY_EXISTS/u);
  await assert.rejects(keygen({ stateDir: dir(), cfg, passphrase: Buffer.from('short'), ownerRef: OWNER, associationRevision: 1 }), /MAC_KEY_PASSPHRASE/u);
});

test('login-url: S256 PKCE, exact redirect/scopes/resource, verifier only in 0600 file and not in URL', async () => {
  const stateDir = dir();
  const { url } = await loginUrl({ stateDir, cfg });
  const u = new URL(url); const q = u.searchParams;
  assert.equal(u.origin + u.pathname, `https://${COGNITO_HOST}/oauth2/authorize`);
  assert.equal(q.get('redirect_uri'), `https://${HOST}/staging/auth/callback`);
  assert.equal(q.get('scope'), `${cfg.resource}/tools.list ${cfg.resource}/tools.call`);
  assert.equal(q.get('resource'), cfg.resource);
  assert.equal(q.get('code_challenge_method'), 'S256');
  const file = join(stateDir, 'oauth', 'pkce-pending.json');
  assert.equal(statSync(file).mode & 0o777, 0o600); assert.equal(statSync(join(stateDir, 'oauth')).mode & 0o777, 0o700);
  const rec = JSON.parse(readFileSync(file, 'utf8'));
  assert.equal(url.includes(rec.verifier), false); assert.equal(q.get('state'), rec.state);
  assert.match(rec.state, /^[A-Za-z0-9_-]{43}$/u);
});

test('callback validation: wrong state, foreign URL, login error, missing pending, expiry', async () => {
  const s = await setup();
  try {
    const good = await s.login();
    await assert.rejects(run({ stateDir: s.stateDir, cfg, passphrase: PASS(), callbackUrl: good.replace(/state=[^&]+/u, 'state=' + 'A'.repeat(43)), tokenRequest: s.cloud.reroute, httpsRequest: s.cloud.reroute }), /CALLBACK_STATE_MISMATCH/u);
    // pending was consumed by the failed attempt: the same URL cannot be retried
    await assert.rejects(run({ stateDir: s.stateDir, cfg, passphrase: PASS(), callbackUrl: good, tokenRequest: s.cloud.reroute, httpsRequest: s.cloud.reroute }), /PKCE_NOT_PENDING/u);
    await assert.rejects(run({ stateDir: s.stateDir, cfg, passphrase: PASS(), callbackUrl: 'https://evil.example/staging/auth/callback?code=a&state=' + 'A'.repeat(43) }), /CALLBACK_URL_INVALID/u);
    await assert.rejects(run({ stateDir: s.stateDir, cfg, passphrase: PASS(), callbackUrl: cfg.redirectUri + '?error=access_denied&error_description=x' }), /CALLBACK_LOGIN_ERROR_access_denied/u);
    await s.login();
    await assert.rejects(run({ stateDir: s.stateDir, cfg, passphrase: PASS(), callbackUrl: await s.login(), clock: () => Date.now() + 700000, tokenRequest: s.cloud.reroute }), /PKCE_EXPIRED/u);
  } finally { await s.cloud.close(); }
});

test('E2E: enqueue -> fetch -> verify -> execute -> receipt -> executed:true; second poll EMPTY; journal written', async () => {
  const s = await setup();
  try {
    const c = s.cloud.submit(true);
    const out = await s.go();
    const r = out.results[0];
    assert.equal(out.mode, 'software-direct');
    assert.equal(r.status, 'SUCCEEDED'); assert.equal(r.executed, true); assert.equal(r.commandId, c.commandId);
    assert.equal(r.result.kind, 'software-test-switch'); assert.equal(r.result.enabled, true); assert.equal(r.result.revision, 1);
    const cloudRow = s.cloud.state.commands.get(c.commandId);
    assert.equal(cloudRow.state, 'SUCCEEDED'); assert.equal(cloudRow.result.enabled, true);
    const files = readdirSync(join(s.stateDir, 'journal')).sort();
    assert.deepEqual(files, [c.commandId + '.claim.json', c.commandId + '.receipt.json']);
    const st = await status({ stateDir: s.stateDir, cfg });
    assert.deepEqual(st.journal, { claimed: 1, receiptWritten: 1, claimedWithoutReceipt: [] });
    // second login/run: nothing queued
    const again = await s.go();
    assert.equal(again.results[0].status, 'EMPTY'); assert.equal(again.results[0].executed, false);
    // enabled:false flows through too
    s.cloud.submit(false); const off = await s.go();
    assert.equal(off.results[0].result.enabled, false);
    // no token material on disk
    const dump = readdirSync(s.stateDir, { recursive: true }).map(f => { try { return readFileSync(join(s.stateDir, f), 'utf8'); } catch { return ''; } }).join('\n');
    assert.equal(dump.includes(s.cloud.state.token), false); assert.equal(dump.includes('unused-refresh-token'), false);
  } finally { await s.cloud.close(); }
});

test('replay: re-sent proof header, replayed receipt and re-executed command are all rejected', async () => {
  const s = await setup();
  try {
    const c = s.cloud.submit(true); await s.go();
    // (a) replayed receipt with fresh proof: cloud refuses because command is no longer CLAIMED
    const signer = await openMacCommandSigningKey({ directory: join(realpathSync(s.stateDir), 'keys'), passphrase: PASS(), ownerRef: OWNER, associationRevision: 1, audience: cfg.audience });
    const client = createMacCommandHttpsClient({ baseUrl: cfg.apiBase, expectedHostname: HOST, getAccessToken: async () => s.cloud.state.token, proofSigner: signer, request: s.cloud.reroute });
    await assert.rejects(client.receipt(s.cloud.state.receipts[0]), /MAC_HTTPS_RESPONSE/u);
    assert.equal(s.cloud.state.log.at(-1).reason, 'RECEIPT_NOT_CLAIMED_OR_REPLAY');
    // (b) byte-identical proof header re-sent: nonce replay
    let captured; const spy = (url, o, cb) => { captured ??= o.headers; return s.cloud.reroute(url, o, cb); };
    const spied = createMacCommandHttpsClient({ baseUrl: cfg.apiBase, expectedHostname: HOST, getAccessToken: async () => s.cloud.state.token, proofSigner: signer, request: spy });
    assert.deepEqual(await spied.fetch(), { status: 'EMPTY' });
    await new Promise((resolve, reject) => { const req = s.cloud.reroute(new URL(cfg.apiBase + '/mac/commands/fetch'), { method: 'POST', headers: { ...captured } }, res => { res.resume(); res.on('end', () => { try { assert.equal(res.statusCode, 403); resolve(); } catch (e) { reject(e); } }); }); req.end('{}'); });
    assert.equal(s.cloud.state.log.at(-1).reason, 'MAC_PROOF_REPLAY');
    // (c) a command already in the local journal is never executed twice (local claim refuses): force cloud to re-deliver it
    s.cloud.state.commands.get(c.commandId).state = 'PENDING';
    const out = await s.go();
    assert.equal(out.results[0].status, 'UNKNOWN'); assert.equal(out.results[0].executed, false);
    assert.equal(s.cloud.state.receipts.length, 1);
    signer.close();
  } finally { await s.cloud.close(); }
});

test('expired command is rejected on the Mac: no execution, no journal claim, no receipt', async () => {
  const s = await setup();
  try {
    s.cloud.state.deliverExpired = true;
    s.cloud.submit(true, { issuedAt: Date.now() - 60000 });
    await assert.rejects(s.go(), /MAC_COMMAND_EXPIRED/u);
    assert.equal(s.cloud.state.receipts.length, 0);
    assert.deepEqual(readdirSync(join(s.stateDir, 'journal')), []);
  } finally { await s.cloud.close(); }
});

test('wrong enrolled key: cloud rejects proof, nothing executes', async () => {
  const other = await keygen({ stateDir: dir(), cfg, passphrase: PASS(), ownerRef: OWNER, associationRevision: 1 });
  const s = await setup({ enrolledSpki: other.publicKeySpki });
  try {
    s.cloud.submit(true);
    await assert.rejects(s.go(), /MAC_HTTPS_RESPONSE/u);
    assert.equal(s.cloud.state.log.at(-1).reason, 'MAC_PROOF_DENIED');
    assert.equal(s.cloud.state.receipts.length, 0);
    assert.equal([...s.cloud.state.commands.values()][0].state, 'PENDING');
  } finally { await s.cloud.close(); }
});

test('wrong passphrase fails before the single-use code is spent; wrong owner command is refused locally', async () => {
  const s = await setup();
  try {
    s.cloud.submit(true);
    await assert.rejects(run({ stateDir: s.stateDir, cfg, passphrase: Buffer.from('definitely the wrong one'), callbackUrl: await s.login(), tokenRequest: s.cloud.reroute, httpsRequest: s.cloud.reroute }), /MAC_KEY_UNAVAILABLE/u);
    assert.equal(s.cloud.state.codes.size, 1, 'authorization code still unspent');
    s.cloud.state.queue.length = 0; s.cloud.state.commands.clear();
    s.cloud.submit(true, { ownerRef: 'owner/foreign' });
    await assert.rejects(s.go(), /MAC_COMMAND_SESSION_OWNER/u);
    assert.equal(s.cloud.state.receipts.length, 0);
  } finally { await s.cloud.close(); }
});

test('token handling: bad code rejected by token endpoint; expired token refused before any Mac call', async () => {
  const s = await setup();
  try {
    const cb = await s.login(); s.cloud.state.codes.clear();
    await assert.rejects(run({ stateDir: s.stateDir, cfg, passphrase: PASS(), callbackUrl: cb, tokenRequest: s.cloud.reroute, httpsRequest: s.cloud.reroute }), /OAUTH_TOKEN_HTTP_400_invalid_grant/u);
    s.cloud.state.tokenLifetimeSeconds = 1; s.cloud.submit(true);
    const before = s.cloud.state.log.length;
    await assert.rejects(s.go(), /OAUTH_TOKEN_EXPIRED/u);
    assert.equal(s.cloud.state.receipts.length, 0); assert.equal(s.cloud.state.log.length, before);
  } finally { await s.cloud.close(); }
});
