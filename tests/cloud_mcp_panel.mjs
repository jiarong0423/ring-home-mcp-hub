// Cloud MCP (AWS) panel: loopback server tests with the mac launcher's in-process fake TLS cloud.
// Isolation rules: the real src/server.mjs runs in a child process whose https.request is replaced (via --import
// preload) by a reroute to the fake cloud on 127.0.0.1 with the fake's self-signed cert pinned; /usr/bin/pbpaste is
// replaced by an IPC-fed fake. No real AWS/Cognito/Ring host, no real clipboard. Temp dirs are fresh and never deleted.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { mkdtempSync, readFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import tls from 'node:tls';
import { fileURLToPath } from 'node:url';
import { DEFAULT_CONFIG, resolveConfig } from '../vendor_mac_launcher/src/config.mjs';
import { keygen } from '../vendor_mac_launcher/src/launcher.mjs';
import { startFakeCloud, HOST } from '../vendor_mac_launcher/tests/helpers/fake-cloud.mjs';
import { createCloudMcpPanel, sanitizeStep, shortCommandId, safeCode } from '../src/cloud_mcp_panel.mjs';
import { I18N_MAP, t as translate } from '../public/i18n-map.mjs';

const projectDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const serverPath = join(projectDir, 'src', 'server.mjs');
const cfg = resolveConfig(DEFAULT_CONFIG);   // the server uses the fixed production config; every request is rerouted
const demoPass = randomBytes(20).toString('base64url');
const operatorPass = randomBytes(32).toString('base64url');
const macPass = 'mac-pass-' + randomBytes(12).toString('hex');
const ownerRef = 'owner/' + randomBytes(8).toString('hex');
const fresh = prefix => mkdtempSync(join(tmpdir(), prefix));

async function peerCertPem(port) {
  return new Promise((resolve, reject) => {
    const s = tls.connect({ host: '127.0.0.1', port, servername: HOST, rejectUnauthorized: false }, () => {
      const raw = s.getPeerCertificate(true).raw; s.end();
      resolve('-----BEGIN CERTIFICATE-----\n' + raw.toString('base64').match(/.{1,64}/gu).join('\n') + '\n-----END CERTIFICATE-----\n');
    });
    s.once('error', reject);
  });
}

function preload({ port, pem }) {
  const code = `
    import https from 'node:https';
    import cp from 'node:child_process';
    import { syncBuiltinESMExports } from 'node:module';
    import { promisify } from 'node:util';
    const realRequest = https.request;
    let clip = null; let clipFail = false;
    process.on('message', (m) => { if (m?.kind === 'clipboard') { clip = m.text; clipFail = m.fail === true; process.send({ kind: 'clipboard-ack' }); } });
    process.channel?.unref();   // the IPC listener must not keep the server alive after SIGTERM
    https.request = function reroutedRequest(url, options, cb) {
      const u = url instanceof URL ? url : new URL(String(url));
      process.send?.({ kind: 'https', host: u.hostname, path: u.pathname });
      return realRequest({ host: '127.0.0.1', port: ${port}, path: u.pathname + u.search, method: options.method, headers: options.headers,
        ca: ${JSON.stringify(pem)}, servername: ${JSON.stringify(HOST)}, minVersion: 'TLSv1.2', rejectUnauthorized: true }, cb);
    };
    function deniedExecFile() { throw new Error('EXEC_DENIED_IN_TEST'); }
    deniedExecFile[promisify.custom] = async (file, args) => {
      if (file !== '/usr/bin/pbpaste' || args.length !== 0) throw new Error('EXEC_DENIED_IN_TEST');
      process.send?.({ kind: 'pbpaste' });
      if (clipFail || clip === null) throw new Error('clipboard unavailable');
      return { stdout: clip, stderr: '' };
    };
    cp.execFile = deniedExecFile;
    syncBuiltinESMExports();
    process.stdout.write('CLOUD_TEST_PRELOAD_ACTIVE\\n');
  `;
  return `data:text/javascript,${encodeURIComponent(code)}`;
}

async function setupCloud({ withKey = true } = {}) {
  const stateDir = join(fresh('ring-cloud-panel-state-'), 'state');
  let k = { publicKeySpki: 'none', keyId: 'none' };
  if (withKey) k = await keygen({ stateDir, cfg, passphrase: Buffer.from(macPass), ownerRef, associationRevision: 1 });
  const cloud = await startFakeCloud({ enrollment: { publicKeySpki: k.publicKeySpki, ownerRef, associationRevision: 1 }, audience: cfg.audience });
  const pem = await peerCertPem(cloud.port);
  return { stateDir, cloud, pem, key: k };
}

// panel/passphrase: null = variable absent from the child environment. The env passphrase is the documented TEST-ONLY
// source and is honoured only with HOME_MCP_CLOUD_PANEL_PASSPHRASE_SOURCE=env-test (envTestFlag); production uses the TTY prompt.
async function startServer({ cloud, pem, stateDir, panel = '1', passphrase = macPass, envTestFlag = true }) {
  const env = { PATH: '/usr/bin:/bin', HOME: fresh('ring-cloud-panel-home-'), HOME_MCP_PORT: '0', HOME_MCP_DEMO_PASS: demoPass,
    HOME_MCP_RING_OPERATOR_PASS: operatorPass, RING_MAC_STATE_DIR: stateDir };
  if (panel !== null) env.HOME_MCP_CLOUD_PANEL = panel;
  if (passphrase !== null) env.RING_MAC_KEY_PASSPHRASE = passphrase;
  if (passphrase !== null && envTestFlag) env.HOME_MCP_CLOUD_PANEL_PASSPHRASE_SOURCE = 'env-test';
  const child = spawn(process.execPath, ['--import', preload({ port: cloud.port, pem }), serverPath],
    { cwd: projectDir, env, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
  const server = { child, stdout: '', stderr: '', https: [], pbpaste: 0, raw: [], acks: [] };
  child.on('message', (m) => {
    if (m?.kind === 'https') server.https.push(m);
    if (m?.kind === 'pbpaste') server.pbpaste += 1;
    if (m?.kind === 'clipboard-ack') server.acks.shift()?.();
  });
  child.stderr.on('data', (c) => { server.stderr += c; });
  server.base = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('server startup timed out: ' + server.stderr)), 15_000);
    child.stdout.on('data', (c) => {
      server.stdout += c;
      const m = server.stdout.match(/Home MCP simulator: http:\/\/127\.0\.0\.1:(\d+)/u);
      if (m && server.stdout.includes('No Wi-Fi')) { clearTimeout(timer); resolve(Number(m[1])); }
    });
    child.once('exit', (code) => { clearTimeout(timer); reject(new Error('server exited ' + code + ' ' + server.stderr)); });
  });
  assert.match(server.stdout, /^CLOUD_TEST_PRELOAD_ACTIVE$/mu, 'reroute preload must be active before the server starts');
  server.clipboard = (text, fail = false) => new Promise((resolve) => { server.acks.push(resolve); child.send({ kind: 'clipboard', text, fail }); });
  server.stop = () => new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve();
    const hard = setTimeout(() => child.kill('SIGKILL'), 5000);
    child.once('exit', () => { clearTimeout(hard); resolve(); });
    if (child.connected) child.disconnect();
    child.kill('SIGTERM');
  });
  return server;
}

function call(server, path, { method = 'GET', bearer, operator, intent, body, origin = 'self', rawBody } = {}) {
  const port = server.base;
  const headers = { host: `127.0.0.1:${port}` };
  if (origin === 'self') headers.origin = `http://127.0.0.1:${port}`; else if (origin) headers.origin = origin;
  if (bearer) headers.authorization = `Bearer ${bearer}`;
  if (operator !== undefined) headers['x-ring-operator-passcode'] = operator;
  if (intent) headers['x-cloud-mcp-intent'] = intent;
  const payload = rawBody ?? (body === undefined ? null : Buffer.from(JSON.stringify(body)));
  if (payload) { headers['content-type'] = 'application/json'; headers['content-length'] = String(payload.length); }
  else if (method === 'POST') headers['content-length'] = '0';
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method, headers }, (res) => {
      const chunks = []; res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8'); server.raw.push(raw);
        const ct = res.headers['content-type'] || '';
        let parsed = null;
        if (ct.startsWith('application/json')) parsed = JSON.parse(raw);
        if (ct.startsWith('application/x-ndjson')) parsed = raw.split('\n').filter(Boolean).map((l) => JSON.parse(l));
        resolve({ status: res.statusCode, headers: res.headers, raw, body: parsed });
      });
    });
    req.once('error', reject); req.end(payload ?? undefined);
  });
}
async function login(server) {
  const r = await call(server, '/api/login', { method: 'POST', body: { passcode: demoPass } });
  assert.equal(r.status, 200); return r.body.token;
}
const op = (bearer, intent, extra = {}) => ({ method: 'POST', bearer, operator: operatorPass, intent, ...extra });
async function loginUrl(server, bearer) {
  const r = await call(server, '/api/cloud-mcp/login-url', op(bearer, 'login-url'));
  assert.equal(r.status, 200, r.raw);
  assert.deepEqual(Object.keys(r.body).sort(), ['authorizeUrl', 'expiresAt']);
  return r.body.authorizeUrl;
}
function assertNoSecrets(server, extra = []) {
  const dump = [server.stdout, server.stderr, ...server.raw].join('\n');
  for (const s of [demoPass, operatorPass, macPass, ownerRef, ...extra]) {
    if (typeof s === 'string' && s.length >= 6) assert.equal(dump.includes(s), false, 'secret leaked: ' + s.slice(0, 4) + '…');
  }
  assert.doesNotMatch(dump, /cmd_[a-f0-9]{64}/u, 'full commandId must not be shown');
  assert.doesNotMatch(dump, /code_verifier|access_token|refresh_token|id_token/u);
}

test('panel is disabled by default: 401 without session, 404 with session, original no-cloud startup label, no egress', async (t) => {
  const s = await setupCloud();
  const server = await startServer({ ...s, panel: null });
  t.after(async () => { await server.stop(); await s.cloud.close(); });
  assert.match(server.stdout, /No Wi-Fi, physical device, or cloud connection/u);
  assert.equal((await call(server, '/api/cloud-mcp/status')).status, 401);
  const bearer = await login(server);
  const r = await call(server, '/api/cloud-mcp/status', { bearer });
  assert.equal(r.status, 404); assert.equal(r.body.error, 'CLOUD_PANEL_DISABLED');
  assert.equal(server.https.length, 0); assert.equal(server.pbpaste, 0);
  const page = await call(server, '/');
  // Rev 3: the markup carries mapping-table keys; the honest labels come from public/i18n-map.mjs (English default, zh kept).
  for (const label of ['data-i18n="cloud.heading"', 'data-i18n="cloud.label.ring"', 'data-i18n="cloud.label.mac"', '/assets/cloud-mcp-panel.mjs', '/assets/i18n-map.mjs']) assert.ok(page.raw.includes(label), label);
  assert.deepEqual({ ...I18N_MAP['cloud.label.ring'] }, { en: 'Ring side: Playground sandbox', zh: 'Ring 側：Playground 沙盒' });
  assert.deepEqual({ ...I18N_MAP['cloud.label.mac'] }, { en: 'Mac side: software-direct (reduced assurance)', zh: 'Mac 端：software-direct（簡化保證）' });
  assert.equal(I18N_MAP['cloud.heading'].en, 'Cloud MCP (AWS) live chain');
  assert.match(I18N_MAP['header.note'].en, /^Seven devices are SIMULATED/u);
  assert.doesNotMatch(page.raw, /[\u4e00-\u9fff]/u, 'no hard-coded CJK left in index.html');
  const map = await call(server, '/assets/i18n-map.mjs');
  assert.equal(map.status, 200); assert.match(map.headers['content-type'], /text\/javascript/u);
  assert.doesNotMatch(map.raw, /window\.open|location\.(assign|replace|href\s*=)|\.click\(\)|innerHTML|localStorage|sessionStorage|fetch\(/u);
  const asset = await call(server, '/assets/cloud-mcp-panel.mjs');
  assert.equal(asset.status, 200); assert.match(asset.headers['content-type'], /text\/javascript/u);
  assert.doesNotMatch(asset.raw, /window\.open|location\.(assign|replace|href\s*=)|\.click\(\)|innerHTML|localStorage|sessionStorage/u);
  assertNoSecrets(server);
});

test('gates: no owner session -> 401 on every route; intent/origin required; wrong operator passcode denied then rate limited', async (t) => {
  const s = await setupCloud();
  const server = await startServer(s);
  t.after(async () => { await server.stop(); await s.cloud.close(); });
  assert.match(server.stdout, /Cloud MCP \(AWS\) panel: ENABLED.*Mac key: ready/u);
  for (const [path, intent, body] of [['/api/cloud-mcp/status'], ['/api/cloud-mcp/login-url', 'login-url'],
    ['/api/cloud-mcp/callback', 'callback', { callbackUrl: 'x' }], ['/api/cloud-mcp/callback-clipboard', 'callback-clipboard'],
    ['/api/cloud-mcp/switch', 'switch', { enabled: true }]]) {
    const r = await call(server, path, { method: intent ? 'POST' : 'GET', operator: operatorPass, intent, body });
    assert.equal(r.status, 401, path); assert.equal(r.body.error, 'AUTH_REQUIRED');
    const forged = await call(server, path, { method: intent ? 'POST' : 'GET', bearer: randomBytes(32).toString('base64url'), operator: operatorPass, intent, body });
    assert.equal(forged.status, 401, path);
  }
  const bearer = await login(server);
  const st = await call(server, '/api/cloud-mcp/status', { bearer });
  assert.equal(st.status, 200);
  assert.deepEqual(Object.keys(st.body).sort(), ['busy', 'callbackStaged', 'enabled', 'key', 'lastRun', 'login', 'mode', 'passphraseSource', 'ringSide']);
  assert.equal(st.body.key, 'ready'); assert.equal(st.body.mode, 'software-direct');
  assert.equal((await call(server, '/api/cloud-mcp/login-url', op(bearer, undefined))).body.error, 'CLOUD_INTENT_REQUIRED');
  assert.equal((await call(server, '/api/cloud-mcp/login-url', op(bearer, 'switch'))).body.error, 'CLOUD_INTENT_REQUIRED');
  assert.equal((await call(server, '/api/cloud-mcp/login-url', op(bearer, 'login-url', { origin: 'http://evil.invalid' }))).status, 403);
  assert.equal((await call(server, '/api/cloud-mcp/login-url', op(bearer, 'login-url', { origin: null }))).status, 403);
  assert.equal((await call(server, '/api/cloud-mcp/login-url', { method: 'GET', bearer, operator: operatorPass, intent: 'login-url' })).status, 405);
  assert.equal((await call(server, '/api/cloud-mcp/status?x=1', { bearer })).status, 400);
  for (let i = 0; i < 5; i += 1) {
    const r = await call(server, '/api/cloud-mcp/login-url', op(bearer, 'login-url', { operator: i === 0 ? '' : 'wrong-' + randomBytes(16).toString('hex') }));
    assert.equal(r.status, 403); assert.equal(r.body.error, 'RING_OPERATOR_DENIED');
  }
  const limited = await call(server, '/api/cloud-mcp/login-url', op(bearer, 'login-url'));
  assert.equal(limited.status, 429); assert.equal(limited.body.error, 'RING_OPERATOR_RATE_LIMIT');
  // shared limiter with the existing Ring import gate
  assert.equal((await call(server, '/api/ring/import-clipboard', { method: 'POST', bearer, operator: operatorPass })).status, 429);
  const sw = await call(server, '/api/cloud-mcp/switch', op(bearer, 'switch', { body: { enabled: true } }));
  assert.equal(sw.status, 429);
  assert.equal(server.https.length, 0, 'no cloud request before the gates pass');
  assert.equal(server.pbpaste, 0); assert.equal(s.cloud.state.tokenCalls ?? 0, 0);
  assertNoSecrets(server);
});

test('bad callback shapes are rejected before any token exchange; clipboard accepts only the exact callback URL', async (t) => {
  const s = await setupCloud();
  const server = await startServer(s);
  t.after(async () => { await server.stop(); await s.cloud.close(); });
  const bearer = await login(server);
  const noStaged = await call(server, '/api/cloud-mcp/callback', op(bearer, 'callback', { body: { callbackUrl: cfg.redirectUri + '?code=abc&state=' + 'A'.repeat(43) } }));
  assert.equal(noStaged.status, 409); assert.equal(noStaged.body.error, 'LOGIN_NOT_PENDING');
  const url = new URL(await loginUrl(server, bearer));
  assert.equal(url.origin + url.pathname, cfg.authorizeUrl);
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256'); assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.has('code_verifier'), false);
  const state = url.searchParams.get('state');
  const good = new URL(s.cloud.authorize(url.href)); const code = good.searchParams.get('code');
  const bad = [
    ['https://evil.example/staging/auth/callback?code=' + code + '&state=' + state, 422, 'CALLBACK_URL_INVALID'],
    [cfg.redirectUri.replace('https:', 'http:') + '?code=' + code + '&state=' + state, 422, 'CALLBACK_URL_INVALID'],
    [cfg.redirectUri + '?code=' + code + '&state=' + state + '&extra=1', 422, 'CALLBACK_URL_INVALID'],
    [cfg.redirectUri + '?code=' + code + '&state=' + state + '#frag', 422, 'CALLBACK_URL_INVALID'],
    [cfg.redirectUri + '?code=' + code, 422, 'CALLBACK_URL_INVALID'],
    [cfg.redirectUri.replace('https://', 'https://user:pw@') + '?code=' + code + '&state=' + state, 422, 'CALLBACK_URL_INVALID'],
    [cfg.redirectUri + '?error=access_denied&state=' + state, 422, 'CALLBACK_LOGIN_ERROR_ACCESS_DENIED'],
    [cfg.redirectUri + '?code=' + code + '&state=' + 'B'.repeat(43), 422, 'CALLBACK_STATE_MISMATCH'],
    ['not a url', 422, 'CALLBACK_URL_INVALID'],
    ['', 400, 'CALLBACK_URL_INVALID']
  ];
  for (const [value, status, error] of bad) {
    const r = await call(server, '/api/cloud-mcp/callback', op(bearer, 'callback', { body: { callbackUrl: value } }));
    assert.equal(r.status, status, value); assert.equal(r.body.error, error, value);
    assert.equal(r.raw.includes(code), false);
  }
  assert.equal((await call(server, '/api/cloud-mcp/callback', op(bearer, 'callback', { body: { callbackUrl: good.href, more: 1 } }))).status, 400);
  assert.equal((await call(server, '/api/cloud-mcp/callback', op(bearer, 'callback', { body: { callbackUrl: 42 } }))).status, 400);
  for (const clip of ['  ' + good.href, good.href + '\t', '\u0000' + good.href, good.href + '\r\n\n', good.href + ' ', good.href + '\nsecond line', 'ring-token-' + randomBytes(16).toString('hex')]) {
    await server.clipboard(clip);
    const r = await call(server, '/api/cloud-mcp/callback-clipboard', op(bearer, 'callback-clipboard'));
    assert.equal(r.status, 422); assert.equal(r.body.error, 'CALLBACK_URL_INVALID');
  }
  await server.clipboard('', true);
  assert.equal((await call(server, '/api/cloud-mcp/callback-clipboard', op(bearer, 'callback-clipboard'))).body.error, 'CLIPBOARD_UNAVAILABLE');
  assert.equal((await call(server, '/api/cloud-mcp/callback-clipboard', op(bearer, 'callback-clipboard', { body: {} }))).status, 400);
  const sw = await call(server, '/api/cloud-mcp/switch', op(bearer, 'switch', { body: { enabled: true } }));
  assert.equal(sw.status, 409); assert.equal(sw.body.error, 'CALLBACK_NOT_STAGED');
  assert.equal((await call(server, '/api/cloud-mcp/switch', op(bearer, 'switch', { body: { enabled: 'true' } }))).status, 400);
  assert.equal(s.cloud.state.tokenCalls ?? 0, 0, 'no Cognito exchange for rejected callbacks');
  assert.equal(server.https.length, 0);
  assert.equal(server.pbpaste, 8);
  assertNoSecrets(server, [code]);
});

test('happy path: login-url -> pasted callback -> switch streams sanitized steps and returns executed:true; clipboard -> switch off', async (t) => {
  const s = await setupCloud();
  const server = await startServer(s);
  t.after(async () => { await server.stop(); await s.cloud.close(); });
  const bearer = await login(server);
  const secrets = [s.key.keyId, s.key.publicKeySpki];
  async function cycle(enabled, via) {
    const authorizeUrl = await loginUrl(server, bearer);
    const callbackUrl = s.cloud.authorize(authorizeUrl);
    secrets.push(new URL(callbackUrl).searchParams.get('code'));
    secrets.push(JSON.parse(readFileSync(join(s.stateDir, 'oauth', 'pkce-pending.json'), 'utf8')).verifier);
    const staged = via === 'paste'
      ? await call(server, '/api/cloud-mcp/callback', op(bearer, 'callback', { body: { callbackUrl } }))
      : (await server.clipboard(callbackUrl + '\n'), await call(server, '/api/cloud-mcp/callback-clipboard', op(bearer, 'callback-clipboard')));
    assert.equal(staged.status, 200, staged.raw);
    assert.deepEqual(Object.keys(staged.body).sort(), ['expiresAt', 'source', 'staged']);
    assert.equal((await call(server, '/api/cloud-mcp/status', { bearer })).body.callbackStaged, true);
    const r = await call(server, '/api/cloud-mcp/switch', op(bearer, 'switch', { body: { enabled } }));
    assert.equal(r.status, 200, r.raw); assert.match(r.headers['content-type'], /^application\/x-ndjson/u);
    const steps = r.body.filter((m) => m.type === 'step'); const final = r.body.at(-1);
    assert.equal(final.type, 'result', r.raw);
    for (const m of r.body) assert.ok(!Number.isNaN(Date.parse(m.at)), 'timestamped');
    assert.equal(final.ok, true); assert.equal(final.mode, 'software-direct');
    assert.equal(final.set.status, 'PENDING'); assert.match(final.set.commandId, /^cmd_[a-f0-9]{8}…$/u);
    assert.deepEqual(final.worker, { status: 'SUCCEEDED', executed: true });
    assert.equal(final.result.executed, true); assert.equal(final.result.enabled, enabled); assert.equal(final.result.status, 'SUCCEEDED');
    for (const m of steps) { assert.deepEqual(Object.keys(m).sort(), ['at', 'key', 'params', 'type']); assert.ok(Object.hasOwn(I18N_MAP, m.key), m.key); }
    const text = steps.map((m) => translate(m.key, m.params)).join('\n');
    assert.match(text, /software_test_switch\.set → PENDING, commandId=cmd_[a-f0-9]{8}…/u);
    assert.match(text, /software_test_switch\.result → SUCCEEDED, executed=true/u);
    assert.match(text, /Cognito authorization code exchanged/u); assert.doesNotMatch(text, /redacted/u);
    assert.match(steps.map((m) => translate(m.key, m.params, 'zh')).join('\n'), /Cognito 授權碼交換完成/u);
    // single use: the same staged callback cannot be replayed
    const again = await call(server, '/api/cloud-mcp/switch', op(bearer, 'switch', { body: { enabled } }));
    assert.equal(again.status, 409); assert.equal(again.body.error, 'CALLBACK_NOT_STAGED');
    return final;
  }
  // revision comes from the Mac's in-memory software switch, which demo-switch re-creates per run (launcher semantics)
  const on = await cycle(true, 'paste');
  assert.equal(on.result.revision, 1);
  const off = await cycle(false, 'clipboard');
  assert.equal(off.result.revision, 1);
  assert.equal(s.cloud.state.tokenCalls, 2, 'exactly one Cognito exchange per switch');
  const mcp = s.cloud.state.seen.filter((x) => x.url === '/staging/mcp');
  assert.equal(mcp.length, 4);
  assert.deepEqual([...new Set(server.https.map((h) => h.host))].sort(), [cfg.expectedHostname, new URL(cfg.cognitoDomain).hostname].sort());
  for (const id of s.cloud.state.commands.keys()) secrets.push(id);
  const st = await call(server, '/api/cloud-mcp/status', { bearer });
  assert.equal(st.body.lastRun.ok, true); assert.equal(st.body.callbackStaged, false);
  assert.match(server.stdout, /cloud-mcp switch enabled=true ok=true executed=true mode=software-direct/u);
  assertNoSecrets(server, [s.cloud.state.token, 'unused-refresh-token', 'unused.id.token', ...secrets]);
});

test('cloud failure after the gates is reported as a sanitized ERROR line and never as success', async (t) => {
  const s = await setupCloud();
  const server = await startServer(s);
  t.after(async () => { await server.stop(); await s.cloud.close(); });
  const bearer = await login(server);
  s.cloud.state.tokenLifetimeSeconds = 1;   // token expires before /mcp is called
  const callbackUrl = s.cloud.authorize(await loginUrl(server, bearer));
  assert.equal((await call(server, '/api/cloud-mcp/callback', op(bearer, 'callback', { body: { callbackUrl } }))).status, 200);
  const r = await call(server, '/api/cloud-mcp/switch', op(bearer, 'switch', { body: { enabled: true } }));
  assert.equal(r.status, 200);
  assert.deepEqual({ type: r.body.at(-1).type, code: r.body.at(-1).code }, { type: 'error', code: 'OAUTH_TOKEN_EXPIRED' });
  assert.equal(s.cloud.state.commands.size, 0);
  assert.match(server.stderr, /^ERROR cloud-mcp switch enabled=true code=OAUTH_TOKEN_EXPIRED$/mu);
  assert.doesNotMatch(server.stdout, /ok=true/u);
  assertNoSecrets(server, [s.cloud.state.token]);
});

test('Mac key not ready (missing / env-without-test-flag / wrong passphrase, no identity): status says so, cloud actions refuse with zero egress', async (t) => {
  for (const [passphrase, withKey, expected, envTestFlag, source] of [[null, true, 'passphrase_missing', true, 'none'],
    [macPass, true, 'passphrase_missing', false, 'none'],   // a correct passphrase in the OS env is ignored without the test flag
    ['wrong-passphrase-123', true, 'key_unlock_failed', true, 'env-test'], [macPass, false, 'state_dir_missing', true, 'env-test']]) {
    const s = await setupCloud({ withKey });
    const server = await startServer({ ...s, passphrase, envTestFlag });
    try {
      const bearer = await login(server);
      const st = (await call(server, '/api/cloud-mcp/status', { bearer })).body;
      assert.equal(st.key, expected); assert.equal(st.passphraseSource, source);
      const r = await call(server, '/api/cloud-mcp/login-url', op(bearer, 'login-url'));
      assert.equal(r.status, 503); assert.equal(r.body.error, 'MAC_KEY_NOT_READY');
      assert.equal(server.https.length, 0);
      assertNoSecrets(server, ['wrong-passphrase-123']);
    } finally { await server.stop(); await s.cloud.close(); }
  }
});

test('module: passphrase leaves the env object, invalid flag rejected, unknown log lines redacted, ids truncated', async () => {
  const env = { HOME_MCP_CLOUD_PANEL: '1', RING_MAC_KEY_PASSPHRASE: macPass, HOME_MCP_CLOUD_PANEL_PASSPHRASE_SOURCE: 'env-test',
    RING_MAC_STATE_DIR: join(fresh('ring-cloud-panel-unit-'), 'absent') };
  const panel = await createCloudMcpPanel({ env, stdin: null });
  assert.equal(Object.hasOwn(env, 'RING_MAC_KEY_PASSPHRASE'), false); assert.equal(Object.hasOwn(env, 'HOME_MCP_CLOUD_PANEL_PASSPHRASE_SOURCE'), false);
  assert.equal(await panel.keyStatus(), 'state_dir_missing'); assert.equal(panel.passphraseSource(), 'env-test');
  const noFlag = { HOME_MCP_CLOUD_PANEL: '1', RING_MAC_KEY_PASSPHRASE: macPass, RING_MAC_STATE_DIR: env.RING_MAC_STATE_DIR };
  assert.equal((await createCloudMcpPanel({ env: noFlag, stdin: null })).passphraseSource(), 'none');
  assert.equal(Object.hasOwn(noFlag, 'RING_MAC_KEY_PASSPHRASE'), false);
  const off = { RING_MAC_KEY_PASSPHRASE: macPass, HOME_MCP_CLOUD_PANEL_PASSPHRASE_SOURCE: 'env-test' };
  assert.deepEqual(await createCloudMcpPanel({ env: off, stdin: null }), { enabled: false });
  assert.deepEqual(off, {});
  await assert.rejects(createCloudMcpPanel({ env: { HOME_MCP_CLOUD_PANEL: 'yes' }, stdin: null }), /must be 0 or 1/u);
  await assert.rejects(createCloudMcpPanel({ env: { HOME_MCP_CLOUD_PANEL: '1', RING_MAC_STATE_DIR: 'relative/dir' }, stdin: null }), /absolute/u);
  const homeEnv = { HOME_MCP_CLOUD_PANEL: '1', HOME: '/nonexistent-home-for-test' };
  assert.equal(await (await createCloudMcpPanel({ env: homeEnv, stdin: null })).keyStatus(), 'state_dir_missing');
  const id = 'cmd_' + 'ab'.repeat(32);
  assert.equal(shortCommandId(id), 'cmd_abababab…');
  assert.deepEqual(sanitizeStep('mcp software_test_switch.set -> PENDING ' + id), { key: 'cloud.step.set', params: { status: 'PENDING', commandId: 'cmd_abababab…' } });
  assert.equal(translate('cloud.step.set', sanitizeStep('mcp software_test_switch.set -> PENDING ' + id).params), 'Cloud MCP tools/call software_test_switch.set → PENDING, commandId=cmd_abababab…');
  for (const line of ['Bearer eyJhbGciOi.secret', 'token=abc', 'mcp software_test_switch.set -> PENDING ' + id + ' extra', null]) {
    assert.deepEqual(sanitizeStep(line), { key: 'cloud.step.redacted', params: {} });
  }
});

// ---- M1: hidden TTY prompt at server start ----
function fakeTty(answer) {
  const stdin = new EventEmitter(); const writes = []; const modes = [];
  Object.assign(stdin, { isTTY: true, setRawMode(v) { modes.push(v); }, resume() { if (answer !== undefined) setImmediate(() => { for (const ch of answer) stdin.emit('data', ch); }); }, pause() {}, setEncoding() {} });
  return { stdin, stderr: { write: (t) => { writes.push(String(t)); return true; } }, writes, modes };
}
async function keyedState() {
  const stateDir = join(fresh('ring-cloud-panel-tty-'), 'state');
  await keygen({ stateDir, cfg, passphrase: Buffer.from(macPass), ownerRef, associationRevision: 1 });
  return stateDir;
}

test('M1 unit: passphrase is read by a hidden single prompt on a (fake) TTY; never echoed; short/skip/Ctrl-C handled; env ignored without test flag', async () => {
  const stateDir = await keyedState();
  const tty = fakeTty(macPass + '\r');
  const env = { HOME_MCP_CLOUD_PANEL: '1', RING_MAC_STATE_DIR: stateDir, RING_MAC_KEY_PASSPHRASE: 'env-value-must-be-ignored' };
  const panel = await createCloudMcpPanel({ env, stdin: tty.stdin, stderr: tty.stderr });
  assert.equal(panel.passphraseSource(), 'tty'); assert.equal(await panel.keyStatus(), 'ready');
  assert.equal(Object.hasOwn(env, 'RING_MAC_KEY_PASSPHRASE'), false);
  assert.deepEqual(tty.modes, [true, false], 'raw (no-echo) mode on, then restored');
  assert.equal(tty.writes.filter((w) => /Mac key passphrase for the Cloud MCP panel \(hidden/u.test(w)).length, 1, 'exactly one prompt');
  assert.equal(tty.writes.join('').includes(macPass), false);
  const short = fakeTty('short\r');
  const p2 = await createCloudMcpPanel({ env: { HOME_MCP_CLOUD_PANEL: '1', RING_MAC_STATE_DIR: stateDir }, stdin: short.stdin, stderr: short.stderr });
  assert.equal(p2.passphraseSource(), 'none'); assert.equal(await p2.keyStatus(), 'passphrase_missing');
  assert.match(short.writes.join(''), /^ERROR cloud-mcp passphrase not accepted/mu);
  const skip = fakeTty('\r');
  const p3 = await createCloudMcpPanel({ env: { HOME_MCP_CLOUD_PANEL: '1', RING_MAC_STATE_DIR: stateDir }, stdin: skip.stdin, stderr: skip.stderr });
  assert.equal(await p3.keyStatus(), 'passphrase_missing'); assert.match(skip.writes.join(''), /^WARN cloud-mcp passphrase skipped/mu);
  const wrong = fakeTty('definitely-wrong-pass\r');
  const p4 = await createCloudMcpPanel({ env: { HOME_MCP_CLOUD_PANEL: '1', RING_MAC_STATE_DIR: stateDir }, stdin: wrong.stdin, stderr: wrong.stderr });
  assert.equal(await p4.keyStatus(), 'key_unlock_failed');
  const ctrlC = fakeTty('ab\u0003');
  await assert.rejects(createCloudMcpPanel({ env: { HOME_MCP_CLOUD_PANEL: '1', RING_MAC_STATE_DIR: stateDir }, stdin: ctrlC.stdin, stderr: ctrlC.stderr }), /prompt aborted/u);
  const notTty = { isTTY: false };
  assert.equal((await createCloudMcpPanel({ env: { HOME_MCP_CLOUD_PANEL: '1', RING_MAC_STATE_DIR: stateDir }, stdin: notTty })).passphraseSource(), 'none');
});

test('M1 server: real pseudo-terminal start path (/usr/bin/script) prompts once, does not echo, key ready with source tty, env never used', async (t) => {
  const s = await setupCloud();
  t.after(() => s.cloud.close());
  const env = { PATH: '/usr/bin:/bin', HOME: fresh('ring-cloud-panel-home-'), HOME_MCP_PORT: '0', HOME_MCP_DEMO_PASS: demoPass,
    HOME_MCP_RING_OPERATOR_PASS: operatorPass, RING_MAC_STATE_DIR: s.stateDir, HOME_MCP_CLOUD_PANEL: '1' };
  // node pipes are sockets, which `script` rejects for tcgetattr; `cat |` gives it a plain pipe. The child gets a real pty.
  const child = spawn('/bin/sh', ['-c', 'cat | /usr/bin/script -q /dev/null "$@"', 'sh', process.execPath, '--import', preload({ port: s.cloud.port, pem: s.pem }), serverPath],
    { cwd: projectDir, env, stdio: ['pipe', 'pipe', 'pipe'] });
  let out = ''; let sent = false;
  const exited = new Promise((resolve) => child.once('exit', resolve));
  const base = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('pty server startup timed out: ' + JSON.stringify(out))), 15_000);
    child.stdout.on('data', (c) => {
      out += c;
      if (!sent && out.includes('Mac key passphrase for the Cloud MCP panel')) { sent = true; child.stdin.write(macPass + '\r'); }
      const m = out.match(/Home MCP simulator: http:\/\/127\.0\.0\.1:(\d+)/u);
      if (m && out.includes('No Wi-Fi')) { clearTimeout(timer); resolve(Number(m[1])); }
    });
  });
  try {
    assert.equal((out.match(/Mac key passphrase for the Cloud MCP panel/gu) || []).length, 1);
    assert.match(out, /Mac key: ready \(passphrase source: tty\)/u);
    assert.equal(out.includes(macPass), false, 'passphrase must not be echoed by the terminal');
    const server = { base, raw: [] };
    const r = await call(server, '/api/login', { method: 'POST', body: { passcode: demoPass } });
    const st = await call(server, '/api/cloud-mcp/status', { bearer: r.body.token });
    assert.equal(st.body.key, 'ready'); assert.equal(st.body.passphraseSource, 'tty');
    assert.equal(server.raw.join('').includes(macPass), false);
  } finally {
    child.stdin.write('\u0003');          // SIGINT through the pty line discipline -> server shutdown handler
    const hard = setTimeout(() => child.stdin.write('\u0003'), 4000);
    child.stdin.end();
    await exited; clearTimeout(hard);
  }
});

// ---- L1 / L2 / L4 ----
async function stagedPanel() {
  const stateDir = await keyedState();
  const panel = await createCloudMcpPanel({ env: { HOME_MCP_CLOUD_PANEL: '1', RING_MAC_STATE_DIR: stateDir, RING_MAC_KEY_PASSPHRASE: macPass,
    HOME_MCP_CLOUD_PANEL_PASSPHRASE_SOURCE: 'env-test' }, stdin: null });
  const stage = async () => {
    const u = new URL((await panel.loginUrl()).authorizeUrl);   // local only: writes the PKCE file, no network
    return panel.stageCallback(u.searchParams.get('redirect_uri') + '?code=c' + randomBytes(6).toString('hex') + '&state=' + u.searchParams.get('state'), 'paste');
  };
  return { panel, stage };
}

test('L1: a prepared switch job that never starts is aborted: busy cleared, lastRun recorded, start() refused afterwards', async () => {
  const { panel, stage } = await stagedPanel();
  await stage();
  const job = await panel.prepareSwitch(true);
  assert.equal((await panel.status()).busy, true);
  await assert.rejects(panel.loginUrl(), /CLOUD_MCP_BUSY/u);
  assert.equal(job.abort(), true); assert.equal(job.abort(), false);
  const st = await panel.status();
  assert.equal(st.busy, false); assert.deepEqual([st.lastRun.ok, st.lastRun.error], [false, 'CLOUD_ABORTED_BEFORE_START']);
  await assert.rejects(job.start(), /CLOUD_JOB_NOT_STARTABLE/u);
  assert.equal(st.callbackStaged, false, 'staged callback was consumed by the aborted job (single use)');
  await stage(); assert.equal((await panel.status()).callbackStaged, true, 'panel usable again after abort');
});

test('L1 server: switch and device routes release the job when the stream cannot be opened (client already gone)', async () => {
  const src = readFileSync(serverPath, 'utf8');
  const i = src.indexOf('const job = isDevice ? await cloudPanel.prepareDevice(body.deviceId, body.action, onStep) : await cloudPanel.prepareSwitch(body.enabled, onStep);'); const seg = src.slice(i, i + 2200);
  assert.ok(i > 0 && /let started = false;\s*try \{/u.test(seg) && /finally \{\s*if \(!started && job\.abort\(\)\)/u.test(seg) && seg.indexOf('started = true') < seg.indexOf('job.start()'));
});

test('L2: busy is claimed synchronously - concurrent loginUrl / stageCallback / prepareSwitch cannot interleave', async () => {
  const { panel, stage } = await stagedPanel();
  const results = await Promise.allSettled([panel.loginUrl(), panel.loginUrl()]);
  assert.deepEqual(results.map((r) => r.status).sort(), ['fulfilled', 'rejected']);
  assert.equal(results.find((r) => r.status === 'rejected').reason.code, 'CLOUD_MCP_BUSY');
  const u = new URL(results.find((r) => r.status === 'fulfilled').value.authorizeUrl);
  const cb = u.searchParams.get('redirect_uri') + '?code=abc123&state=' + u.searchParams.get('state');
  const staged = await Promise.allSettled([panel.stageCallback(cb, 'paste'), panel.stageCallback(cb, 'paste'), panel.loginUrl()]);
  assert.deepEqual(staged.map((r) => r.status), ['fulfilled', 'rejected', 'rejected']);
  assert.ok(staged.slice(1).every((r) => r.reason.code === 'CLOUD_MCP_BUSY'));
  const jobs = await Promise.allSettled([panel.prepareSwitch(true), panel.prepareSwitch(true)]);
  assert.deepEqual(jobs.map((r) => r.status), ['fulfilled', 'rejected']); assert.equal(jobs[1].reason.code, 'CLOUD_MCP_BUSY');
  jobs[0].value.abort();
  assert.equal((await panel.status()).busy, false);
  await assert.rejects(panel.prepareSwitch(true), (e) => e.code === 'CALLBACK_NOT_STAGED');
  assert.equal((await panel.status()).busy, false, 'failed prepare releases busy');
  await stage();
});

test('L4: safeCode maps known lowercase-suffixed codes to fixed allowlisted labels', () => {
  const cases = [['OAUTH_TOKEN_HTTP_400_invalid_grant', 'OAUTH_TOKEN_HTTP_400_INVALID_GRANT'], ['OAUTH_TOKEN_HTTP_401_invalid_client', 'OAUTH_TOKEN_HTTP_401_INVALID_CLIENT'],
    ['OAUTH_TOKEN_HTTP_400_some_new_thing', 'OAUTH_TOKEN_HTTP_400'], ['OAUTH_TOKEN_HTTP_503', 'OAUTH_TOKEN_HTTP_503'],
    ['CALLBACK_LOGIN_ERROR_access_denied', 'CALLBACK_LOGIN_ERROR_ACCESS_DENIED'], ['CALLBACK_LOGIN_ERROR_weird_value', 'CALLBACK_LOGIN_ERROR'],
    ['MCP_HTTP_400_mcp_rest_denied', 'MCP_HTTP_400'], ['MCP_HTTP_406_B02_FORMAL_WIRE_ACCEPT_DENIED', 'MCP_HTTP_406_B02_FORMAL_WIRE_ACCEPT_DENIED'],
    ['MCP_HTTP_400_RPC-32020', 'MCP_HTTP_400_RPC-32020'], ['OAUTH_TOKEN_EXPIRED', 'OAUTH_TOKEN_EXPIRED'], ['MAC_KEY_UNAVAILABLE', 'MAC_KEY_UNAVAILABLE'],
    ['Bearer abc.def', 'CLOUD_STEP_FAILED'], ['lowercase_secret_value', 'CLOUD_STEP_FAILED'], [undefined, 'CLOUD_STEP_FAILED']];
  for (const [input, expected] of cases) assert.equal(safeCode({ code: input }), expected, String(input));
});

test('home device: unpaired -> not executed; paired -> executed and the simulated light really changes; gateway offline -> not executed', async (t) => {
  const s = await setupCloud();
  const server = await startServer(s);
  t.after(async () => { await server.stop(); await s.cloud.close(); });
  const bearer = await login(server);
  const owner = (path, body) => call(server, path, { method: 'POST', bearer, body });
  const lightOn = async () => (await call(server, '/api/state', { bearer })).body.devices.find((d) => d.id === 'living_light').state.power;
  async function runDevice(deviceId, action) {
    const callbackUrl = s.cloud.authorize(await loginUrl(server, bearer));
    assert.equal((await call(server, '/api/cloud-mcp/callback', op(bearer, 'callback', { body: { callbackUrl } }))).status, 200);
    const r = await call(server, '/api/cloud-mcp/device', op(bearer, 'device', { body: { deviceId, action } }));
    assert.equal(r.status, 200, r.raw); return r;
  }
  // 1) not paired: the cloud command is queued and claimed, but the Mac refuses locally -> no receipt, executed=false
  const unpaired = (await runDevice('living_light', 'on')).body.at(-1);
  assert.equal(unpaired.type, 'result'); assert.equal(unpaired.ok, false); assert.equal(unpaired.result.executed, false);
  assert.equal(s.cloud.state.receipts.length, 0); assert.equal(await lightOn(), false);
  // 2) pair with the 6-digit code, then the same chain applies exactly once
  const code = (await owner('/api/pair/start', { deviceId: 'living_light' })).body.code;
  assert.equal((await owner('/api/pair/confirm', { deviceId: 'living_light', code })).status, 200);
  const r = await runDevice('living_light', 'on'); const final = r.body.at(-1);
  assert.equal(final.ok, true, r.raw); assert.deepEqual(final.worker, { status: 'SUCCEEDED', executed: true });
  assert.deepEqual({ ...final.result, revision: undefined }, { status: 'SUCCEEDED', executed: true, deviceId: 'living_light', action: 'on', deviceStatus: 'simulated_applied', revision: undefined });
  assert.equal(await lightOn(), true);
  const text = r.body.filter((m) => m.type === 'step').map((m) => translate(m.key, m.params)).join('\n');
  assert.match(text, /demo-device started: mode=software-direct, device=living_light, action=on/u);
  assert.match(text, /home_device\.command → PENDING, commandId=cmd_[a-f0-9]{8}…/u);
  assert.match(text, /home_device\.result → SUCCEEDED, executed=true/u); assert.doesNotMatch(text, /redacted/u);
  const audit = (await call(server, '/api/state', { bearer })).body.audit;
  assert.ok(audit.some((e) => e.deviceId === 'living_light' && e.action === 'on' && e.origin === 'cloud_mcp' && e.outcome === 'applied'));
  // red team F1/F2: a device without acknowledgement is refused and NEVER queued (no later apply after the fault clears);
  // the cloud path sends no heartbeat, so the local stale-gateway state is untouched
  const before = (await call(server, '/api/state', { bearer })).body.edge.lastHeartbeatAt;
  assert.equal((await owner('/api/edge/fault', { deviceId: 'living_light', mode: 'no_ack' })).status, 200);
  const noAck = (await runDevice('living_light', 'off')).body.at(-1);
  assert.equal(noAck.ok, false); assert.equal(noAck.result.executed, false);
  const mid = (await call(server, '/api/state', { bearer })).body;
  assert.equal(mid.edge.pendingCount, 0, 'cloud command must not be queued'); assert.equal(mid.edge.lastHeartbeatAt, before, 'no heartbeat from the cloud path');
  assert.equal((await owner('/api/edge/fault', { deviceId: 'living_light', mode: 'none' })).status, 200);
  assert.equal((await owner('/api/edge/heartbeat', {})).status, 200);
  assert.equal(await lightOn(), true, 'refused cloud OFF is not applied later');
  // 3) gateway set offline: refused before any device change
  assert.equal((await owner('/api/edge/online', { online: false })).status, 200);
  const offline = (await runDevice('living_light', 'off')).body.at(-1);
  assert.equal(offline.ok, false); assert.equal(offline.result.executed, false); assert.equal(await lightOn(), true);
  // allowlist and body shape are enforced by the server before any cloud call
  for (const body of [{ deviceId: 'front_door', action: 'unlock' }, { deviceId: 'living_light' }, { deviceId: 'living_light', action: 'on', x: 1 }]) {
    const bad = await call(server, '/api/cloud-mcp/device', op(bearer, 'device', { body }));
    assert.ok([400].includes(bad.status), bad.raw);
  }
  assert.match(server.stdout, /cloud-mcp device living_light on ok=true executed=true mode=software-direct/u);
  assertNoSecrets(server, [s.cloud.state.token, s.key.keyId]);
});
