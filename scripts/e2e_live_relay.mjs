// End-to-end against a DEPLOYED family relay (cloud/aws/family-relay/template.json): a throw-away hub on a random port (Ring off,
// temp stores, the hub relay key whose public key is pinned in the stack) + a scripted family phone that signs exactly like the
// /family page (WebCrypto P-256) and talks only to the relay URL. Prints one JSON summary with timings; no secrets printed.
//   node scripts/e2e_live_relay.mjs https://<id>.lambda-url.<region>.on.aws [relay-key-path]
import { spawn } from 'node:child_process';
import { randomBytes, webcrypto } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import http from 'node:http';
import { homedir, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
const C = join(dirname(fileURLToPath(import.meta.url)), '..');
const { canonical, phoneKeyId } = await import(`${C}/cloud/aws/ring-private/family-relay.mjs`);
const BASE = process.argv[2].replace(/\/$/u, '');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const dir = mkdtempSync(join(tmpdir(), 'e2e-relay-'));
const pass = randomBytes(18).toString('base64url');
const env = { ...process.env, HOME_MCP_PORT: '0', HOME_MCP_DEMO_PASS: pass, HOME_MCP_RING_OPERATOR_PASS: randomBytes(24).toString('base64url'),
  HOME_MCP_PHONE_STORE: join(dir, 'phones.json'), HOME_MCP_RING_PROBE: 'off', HOME_MCP_RELAY_BASE: BASE,
  HOME_MCP_RELAY_KEY: process.argv[3] || join(homedir(), '.home-mcp-console', 'relay.key'), HOME_MCP_RELAY_STORE: join(dir, 'relay_phones.json') };
for (const k of Object.keys(env)) if (k.startsWith('HOME_MCP_NOTIFY_') || k.startsWith('HOME_MCP_BEDROCK_') || k === 'HOME_MCP_VOICE' || k === 'HOME_MCP_PAIR_DIALOG') delete env[k];
const child = spawn(process.execPath, [join(C, 'src', 'server.mjs')], { env, stdio: ['pipe', 'pipe', 'pipe'] });
let out = '', err = ''; child.stdout.on('data', (c) => { out += c; }); child.stderr.on('data', (c) => { err += c; });
const port = await new Promise((res, rej) => { const t = setInterval(() => { const m = out.match(/simulator: http:\/\/127\.0\.0\.1:(\d+)/u); if (m && /pairing code|Paired phones/u.test(out)) { clearInterval(t); res(Number(m[1])); } }, 20); child.once('exit', (c) => rej(new Error('exit ' + c + err))); });
const call = (path, { method = 'GET', bearer, body, headers = {} } = {}) => new Promise((resolve) => {
  const h = { host: `127.0.0.1:${port}`, origin: `http://127.0.0.1:${port}`, ...headers }; if (bearer) h.authorization = `Bearer ${bearer}`;
  const p = body === undefined ? null : Buffer.from(JSON.stringify(body)); if (p) { h['content-type'] = 'application/json'; h['content-length'] = String(p.length); }
  const r = http.request({ host: '127.0.0.1', port, path, method, headers: h, agent: false }, (s) => { const ch = []; s.on('data', (c) => ch.push(c)); s.on('end', () => { let j = null; try { j = JSON.parse(Buffer.concat(ch)); } catch {} resolve({ status: s.statusCode, body: j }); }); });
  r.on('error', () => resolve({ status: 'ERR' })); r.end(p ?? undefined);
});
const result = { at: new Date().toISOString(), relayHost: new URL(BASE).host, phone: 'scripted (Node WebCrypto, same signing as the /family page)' };
try {
  result.startupLine = /Remote approval: via [^ ]+ \(relay public key/u.test(out);
  const code = (out.match(/ADMIN phone pairing code: (\d{4}) (\d{4})/u) || []).slice(1).join('');
  const req = await call('/api/phones/pair-request', { method: 'POST', body: { code, name: 'Admin' } });
  for (let i = 0; i < 100 && !/PAIR PHONE/u.test(err); i += 1) await sleep(30);
  child.stdin.write('y\n');
  let admin;
  for (let i = 0; i < 100; i += 1) { const st = await call('/api/phones/pair-status', { method: 'POST', body: { requestId: req.body.requestId } }); if (st.body?.status === 'approved') { admin = (await call('/api/phones/session', { method: 'POST', body: { deviceToken: st.body.deviceToken } })).body; break; } await sleep(30); }
  const desk = (await call('/api/login', { method: 'POST', body: { passcode: pass } })).body.token;
  const pc = (await call('/api/pair/start', { method: 'POST', bearer: admin.token, body: { deviceId: 'front_door' } })).body.code;
  await call('/api/pair/confirm', { method: 'POST', bearer: admin.token, body: { deviceId: 'front_door', code: pc } });
  const en = await call('/api/relay/enable', { method: 'POST', bearer: admin.token, body: {} });
  result.enable = en.status; result.familyUrlOnRelay = en.body?.url?.startsWith(`${BASE}/family#code=`);
  // family phone (WebCrypto P-256, like the page)
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const { kty, crv, x, y } = await webcrypto.subtle.exportKey('jwk', pair.publicKey); const jwk = { kty, crv, x, y }; const keyId = phoneKeyId(jwk);
  const phone = async (op, payload) => { const ts = Date.now(); const nonce = randomBytes(18).toString('base64url');
    const sig = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, Buffer.from(canonical({ op, payload, keyId, ts, nonce })));
    const r = await fetch(`${BASE}/relay/phone`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ op, payload, keyId, ts, nonce, signature: Buffer.from(sig).toString('base64url') }) });
    return { status: r.status, body: await r.json() }; };
  result.register = (await phone('register', { code: en.body.code, jwk, name: 'Amy' })).status;
  let t0 = Date.now(); let st;
  for (let i = 0; i < 40; i += 1) { st = await call('/api/relay/status', { bearer: admin.token }); if (st.body?.phones?.length) break; await sleep(500); }
  result.activatedAfterMs = Date.now() - t0; result.phonesOnHub = st.body?.phones?.map((p) => p.name);
  const ask = await call('/mcp', { method: 'POST', bearer: desk, body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'device_front_door', arguments: { action: 'unlock' } } }, headers: { accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-11-25' } });
  const asked = ask.body?.result?.structuredContent;
  result.aiAsked = asked?.status;
  let pend; t0 = Date.now();
  for (let i = 0; i < 30; i += 1) { pend = await phone('pending', {}); if (pend.body?.request) break; await sleep(300); }
  result.requestOnPhoneAfterMs = Date.now() - t0; result.phoneSees = pend.body?.request && { label: pend.body.request.label, keys: Object.keys(pend.body.request).sort() };
  const locked = async () => (await call('/api/state', { bearer: desk })).body.devices.find((d) => d.id === 'front_door').state.locked;
  result.lockedBeforeDecision = await locked();
  t0 = Date.now();
  result.decide = (await phone('decide', { requestId: asked.requestId, decision: 'approve' })).status;
  for (let i = 0; i < 40 && await locked(); i += 1) await sleep(250);
  result.decisionToOpenMs = Date.now() - t0; result.lockedAfter = await locked();
  const done = await call('/api/door/status', { method: 'POST', bearer: desk, body: { requestId: asked.requestId } });
  result.status = done.body?.status; result.approver = done.body?.approver;
  for (let i = 0; i < 20; i += 1) { pend = await phone('pending', {}); if (pend.body?.result) break; await sleep(300); }
  result.phoneSeesResult = pend.body?.result?.status;
  result.secondDecision = (await phone('decide', { requestId: asked.requestId, decision: 'deny' })).status;
  const rv = await call('/api/relay/revoke', { method: 'POST', bearer: admin.token, body: { keyId } });
  result.revoke = rv.status; result.afterRevoke = (await phone('pending', {})).body?.error;
  result.hubErrors = (err.match(/^ERROR[^\n]*/gmu) || []).slice(0, 5);
} finally { child.stdin.end(); child.kill('SIGTERM'); }
console.log(JSON.stringify(result, null, 1));
