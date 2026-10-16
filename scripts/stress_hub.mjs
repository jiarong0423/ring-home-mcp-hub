// Stress test of the real src/server.mjs on a throw-away port (Ring network off, temp stores, fake relay cloud that fails on
// purpose). Prints one JSON line per scenario and a summary; exit 1 if any safety check fails. Never touches a real token.
//   node scripts/stress_hub.mjs [--quick]
import { spawn } from 'node:child_process';
import { randomBytes, webcrypto } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonical, createFamilyRelay, createMemoryRelayStore, phoneKeyId } from '../cloud/aws/ring-private/family-relay.mjs';
import { createFamilyRelayHttp } from '../cloud/aws/ring-private/family-relay-http.mjs';
import { loadOrCreateRelayKey, relayPublicKeySpki } from '../src/remote_relay.mjs';

const QUICK = process.argv.includes('--quick');
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = []; let failed = 0;
function report(name, metrics, checks) {
  const bad = Object.entries(checks).filter(([, ok]) => !ok).map(([k]) => k);
  if (bad.length) failed += 1;
  const line = { scenario: name, ok: bad.length === 0, failedChecks: bad, ...metrics };
  results.push(line); console.log(JSON.stringify(line));
}
const pct = (arr, p) => { const s = [...arr].sort((a, b) => a - b); return s.length ? Math.round(s[Math.min(s.length - 1, Math.floor(p / 100 * s.length))]) : null; };
const hist = (arr) => arr.reduce((m, v) => { m[v] = (m[v] ?? 0) + 1; return m; }, {});
async function pool(n, conc, fn) { let i = 0; const out = []; await Promise.all(Array.from({ length: conc }, async () => { while (i < n) { const k = i++; out[k] = await fn(k); } })); return out; }

// ---- fake relay cloud: real relay logic, with injected 500s and delays ----
const dir = mkdtempSync(join(tmpdir(), 'stress-hub-'));
const keyPath = join(dir, 'relay.key');
const edge = createFamilyRelayHttp({ relay: createFamilyRelay({ store: createMemoryRelayStore(), macPublicKeySpki: relayPublicKeySpki(loadOrCreateRelayKey(keyPath)) }) });
let faultRate = 0; let maxDelay = 0; const cloudStats = { calls: 0, injected500: 0 };
const cloud = http.createServer((req, res) => {
  const chunks = []; req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    cloudStats.calls += 1;
    await sleep(Math.random() * maxDelay);
    if (Math.random() < faultRate) { cloudStats.injected500 += 1; res.writeHead(500, { 'content-type': 'application/json' }); res.end('{"error":"INJECTED"}'); return; }
    const route = { '/staging/relay/mac': 'relay-mac', '/staging/relay/phone': 'relay-phone' }[req.url];
    const out = route ? await edge(route, { body: Buffer.concat(chunks).toString('utf8'), isBase64Encoded: false }) : { statusCode: 404, headers: {}, body: '{}' };
    res.writeHead(out.statusCode, out.headers); res.end(out.body);
  });
});
await new Promise((r) => cloud.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${cloud.address().port}/staging`;

// ---- hub ----
const demoPass = randomBytes(18).toString('base64url');
const env = { ...process.env, NODE_ENV: 'test', HOME_MCP_PORT: '0', HOME_MCP_DEMO_PASS: demoPass, HOME_MCP_RING_OPERATOR_PASS: randomBytes(24).toString('base64url'),
  HOME_MCP_PHONE_STORE: join(dir, 'phones.json'), HOME_MCP_RING_PROBE: 'off', HOME_MCP_CLOCK_SPEED: '600',
  HOME_MCP_RELAY_BASE: base, HOME_MCP_RELAY_KEY: keyPath, HOME_MCP_RELAY_STORE: join(dir, 'relay_phones.json') };
for (const k of Object.keys(env)) if (k.startsWith('HOME_MCP_NOTIFY_') || k.startsWith('HOME_MCP_BEDROCK_') || k === 'HOME_MCP_VOICE' || k.startsWith('AWS_') || k === 'RING_ACCESS_TOKEN' || k === 'HOME_MCP_CLOUD_PANEL' || k === 'HOME_MCP_PAIR_DIALOG') delete env[k];
const child = spawn(process.execPath, [join(root, 'src', 'server.mjs')], { env, stdio: ['pipe', 'pipe', 'pipe'] });
let stdout = '', stderr = '';
child.stdout.on('data', (c) => { stdout += c; }); child.stderr.on('data', (c) => { stderr += c; });
const port = await new Promise((resolve, reject) => {
  const t = setInterval(() => { const m = stdout.match(/Home MCP simulator: http:\/\/127\.0\.0\.1:(\d+)/u); if (m && /phone pairing code|Paired phones/u.test(stdout)) { clearInterval(t); resolve(Number(m[1])); } }, 20);
  child.once('exit', (c) => { clearInterval(t); reject(new Error('server exited ' + c + ' ' + stderr)); });
});
const rss = () => { try { return Number(readFileSync(`/proc/${child.pid}/status`, 'utf8').match(/VmRSS:\s+(\d+)/u)[1]) * 1024; } catch { return null; } };
async function rssMac() {
  const { execFileSync } = await import('node:child_process');
  try { return Number(execFileSync('/bin/ps', ['-o', 'rss=', '-p', String(child.pid)]).toString().trim()) * 1024; } catch { return rss(); }
}
function call(path, { method = 'GET', bearer, body, raw, origin = 'self', headers = {} } = {}) {
  const h = { host: `127.0.0.1:${port}`, ...headers };
  if (origin === 'self') h.origin = `http://127.0.0.1:${port}`;
  if (bearer) h.authorization = `Bearer ${bearer}`;
  const payload = raw !== undefined ? Buffer.from(raw) : body === undefined ? null : Buffer.from(JSON.stringify(body));
  if (payload) { h['content-type'] ??= 'application/json'; h['content-length'] = String(payload.length); }
  const t0 = performance.now();
  return new Promise((resolve) => {
    const req = http.request({ host: '127.0.0.1', port, path, method, headers: h, agent: false }, (r) => {
      const chunks = []; r.on('data', (c) => chunks.push(c));
      r.on('end', () => { const s = Buffer.concat(chunks).toString('utf8'); let j = null; try { j = JSON.parse(s); } catch {} resolve({ status: r.statusCode, body: j, ms: performance.now() - t0 }); });
      r.on('error', () => resolve({ status: 'ERR', ms: performance.now() - t0 }));
    });
    req.on('error', (e) => resolve({ status: e.code ?? 'ERR', ms: performance.now() - t0 }));
    req.end(payload ?? undefined);
  });
}
const mcp = (bearer, name, args) => call('/mcp', { method: 'POST', bearer, body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } },
  headers: { accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-11-25' } });
let deskToken = null;   // door state is read with the desktop session, so a revoked phone cannot hide the result
const doorLocked = async () => (await call('/api/state', { bearer: deskToken })).body.devices.find((d) => d.id === 'front_door').state.locked;
async function pairPhone(code, name) {
  const req = await call('/api/phones/pair-request', { method: 'POST', body: { code, name } });
  const seen = (stderr.match(/PAIR PHONE/gu) || []).length;
  for (let i = 0; i < 250 && (stderr.match(/PAIR PHONE/gu) || []).length < Math.max(1, seen); i += 1) await sleep(20);
  child.stdin.write('y\n');
  for (let i = 0; i < 200; i += 1) {
    const st = await call('/api/phones/pair-status', { method: 'POST', body: { requestId: req.body.requestId } });
    if (st.status === 200 && st.body.status === 'approved') {
      const s = await call('/api/phones/session', { method: 'POST', body: { deviceToken: st.body.deviceToken } });
      return { bearer: s.body.token, deviceToken: s.body.deviceToken };
    }
    await sleep(30);
  }
  throw new Error('pairing never settled');
}

try {
  const adminCode = (stdout.match(/ADMIN phone pairing code: (\d{4}) (\d{4})/u) || []).slice(1).join('');
  const admin = await pairPhone(adminCode, 'Admin');
  let dt = admin.deviceToken;
  const desk = (await call('/api/login', { method: 'POST', body: { passcode: demoPass } })).body.token; deskToken = desk;
  for (const deviceId of ['front_door', 'living_light', 'dehumidifier', 'air_conditioner', 'alarm_clock', 'camera']) {
    const c = (await call('/api/pair/start', { method: 'POST', bearer: admin.bearer, body: { deviceId } })).body.code;
    await call('/api/pair/confirm', { method: 'POST', bearer: admin.bearer, body: { deviceId, code: c } });
  }
  const rss0 = await rssMac();

  // S1 read load
  { const n = QUICK ? 500 : 3000; const t0 = performance.now();
    const r = await pool(n, 50, () => call('/api/state', { bearer: desk }));
    const secs = (performance.now() - t0) / 1000; const st = hist(r.map((x) => x.status));
    report('S1 read load /api/state', { requests: n, concurrency: 50, rps: Math.round(n / secs), p50ms: pct(r.map((x) => x.ms), 50), p95ms: pct(r.map((x) => x.ms), 95), p99ms: pct(r.map((x) => x.ms), 99), status: st },
      { all200: st[200] === n }); }

  // S2 MCP door burst: many agents ask at once -> one request, nothing opens
  { const r = await pool(100, 100, () => mcp(desk, 'device_front_door', { action: 'unlock' }));
    const ids = new Set(r.map((x) => x.body?.result?.structuredContent?.requestId).filter(Boolean));
    report('S2 100 concurrent AI unlock requests', { distinctRequests: ids.size, p95ms: pct(r.map((x) => x.ms), 95) },
      { oneRequest: ids.size === 1, doorStaysLocked: await doorLocked() });
    // S3 decide race: one admin phone's credential sent 20 times at once (replay / double send). Design (black-box F2, kept):
    // strict rotation, so exactly one approval goes through and the reused credential revokes THAT phone (fail-safe).
    const racerCode = (await call('/api/phones/pair-code', { method: 'POST', bearer: admin.bearer, body: { role: 'admin' } })).body.code;
    const racer = await pairPhone(racerCode, 'Racer');
    const requestId = [...ids][0];
    const d = await pool(20, 20, () => call('/api/door/decide', { method: 'POST', bearer: racer.bearer, body: { requestId, decision: 'approve', deviceToken: racer.deviceToken } }));
    const ok = d.filter((x) => x.status === 200 && x.body?.status === 'approved');
    const st = hist(d.map((x) => `${x.status}:${x.body?.error ?? x.body?.status}`));
    const racerAfter = (await call('/api/door/pending', { bearer: racer.bearer })).status;
    const mainAdminAfter = (await call('/api/door/pending', { bearer: admin.bearer })).status;
    report('S3 20 concurrent approvals with one credential', { outcomes: st, racerPhoneAfter: racerAfter, mainAdminAfter },
      { exactlyOneApproved: ok.length === 1, doorOpenedOnce: !(await doorLocked()), reusedPhoneRevoked: racerAfter === 401, otherAdminUnaffected: mainAdminAfter === 200 });
    await call('/api/action', { method: 'POST', bearer: admin.bearer, body: { deviceId: 'front_door', action: 'lock' } });
  }

  // S4 malformed flood: junk, oversized, wrong type, wrong origin -> only 4xx, hub alive
  { const junk = ['{', '[]', 'null', '{"a":'.repeat(500), 'x'.repeat(70_000), '{"requestId":1e309}', '\u0000\u0001', JSON.stringify({ sdp: 'v=0' + 'a'.repeat(50_000) })];
    const paths = ['/api/door/request', '/api/door/decide', '/api/door/live', '/api/relay/enable', '/api/relay/revoke', '/api/guardian/summary', '/api/ring/token', '/api/phones/pair-request', '/mcp', '/api/action'];
    const r = await pool(QUICK ? 200 : 800, 40, (k) => call(paths[k % paths.length], { method: 'POST', bearer: k % 3 ? admin.bearer : undefined, raw: junk[k % junk.length],
      origin: k % 7 === 0 ? 'http://evil.invalid' : 'self', headers: k % 5 === 0 ? { 'content-type': 'text/plain' } : {} }));
    const st = hist(r.map((x) => x.status)); const five = r.filter((x) => typeof x.status !== 'number' || x.status >= 500).length;
    const alive = (await call('/api/state', { bearer: desk })).status;
    report('S4 malformed / oversized / cross-origin flood', { requests: r.length, status: st }, { no5xxOrReset: five === 0, hubAlive: alive === 200 });
  }

  // S5 live view and care summary spam without a Ring token
  { await call('/api/door/request', { method: 'POST', bearer: admin.bearer, body: {} });
    const sdp = 'v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\n';
    const lv = await pool(200, 50, () => call('/api/door/live', { method: 'POST', bearer: admin.bearer, body: { sdp } }));
    const sm = await pool(30, 30, () => call('/api/guardian/summary', { method: 'POST', bearer: admin.bearer, body: {} }));
    const pend = (await call('/api/door/pending', { bearer: admin.bearer })).body.pending;
    if (pend) { const r = await call('/api/door/decide', { method: 'POST', bearer: admin.bearer, body: { requestId: pend.requestId, decision: 'deny', deviceToken: dt } }); if (r.body?.deviceToken) dt = r.body.deviceToken; }
    report('S5 live-view x200 and summary x30 without Ring/Bedrock', { live: hist(lv.map((x) => `${x.status}:${x.body?.error}`)), livep95ms: pct(lv.map((x) => x.ms), 95), summary: hist(sm.map((x) => `${x.status}:${x.body?.source}`)) },
      { liveRefusedCleanly: lv.every((x) => x.status === 409 && x.body?.error === 'RING_NOT_CONNECTED'), summaryAllTemplate: sm.every((x) => x.status === 200 && x.body?.source === 'template') });
  }

  // S6 remote approval through a flaky cloud (25 % injected 500s, up to 600 ms delay)
  { faultRate = 0.25; maxDelay = 600;
    let en; for (let i = 0; i < 10 && en?.status !== 200; i += 1) en = await call('/api/relay/enable', { method: 'POST', bearer: admin.bearer, body: {} });
    const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    const { kty, crv, x, y } = await webcrypto.subtle.exportKey('jwk', pair.publicKey); const jwk = { kty, crv, x, y }; const keyId = phoneKeyId(jwk);
    const phone = async (op, payload) => {
      for (let i = 0; i < 8; i += 1) {   // the page retries every 3 s; here faster
        const ts = Date.now(); const nonce = randomBytes(18).toString('base64url');
        const sig = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, Buffer.from(canonical({ op, payload, keyId, ts, nonce })));
        const r = await fetch(`${base}/relay/phone`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ op, payload, keyId, ts, nonce, signature: Buffer.from(sig).toString('base64url') }) }).catch(() => null);
        if (r && r.status !== 500) return { status: r.status, body: await r.json() };
        await sleep(300);
      }
      return { status: 'gave_up' };
    };
    await phone('register', { code: en.body.code, jwk, name: 'Away' });
    for (let i = 0; i < 80 && !(await call('/api/relay/status', { bearer: admin.bearer })).body.phones?.length; i += 1) await sleep(250);
    const rounds = QUICK ? 4 : 10; let opened = 0, denied = 0, lostToFaults = 0, wrongOutcome = 0; const lat = [];
    for (let k = 0; k < rounds; k += 1) {
      const want = k % 2 ? 'deny' : 'approve';
      const ask = (await call('/api/door/request', { method: 'POST', bearer: admin.bearer, body: {} })).body;
      let seen = null; for (let i = 0; i < 40 && !seen; i += 1) { const p = await phone('pending', {}); if (p.body?.request?.requestId === ask.requestId) seen = p; else await sleep(200); }
      const t0 = Date.now();
      if (seen) await phone('decide', { requestId: ask.requestId, decision: want });
      let st; for (let i = 0; i < 100; i += 1) { st = (await call('/api/door/status', { method: 'POST', bearer: admin.bearer, body: { requestId: ask.requestId } })).body; if (st.status !== 'pending') break; await sleep(200); }
      if (st.status === 'pending') { lostToFaults += 1; const r = await call('/api/door/decide', { method: 'POST', bearer: admin.bearer, body: { requestId: ask.requestId, decision: 'deny', deviceToken: dt } }); if (r.body?.deviceToken) dt = r.body.deviceToken; continue; }
      lat.push(Date.now() - t0);
      if (st.status === 'approved' && want === 'approve') opened += 1; else if (st.status === 'denied' && want === 'deny') denied += 1; else wrongOutcome += 1;
      await call('/api/action', { method: 'POST', bearer: admin.bearer, body: { deviceId: 'front_door', action: 'lock' } });
    }
    faultRate = 0; maxDelay = 0;
    const relayErrors = (stderr.match(/ERROR remote approval relay/gu) || []).length;
    report('S6 remote approval through a flaky cloud', { rounds, opened, denied, notDeliveredInTime: lostToFaults, decisionToDoorP50ms: pct(lat, 50), decisionToDoorMaxMs: lat.length ? Math.max(...lat) : null, cloudCalls: cloudStats.calls, injected500: cloudStats.injected500, hubLoggedRelayErrors: relayErrors },
      { noWrongOutcome: wrongOutcome === 0, mostDelivered: lostToFaults <= Math.ceil(rounds * 0.2), errorsVisibleInLog: cloudStats.injected500 === 0 || relayErrors > 0 });
  }

  // S7 long run: demo clock x600 (10 sim-min per second), gateway flapping, memory sampled
  { const secs = QUICK ? 20 : 90; const samples = []; const t0 = Date.now(); let flips = 0;
    while (Date.now() - t0 < secs * 1000) {
      await call('/api/edge/online', { method: 'POST', bearer: admin.bearer, body: { online: flips % 2 === 1 } }); flips += 1;
      await pool(20, 10, () => call('/api/guardian/status', { bearer: desk }));
      if (flips % 5 === 0) samples.push(await rssMac());
      await sleep(1000);
    }
    await call('/api/edge/online', { method: 'POST', bearer: admin.bearer, body: { online: true } });
    const g = (await call('/api/guardian/status', { bearer: desk })).body;
    const first = samples[0], last = samples.at(-1), peak = Math.max(...samples);
    report('S7 long run with flapping gateway (clock x600)', { seconds: secs, simulatedHours: Math.round(secs * 600 / 3600), gatewayFlips: flips, eventsKept: g.events?.length, rssStartMB: Math.round(rss0 / 1e6), rssFirstMB: Math.round(first / 1e6), rssLastMB: Math.round(last / 1e6), rssPeakMB: Math.round(peak / 1e6) },
      { eventsCapped: (g.events?.length ?? 0) <= 200, rssGrowthUnder40MB: last - first < 40e6, hubAlive: child.exitCode === null });
  }

  const unhandled = /UnhandledPromiseRejection|TypeError|ReferenceError|RangeError/u.test(stderr);
  report('S8 hub log after all scenarios', { stderrErrorLines: (stderr.match(/^ERROR/gmu) || []).length, sampleErrors: [...new Set((stderr.match(/^ERROR[^\n]{0,80}/gmu) || []))].slice(0, 6) },
    { noCrashOrUnhandled: !unhandled && child.exitCode === null, noSecretsInLog: ![demoPass, admin.deviceToken, dt].some((s) => (stdout + stderr).includes(s)) });
} finally {
  child.stdin.end(); child.kill('SIGTERM'); cloud.close();
}
const out = process.env.STRESS_OUT;
if (out) writeFileSync(out, JSON.stringify({ at: new Date().toISOString(), quick: QUICK, results }, null, 1));
console.log(failed ? `STRESS_FAIL ${failed} scenario(s)` : 'STRESS_PASS');
process.exit(failed ? 1 : 0);
