// Door approval (DOOR_APPROVAL_PLAN_zh.md §7.1 D1–D12): module tests with a fake clock, Ring snapshot tests with a fake fetch,
// and a server integration run against the real src/server.mjs (temp phone store, Ring network off, the test answers "y").
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createDoorRequests } from '../src/door_requests.mjs';
import { createRingSnapshot, simulatedDoorSnapshot, SNAPSHOT_MAX_BYTES } from '../src/ring_snapshot.mjs';

function setup() {
  let now = 1_800_000_000_000; let n = 0;
  const events = [];
  const doors = createDoorRequests({ clock: () => now, newId: () => String(++n).padStart(22, 'x'), onEvent: (kind, r) => events.push([kind, r.status]) });
  return { doors, events, tick: (ms) => { now += ms; } };
}

test('module: a request never opens anything; approve runs the executor once and keeps the receipt', () => {
  const { doors, events } = setup();
  const r = doors.request({ kind: 'mcp', name: 'AI agent' });
  assert.equal(r.status, 'pending'); assert.equal(r.simulated, true); assert.equal(r.secondsLeft, 60);
  let runs = 0;
  const done = doors.decide({ requestId: r.requestId, decision: 'approve', approver: 'Me', execute: () => { runs += 1; return { receiptId: 'abc' }; } });
  assert.equal(done.status, 'approved'); assert.equal(done.approver, 'Me'); assert.deepEqual(done.receipt, { receiptId: 'abc' });
  assert.equal(runs, 1);
  // D6: single use
  assert.throws(() => doors.decide({ requestId: r.requestId, decision: 'approve', approver: 'Me', execute: () => { runs += 1; } }), { code: 'DOOR_REQUEST_ALREADY_DECIDED' });
  assert.throws(() => doors.decide({ requestId: r.requestId, decision: 'deny', approver: 'Me' }), { code: 'DOOR_REQUEST_ALREADY_DECIDED' });
  assert.equal(runs, 1);
  assert.deepEqual(events, [['requested', 'pending'], ['approved', 'approved']]);
});

test('module D3 (clock): expiry at exactly 60 s, snapshot dropped with the request', () => {
  let now = 1_000;
  const events = [];
  const doors = createDoorRequests({ clock: () => now, onEvent: (kind) => events.push(kind) });
  const r = doors.request({ kind: 'phone', name: 'Mom' });
  doors.attachSnapshot(r.requestId, { bytes: Buffer.from('x'), type: 'image/jpeg', source: 'ring' });
  now += 59_999;
  assert.equal(doors.pending().secondsLeft, 1);
  assert.equal(doors.snapshot().source, 'ring');
  now += 1;
  assert.equal(doors.pending(), null);
  assert.throws(() => doors.snapshot(), { code: 'DOOR_SNAPSHOT_NONE' });
  let ran = 0;
  assert.throws(() => doors.decide({ requestId: r.requestId, decision: 'approve', approver: 'Me', execute: () => { ran += 1; } }), { code: 'DOOR_REQUEST_EXPIRED' });
  assert.equal(ran, 0);
  assert.equal(doors.status({ requestId: r.requestId }).status, 'expired');
  assert.deepEqual(events, ['requested', 'expired']);
});

test('module D7: one request at a time; the same asker gets the same one back, anyone else gets 409', () => {
  const { doors } = setup();
  const a = doors.request({ kind: 'mcp', name: 'AI agent' });
  const again = doors.request({ kind: 'mcp', name: 'AI agent' });
  assert.equal(again.requestId, a.requestId); assert.equal(again.existing, true);
  assert.throws(() => doors.request({ kind: 'phone', name: 'Mom' }), { status: 409, code: 'DOOR_REQUEST_PENDING' });
  doors.decide({ requestId: a.requestId, decision: 'deny', approver: 'Me' });
  assert.equal(doors.request({ kind: 'phone', name: 'Mom' }).status, 'pending');
});

test('module: gateway failure on approve -> "failed" with the reason, not "approved"; bad input refused', () => {
  const { doors } = setup();
  const r = doors.request({ kind: 'console', name: 'console' });
  const out = doors.decide({ requestId: r.requestId, decision: 'approve', approver: 'Me', execute: () => { const e = new Error('x'); e.code = 'EDGE_OFFLINE_UNSAFE'; throw e; } });
  assert.equal(out.status, 'failed'); assert.equal(out.reason, 'EDGE_OFFLINE_UNSAFE'); assert.equal(out.receipt, undefined);
  assert.throws(() => doors.request({ kind: 'root', name: 'x' }), { code: 'INVALID_REQUESTER' });
  assert.throws(() => doors.status({ requestId: '../../etc' }), { code: 'INVALID_REQUEST_ID' });
  assert.throws(() => doors.status({ requestId: 'y'.repeat(22) }), { code: 'DOOR_REQUEST_UNKNOWN' });
  const r2 = doors.request({ kind: 'phone', name: '<b>Mom</b>\u0007' });
  assert.equal(r2.requester.name, 'bMom/b');
  assert.throws(() => doors.decide({ requestId: r2.requestId, decision: 'maybe', approver: 'Me' }), { code: 'INVALID_DECISION' });
});

// ---- Ring snapshot (fake fetch; no network) ----
function fakeRing(steps) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url: String(url), auth: init.headers?.Authorization ?? null, method: init.method ?? 'GET', body: init.body ?? null });
    const step = steps.shift();
    if (!step) throw new Error('unexpected call ' + url);
    return step;
  };
  return { calls, fetchImpl };
}
const res = (status, { json, headers = {}, bytes } = {}) => ({ status, ok: status >= 200 && status < 300,
  headers: new Headers(headers), json: async () => json, arrayBuffer: async () => (bytes ?? Buffer.alloc(0)) });
const devices = () => res(200, { json: { data: [{ id: 'cam-1' }] } });

test('snapshot D10: 303 -> pre-signed URL -> JPEG; the Ring token is never sent to the pre-signed URL', async () => {
  const jpeg = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3]);
  const ring = fakeRing([devices(), res(303, { headers: { location: 'https://media.example/p?sig=1' } }), res(200, { headers: { 'content-type': 'image/jpeg' }, bytes: jpeg })]);
  const snap = createRingSnapshot({ getToken: () => 'ring-token-x', fetchImpl: ring.fetchImpl, sleep: async () => {}, now: () => 1_700_000_600_000 });
  const out = await snap();
  assert.equal(out.source, 'ring'); assert.equal(out.type, 'image/jpeg'); assert.deepEqual(out.bytes, jpeg);
  assert.equal(ring.calls[1].method, 'POST'); assert.match(ring.calls[1].url, /\/v1\/devices\/cam-1\/media\/image\/download$/u);
  assert.deepEqual(JSON.parse(ring.calls[1].body), { type: 'latest_in_range', start_timestamp: 1_700_000_000_000, image_options: { format: 'jpeg' } });
  assert.equal(ring.calls[0].auth, 'Bearer ring-token-x'); assert.equal(ring.calls[2].auth, null);
});

test('snapshot: the pre-signed image GET answering 416 (real Playground, no image yet) means no_recent_image; 425 there is retried', async () => {
  const loc = { headers: { location: 'https://media.example/p?sig=1' } };
  const none = fakeRing([devices(), res(303, loc), res(416, { headers: { 'content-type': 'application/json' } })]);
  const out = await createRingSnapshot({ getToken: () => 't', fetchImpl: none.fetchImpl, sleep: async () => {} })();
  assert.deepEqual(out, { reason: 'no_recent_image', detail: 'image GET HTTP 416' });
  const jpeg = Buffer.from([0xff, 0xd8, 0xff]);
  const later = fakeRing([devices(), res(303, loc), res(425), res(303, loc), res(200, { headers: { 'content-type': 'image/jpeg' }, bytes: jpeg })]);
  assert.equal((await createRingSnapshot({ getToken: () => 't', fetchImpl: later.fetchImpl, sleep: async () => {} })()).source, 'ring');
  assert.equal(simulatedDoorSnapshot('no_recent_image').reason, 'no_recent_image');
});

test('snapshot at the doorbell moment: at_timestamp with the press time', async () => {
  const jpeg = Buffer.from([0xff, 0xd8, 0xff, 1]);
  const ring = fakeRing([devices(), res(303, { headers: { location: 'https://m.example/p' } }), res(200, { headers: { 'content-type': 'image/jpeg' }, bytes: jpeg })]);
  const out = await createRingSnapshot({ getToken: () => 't', fetchImpl: ring.fetchImpl, sleep: async () => {}, now: () => 1_700_000_100_000 })({ at: 1_700_000_090_000 });
  assert.equal(out.source, 'ring');
  assert.deepEqual(JSON.parse(ring.calls[1].body), { type: 'at_timestamp', timestamp: 1_700_000_090_000, image_options: { format: 'jpeg' } });
  // a future or bogus time falls back to the latest image
  const ring2 = fakeRing([devices(), res(416)]);
  await createRingSnapshot({ getToken: () => 't', fetchImpl: ring2.fetchImpl, sleep: async () => {}, now: () => 1_700_000_100_000 })({ at: 1_800_000_000_000 });
  assert.equal(JSON.parse(ring2.calls[1].body).type, 'latest_in_range');
});

test('snapshot D11: no token / 401 / 416 / 425 x3 / 5xx / non-https / wrong type / too big -> a reason, never an image', async () => {
  const cases = [
    [null, [], 'token_missing'],
    ['t', [res(401)], 'token_expired'],
    ['t', [devices(), res(401)], 'token_expired'],
    ['t', [devices(), res(416)], 'no_recent_image'],
    ['t', [devices(), res(425), res(425), res(425)], 'ring_not_ready'],
    ['t', [devices(), res(503), res(503), res(500)], 'ring_not_ready'],
    ['t', [devices(), res(303, { headers: { location: 'http://media.example/p' } })], 'ring_error'],
    ['t', [devices(), res(303, { headers: { location: 'https://media.example/p' } }), res(200, { headers: { 'content-type': 'text/html' }, bytes: Buffer.from('<x>') })], 'ring_error'],
    ['t', [devices(), res(303, { headers: { location: 'https://media.example/p' } }), res(200, { headers: { 'content-type': 'image/jpeg', 'content-length': String(SNAPSHOT_MAX_BYTES + 1) } })], 'ring_error'],
    ['t', [res(200, { json: { data: [{ id: '../x' }] } })], 'ring_error'],
  ];
  for (const [token, steps, reason] of cases) {
    const ring = fakeRing([...steps]);
    const out = await createRingSnapshot({ getToken: () => token, fetchImpl: ring.fetchImpl, sleep: async () => {} })();
    assert.equal(out.reason, reason, JSON.stringify(steps.map((s) => s.status)));
    assert.equal(out.bytes, undefined);
  }
  // 425 then success: retried
  const jpeg = Buffer.from([0xff, 0xd8, 9]);
  const ring = fakeRing([devices(), res(425), res(303, { headers: { location: 'https://m.example/p' } }), res(200, { headers: { 'content-type': 'image/jpeg' }, bytes: jpeg })]);
  assert.equal((await createRingSnapshot({ getToken: () => 't', fetchImpl: ring.fetchImpl, sleep: async () => {} })()).source, 'ring');
  const stand = simulatedDoorSnapshot('<script>');
  assert.equal(stand.source, 'simulated'); assert.equal(stand.reason, 'ring_error');
  assert.match(stand.bytes.toString(), /SIMULATED/u); assert.doesNotMatch(stand.bytes.toString(), /<script>/u);
});

// ---- Server integration ----
const serverPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'server.mjs');
const waitFor = async (check, ms = 5000) => { const end = Date.now() + ms; while (!check()) { if (Date.now() > end) throw new Error('timeout'); await new Promise((r) => setTimeout(r, 20)); } };
async function startServer(extraEnv = {}) {
  const store = join(mkdtempSync(join(tmpdir(), 'door-server-')), 'phones.json');
  const demoPass = randomBytes(18).toString('base64url');
  const env = { ...process.env, HOME_MCP_PORT: '0', HOME_MCP_DEMO_PASS: demoPass, HOME_MCP_RING_OPERATOR_PASS: randomBytes(24).toString('base64url'),
    HOME_MCP_PHONE_STORE: store, HOME_MCP_RING_PROBE: 'off', ...extraEnv };
  for (const k of Object.keys(env)) if ((k.startsWith('HOME_MCP_RELAY_') && !(k in extraEnv)) || k.startsWith('HOME_MCP_NOTIFY_') || k.startsWith('HOME_MCP_BEDROCK_') || k === 'HOME_MCP_VOICE' || k.startsWith('AWS_') || k === 'RING_ACCESS_TOKEN' || k === 'HOME_MCP_CLOUD_PANEL') delete env[k];
  const child = spawn(process.execPath, [serverPath], { env, stdio: ['pipe', 'pipe', 'pipe'] });
  const server = { child, stdout: '', stderr: '', store, demoPass };
  child.stdout.on('data', (c) => { server.stdout += c; }); child.stderr.on('data', (c) => { server.stderr += c; });
  server.port = await new Promise((resolve, reject) => {
    const timer = setInterval(() => { const m = server.stdout.match(/Home MCP simulator: http:\/\/127\.0\.0\.1:(\d+)/u); if (m && /phone pairing code|Paired phones/u.test(server.stdout)) { clearInterval(timer); resolve(Number(m[1])); } }, 20);
    child.once('exit', (code) => { clearInterval(timer); reject(new Error('server exited ' + code + ' ' + server.stderr)); });
  });
  server.adminCode = (server.stdout.match(/ADMIN phone pairing code: (\d{4}) (\d{4})/u) || []).slice(1).join('');
  server.stop = () => new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve();
    const hard = setTimeout(() => child.kill('SIGKILL'), 3000);
    child.once('exit', () => { clearTimeout(hard); resolve(); });
    child.stdin.end(); child.kill('SIGTERM');
  });
  return server;
}
function call(server, path, { method = 'GET', bearer, body, origin = 'self', headers = {} } = {}) {
  const h = { host: `127.0.0.1:${server.port}`, ...headers };
  if (origin === 'self') h.origin = `http://127.0.0.1:${server.port}`; else if (origin) h.origin = origin;
  if (bearer) h.authorization = `Bearer ${bearer}`;
  const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
  if (payload) { h['content-type'] = 'application/json'; h['content-length'] = String(payload.length); }
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: server.port, path, method, headers: h }, (r) => {
      const chunks = []; r.on('data', (c) => chunks.push(c));
      r.on('end', () => { const buf = Buffer.concat(chunks); const raw = buf.toString('utf8'); let parsed = null; try { parsed = JSON.parse(raw); } catch {} resolve({ status: r.statusCode, headers: r.headers, body: parsed, raw, buf }); });
    });
    req.once('error', reject); req.end(payload ?? undefined);
  });
}
async function pairPhone(server, code, name) {
  const req = await call(server, '/api/phones/pair-request', { method: 'POST', body: { code, name } });
  assert.equal(req.status, 202, req.raw);
  const seen = (server.stderr.match(/PAIR PHONE/gu) || []).length;
  await waitFor(() => (server.stderr.match(/PAIR PHONE/gu) || []).length >= Math.max(1, seen));
  server.child.stdin.write('y\n');
  for (let i = 0; i < 100; i += 1) {
    const st = await call(server, '/api/phones/pair-status', { method: 'POST', body: { requestId: req.body.requestId } });
    if (st.status === 200 && st.body.status === 'approved') {
      const s = await call(server, '/api/phones/session', { method: 'POST', body: { deviceToken: st.body.deviceToken } });
      assert.equal(s.status, 200, s.raw);
      return { bearer: s.body.token, deviceToken: s.body.deviceToken, all: [st.body.deviceToken, s.body.deviceToken, s.body.token] };
    }
    await new Promise((r) => setTimeout(r, 30));
  }
  throw new Error('pairing never settled');
}
const mcp = (server, bearer, name, args) => call(server, '/mcp', { method: 'POST', bearer, body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } },
  headers: { accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-11-25' } });
const doorLocked = async (server, bearer) => (await call(server, '/api/state', { bearer })).body.devices.find((d) => d.id === 'front_door').state.locked;

test('server D1–D12: agent / family ask, only the admin phone (with its own credential) decides; snapshot admin-only and gone after', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());
  const secrets = [];
  const admin = await pairPhone(server, server.adminCode, 'Me'); secrets.push(...admin.all);
  let dt = admin.deviceToken;
  const desk = (await call(server, '/api/login', { method: 'POST', body: { passcode: server.demoPass } })).body.token; secrets.push(desk);
  const pc = (await call(server, '/api/pair/start', { method: 'POST', bearer: admin.bearer, body: { deviceId: 'front_door' } })).body.code;
  assert.equal((await call(server, '/api/pair/confirm', { method: 'POST', bearer: admin.bearer, body: { deviceId: 'front_door', code: pc } })).status, 200);
  const memberCode = (await call(server, '/api/phones/pair-code', { method: 'POST', bearer: admin.bearer, body: { role: 'member' } })).body.code;
  const mom = await pairPhone(server, memberCode, 'Mom'); secrets.push(...mom.all);

  // D1: AI agent over MCP asks -> pending, SIMULATED, door still locked
  const ask = await mcp(server, desk, 'device_front_door', { action: 'unlock' });
  const asked = ask.body.result?.structuredContent;
  assert.equal(ask.body.result?.isError, false, ask.raw);
  assert.equal(asked.status, 'pending_approval'); assert.equal(asked.simulated, true); assert.equal(asked.requester.kind, 'mcp');
  assert.equal(await doorLocked(server, admin.bearer), true);
  // D7: a different asker while pending -> refused; the agent asking again gets the same request
  assert.equal((await call(server, '/api/door/request', { method: 'POST', bearer: mom.bearer, body: {} })).status, 409);
  assert.equal((await mcp(server, desk, 'device_front_door', { action: 'unlock' })).body.result.structuredContent.requestId, asked.requestId);
  // admin phone sees it; nobody else does
  const pend = await call(server, '/api/door/pending', { bearer: admin.bearer });
  assert.equal(pend.body.pending.requestId, asked.requestId);
  for (const who of [desk, mom.bearer]) assert.equal((await call(server, '/api/door/pending', { bearer: who })).status, 403);
  // D10: snapshot admin phone only (Ring network off -> labelled stand-in)
  let shot;
  for (let i = 0; i < 50; i += 1) { shot = await call(server, '/api/door/snapshot', { bearer: admin.bearer }); if (shot.status === 200) break; await new Promise((r) => setTimeout(r, 20)); }
  assert.equal(shot.status, 200); assert.equal(shot.headers['x-snapshot-source'], 'simulated'); assert.equal(shot.headers['cache-control'], 'no-store');
  assert.match(shot.raw, /SIMULATED/u); assert.match(shot.raw, /token_missing/u);
  for (const who of [desk, mom.bearer]) assert.equal((await call(server, '/api/door/snapshot', { bearer: who })).status, 403);
  // D4: session alone cannot decide: desktop session, admin session without / with a wrong credential, family phone, cross-origin
  assert.equal((await call(server, '/api/door/decide', { method: 'POST', bearer: desk, body: { requestId: asked.requestId, decision: 'approve', deviceToken: dt } })).body.error, 'ADMIN_PHONE_REQUIRED');
  assert.equal((await call(server, '/api/door/decide', { method: 'POST', bearer: admin.bearer, body: { requestId: asked.requestId, decision: 'approve' } })).status, 400);
  assert.equal((await call(server, '/api/door/decide', { method: 'POST', bearer: admin.bearer, body: { requestId: asked.requestId, decision: 'approve', deviceToken: randomBytes(32).toString('base64url') } })).status, 401);
  // D5: family phone, even with its own credential
  assert.equal((await call(server, '/api/door/decide', { method: 'POST', bearer: mom.bearer, body: { requestId: asked.requestId, decision: 'approve', deviceToken: mom.deviceToken } })).body.error, 'MEMBER_NOT_ALLOWED');
  assert.equal((await call(server, '/api/door/decide', { method: 'POST', bearer: admin.bearer, origin: 'http://evil.invalid', body: { requestId: asked.requestId, decision: 'approve', deviceToken: dt } })).status, 403);
  assert.equal(await doorLocked(server, admin.bearer), true);
  // the agent cannot get the one-use phrase any more
  assert.equal((await call(server, '/api/confirm/start', { method: 'POST', bearer: desk, body: { deviceId: 'front_door', action: 'unlock' } })).body.error, 'DOOR_APPROVAL_REQUIRED');
  // D1: admin phone approves -> opened (SIMULATED), receipt, credential rotated
  const ok = await call(server, '/api/door/decide', { method: 'POST', bearer: admin.bearer, body: { requestId: asked.requestId, decision: 'approve', deviceToken: dt } });
  assert.equal(ok.status, 200, ok.raw); assert.equal(ok.body.status, 'approved'); assert.equal(ok.body.approver, 'Me'); assert.equal(ok.body.simulated, true);
  assert.match(ok.body.receipt.receiptId, /^.{12}$/u);
  assert.notEqual(ok.body.deviceToken, dt); dt = ok.body.deviceToken; secrets.push(dt);
  assert.equal(await doorLocked(server, admin.bearer), false);
  assert.equal((await call(server, '/api/door/status', { method: 'POST', bearer: desk, body: { requestId: asked.requestId } })).body.status, 'approved');
  // D6: approving twice -> refused, door opened once; credential still rotated and handed back
  const twice = await call(server, '/api/door/decide', { method: 'POST', bearer: admin.bearer, body: { requestId: asked.requestId, decision: 'approve', deviceToken: dt } });
  assert.equal(twice.status, 409); assert.equal(twice.body.error, 'DOOR_REQUEST_ALREADY_DECIDED'); dt = twice.body.deviceToken; secrets.push(dt);
  // D12: snapshot gone once decided
  assert.equal((await call(server, '/api/door/snapshot', { bearer: admin.bearer })).status, 404);
  assert.equal((await call(server, '/api/action', { method: 'POST', bearer: admin.bearer, body: { deviceId: 'front_door', action: 'lock' } })).status, 200);

  // D2: family phone asks -> admin denies -> stays locked; family sees "denied"
  const famAsk = await call(server, '/api/action', { method: 'POST', bearer: mom.bearer, body: { deviceId: 'front_door', action: 'unlock' } });
  assert.equal(famAsk.status, 202, famAsk.raw); assert.equal(famAsk.body.requester.name, 'Mom');
  const no = await call(server, '/api/door/decide', { method: 'POST', bearer: admin.bearer, body: { requestId: famAsk.body.requestId, decision: 'deny', deviceToken: dt } });
  assert.equal(no.body.status, 'denied'); dt = no.body.deviceToken; secrets.push(dt);
  assert.equal((await call(server, '/api/door/status', { method: 'POST', bearer: mom.bearer, body: { requestId: famAsk.body.requestId } })).body.status, 'denied');
  assert.equal(await doorLocked(server, admin.bearer), true);

  // gateway offline: approve -> "failed", door stays locked, ERROR logged
  await call(server, '/api/edge/online', { method: 'POST', bearer: admin.bearer, body: { online: false } });
  const off = await call(server, '/api/door/request', { method: 'POST', bearer: mom.bearer, body: {} });
  const failed = await call(server, '/api/door/decide', { method: 'POST', bearer: admin.bearer, body: { requestId: off.body.requestId, decision: 'approve', deviceToken: dt } });
  assert.equal(failed.body.status, 'failed'); assert.equal(failed.body.reason, 'EDGE_OFFLINE_UNSAFE'); dt = failed.body.deviceToken; secrets.push(dt);
  assert.equal(await doorLocked(server, admin.bearer), true);
  assert.match(server.stderr, /ERROR door approved but not opened: EDGE_OFFLINE_UNSAFE/u);
  await call(server, '/api/edge/online', { method: 'POST', bearer: admin.bearer, body: { online: true } });

  // D8: schedules and batches still cannot unlock
  assert.equal((await call(server, '/api/schedules', { method: 'POST', bearer: admin.bearer, body: { deviceId: 'front_door', action: 'unlock', at: new Date(Date.now() + 5000).toISOString() } })).status, 403);
  const batch = await mcp(server, admin.bearer, 'device_batch', { commands: [{ deviceId: 'front_door', action: 'unlock' }] });
  assert.deepEqual(batch.body.result?.structuredContent?.results?.map((r) => [r.status, r.code]), [['denied', 'BATCH_UNSAFE']], batch.raw);
  assert.equal(await doorLocked(server, admin.bearer), true);

  // D9: timeline has each step once; no credential, token or snapshot bytes in any output or the store
  const events = (await call(server, '/api/guardian/status', { bearer: admin.bearer })).body.events.filter((e) => e.target === 'front_door').map((e) => e.kind).reverse();
  assert.deepEqual(events, ['door_requested', 'door_approved', 'door_requested', 'door_denied', 'door_requested', 'door_failed']);
  const dump = [server.stdout, server.stderr, readFileSync(server.store, 'utf8')].join('\n');
  for (const secret of secrets) assert.equal(dump.includes(secret), false, 'secret leaked');
  assert.doesNotMatch(dump, /<svg/u);
  assert.match(server.stdout, /door request approved: by "AI agent \(MCP\)" decided by "Me" SIMULATED/u);

  // Ring doorbell (simulated, no token): admin may ring it; family may not; it is only a request; the admin phone still decides
  assert.match(server.stdout, /Ring doorbell: off \(HOME_MCP_RING_PROBE=off\)/u);
  assert.equal((await call(server, '/api/door/doorbell-demo', { method: 'POST', bearer: mom.bearer, body: {} })).body.error, 'MEMBER_NOT_ALLOWED');
  assert.equal((await call(server, '/api/door/doorbell-demo', { method: 'POST', bearer: desk, body: {} })).body.error, 'ADMIN_PHONE_REQUIRED', 'desktop cannot fake a doorbell');
  const bell = await call(server, '/api/door/doorbell-demo', { method: 'POST', bearer: admin.bearer, body: {} });
  assert.equal(bell.status, 202, bell.raw); assert.equal(bell.body.requester.kind, 'ring'); assert.equal(bell.body.status, 'pending_approval');
  assert.equal(await doorLocked(server, admin.bearer), true);
  // pressing again while it waits: same request, and the timeline says so
  assert.equal((await call(server, '/api/door/doorbell-demo', { method: 'POST', bearer: admin.bearer, body: {} })).body.requestId, bell.body.requestId);
  const ringPending = (await call(server, '/api/door/pending', { bearer: admin.bearer })).body.pending;
  // Ring live view: admin phone only, only while someone waits; no token -> a clear reason (the snapshot still works)
  const offer = 'v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\n';
  for (const who of [desk, mom.bearer]) assert.equal((await call(server, '/api/door/live', { method: 'POST', bearer: who, body: { sdp: offer } })).status, 403);
  const noRing = await call(server, '/api/door/live', { method: 'POST', bearer: admin.bearer, body: { sdp: offer } });
  assert.equal(noRing.status, 409); assert.equal(noRing.body.error, 'RING_NOT_CONNECTED');
  assert.equal((await call(server, '/api/door/live', { method: 'POST', bearer: admin.bearer, body: { sdp: offer, extra: 1 } })).status, 400);
  assert.equal(ringPending.requester.kind, 'ring');
  assert.equal((await call(server, '/api/door/decide', { method: 'POST', bearer: desk, body: { requestId: bell.body.requestId, decision: 'approve', deviceToken: dt } })).body.error, 'ADMIN_PHONE_REQUIRED');
  const bellOk = await call(server, '/api/door/decide', { method: 'POST', bearer: admin.bearer, body: { requestId: bell.body.requestId, decision: 'approve', deviceToken: dt } });
  assert.equal(bellOk.body.status, 'approved'); dt = bellOk.body.deviceToken;
  assert.equal(await doorLocked(server, admin.bearer), false);
  assert.equal((await call(server, '/api/door/live', { method: 'POST', bearer: admin.bearer, body: { sdp: offer } })).body.error, 'DOOR_REQUEST_NONE');
  const ringEvents = (await call(server, '/api/guardian/status', { bearer: admin.bearer })).body.events.filter((e) => e.params?.requesterKind === 'ring').map((e) => e.kind);
  assert.deepEqual(ringEvents, ['door_approved', 'doorbell_again', 'door_requested']);
  // daily care summary on request: admin only; Bedrock not configured here -> plain template note from today's log
  assert.equal((await call(server, '/api/guardian/summary', { method: 'POST', bearer: mom.bearer, body: {} })).status, 403);
  const summary = await call(server, '/api/guardian/summary', { method: 'POST', bearer: admin.bearer, body: {} });
  assert.equal(summary.status, 200, summary.raw); assert.equal(summary.body.source, 'template'); assert.equal(summary.body.reason, 'BEDROCK_NOT_CONFIGURED');
  assert.deepEqual(summary.body.facts.door.map((d) => d.outcome), ['approved', 'denied', 'failed', 'approved']);
  assert.match(summary.body.text, /Front door: .*Ring doorbell → approved by Me/u);
  assert.match(server.stdout, /care summary \(on request\): template BEDROCK_NOT_CONFIGURED; email not sent \(NOTIFY_DISABLED\)/u);
});

test('Ring connection card: admin pastes a token (memory only, never echoed or logged); family and desktop-without-operator refused; clear works', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());
  const admin = await pairPhone(server, server.adminCode, 'Me');
  const desk = (await call(server, '/api/login', { method: 'POST', body: { passcode: server.demoPass } })).body.token;
  const memberCode = (await call(server, '/api/phones/pair-code', { method: 'POST', bearer: admin.bearer, body: { role: 'member' } })).body.code;
  const mom = await pairPhone(server, memberCode, 'Mom');
  const token = 'ring_' + randomBytes(40).toString('base64url');
  assert.equal((await call(server, '/api/ring/token-status', { bearer: admin.bearer })).body.state, 'none');
  assert.equal((await call(server, '/api/ring/token', { method: 'POST', bearer: mom.bearer, body: { token } })).body.error, 'MEMBER_NOT_ALLOWED');
  assert.equal((await call(server, '/api/ring/token', { method: 'POST', bearer: desk, body: { token } })).body.error, 'RING_OPERATOR_DENIED');
  assert.equal((await call(server, '/api/ring/token', { method: 'POST', bearer: admin.bearer, origin: 'http://evil.invalid', body: { token } })).status, 403);
  assert.equal((await call(server, '/api/ring/token', { method: 'POST', bearer: admin.bearer, body: { token: 'not a token <script>' } })).body.error, 'RING_TOKEN_INVALID');
  assert.equal((await call(server, '/api/ring/token', { method: 'POST', bearer: admin.bearer, body: { token, extra: 1 } })).status, 400);
  const ok = await call(server, '/api/ring/token', { method: 'POST', bearer: admin.bearer, body: { token } });
  assert.equal(ok.status, 200, ok.raw); assert.equal(ok.body.state, 'offline_mode', 'test hub keeps Ring network off');
  assert.equal(Date.parse(ok.body.expiresAtEstimate) - Date.parse(ok.body.loadedAt), 30 * 60_000);
  assert.equal(ok.body.playgroundUrl, 'https://developer.amazon.com/ring/console/playground');
  const st = await call(server, '/api/ring/token-status', { bearer: admin.bearer });
  for (const r of [ok, st]) assert.equal(r.raw.includes(token), false, 'token never echoed');
  assert.match(server.stdout, /ring token: loaded into memory from the console \(phone "Me"\)/u);
  assert.equal((server.stdout + server.stderr).includes(token), false, 'token never logged');
  assert.equal(readFileSync(server.store, 'utf8').includes(token), false, 'token never written to the phone store');
  const cleared = await call(server, '/api/ring/token-clear', { method: 'POST', bearer: admin.bearer, body: {} });
  assert.equal(cleared.body.state, 'none');
});

// ---- Family remote approval through the relay (AWS_REMOTE_APPROVAL_PLAN_zh.md): a local stand-in for the cloud runs the real
// relay logic + HTTP edge; a "family phone" signs like the browser page (WebCrypto P-256). The hub decides only after it has
// verified that phone's signature itself.
test('remote approval: admin phone enables, family phone enrols with the one-time code, approves from "away", hub opens; revoke stops it', async (t) => {
  const { createFamilyRelay, createMemoryRelayStore, canonical, phoneKeyId } = await import('../cloud/aws/ring-private/family-relay.mjs');
  const { createFamilyRelayHttp } = await import('../cloud/aws/ring-private/family-relay-http.mjs');
  const { loadOrCreateRelayKey, relayPublicKeySpki } = await import('../src/remote_relay.mjs');
  const { webcrypto } = await import('node:crypto');
  const dir = mkdtempSync(join(tmpdir(), 'relay-server-'));
  const keyPath = join(dir, 'relay.key');
  const edge = createFamilyRelayHttp({ relay: createFamilyRelay({ store: createMemoryRelayStore(), macPublicKeySpki: relayPublicKeySpki(loadOrCreateRelayKey(keyPath)) }) });
  const cloud = http.createServer((req, res) => {
    const chunks = []; req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      const route = { '/staging/relay/mac': 'relay-mac', '/staging/relay/phone': 'relay-phone' }[req.url];
      const out = route ? await edge(route, { body: Buffer.concat(chunks).toString('utf8'), isBase64Encoded: false }) : { statusCode: 404, headers: {}, body: '{}' };
      res.writeHead(out.statusCode, out.headers); res.end(out.body);
    });
  });
  await new Promise((r) => cloud.listen(0, '127.0.0.1', r));
  t.after(() => cloud.close());
  const base = `http://127.0.0.1:${cloud.address().port}/staging`;
  const server = await startServer({ NODE_ENV: 'test', HOME_MCP_RELAY_BASE: base, HOME_MCP_RELAY_KEY: keyPath, HOME_MCP_RELAY_STORE: join(dir, 'relay_phones.json') });
  t.after(() => server.stop());
  assert.match(server.stdout, /Remote approval: via 127\.0\.0\.1:\d+ \(relay public key, pin as FamilyRelayMacKeySpki: [A-Za-z0-9_-]+\)/u);

  const admin = await pairPhone(server, server.adminCode, 'Me');
  const desk = (await call(server, '/api/login', { method: 'POST', body: { passcode: server.demoPass } })).body.token;
  const memberCode = (await call(server, '/api/phones/pair-code', { method: 'POST', bearer: admin.bearer, body: { role: 'member' } })).body.code;
  const mom = await pairPhone(server, memberCode, 'Mom');
  // only the admin PHONE sets it up
  for (const who of [desk, mom.bearer]) assert.equal((await call(server, '/api/relay/enable', { method: 'POST', bearer: who, body: {} })).status, 403);
  assert.equal((await call(server, '/api/relay/enable', { method: 'POST', bearer: admin.bearer, origin: 'http://evil.invalid', body: {} })).status, 403);
  const en = await call(server, '/api/relay/enable', { method: 'POST', bearer: admin.bearer, body: {} });
  assert.equal(en.status, 200, en.raw); assert.match(en.body.code, /^[A-Z2-9]{8}$/u); assert.equal(en.body.url, `${base}/family#code=${en.body.code}`);

  // the family phone, away from home, talks only to the cloud
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const { kty, crv, x, y } = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const jwk = { kty, crv, x, y }; const keyId = phoneKeyId(jwk);
  const phone = async (op, payload) => {
    const ts = Date.now(); const nonce = randomBytes(18).toString('base64url');
    const sig = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, Buffer.from(canonical({ op, payload, keyId, ts, nonce })));
    const r = await fetch(`${base}/relay/phone`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ op, payload, keyId, ts, nonce, signature: Buffer.from(sig).toString('base64url') }) });
    return { status: r.status, body: await r.json() };
  };
  assert.equal((await phone('register', { code: en.body.code, jwk, name: 'Amy' })).status, 200);
  let st;
  for (let i = 0; i < 60; i += 1) { st = await call(server, '/api/relay/status', { bearer: admin.bearer }); if (st.body.phones?.length === 1) break; await new Promise((r) => setTimeout(r, 200)); }
  assert.deepEqual(st.body.phones.map((p) => [p.name, p.keyId]), [['Amy', keyId]], 'hub activated the phone after the code came back');
  assert.match(server.stdout, /remote approval: phone "Amy" activated/u);

  // AI agent asks; the family phone sees only a text summary (no snapshot bytes, no token)
  const pc = (await call(server, '/api/pair/start', { method: 'POST', bearer: admin.bearer, body: { deviceId: 'front_door' } })).body.code;
  assert.equal((await call(server, '/api/pair/confirm', { method: 'POST', bearer: admin.bearer, body: { deviceId: 'front_door', code: pc } })).status, 200);
  const asked = (await mcp(server, desk, 'device_front_door', { action: 'unlock' })).body.result.structuredContent;
  let pend;
  for (let i = 0; i < 30; i += 1) { pend = await phone('pending', {}); if (pend.body.request) break; await new Promise((r) => setTimeout(r, 100)); }
  assert.deepEqual(Object.keys(pend.body.request).sort(), ['hasSnapshot', 'kind', 'label', 'requestId', 'secondsLeft']);
  assert.equal(pend.body.request.requestId, asked.requestId); assert.equal(pend.body.request.label, 'AI agent (MCP)');
  assert.equal(await doorLocked(server, admin.bearer), true, 'nothing opens before a decision');
  assert.equal((await phone('decide', { requestId: asked.requestId, decision: 'approve' })).status, 200);
  for (let i = 0; i < 60 && await doorLocked(server, admin.bearer); i += 1) await new Promise((r) => setTimeout(r, 200));
  assert.equal(await doorLocked(server, admin.bearer), false, 'hub verified the phone signature and opened (SIMULATED)');
  const done = await call(server, '/api/door/status', { method: 'POST', bearer: desk, body: { requestId: asked.requestId } });
  assert.equal(done.body.status, 'approved'); assert.equal(done.body.approver, 'Amy (remote)');
  for (let i = 0; i < 30; i += 1) { pend = await phone('pending', {}); if (pend.body.result) break; await new Promise((r) => setTimeout(r, 100)); }
  assert.equal(pend.body.result.status, 'approved');
  // a second answer for the same request is refused by the cloud (first write wins) and the door was opened once
  assert.notEqual((await phone('decide', { requestId: asked.requestId, decision: 'deny' })).status, 200);

  // admin removes the phone: at home first, then the cloud; the phone can no longer answer
  assert.equal((await call(server, '/api/relay/revoke', { method: 'POST', bearer: mom.bearer, body: { keyId } })).status, 403);
  const rv = await call(server, '/api/relay/revoke', { method: 'POST', bearer: admin.bearer, body: { keyId } });
  assert.equal(rv.status, 200, rv.raw); assert.deepEqual(rv.body.phones, []);
  assert.equal((await phone('pending', {})).body.error, 'PHONE_NOT_ACTIVE');
  // the one-time code and phone credentials never reach the hub's logs
  for (const secret of [en.body.code, admin.deviceToken, mom.deviceToken]) assert.equal((server.stdout + server.stderr).includes(secret), false, 'secret leaked');
});
