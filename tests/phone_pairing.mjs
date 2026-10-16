// Phone pairing: module tests (plan PHONE_PAIRING_PLAN_zh.md §9.1 U1–U12) with a fake clock and a scripted owner answer.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createPhoneRegistry, PAIR_CODE_TTL_MS, CONFIRM_TTL_MS, USED_TOKEN_HISTORY, normalizePhoneName } from '../src/phone_pairing.mjs';

function setup({ answers = [], storePath } = {}) {
  let now = 1_800_000_000_000;
  const asked = []; const revoked = [];
  const queue = [...answers];
  const path = storePath ?? join(mkdtempSync(join(tmpdir(), 'phone-pairing-')), 'store', 'phones.json');
  const make = () => createPhoneRegistry({ storePath: path, clock: () => now, onRevoke: (id, why) => revoked.push([id, why]),
    confirm: async (q) => { asked.push(q); const a = queue.shift(); return typeof a === 'function' ? a() : a; } });
  const reg = make();
  return { reg, make, path, asked, revoked, tick: ms => { now += ms; }, now: () => now };
}
async function pairPhone(s, { role = 'admin', name = 'Me', answer = true } = {}) {
  const { code } = s.reg.createPairCode({ role });
  const { requestId } = s.reg.requestPairing({ code, name });
  await s.reg.settled();
  return { code, requestId, answer };
}

test('U1: right code + owner "y" -> credential handed out once; the code cannot be reused', async () => {
  const s = setup({ answers: [true] });
  const { code, requestId } = await pairPhone(s);
  assert.equal(s.asked.length, 1);
  assert.deepEqual({ ...s.asked[0], check: undefined, signal: undefined }, { name: 'Me', role: 'admin', expiresAt: s.now() + CONFIRM_TTL_MS, check: undefined, signal: undefined });
  assert.equal(s.asked[0].signal.aborted, true, 'the Mac prompt is told the request is settled');
  assert.match(s.asked[0].check, /^[1-9]\d$/u, 'the Mac is shown the two check digits');
  const r = s.reg.pairStatus({ requestId });
  assert.equal(r.status, 'approved'); assert.match(r.deviceToken, /^[A-Za-z0-9_-]{43}$/u); assert.equal(r.role, 'admin');
  assert.throws(() => s.reg.pairStatus({ requestId }), { code: 'PAIR_REQUEST_UNKNOWN' }, 'credential only once');
  assert.throws(() => s.reg.requestPairing({ code, name: 'Again' }), { code: 'PAIR_CODE_INVALID' });
  assert.equal(s.reg.hasAdmin(), true);
});

test('U2/U3: owner says no -> 403; no answer within 120 s -> 410; neither creates a phone', async () => {
  const s = setup({ answers: [false] });
  const { requestId } = await pairPhone(s);
  assert.throws(() => s.reg.pairStatus({ requestId }), { status: 403, code: 'PAIR_REJECTED' });
  const t = setup({ answers: [() => new Promise(() => {})] });
  const { code } = t.reg.createPairCode({ role: 'admin' });
  const { requestId: r2 } = t.reg.requestPairing({ code, name: 'Me' });
  const waiting = t.reg.pairStatus({ requestId: r2 });
  assert.equal(waiting.status, 'pending'); assert.equal(waiting.approver, 'mac'); assert.equal(waiting.secondsLeft, 120); assert.match(waiting.check, /^\d{2}$/u);
  t.tick(CONFIRM_TTL_MS);
  assert.throws(() => t.reg.pairStatus({ requestId: r2 }), { status: 410, code: 'PAIR_CONFIRM_TIMEOUT' });
  assert.equal(s.reg.list().length + t.reg.list().length, 0);
});

test('U4/U5: wrong codes are rate limited after 5 per minute; an expired code is refused', () => {
  const s = setup();
  for (let i = 0; i < 5; i += 1) assert.throws(() => s.reg.requestPairing({ code: '0000000' + i, name: 'X' }), { status: 403 });
  assert.throws(() => s.reg.requestPairing({ code: '12345678', name: 'X' }), { status: 429, code: 'PAIR_RATE_LIMIT' });
  s.tick(60_000);
  const { code } = s.reg.createPairCode({ role: 'admin' });
  s.tick(PAIR_CODE_TTL_MS + 60_000);
  assert.throws(() => s.reg.requestPairing({ code, name: 'X' }), { status: 403, code: 'PAIR_CODE_INVALID' });
  assert.equal(s.asked.length, 0);
});

test('U6: exchange rotates the credential; it carries no expiry; there is no reuse window', async () => {
  const s = setup({ answers: [true] });
  const { requestId } = await pairPhone(s);
  const first = s.reg.pairStatus({ requestId }).deviceToken;
  s.tick(10 * 24 * 60 * 60_000);
  const a = s.reg.exchange({ deviceToken: first });
  assert.notEqual(a.deviceToken, first);
  assert.equal(a.deviceExpiresAt, null);
  const b = s.reg.exchange({ deviceToken: a.deviceToken });
  assert.notEqual(b.deviceToken, a.deviceToken);
});

test('U7: reusing any of the last rotated-out credentials (even immediately, even two generations old) revokes that phone; others unaffected', async () => {
  for (const back of [1, 2, USED_TOKEN_HISTORY]) {
    const s = setup({ answers: [true, true] });
    const admin = s.reg.pairStatus({ requestId: (await pairPhone(s)).requestId });
    const mom = s.reg.pairStatus({ requestId: (await pairPhone(s, { role: 'member', name: 'Mom' })).requestId });
    const chain = [mom.deviceToken];
    for (let i = 0; i < back; i += 1) chain.push(s.reg.exchange({ deviceToken: chain.at(-1) }).deviceToken);
    const stolen = chain[chain.length - 1 - back];
    assert.throws(() => s.reg.exchange({ deviceToken: stolen }), { status: 401, code: 'DEVICE_REVOKED' }, 'back ' + back);
    assert.throws(() => s.reg.exchange({ deviceToken: chain.at(-1) }), { status: 401, code: 'DEVICE_REVOKED' });
    assert.deepEqual(s.revoked, [[mom.deviceId, 'reuse']]);
    assert.equal(s.reg.exchange({ deviceToken: admin.deviceToken }).role, 'admin');
  }
});

test('U8/U9/U10: trusted until removed (a year unused still works); owner revoke is immediate; the last admin cannot be revoked', async () => {
  const s = setup({ answers: [true, true] });
  const admin = s.reg.pairStatus({ requestId: (await pairPhone(s)).requestId });
  const mom = s.reg.pairStatus({ requestId: (await pairPhone(s, { role: 'member', name: 'Mom' })).requestId });
  assert.throws(() => s.reg.revoke({ deviceId: admin.deviceId }), { status: 409, code: 'LAST_ADMIN' });
  assert.deepEqual(s.reg.revoke({ deviceId: mom.deviceId }), { revoked: true, deviceId: mom.deviceId });
  assert.throws(() => s.reg.exchange({ deviceToken: mom.deviceToken }), { status: 401, code: 'DEVICE_REVOKED' });
  assert.equal(s.reg.isActive(mom.deviceId), false);
  s.tick(365 * 24 * 60 * 60_000);
  assert.equal(s.reg.exchange({ deviceToken: admin.deviceToken }).role, 'admin', 'still trusted after a year without use');
});

test('U11: pairing survives a restart; the store file holds digests only and is 0600 in a 0700 folder', async () => {
  const s = setup({ answers: [true] });
  const r = s.reg.pairStatus({ requestId: (await pairPhone(s)).requestId });
  const raw = readFileSync(s.path, 'utf8');
  assert.equal(raw.includes(r.deviceToken), false);
  assert.equal(statSync(s.path).mode & 0o777, 0o600);
  assert.equal(statSync(join(s.path, '..')).mode & 0o777, 0o700);
  const reborn = s.make();
  assert.equal(reborn.hasAdmin(), true);
  const next = reborn.exchange({ deviceToken: r.deviceToken });
  assert.equal(next.deviceId, r.deviceId);
  writeFileSync(s.path, '{"schema":"other"}');
  assert.throws(() => s.make(), /corrupt/u);
});

test('U12: names are 1-20 letters/digits/spaces; control characters and long names are refused before the owner is asked', () => {
  const s = setup();
  assert.equal(normalizePhoneName('  媽媽  手機 '), '媽媽 手機');
  for (const bad of ['', ' ', 'a'.repeat(21), 'Mom\u001b[2J', 'Mom\nyes', '<script>', 42, null]) {
    const { code } = s.reg.createPairCode({ role: 'admin' });
    assert.throws(() => s.reg.requestPairing({ code, name: bad }), { status: 400, code: 'PHONE_NAME_INVALID' }, String(bad));
  }
  assert.equal(s.asked.length, 0);
});

test('members cannot be approved before an admin exists; role must be admin or member', async () => {
  const s = setup({ answers: [true] });
  const { requestId } = await pairPhone(s, { role: 'member', name: 'Mom' });
  assert.throws(() => s.reg.pairStatus({ requestId }), { code: 'PAIR_REJECTED' });
  assert.throws(() => s.reg.createPairCode({ role: 'owner' }), { code: 'PHONE_ROLE_INVALID' });
});

// ---- Server integration (U13–U18): the real src/server.mjs with a temp phone store; the test plays the owner on stdin. ----
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import http from 'node:http';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const serverPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'server.mjs');
async function startServer() {
  const store = join(mkdtempSync(join(tmpdir(), 'phone-server-')), 'phones.json');
  const demoPass = randomBytes(18).toString('base64url'); const operatorPass = randomBytes(24).toString('base64url');
  const env = { ...process.env, HOME_MCP_PORT: '0', HOME_MCP_DEMO_PASS: demoPass, HOME_MCP_RING_OPERATOR_PASS: operatorPass, HOME_MCP_PHONE_STORE: store, HOME_MCP_RING_PROBE: 'off' };
  delete env.HOME_MCP_CLOUD_PANEL;
  const child = spawn(process.execPath, [serverPath], { env, stdio: ['pipe', 'pipe', 'pipe'] });
  const server = { child, stdout: '', stderr: '', raw: [], store, demoPass, operatorPass };
  child.stdout.on('data', (c) => { server.stdout += c; });
  child.stderr.on('data', (c) => { server.stderr += c; });
  server.port = await new Promise((resolve, reject) => {
    const timer = setInterval(() => { const m = server.stdout.match(/Home MCP simulator: http:\/\/127\.0\.0\.1:(\d+)/u); if (m && /phone pairing code|Paired phones/u.test(server.stdout)) { clearInterval(timer); resolve(Number(m[1])); } }, 20);
    child.once('exit', (code) => { clearInterval(timer); reject(new Error('server exited ' + code + ' ' + server.stderr)); });
  });
  server.adminCode = (server.stdout.match(/ADMIN phone pairing code: (\d{4}) (\d{4})/u) || []).slice(1).join('');
  server.answer = async (text) => {
    const seen = (server.stderr.match(/PAIR PHONE/gu) || []).length;
    await waitFor(() => (server.stderr.match(/PAIR PHONE/gu) || []).length >= seen && /PAIR PHONE/u.test(server.stderr));
    child.stdin.write(text + '\n');
  };
  server.stop = () => new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve();
    const hard = setTimeout(() => child.kill('SIGKILL'), 3000);
    child.once('exit', () => { clearTimeout(hard); resolve(); });
    child.stdin.end(); child.kill('SIGTERM');
  });
  return server;
}
const waitFor = async (check, ms = 5000) => { const end = Date.now() + ms; while (!check()) { if (Date.now() > end) throw new Error('timeout'); await new Promise((r) => setTimeout(r, 20)); } };
function call(server, path, { method = 'GET', bearer, body, origin = 'self', headers = {} } = {}) {
  const h = { host: `127.0.0.1:${server.port}`, ...headers };
  if (origin === 'self') h.origin = `http://127.0.0.1:${server.port}`; else if (origin) h.origin = origin;
  if (bearer) h.authorization = `Bearer ${bearer}`;
  const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
  if (payload) { h['content-type'] = 'application/json'; h['content-length'] = String(payload.length); }
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: server.port, path, method, headers: h }, (res) => {
      const chunks = []; res.on('data', (c) => chunks.push(c));
      res.on('end', () => { const raw = Buffer.concat(chunks).toString('utf8'); server.raw.push(raw); let parsed = null; try { parsed = JSON.parse(raw); } catch {} resolve({ status: res.statusCode, body: parsed, raw }); });
    });
    req.once('error', reject); req.end(payload ?? undefined);
  });
}
async function pairOverHttp(server, code, name, answer = 'y') {
  const req = await call(server, '/api/phones/pair-request', { method: 'POST', body: { code, name } });
  assert.equal(req.status, 202, req.raw);
  await server.answer(answer);
  for (let i = 0; i < 100; i += 1) {
    const st = await call(server, '/api/phones/pair-status', { method: 'POST', body: { requestId: req.body.requestId } });
    if (st.status !== 200 || st.body.status !== 'pending') return st;
    await new Promise((r) => setTimeout(r, 30));
  }
  throw new Error('pairing never settled');
}
const session = async (server, deviceToken) => call(server, '/api/phones/session', { method: 'POST', body: { deviceToken } });
const mcp = (server, bearer, name, args) => call(server, '/mcp', { method: 'POST', bearer, body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } },
  headers: { accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-11-25' } });

test('U16/U17/U13/U14/U15/U18 server: admin phone pairs via terminal "y", controls devices through /mcp without the operator code; family phone is limited; revoke is immediate; nothing secret is printed', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());
  assert.match(server.adminCode, /^\d{8}$/u, 'startup prints the admin code when no admin exists');
  // origin is required on the unauthenticated phone routes
  assert.equal((await call(server, '/api/phones/pair-request', { method: 'POST', body: { code: server.adminCode, name: 'Me' }, origin: 'http://evil.invalid' })).status, 403);
  const admin = await pairOverHttp(server, server.adminCode, 'Me');
  assert.equal(admin.status, 200, admin.raw); assert.equal(admin.body.role, 'admin');
  const a = await session(server, admin.body.deviceToken);
  assert.equal(a.status, 200, a.raw); assert.equal(a.body.role, 'admin'); assert.notEqual(a.body.deviceToken, admin.body.deviceToken);
  const adminBearer = a.body.token;
  // U16: pair the light and turn it on through /mcp; admin phone passes the operator gate without the code
  const code = (await call(server, '/api/pair/start', { method: 'POST', bearer: adminBearer, body: { deviceId: 'living_light' } })).body.code;
  assert.equal((await call(server, '/api/pair/confirm', { method: 'POST', bearer: adminBearer, body: { deviceId: 'living_light', code } })).status, 200);
  const on = await mcp(server, adminBearer, 'device_living_light', { action: 'on' });
  assert.equal(on.status, 200, on.raw); assert.equal(on.body.result?.isError, false, on.raw);
  const disc = await call(server, '/api/ring/discovery', { bearer: adminBearer });
  assert.notEqual(disc.body?.error, 'RING_OPERATOR_DENIED', 'admin phone stands in for the operator code');
  // U17: the desktop passcode still works and still needs the operator code
  const desk = (await call(server, '/api/login', { method: 'POST', body: { passcode: server.demoPass } })).body.token;
  assert.equal((await call(server, '/api/ring/discovery', { bearer: desk })).body.error, 'RING_OPERATOR_DENIED');
  // family phone
  const memberCode = await call(server, '/api/phones/pair-code', { method: 'POST', bearer: adminBearer, body: { role: 'member' } });
  assert.equal(memberCode.status, 201, memberCode.raw);
  const mom = await pairOverHttp(server, memberCode.body.code, 'Mom');
  assert.equal(mom.status, 200, mom.raw); assert.equal(mom.body.role, 'member');
  const m = await session(server, mom.body.deviceToken);
  const momBearer = m.body.token;
  // U15: everyday device works for the family phone
  const momOff = await mcp(server, momBearer, 'device_living_light', { action: 'off' });
  assert.equal(momOff.body.result?.isError, false, momOff.raw);
  assert.equal((await call(server, '/api/action', { method: 'POST', bearer: momBearer, body: { deviceId: 'living_light', action: 'on' } })).status, 200);
  assert.match(server.stdout, /phone "Mom" (mcp device_living_light off|action living_light on)/u);
  // U14: no disarm for family; door unlock is only ever a request (front door not paired here, so even that is refused)
  assert.equal((await mcp(server, momBearer, 'device_camera', { action: 'disarm' })).body.error?.code, -32003);
  assert.equal((await mcp(server, momBearer, 'device_front_door', { action: 'unlock' })).body.error?.code, -32003);
  assert.equal((await call(server, '/api/action', { method: 'POST', bearer: momBearer, body: { deviceId: 'front_door', action: 'unlock' } })).body.error, 'DEVICE_NOT_PAIRED');
  // U13: admin-only routes refused for family
  for (const [path, method, body] of [['/api/phones/pair-code', 'POST', { role: 'member' }], ['/api/phones', 'GET'], ['/api/pair/start', 'POST', { deviceId: 'camera' }],
    ['/api/confirm/start', 'POST', { deviceId: 'front_door', action: 'unlock' }], ['/api/ring/discovery', 'GET'], ['/api/wifi-trust/status', 'GET'], ['/api/cloud-mcp/status', 'GET'], ['/api/schedules', 'POST', {}]]) {
    const r = await call(server, path, { method, bearer: momBearer, body });
    assert.equal(r.status, 403, path + ' ' + r.raw); assert.equal(r.body.error, 'MEMBER_NOT_ALLOWED', path);
  }
  // family phone refused when the owner says no
  const another = await call(server, '/api/phones/pair-code', { method: 'POST', bearer: adminBearer, body: { role: 'member' } });
  assert.equal((await pairOverHttp(server, another.body.code, 'Guest', 'n')).status, 403);
  // U9: revoke is immediate for credential and live session
  const list = (await call(server, '/api/phones', { bearer: adminBearer })).body.phones;
  assert.deepEqual(list.filter((p) => p.active).map((p) => [p.name, p.role]).sort(), [['Me', 'admin'], ['Mom', 'member']]);
  const momId = list.find((p) => p.name === 'Mom').deviceId;
  assert.equal((await call(server, '/api/phones/revoke', { method: 'POST', bearer: adminBearer, body: { deviceId: momId } })).status, 200);
  assert.equal((await call(server, '/api/state', { bearer: momBearer })).status, 401);
  assert.equal((await session(server, m.body.deviceToken)).status, 401);
  // U18: no credential, code or request id in any output
  const dump = [server.stdout, server.stderr, readFileSync(server.store, 'utf8')].join('\n');
  for (const secret of [admin.body.deviceToken, a.body.deviceToken, mom.body.deviceToken, m.body.deviceToken, memberCode.body.code, adminBearer, momBearer]) {
    assert.equal(dump.includes(secret), false, 'secret leaked');
  }
});

test('guardian routes: family and admin read status and may retry; only admin flips the demo camera; same-origin POSTs; Ring token from env never printed', async (t) => {
  const prev = process.env.RING_ACCESS_TOKEN;
  const ringToken = 'rt_' + randomBytes(24).toString('base64url');
  process.env.RING_ACCESS_TOKEN = ringToken;
  const server = await startServer();
  if (prev === undefined) delete process.env.RING_ACCESS_TOKEN; else process.env.RING_ACCESS_TOKEN = prev;
  t.after(() => server.stop());
  assert.match(server.stdout, /Guardian: ON \(gateway heartbeat 60 s, camera check 5 min, daily routine 8 items; clock x1\)\. Ring camera: Playground token loaded/u);
  const admin = await pairOverHttp(server, server.adminCode, 'Me');
  const adminBearer = (await session(server, admin.body.deviceToken)).body.token;
  const code = await call(server, '/api/phones/pair-code', { method: 'POST', bearer: adminBearer, body: { role: 'member' } });
  const mom = await pairOverHttp(server, code.body.code, 'Mom');
  const momBearer = (await session(server, mom.body.deviceToken)).body.token;
  for (const bearer of [adminBearer, momBearer]) {
    const st = await call(server, '/api/guardian/status', { bearer });
    assert.equal(st.status, 200, st.raw);
    assert.deepEqual(Object.keys(st.body).sort(), ['attention', 'camera', 'clock', 'email', 'events', 'gateway', 'now', 'overall', 'routine', 'simulated', 'time']);
    assert.equal(st.body.routine.total, 8); assert.equal(st.body.email.email, 'disabled');
    assert.equal((await call(server, '/api/guardian/retry', { method: 'POST', bearer, body: { runId: 'nope' } })).body.error, 'RUN_UNKNOWN');
  }
  const momCam = await call(server, '/api/guardian/camera', { method: 'POST', bearer: momBearer, body: { online: false } });
  assert.equal(momCam.status, 403); assert.equal(momCam.body.error, 'MEMBER_NOT_ALLOWED');
  assert.equal((await call(server, '/api/guardian/camera', { method: 'POST', bearer: adminBearer, body: { online: false }, origin: 'http://evil.invalid' })).status, 403);
  assert.deepEqual((await call(server, '/api/guardian/camera', { method: 'POST', bearer: adminBearer, body: { online: false } })).body, { ok: true, online: false });
  assert.equal((await call(server, '/api/guardian/camera', { method: 'POST', bearer: adminBearer, body: { online: 'no' } })).status, 400);
  assert.equal((await call(server, '/api/guardian/status')).status, 401);
  assert.equal([server.stdout, server.stderr, ...server.raw].join('\n').includes(ringToken), false, 'Ring token never printed or returned');
});

test('family request: the admin phone decides (no Mac needed); same check digits on both sides; one at a time; admin roles never via phone', async () => {
  const s = setup({ answers: [true, () => new Promise(() => {}), () => new Promise(() => {}), () => new Promise(() => {})] });
  await pairPhone(s, { role: 'admin', name: 'Me' });
  assert.equal(s.reg.hasAdmin(), true);
  const { code } = s.reg.createPairCode({ role: 'member' });
  const req = s.reg.requestPairing({ code, name: 'Mom' });
  await new Promise((r) => setImmediate(r));
  const pend = s.reg.pendingMembers();
  assert.equal(pend.length, 1); assert.equal(pend[0].name, 'Mom'); assert.equal(pend[0].check, req.check);
  assert.equal(JSON.stringify(pend).includes(req.requestId), false, 'the approver never sees the asking phone\'s secret id');
  assert.equal(s.reg.pairStatus({ requestId: req.requestId }).approver, 'admin_phone');
  // a second family request while one waits: refused, and its code is NOT spent
  const second = s.reg.createPairCode({ role: 'member' });
  assert.throws(() => s.reg.requestPairing({ code: second.code, name: 'Dad' }), { status: 409, code: 'PAIR_BUSY' });
  assert.throws(() => s.reg.decideMember({ approvalId: 'x', decision: 'approve' }), { code: 'PAIR_APPROVAL_INVALID' });
  assert.throws(() => s.reg.decideMember({ approvalId: pend[0].approvalId, decision: 'maybe' }), { code: 'PAIR_DECISION_INVALID' });
  assert.deepEqual(s.reg.decideMember({ approvalId: pend[0].approvalId, decision: 'approve' }), { decided: 'approve', name: 'Mom' });
  assert.throws(() => s.reg.decideMember({ approvalId: pend[0].approvalId, decision: 'approve' }), { code: 'PAIR_APPROVAL_CLOSED' }, 'single use');
  await s.reg.settled();
  const ok = s.reg.pairStatus({ requestId: req.requestId });
  assert.equal(ok.status, 'approved'); assert.equal(ok.role, 'member');
  // now the spare code works; a deny is final
  const req2 = s.reg.requestPairing({ code: second.code, name: 'Dad' });
  await new Promise((r) => setImmediate(r));
  s.reg.decideMember({ approvalId: s.reg.pendingMembers()[0].approvalId, decision: 'deny' });
  await s.reg.settled();
  assert.throws(() => s.reg.pairStatus({ requestId: req2.requestId }), { code: 'PAIR_REJECTED' });
  // an ADMIN request never shows up for phone approval
  const adminCode = s.reg.createPairCode({ role: 'admin' });
  s.reg.requestPairing({ code: adminCode.code, name: 'Second' });
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(s.reg.pendingMembers(), []);
});

// ---- Mac dialog (a stand-in for osascript; no real window opens in tests) ----
import { createMacDialog, macDialogEnabled } from '../src/mac_dialog.mjs';
test('Mac dialog: text goes in as arguments, not into the script; allow / deny / timeout / failure mapped; only on a Mac with a person present', async () => {
  const calls = [];
  const fake = (out, err = null) => (bin, args, opts, cb) => { calls.push({ bin, args }); setImmediate(() => cb(err, out)); return { kill() {} }; };
  const ask = (impl) => createMacDialog({ execFileImpl: impl }).ask({ message: 'Phone "x"; do shell script "rm"', title: 'T', deny: 'No', allow: 'Yes', seconds: 120 }).answer;
  assert.equal(await ask(fake('allow\n')), 'allow');
  assert.equal(calls[0].bin, '/usr/bin/osascript');
  assert.equal(calls[0].args[0], '-e');
  assert.equal(calls[0].args[1].includes('rm'), false, 'the message is never part of the script');
  assert.deepEqual(calls[0].args.slice(2), ['Phone "x"; do shell script "rm"', 'T', 'No', 'Yes', '120']);
  assert.equal(await ask(fake('deny')), 'deny');
  assert.equal(await ask(fake('timeout')), 'timeout');
  assert.equal(await ask(fake('', new Error('no GUI'))), 'unavailable');
  assert.equal(await ask(fake('something else')), 'unavailable');
  assert.equal(await ask(() => { throw new Error('spawn failed'); }), 'unavailable');
  assert.equal(macDialogEnabled({ platform: 'linux', env: {}, isTTY: true }), false);
  assert.equal(macDialogEnabled({ platform: 'darwin', env: {}, isTTY: true }), true);
  assert.equal(macDialogEnabled({ platform: 'darwin', env: {}, isTTY: false }), false, 'tests / background runs: no window');
  assert.equal(macDialogEnabled({ platform: 'darwin', env: { HOME_MCP_PAIR_DIALOG: 'on' }, isTTY: false }), true);
  assert.equal(macDialogEnabled({ platform: 'darwin', env: { HOME_MCP_PAIR_DIALOG: 'off' }, isTTY: true }), false);
});

test('server: a family phone is approved on the admin PHONE (with its credential), never by a session alone, the desktop, or another family phone', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());
  const admin = await pairOverHttp(server, server.adminCode, 'Me');
  assert.equal(admin.status, 200, admin.raw);
  const a = await session(server, admin.body.deviceToken);
  let dt = a.body.deviceToken; const adminBearer = a.body.token;
  const desk = (await call(server, '/api/login', { method: 'POST', body: { passcode: server.demoPass } })).body.token;
  const code = (await call(server, '/api/phones/pair-code', { method: 'POST', bearer: adminBearer, body: { role: 'member' } })).body.code;
  const req = await call(server, '/api/phones/pair-request', { method: 'POST', body: { code, name: 'Mom' } });
  assert.equal(req.status, 202); assert.equal(req.body.approver, 'admin_phone'); assert.match(req.body.check, /^\d{2}$/u);
  const st = await call(server, '/api/phones/pair-status', { method: 'POST', body: { requestId: req.body.requestId } });
  assert.equal(st.body.status, 'pending'); assert.equal(st.body.check, req.body.check);
  // the admin phone sees it (name + same check digits), the desktop does not
  let pending;
  for (let i = 0; i < 50; i += 1) { pending = (await call(server, '/api/phones/pending', { bearer: adminBearer })).body.pending; if (pending?.length) break; await new Promise((r) => setTimeout(r, 20)); }
  assert.equal(pending[0].name, 'Mom'); assert.equal(pending[0].check, req.body.check);
  assert.equal(JSON.stringify(pending).includes(req.body.requestId), false);
  assert.equal((await call(server, '/api/phones/pending', { bearer: desk })).body.error, 'ADMIN_PHONE_REQUIRED');
  const approvalId = pending[0].approvalId;
  // refused: desktop session; admin session without a credential; wrong credential
  assert.equal((await call(server, '/api/phones/decide', { method: 'POST', bearer: desk, body: { approvalId, decision: 'approve', deviceToken: dt } })).body.error, 'ADMIN_PHONE_REQUIRED');
  assert.equal((await call(server, '/api/phones/decide', { method: 'POST', bearer: adminBearer, body: { approvalId, decision: 'approve' } })).status, 400);
  assert.equal((await call(server, '/api/phones/decide', { method: 'POST', bearer: adminBearer, body: { approvalId, decision: 'approve', deviceToken: randomBytes(32).toString('base64url') } })).status, 401);
  // approved on the admin phone: the family phone gets in; the admin's credential was rotated
  const ok = await call(server, '/api/phones/decide', { method: 'POST', bearer: adminBearer, body: { approvalId, decision: 'approve', deviceToken: dt } });
  assert.equal(ok.status, 200, ok.raw); assert.equal(ok.body.decided, 'approve'); assert.notEqual(ok.body.deviceToken, dt); dt = ok.body.deviceToken;
  let mom;
  for (let i = 0; i < 50; i += 1) { mom = await call(server, '/api/phones/pair-status', { method: 'POST', body: { requestId: req.body.requestId } }); if (mom.body?.status !== 'pending') break; await new Promise((r) => setTimeout(r, 20)); }
  assert.equal(mom.body.status, 'approved'); assert.equal(mom.body.role, 'member');
  assert.match(server.stdout, /phone pairing "Mom": APPROVED on admin phone "Me"/u);
  const m = await session(server, mom.body.deviceToken);
  // single use; a family phone cannot approve anyone
  assert.equal((await call(server, '/api/phones/decide', { method: 'POST', bearer: adminBearer, body: { approvalId, decision: 'approve', deviceToken: dt } })).body.error, 'PAIR_APPROVAL_UNKNOWN');
  assert.equal((await call(server, '/api/phones/pending', { bearer: m.body.token })).body.error, 'MEMBER_NOT_ALLOWED');
  // nothing secret printed
  for (const secret of [dt, a.body.deviceToken, mom.body.deviceToken, approvalId, req.body.requestId]) assert.equal((server.stdout + server.stderr).includes(secret), false);
});

test('server: black-box round 2 fixes: a refused cross-phone decision leaves the other phone untouched; a decided family request leaves no live terminal prompt', async (t) => {
  const server = await startServer();
  t.after(() => server.stop());
  const a = await session(server, (await pairOverHttp(server, server.adminCode, 'Me')).body.deviceToken);
  const adminCode2 = (await call(server, '/api/phones/pair-code', { method: 'POST', bearer: a.body.token, body: { role: 'admin' } })).body.code;
  const b = await session(server, (await pairOverHttp(server, adminCode2, 'Admin2')).body.deviceToken);
  const memberCode = (await call(server, '/api/phones/pair-code', { method: 'POST', bearer: a.body.token, body: { role: 'member' } })).body.code;
  const req = await call(server, '/api/phones/pair-request', { method: 'POST', body: { code: memberCode, name: 'Dad' } });
  let pending;
  for (let i = 0; i < 50; i += 1) { pending = (await call(server, '/api/phones/pending', { bearer: a.body.token })).body.pending; if (pending?.length) break; await new Promise((r) => setTimeout(r, 20)); }
  // A's session + B's credential: refused, no credential handed out, B's credential still works
  const cross = await call(server, '/api/phones/decide', { method: 'POST', bearer: a.body.token, body: { approvalId: pending[0].approvalId, decision: 'approve', deviceToken: b.body.deviceToken } });
  assert.equal(cross.status, 403); assert.equal(cross.body.error, 'DEVICE_SESSION_MISMATCH'); assert.equal(cross.body.deviceToken, undefined);
  assert.equal((await session(server, b.body.deviceToken)).status, 200, 'B was not rotated or revoked');
  // deny on the admin phone, then a stray "y": nothing is approved and no false APPROVED line is printed
  const no = await call(server, '/api/phones/decide', { method: 'POST', bearer: a.body.token, body: { approvalId: pending[0].approvalId, decision: 'deny', deviceToken: a.body.deviceToken } });
  assert.equal(no.body.decided, 'deny');
  await new Promise((r) => setTimeout(r, 100));
  server.child.stdin.write('y\n');
  await new Promise((r) => setTimeout(r, 200));
  assert.doesNotMatch(server.stdout, /"Dad": APPROVED/u);
  const st = await call(server, '/api/phones/pair-status', { method: 'POST', body: { requestId: req.body.requestId } });
  assert.equal(st.body.error, 'PAIR_REJECTED');
  assert.match(server.stdout, /waiting for approval on the admin phone \(or y on this terminal\)/u);
});
