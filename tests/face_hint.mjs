// Face hint (DOOR_APPROVAL_PLAN_zh.md §3.6, D13–D15): encrypted store, consent, delete, hint-only; a fake worker for the
// matching logic, the real OpenCV worker on synthetic images (no real face is used anywhere), and the server routes.
// The real-worker and server parts run when the isolated face venv + models exist (HOME_MCP_FACE_TEST_PYTHON / _MODELS, or the
// default ../face_env and ../face_models next to this candidate); otherwise they are skipped with the reason.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, statSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { deflateSync } from 'node:zlib';
import { COSINE_MATCH, cosine, createFaceHint, createFaceStore, createFaceWorker, MAX_PEOPLE } from '../src/face_hint.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const tmp = () => mkdtempSync(join(tmpdir(), 'face-hint-'));
const paths = () => { const d = tmp(); return { storePath: join(d, 'faces', 'faces.enc'), keyPath: join(d, 'key', 'face.key') }; };
const vec = (seed) => Array.from({ length: 128 }, (_, i) => Math.sin(seed * 31 + i * 0.7));
// Minimal PNG (grey square, no face) built here, so no image file is downloaded or stored.
function png(size = 96, grey = 128) {
  const crc = (buf) => { let c = ~0; for (const b of buf) { c ^= b; for (let k = 0; k < 8; k += 1) c = (c >>> 1) ^ (0xedb88320 & -(c & 1)); } return ~c >>> 0; };
  const chunk = (type, data) => { const len = Buffer.alloc(4); len.writeUInt32BE(data.length); const td = Buffer.concat([Buffer.from(type), data]); const c = Buffer.alloc(4); c.writeUInt32BE(crc(td)); return Buffer.concat([len, td, c]); };
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4); ihdr[8] = 8; ihdr[9] = 2;
  const row = Buffer.concat([Buffer.from([0]), Buffer.alloc(size * 3, grey)]);
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(Buffer.concat(Array(size).fill(row)))), chunk('IEND', Buffer.alloc(0))]);
}
const fakeWorker = (answers) => { const calls = []; return { calls, analyse: async (bytes) => { calls.push(bytes.length); const a = answers.shift(); if (a instanceof Error) throw a; return a; }, close() {} }; };

test('store: AES-256-GCM file with no plaintext name or feature; 0600 files, 0700 folders, key in a separate folder; reload works', () => {
  const p = paths();
  const store = createFaceStore(p);
  const a = store.add({ name: 'Carer Wang', feature: vec(1) });
  const raw = readFileSync(p.storePath, 'utf8');
  assert.doesNotMatch(raw, /Carer Wang/u);
  assert.equal(JSON.parse(raw).schema, 'home-mcp-faces-v1');
  for (const f of [p.storePath, p.keyPath]) assert.equal(statSync(f).mode & 0o777, 0o600, f);
  for (const d of [dirname(p.storePath), dirname(p.keyPath)]) assert.equal(statSync(d).mode & 0o777, 0o700, d);
  const again = createFaceStore(p);
  assert.deepEqual(again.list().map((x) => [x.id, x.name]), [[a.id, 'Carer Wang']]);
  assert.ok(Math.abs(cosine(again.features()[0].feature, vec(1)) - 1) < 1e-6, 'feature survives (float32)');
  assert.match(again.list()[0].consentAt, /^\d{4}-/u);
  assert.throws(() => createFaceStore({ storePath: p.storePath, keyPath: join(dirname(p.storePath), 'k') }), /outside/u);
});

test('store: duplicate name and the 20-person limit are refused', () => {
  const s2 = createFaceStore(paths()); s2.add({ name: 'B', feature: vec(2) });
  assert.throws(() => s2.add({ name: 'B', feature: vec(3) }), { code: 'FACE_NAME_TAKEN' });
  for (let i = 0; i < MAX_PEOPLE - 1; i += 1) s2.add({ name: 'P' + i, feature: vec(10 + i) });
  assert.throws(() => s2.add({ name: 'Z', feature: vec(99) }), { code: 'FACE_LIMIT' });
});

test('store: tamper detection and missing key (explicit)', async () => {
  const { writeFileSync, rmSync } = await import('node:fs');
  const p = paths();
  createFaceStore(p).add({ name: 'A', feature: vec(1) });
  const box = JSON.parse(readFileSync(p.storePath, 'utf8'));
  const data = Buffer.from(box.data, 'base64'); data[0] ^= 1;
  writeFileSync(p.storePath, JSON.stringify({ ...box, data: data.toString('base64') }));
  assert.throws(() => createFaceStore(p));
  const q = paths();
  createFaceStore(q).add({ name: 'A', feature: vec(1) });
  rmSync(q.keyPath);
  assert.throws(() => createFaceStore(q), /key is missing/u);
});

test('D14: delete one rewrites the file without that person; delete everyone removes the file and its key', () => {
  const p = paths();
  const store = createFaceStore(p);
  const a = store.add({ name: 'A', feature: vec(1) }); store.add({ name: 'B', feature: vec(2) });
  assert.deepEqual(store.remove(a.id), { removed: 1 });
  assert.deepEqual(createFaceStore(p).list().map((x) => x.name), ['B']);
  assert.throws(() => store.remove(a.id), { code: 'FACE_UNKNOWN' });
  assert.deepEqual(store.removeAll(), { removed: 1 });
  assert.equal(existsSync(p.storePath), false); assert.equal(existsSync(p.keyPath), false);
  assert.deepEqual(createFaceStore(p).list(), []);
});

test('enrol: consent must be exactly true (checked before any image work); name rules; image must be JPEG/PNG; one face only', async () => {
  const worker = fakeWorker([{ faces: [] }, { faces: [{ score: 0.9, feature: vec(1) }, { score: 0.8, feature: vec(2) }] }, { faces: [{ score: 0.95, feature: vec(1) }] }]);
  const hint = createFaceHint({ store: createFaceStore(paths()), worker });
  for (const consent of [undefined, false, 'true', 1]) await assert.rejects(hint.enroll({ name: 'A', consent, image: png() }), { code: 'FACE_CONSENT_REQUIRED' });
  await assert.rejects(hint.enroll({ name: '<x>', consent: true, image: png() }), { code: 'FACE_NAME_INVALID' });
  await assert.rejects(hint.enroll({ name: 'A', consent: true, image: Buffer.from('GIF89a') }), { code: 'IMAGE_INVALID' });
  assert.equal(worker.calls.length, 0, 'nothing analysed before consent, name and type pass');
  await assert.rejects(hint.enroll({ name: 'A', consent: true, image: png() }), { code: 'NO_FACE' });
  await assert.rejects(hint.enroll({ name: 'A', consent: true, image: png() }), { code: 'MULTIPLE_FACES' });
  const ok = await hint.enroll({ name: 'Carer Wang', consent: true, image: png() });
  assert.equal(ok.name, 'Carer Wang');
  assert.deepEqual(hint.list().map((p) => p.name), ['Carer Wang']);
});

test('D13: hint names an enrolled person only above the threshold; others are "not enrolled"; it never throws', async () => {
  const near = vec(1).map((v, i) => v + (i % 7 === 0 ? 0.05 : 0));
  const worker = fakeWorker([{ faces: [{ score: 0.9, feature: vec(1) }] },
    { faces: [{ score: 0.9, feature: near }, { score: 0.8, feature: vec(50) }] },
    { faces: [{ score: 0.9, feature: vec(50) }] }, { faces: [] }, new Error('boom')]);
  const hint = createFaceHint({ store: createFaceStore(paths()), worker });
  await hint.enroll({ name: 'Carer Wang', consent: true, image: png() });
  const two = await hint.hint(png());
  assert.equal(two.state, 'match');
  assert.equal(two.faces[0].match, true); assert.equal(two.faces[0].name, 'Carer Wang'); assert.ok(two.faces[0].score >= COSINE_MATCH);
  assert.deepEqual(two.faces[1], { match: false }, 'an unknown face carries no name and no score');
  assert.deepEqual(await hint.hint(png()), { state: 'unknown', faces: [{ match: false }] });
  assert.deepEqual(await hint.hint(png()), { state: 'no_face' });
  assert.equal((await hint.hint(png())).state, 'error');
  assert.deepEqual(await hint.hint(Buffer.from('<svg/>')), { state: 'no_image' });
  assert.deepEqual(await createFaceHint({ disabledReason: 'files_missing' }).hint(png()), { state: 'disabled', reason: 'files_missing' });
  await assert.rejects(createFaceHint({ disabledReason: 'x' }).enroll({ name: 'A', consent: true, image: png() }), { code: 'FACE_HINT_DISABLED' });
});

test('D14: after deleting a person the same face is no longer matched', async () => {
  const worker = fakeWorker([{ faces: [{ score: 0.9, feature: vec(1) }] }, { faces: [{ score: 0.9, feature: vec(1) }] }, { faces: [{ score: 0.9, feature: vec(1) }] }]);
  const hint = createFaceHint({ store: createFaceStore(paths()), worker });
  const a = await hint.enroll({ name: 'A', consent: true, image: png() });
  assert.equal((await hint.hint(png())).state, 'match');
  hint.remove(a.id);
  assert.equal((await hint.hint(png())).state, 'unknown');
});

// ---- Real OpenCV worker (synthetic images only) ----
const facePython = process.env.HOME_MCP_FACE_TEST_PYTHON || resolve(here, '..', '..', 'face_env', 'bin', 'python');
const faceModels = process.env.HOME_MCP_FACE_TEST_MODELS || resolve(here, '..', '..', 'face_models');
const det = join(faceModels, 'face_detection_yunet_2023mar.onnx'); const rec = join(faceModels, 'face_recognition_sface_2021dec.onnx');
const realSkip = [facePython, det, rec].every((p) => existsSync(p)) ? false : 'face venv / models not present (see CANDIDATE_NOTES round 9)';

test('real worker: OpenCV YuNet+SFace load; grey image -> no face; bad bytes -> IMAGE_INVALID; a killed worker restarts', { skip: realSkip }, async () => {
  const worker = createFaceWorker({ python: facePython, detModel: det, recModel: rec });
  try {
    assert.deepEqual(await worker.analyse(png(160)), { faces: [] });
    await assert.rejects(worker.analyse(Buffer.concat([Buffer.from([0xff, 0xd8, 0xff]), randomBytes(64)])), { code: 'IMAGE_INVALID' });
    // black-box F2: a tiny PNG declaring 30000x30000 is refused from its header, before any decoding
    const bomb = png(16); bomb.writeUInt32BE(30000, 16); bomb.writeUInt32BE(30000, 20);
    await assert.rejects(worker.analyse(bomb), { code: 'IMAGE_INVALID' });
    // real JPEGs (as the browser sends): a 128 px one is read through its SOF header and decoded; a 16 px one is refused as too small
    const jpegOf = (side) => Buffer.from(execFileSync(facePython, ['-I', '-c', `import cv2,numpy as n,sys;sys.stdout.write(cv2.imencode('.jpg',n.full((${side},${side},3),128,n.uint8))[1].tobytes().hex())`]).toString(), 'hex');
    assert.deepEqual(await worker.analyse(jpegOf(128)), { faces: [] });
    await assert.rejects(worker.analyse(jpegOf(16)), { code: 'IMAGE_INVALID' });
    await assert.rejects(worker.analyse(png(32)), { code: 'IMAGE_INVALID' });
    const [a, b] = await Promise.all([worker.analyse(png(64, 10)), worker.analyse(png(64, 240))]);
    assert.deepEqual([a, b], [{ faces: [] }, { faces: [] }], 'requests are serialised');
    worker.close();
    assert.deepEqual(await worker.analyse(png(80)), { faces: [] }, 'restarted on demand');
  } finally { worker.close(); }
});

// ---- Server routes ----
const serverPath = join(here, '..', 'src', 'server.mjs');
const waitFor = async (check, ms = 8000) => { const end = Date.now() + ms; while (!check()) { if (Date.now() > end) throw new Error('timeout'); await new Promise((r) => setTimeout(r, 20)); } };
async function startServer(extraEnv) {
  const dir = tmp();
  const demoPass = randomBytes(18).toString('base64url');
  const env = { ...process.env, HOME_MCP_PORT: '0', HOME_MCP_DEMO_PASS: demoPass, HOME_MCP_RING_OPERATOR_PASS: randomBytes(24).toString('base64url'),
    HOME_MCP_PHONE_STORE: join(dir, 'phones.json'), HOME_MCP_RING_PROBE: 'off', HOME_MCP_FACE_STORE: join(dir, 'faces', 'faces.enc'), HOME_MCP_FACE_KEY: join(dir, 'k', 'face.key'), ...extraEnv };
  for (const k of Object.keys(env)) if (k.startsWith('HOME_MCP_NOTIFY_') || k.startsWith('AWS_') || k === 'RING_ACCESS_TOKEN' || k === 'HOME_MCP_CLOUD_PANEL') delete env[k];
  const child = spawn(process.execPath, [serverPath], { env, stdio: ['pipe', 'pipe', 'pipe'] });
  const server = { child, stdout: '', stderr: '', demoPass, dir, env };
  child.stdout.on('data', (c) => { server.stdout += c; }); child.stderr.on('data', (c) => { server.stderr += c; });
  server.port = await new Promise((resolveP, reject) => {
    const timer = setInterval(() => { const m = server.stdout.match(/Home MCP simulator: http:\/\/127\.0\.0\.1:(\d+)/u); if (m && /Face hint: (ON|OFF)/u.test(server.stdout) && /phone pairing code|Paired phones/u.test(server.stdout)) { clearInterval(timer); resolveP(Number(m[1])); } }, 20);
    child.once('exit', (code) => { clearInterval(timer); reject(new Error('server exited ' + code + ' ' + server.stderr)); });
  });
  server.adminCode = (server.stdout.match(/ADMIN phone pairing code: (\d{4}) (\d{4})/u) || []).slice(1).join('');
  server.stop = () => new Promise((done) => { if (child.exitCode !== null) return done(); const hard = setTimeout(() => child.kill('SIGKILL'), 3000); child.once('exit', () => { clearTimeout(hard); done(); }); child.stdin.end(); child.kill('SIGTERM'); });
  return server;
}
function call(server, path, { method = 'GET', bearer, body, raw, headers = {} } = {}) {
  const h = { host: `127.0.0.1:${server.port}`, origin: `http://127.0.0.1:${server.port}`, ...headers };
  if (bearer) h.authorization = `Bearer ${bearer}`;
  const payload = raw ?? (body === undefined ? null : Buffer.from(JSON.stringify(body)));
  if (payload) { h['content-type'] = 'application/json'; h['content-length'] = String(payload.length); }
  return new Promise((resolveP, reject) => {
    // A fresh connection per call (agent: false) and every socket error handled: an oversized upload may be cut mid-send.
    const req = http.request({ host: '127.0.0.1', port: server.port, path, method, headers: h, agent: false }, (r) => {
      const chunks = []; r.on('data', (c) => chunks.push(c));
      r.on('error', () => {});
      r.on('end', () => { const s = Buffer.concat(chunks).toString('utf8'); let parsed = null; try { parsed = JSON.parse(s); } catch {} resolveP({ status: r.statusCode, body: parsed, raw: s }); });
    });
    req.on('error', reject); req.end(payload ?? undefined);
  });
}
async function pairPhone(server, code, name) {
  const seen = (server.stderr.match(/PAIR PHONE/gu) || []).length;
  const req = await call(server, '/api/phones/pair-request', { method: 'POST', body: { code, name } });
  assert.equal(req.status, 202, req.raw);
  await waitFor(() => (server.stderr.match(/PAIR PHONE/gu) || []).length > seen);
  server.child.stdin.write('y\n');
  for (let i = 0; i < 200; i += 1) {
    const st = await call(server, '/api/phones/pair-status', { method: 'POST', body: { requestId: req.body.requestId } });
    if (st.status === 200 && st.body.status === 'approved') return (await call(server, '/api/phones/session', { method: 'POST', body: { deviceToken: st.body.deviceToken } })).body;
    await new Promise((r) => setTimeout(r, 30));
  }
  throw new Error('pairing never settled');
}

test('server: face hint OFF without config; door approval still works and says "off"', async (t) => {
  const server = await startServer({});
  t.after(() => server.stop());
  assert.match(server.stdout, /Face hint: OFF \(not_configured\)/u);
  const admin = await pairPhone(server, server.adminCode, 'Me');
  const st = await call(server, '/api/faces', { bearer: admin.token });
  assert.equal(st.body.enabled, false); assert.equal(st.body.reason, 'not_configured');
  assert.equal((await call(server, '/api/faces/enroll', { method: 'POST', bearer: admin.token, body: { name: 'A', consent: true, image: png().toString('base64') } })).body.error, 'FACE_HINT_DISABLED');
  const desk = (await call(server, '/api/login', { method: 'POST', body: { passcode: server.demoPass } })).body.token;
  const pc = (await call(server, '/api/pair/start', { method: 'POST', bearer: desk, body: { deviceId: 'front_door' } })).body.code;
  await call(server, '/api/pair/confirm', { method: 'POST', bearer: desk, body: { deviceId: 'front_door', code: pc } });
  await call(server, '/api/door/request', { method: 'POST', bearer: desk, body: {} });
  let p;
  for (let i = 0; i < 50; i += 1) { p = (await call(server, '/api/door/pending', { bearer: admin.token })).body.pending; if (p.faceHint.state !== 'pending') break; await new Promise((r) => setTimeout(r, 20)); }
  assert.deepEqual(p.faceHint, { state: 'disabled' });
});

test('server D13–D15: admin phone only; consent; no face refused; check keeps nothing; hint never reaches family, MCP, status or logs', { skip: realSkip }, async (t) => {
  const server = await startServer({ HOME_MCP_FACE_PYTHON: facePython, HOME_MCP_FACE_MODELS: faceModels });
  t.after(() => server.stop());
  assert.match(server.stdout, /Face hint: ON \(local OpenCV YuNet \+ SFace; 0 enrolled with consent; hint only, never opens the door\)/u);
  const admin = await pairPhone(server, server.adminCode, 'Me');
  const desk = (await call(server, '/api/login', { method: 'POST', body: { passcode: server.demoPass } })).body.token;
  const memberCode = (await call(server, '/api/phones/pair-code', { method: 'POST', bearer: admin.token, body: { role: 'member' } })).body.code;
  const mom = await pairPhone(server, memberCode, 'Mom');
  const img = png(160).toString('base64');
  // only the admin phone
  assert.equal((await call(server, '/api/faces', { bearer: desk })).body.error, 'ADMIN_PHONE_REQUIRED');
  assert.equal((await call(server, '/api/faces', { bearer: mom.token })).body.error, 'MEMBER_NOT_ALLOWED');
  assert.equal((await call(server, '/api/faces/check', { method: 'POST', bearer: desk, body: { image: img } })).status, 403);
  // consent, shape, size
  assert.equal((await call(server, '/api/faces/enroll', { method: 'POST', bearer: admin.token, body: { name: 'Carer', consent: false, image: img } })).body.error, 'FACE_CONSENT_REQUIRED');
  assert.equal((await call(server, '/api/faces/enroll', { method: 'POST', bearer: admin.token, body: { name: 'Carer', image: img } })).status, 400);
  assert.equal((await call(server, '/api/faces/enroll', { method: 'POST', bearer: admin.token, body: { name: 'Carer', consent: true, image: 'not*base64' } })).body.error, 'IMAGE_INVALID');
  // oversized body: refused with 413 (or the socket is cut while the client is still sending)
  const big = await call(server, '/api/faces/check', { method: 'POST', bearer: admin.token, raw: Buffer.from(JSON.stringify({ image: 'A'.repeat(2_200_000) })) }).catch((e) => ({ status: e.code }));
  assert.ok([413, 'ECONNRESET', 'EPIPE'].includes(big.status), String(big.status));
  // no face -> refused, nothing stored; check -> no_face, nothing stored
  const noFace = await call(server, '/api/faces/enroll', { method: 'POST', bearer: admin.token, body: { name: 'Carer', consent: true, image: img } });
  assert.equal(noFace.status, 422); assert.equal(noFace.body.error, 'NO_FACE');
  assert.deepEqual((await call(server, '/api/faces/check', { method: 'POST', bearer: admin.token, body: { image: img } })).body, { hint: { state: 'no_face' }, hintOnly: true });
  assert.deepEqual((await call(server, '/api/faces', { bearer: admin.token })).body.people, []);
  assert.equal(existsSync(join(server.dir, 'faces', 'faces.enc')), false, 'nothing written for a refused enrolment');
  // door: the admin banner carries the hint (Ring off -> no image), nobody else sees it
  const pc = (await call(server, '/api/pair/start', { method: 'POST', bearer: admin.token, body: { deviceId: 'front_door' } })).body.code;
  await call(server, '/api/pair/confirm', { method: 'POST', bearer: admin.token, body: { deviceId: 'front_door', code: pc } });
  const ask = await call(server, '/mcp', { method: 'POST', bearer: desk, body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'device_front_door', arguments: { action: 'unlock' } } },
    headers: { accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-11-25' } });
  assert.equal(ask.body.result?.structuredContent?.status, 'pending_approval', ask.raw);
  assert.equal(JSON.stringify(ask.body).includes('faceHint'), false, 'MCP answer has no face hint');
  let p;
  for (let i = 0; i < 50; i += 1) { p = (await call(server, '/api/door/pending', { bearer: admin.token })).body.pending; if (p.faceHint.state !== 'pending') break; await new Promise((r) => setTimeout(r, 20)); }
  assert.deepEqual(p.faceHint, { state: 'no_image' });
  const st = await call(server, '/api/door/status', { method: 'POST', bearer: mom.token, body: { requestId: p.requestId } });
  assert.equal(JSON.stringify(st.body).includes('faceHint'), false, 'requester status has no face hint');
  assert.equal((await call(server, '/api/door/pending', { bearer: mom.token })).status, 403);
  // logs never carry names or features
  assert.doesNotMatch(server.stdout + server.stderr, /Carer|feature/u);
});
