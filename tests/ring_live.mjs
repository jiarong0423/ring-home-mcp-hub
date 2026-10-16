// Ring live view (WHEP) proxy: fake fetch, no network. The token goes to the Ring API origin only; the phone gets an opaque id.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createRingLive } from '../src/ring_live.mjs';

const ORIGIN = 'https://api.amazonvision.com';
const OFFER = 'v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\n';
const ANSWER = 'v=0\r\no=ring 1 2 IN IP4 0.0.0.0\r\ns=-\r\n';
const res = (status, { json, text, headers = {} } = {}) => ({ status, ok: status >= 200 && status < 300, headers: new Headers(headers),
  json: async () => json, text: async () => text ?? '' });
function fake(steps) {
  const calls = [];
  return { calls, fetchImpl: async (url, init = {}) => { calls.push({ url, method: init.method ?? 'GET', auth: init.headers?.Authorization ?? null, type: init.headers?.['Content-Type'] ?? null, body: init.body ?? null });
    const s = steps.shift(); if (s instanceof Error) throw s; return s; } };
}
const devices = () => res(200, { json: { data: [{ id: 'dev-1', type: 'doorbell' }] } });
function timers() { const list = []; return { list, setTimer: (fn, ms) => { const h = { fn, ms, unref() {} }; list.push(h); return h; }, clearTimer: (h) => { if (h) h.cleared = true; } }; }

test('start: devices -> POST SDP to whep/sessions with the token; answer back with an opaque id; DELETE on stop', async () => {
  const f = fake([devices(), res(201, { text: ANSWER, headers: { location: '/v1/devices/dev-1/media/streaming/whep/sessions/s-9' } }), res(204)]);
  const tm = timers(); const logs = [];
  const live = createRingLive({ getToken: () => 'TOKEN-X', fetchImpl: f.fetchImpl, ...tm, log: (l) => logs.push(l) });
  const r = await live.start({ sdp: OFFER });
  assert.equal(r.sdp, ANSWER); assert.equal(r.maxSeconds, 60); assert.match(r.sessionId, /^[A-Za-z0-9_-]{22}$/u);
  assert.equal(JSON.stringify(r).includes('whep/sessions'), false, 'Ring session URL stays on the hub');
  assert.deepEqual(f.calls[1], { url: `${ORIGIN}/v1/devices/dev-1/media/streaming/whep/sessions`, method: 'POST', auth: 'Bearer TOKEN-X', type: 'application/sdp', body: OFFER });
  assert.equal(live.active(), true);
  assert.deepEqual(await live.stop({ sessionId: 'someone-else' }), { stopped: false });
  assert.deepEqual(await live.stop({ sessionId: r.sessionId }), { stopped: true });
  assert.deepEqual([f.calls[2].method, f.calls[2].url, f.calls[2].auth], ['DELETE', `${ORIGIN}/v1/devices/dev-1/media/streaming/whep/sessions/s-9`, 'Bearer TOKEN-X']);
  assert.equal(live.active(), false);
  assert.equal(logs.join('\n').includes('TOKEN-X'), false);
});

test('time limit closes the Ring session; a new start replaces (and closes) the old one', async () => {
  const loc = { headers: { location: `${ORIGIN}/v1/devices/dev-1/media/streaming/whep/sessions/a` } };
  const f = fake([devices(), res(201, { text: ANSWER, ...loc }), res(204), devices(), res(201, { text: ANSWER, ...loc }), res(204)]);
  const tm = timers();
  const live = createRingLive({ getToken: () => 't', fetchImpl: f.fetchImpl, maxMs: 30_000, ...tm });
  await live.start({ sdp: OFFER });
  assert.equal(tm.list[0].ms, 30_000);
  tm.list[0].fn(); await new Promise((r) => setImmediate(r));
  assert.equal(f.calls[2].method, 'DELETE'); assert.equal(live.active(), false);
  await live.start({ sdp: OFFER });
  await live.start({ sdp: OFFER }).catch(() => {});   // steps run out after the replace-close; the old one was closed first
  assert.equal(f.calls.filter((c) => c.method === 'DELETE').length, 2);
});

test('refusals: bad SDP, no token, expired token, Ring refusal, non-SDP answer; a Location on another origin is never called', async () => {
  const none = createRingLive({ getToken: () => null, fetchImpl: async () => { throw new Error('no call expected'); } });
  await assert.rejects(none.start({ sdp: 'hello' }), { code: 'SDP_INVALID', status: 400 });
  await assert.rejects(none.start({ sdp: 'v=0' + 'x'.repeat(40_000) }), { code: 'SDP_INVALID' });
  await assert.rejects(none.start({ sdp: OFFER }), { code: 'RING_NOT_CONNECTED', status: 409 });
  const run = async (steps) => { const f = fake(steps); const live = createRingLive({ getToken: () => 't', fetchImpl: f.fetchImpl, ...timers() }); return { f, live, out: await live.start({ sdp: OFFER }).catch((e) => e) }; };
  assert.equal((await run([res(401)])).out.code, 'RING_TOKEN_EXPIRED');
  assert.equal((await run([devices(), res(401)])).out.code, 'RING_TOKEN_EXPIRED');
  const refused = (await run([devices(), res(403)])).out; assert.equal(refused.code, 'RING_LIVE_REFUSED'); assert.equal(refused.detail, 'whep HTTP 403');
  assert.equal((await run([devices(), res(201, { text: '<html>' })])).out.code, 'RING_ERROR');
  assert.equal((await run([new TypeError('fetch failed')])).out.code, 'RING_UNREACHABLE');
  const evil = await run([devices(), res(201, { text: ANSWER, headers: { location: 'https://evil.example/collect' } })]);
  assert.equal(evil.out.sdp, ANSWER); assert.equal(evil.live.active(), false);
  await evil.live.stop({});
  assert.equal(evil.f.calls.some((c) => c.url.startsWith('https://evil.example')), false);
});
