// Ring doorbell watcher (RING_DOORBELL_STORY_PLAN_zh.md §5): fake Ring Event History, no network.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createRingDoorbell } from '../src/ring_doorbell.mjs';

const res = (status, json) => ({ status, ok: status >= 200 && status < 300, json: async () => json });
const devices = () => res(200, { data: [{ id: 'doorbell-1' }] });
const ding = (id, start, type = 'ding') => ({ type: 'history-events', id, attributes: { event_type: type, start, end: start + 1000 } });
function setup(t0 = 1_800_000_000_000) {
  let now = t0; const calls = []; const dings = []; const stops = []; const replies = [];
  const fetchImpl = async (url, init) => { calls.push({ url, auth: init.headers.Authorization }); const r = replies.shift(); if (r instanceof Error) throw r; return r; };
  let token = 'tok';
  const bell = createRingDoorbell({ getToken: () => token, fetchImpl, now: () => now, onDing: (d) => dings.push(d), onStop: (r) => stops.push(r) });
  return { bell, calls, dings, stops, replies, tick: (ms) => { now += ms; }, now: () => now, setToken: (v) => { token = v; } };
}

test('first look only remembers old events; a new ding or person-at-door fires once; the same event never twice; other types ignored', async () => {
  const s = setup();
  s.replies.push(devices(), res(200, { data: [ding('old-1', s.now() - 3_600_000)] }));
  assert.deepEqual(await s.bell.poll(), { state: 'watching', fired: 0 });
  assert.match(s.calls[1].url, /\/v1\/history\/devices\/doorbell-1\/events\?event_types=ding,motion\.human$/u);
  assert.equal(s.calls[1].auth, 'Bearer tok');
  s.tick(10_000);
  s.replies.push(res(200, { data: [ding('new-1', s.now() - 2000), ding('p-1', s.now() - 1000, 'motion.human'), ding('od-1', s.now() - 500, 'on_demand'), ding('old-1', s.now() - 3_600_000)] }));
  assert.equal((await s.bell.poll()).fired, 2);
  assert.deepEqual(s.dings, [{ eventId: 'new-1', at: s.now() - 2000, deviceId: 'doorbell-1', kind: 'ding' }, { eventId: 'p-1', at: s.now() - 1000, deviceId: 'doorbell-1', kind: 'person' }]);
  s.tick(10_000);
  s.replies.push(res(200, { data: [ding('new-1', s.now() - 12_000)] }));
  assert.equal((await s.bell.poll()).fired, 0, 'same press is not repeated');
  assert.equal(s.dings.length, 2);
});

test('two presses between polls fire oldest first; a press from before watching started is ignored', async () => {
  const s = setup();
  s.replies.push(devices(), res(200, { data: [] }));
  await s.bell.poll();
  s.tick(10_000);
  s.replies.push(res(200, { data: [ding('b', s.now() - 1000), ding('a', s.now() - 5000), ding('ancient', s.now() - 7_200_000)] }));
  assert.equal((await s.bell.poll()).fired, 2);
  assert.deepEqual(s.dings.map((d) => d.eventId), ['a', 'b']);
});

test('expired token (401) pauses watching and says so once; no token = idle and no request; 5xx / network errors never throw', async () => {
  const s = setup();
  s.replies.push(devices(), res(200, { data: [] }));
  await s.bell.poll();
  s.replies.push(res(401, {}));
  assert.equal((await s.bell.poll()).state, 'token_expired');
  s.replies.push(res(401, {}));
  await s.bell.poll();
  assert.deepEqual(s.stops, ['token_expired'], 'said once');
  s.setToken(null);
  const before = s.calls.length;
  assert.equal((await s.bell.poll()).state, 'token_missing');
  assert.equal(s.calls.length, before, 'nothing sent without a token');
  s.setToken('tok2');
  s.replies.push(res(503, {}));
  assert.equal((await s.bell.poll()).state, 'error');
  s.replies.push(new Error('network down'));
  assert.equal((await s.bell.poll()).state, 'error');
  // after a new token the first look is a baseline again (old presses never fire)
  s.replies.push(res(200, { data: [ding('x', s.now() - 1000)] }));
  assert.equal((await s.bell.poll()).fired, 0);
  assert.equal(s.dings.length, 0);
});

test('malformed Ring data (bad device id, bad event ids, missing times) is ignored, never fired', async () => {
  const s = setup();
  s.replies.push(res(200, { data: [{ id: '../../x' }] }));
  assert.equal((await s.bell.poll()).state, 'error');
  const t = setup();
  t.replies.push(devices(), res(200, { data: [] }));
  await t.bell.poll();
  t.tick(10_000);
  t.replies.push(res(200, { data: [{ id: 'no-time', attributes: { event_type: 'ding' } }, { id: '<script>', attributes: { event_type: 'ding', start: t.now() } }, null] }));
  assert.equal((await t.bell.poll()).fired, 0);
});
