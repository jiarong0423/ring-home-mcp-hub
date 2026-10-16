// Ring Chime announcements (src/ring_chime.mjs) against a fake Ring API shaped like the documented examples.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createRingChime } from '../src/ring_chime.mjs';

function fakeRing({ chimeOnline = true, snoozed = false, slots = [{ event: 'ring-appstore-event-1', disabled: false, audio_ref: 'ref-1', audio_name: 'Hello' }],
  playStatus = 'completed', withChime = true } = {}) {
  const calls = [];
  const reply = (status, body) => ({ ok: status < 300, status, json: async () => body });
  const fetchImpl = async (url, init = {}) => {
    const path = new URL(url).pathname; calls.push(`${init.method ?? 'GET'} ${path}`);
    assert.equal(init.headers.Authorization, 'Bearer tok');
    if (path === '/v1/devices') return reply(200, { data: [{ id: 'cam1' }, ...(withChime ? [{ id: 'chime1' }] : [])] });
    if (path === '/v1/devices/cam1/capabilities') return reply(200, { data: { attributes: { video: { codecs: ['h264'] }, motion_detection: { configurations: {} }, audio: null } } });
    if (path === '/v1/devices/chime1/capabilities') return reply(200, { data: { attributes: { audio: { customizable_slots: 2 }, video: null, motion_detection: null } } });
    if (path === '/v1/devices/chime1/status') return reply(200, { data: { attributes: { online: chimeOnline, audio: { snooze: { active: snoozed, until: snoozed ? '2026-10-16T12:00:00Z' : null } } } } });
    if (path === '/v1/devices/chime1/configurations') return reply(200, { data: { attributes: { audio: { customizable_slots: slots, volume: 5 } } } });
    if (path === '/v1/devices/chime1/media/audio/playback') {
      assert.deepEqual(JSON.parse(init.body), { data: { type: 'audio', attributes: { audio_ref: 'ref-1' } } });
      return reply(200, { data: { type: 'audio', id: 'ref-1', attributes: { status: playStatus } }, meta: { time: 't' } });
    }
    return reply(404, {});
  };
  return { fetchImpl, calls };
}

test('finds the Chime by its documented capabilities, checks status and slots, plays the first enabled slot; once a minute at most', async () => {
  let t = 1_000_000; const r = fakeRing();
  const chime = createRingChime({ getToken: () => 'tok', fetchImpl: r.fetchImpl, clock: () => t, enabled: true });
  assert.deepEqual(await chime.play('door_requested'), { played: true, outcome: 'played', detail: null });
  assert.ok(r.calls.includes('POST /v1/devices/chime1/media/audio/playback'));
  assert.equal(chime.status().chime, true); assert.equal(chime.status().cameras, 1);
  assert.equal((await chime.play('door_approved')).outcome, 'too_soon');
  t += 61_000;
  assert.equal((await chime.play('door_approved')).outcome, 'played');
});

test('stays quiet when it should: off, no token, no Chime, Chime offline, snoozed, no enabled slot, playback not completed', async () => {
  const run = async (opts, chimeOpts = {}) => createRingChime({ getToken: () => ('token' in chimeOpts ? chimeOpts.token : 'tok'), fetchImpl: fakeRing(opts).fetchImpl,
    enabled: chimeOpts.enabled ?? true }).play('x');
  assert.equal((await run({}, { enabled: false })).outcome, 'off');
  assert.equal((await run({}, { token: null })).outcome, 'no_token');
  assert.equal((await run({ withChime: false })).outcome, 'no_chime');
  assert.equal((await run({ chimeOnline: false })).outcome, 'chime_offline');
  assert.equal((await run({ snoozed: true })).outcome, 'chime_snoozed');
  assert.equal((await run({ slots: [{ event: 'e', disabled: true, audio_ref: 'ref-1' }] })).outcome, 'no_audio_slot');
  assert.equal((await run({ playStatus: 'failed' })).outcome, 'error');
});

test('a Ring outage or a network error is reported, never thrown; a new token forgets the old devices', async () => {
  const down = createRingChime({ getToken: () => 'tok', enabled: true, fetchImpl: async () => { throw Object.assign(new Error('x'), { name: 'TimeoutError' }); } });
  assert.deepEqual(await down.play('x'), { played: false, outcome: 'error', detail: 'network TimeoutError' });
  const r = fakeRing(); let t = 0;
  const chime = createRingChime({ getToken: () => 'tok', fetchImpl: r.fetchImpl, clock: () => t, enabled: true });
  await chime.play('x'); const before = r.calls.filter((c) => c === 'GET /v1/devices').length;
  chime.forget(); t += 61_000; await chime.play('x');
  assert.equal(r.calls.filter((c) => c === 'GET /v1/devices').length, before + 1);
});
