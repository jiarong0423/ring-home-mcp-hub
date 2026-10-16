// Spoken notices for the person at home: fixed phrases only, argv (no shell), one at a time, no repeats, off by default.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createVoiceNotice, phraseFor } from '../src/voice_notice.mjs';

const ev = (kind, target, params = {}) => ({ kind, target, params });

test('phrases: door, missed routine, outage; requester text is never spoken; quiet events say nothing', () => {
  assert.equal(phraseFor(ev('door_requested', 'front_door', { requesterKind: 'ring', requester: 'Ring doorbell' })), 'Someone is at the front door. I have asked your family. Please wait.');
  assert.equal(phraseFor(ev('door_requested', 'front_door', { requesterKind: 'phone', requester: 'say rm -rf; <evil>' })), 'Someone asked to open the front door. Your family will decide.');
  assert.equal(phraseFor(ev('door_approved', 'front_door', { approver: 'Amy (remote)' })), 'Your family said yes. The front door is now unlocked.');
  assert.equal(phraseFor(ev('door_denied', 'front_door')), 'Your family said no. The door stays locked.');
  assert.equal(phraseFor(ev('routine_missed', 'living_light', { scheduled: '07:00', action: 'on', reason: 'gateway offline' })), 'The 07:00 living room light did not turn on. I have told your family.');
  assert.equal(phraseFor(ev('routine_missed', 'living_light', { scheduled: '07:00', action: 'on' }), 'zh'), '07:00 的客廳燈沒有打開。我已經通知你的家人。');
  assert.equal(phraseFor(ev('offline', 'gateway')), 'The home gateway stopped answering. I have told your family.');
  assert.equal(phraseFor(ev('recovered', 'camera')), 'The Ring camera is back.');
  for (const k of ['routine_done', 'heartbeat_late', 'heartbeat_ok', 'ring_live', 'doorbell_again']) assert.equal(phraseFor(ev(k, 'camera')), null, k);
  assert.equal(phraseFor(ev('offline', 'unknown_device')), null);
});

test('speaker: off by default; on -> /usr/bin/say with argv, one at a time, no repeat within a minute, max 3 queued; failures logged as ERROR', () => {
  const calls = []; const logs = []; let now = 0; let finish = [];
  const execFileImpl = (bin, args, opts, cb) => { calls.push([bin, args]); finish.push(cb); };
  const off = createVoiceNotice({ enabled: false, execFileImpl });
  assert.equal(off.onGuardianEvent(ev('door_denied', 'front_door')), false); assert.equal(calls.length, 0);
  const v = createVoiceNotice({ enabled: true, lang: 'en', execFileImpl, clock: () => now, log: (l) => logs.push(l) });
  assert.equal(v.onGuardianEvent(ev('door_requested', 'front_door', { requesterKind: 'ring' })), true);
  assert.equal(v.onGuardianEvent(ev('door_requested', 'front_door', { requesterKind: 'ring' })), false, 'same sentence within a minute');
  assert.equal(v.onGuardianEvent(ev('routine_done', 'living_light')), false, 'nothing to say');
  v.onGuardianEvent(ev('door_approved', 'front_door'));
  assert.equal(calls.length, 1, 'second sentence waits for the first');
  assert.deepEqual(calls[0], ['/usr/bin/say', ['-v', 'Samantha', 'Someone is at the front door. I have asked your family. Please wait.']]);
  finish.shift()(null);
  assert.equal(calls.length, 2); assert.equal(calls[1][1][2], 'Your family said yes. The front door is now unlocked.');
  const e = new Error('x'); e.code = 'ENOENT'; finish.shift()(e);
  assert.deepEqual(logs, ['voice notice: "Someone is at the front door. I have asked your family. Please wait."', 'ERROR voice notice not spoken: ENOENT']);
  // backlog cap
  v.onGuardianEvent(ev('offline', 'gateway')); for (const t of ['camera', 'living_light', 'dehumidifier', 'air_conditioner']) v.onGuardianEvent(ev('recovered', t));
  assert.equal(calls.length, 3, 'one speaking'); finish.shift()(null); finish.shift()(null); finish.shift()(null); finish.shift()(null);
  assert.equal(calls.length, 6, '1 speaking + at most 3 queued; the rest dropped');
  now = 61_000;
  assert.equal(v.onGuardianEvent(ev('door_requested', 'front_door', { requesterKind: 'ring' })), true, 'repeat allowed after a minute');
});
