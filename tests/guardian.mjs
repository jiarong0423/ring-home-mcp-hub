// Elderly guardian (plan ELDER_HOME_PLAN_zh.md §6.1 E1–E11) on the real simulator with a fake clock.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createSimulator } from '../src/core.mjs';
import { createGuardian, DEFAULT_ROUTINE } from '../src/guardian.mjs';

const at = (hh, mm) => { const d = new Date(2026, 9, 16, hh, mm, 0, 0); return d.getTime(); };
function setup({ start = at(6, 58), ringStatus = null, pair = ['living_light', 'dehumidifier', 'air_conditioner', 'alarm_clock'] } = {}) {
  let t = start;
  const clock = () => t;
  const sim = createSimulator({ now: clock });
  for (const deviceId of pair) { const { code } = sim.beginPair({ actor: 'owner', deviceId }); sim.completePair({ actor: 'owner', deviceId, code }); }
  const emails = [];
  const notifier = { enabled: true, publish: async (m) => { emails.push(m); return { sent: true }; }, status: () => ({ email: 'enabled' }) };
  let real = 0;
  const g = createGuardian({ simulator: sim, clock, realClock: () => real, notifier, ringStatus });
  const advanceTo = (target, stepMs = 30_000) => { while (t < target) { t = Math.min(target, t + stepMs); real += stepMs; sim.tick(); g.tick(); } };
  const kinds = () => g.status().events.map((e) => `${e.kind}:${e.target}`).reverse();
  return { sim, g, emails, advanceTo, kinds, clock };
}
const run = (s, id) => s.g.status().routine.today.find((r) => r.runId.endsWith(':' + id));

test('E1/E6: normal morning: gateway heartbeats every 60 s stay "online"; 07:00 light runs once with a receipt; no email', () => {
  const s = setup();
  s.advanceTo(at(7, 1));
  const st = s.g.status();
  assert.equal(st.gateway.state, 'online'); assert.equal(st.camera.state, 'online'); assert.equal(st.overall, 'ok');
  assert.deepEqual({ result: run(s, 'light-am-on').result, hasReceipt: /^[A-Za-z0-9_-]{8,12}$/u.test(run(s, 'light-am-on').receiptId) }, { result: 'confirmed', hasReceipt: true });
  assert.equal(s.sim.getState().devices.find((d) => d.id === 'living_light').state.power, true);
  assert.deepEqual(s.emails, []);
});

test('E2/E3/E10: gateway unplugged -> late at 3 min, offline at 5 min (one email), no repeats; back -> recovered (one email)', () => {
  const s = setup();
  s.advanceTo(at(10, 0));
  s.sim.setEdgeOnline({ actor: 'owner', online: false });
  s.advanceTo(at(10, 2));  assert.equal(s.g.status().gateway.state, 'online');
  s.advanceTo(at(10, 3, 30)); assert.equal(s.g.status().gateway.state, 'late');
  s.advanceTo(at(10, 30));  assert.equal(s.g.status().gateway.state, 'offline');
  assert.equal(s.kinds().filter((k) => k === 'offline:gateway').length, 1, 'one offline event despite many ticks');
  assert.equal(s.emails.length, 1); assert.match(s.emails[0].subject, /^\[Home MCP\] Home gateway offline$/u);
  assert.match(s.emails[0].message, /家中閘道斷線/u);
  s.sim.setEdgeOnline({ actor: 'owner', online: true });
  s.advanceTo(at(10, 31));
  assert.equal(s.g.status().gateway.state, 'online');
  assert.equal(s.emails.length, 2); assert.match(s.emails[1].subject, /back online/u);
});

test('E7/E8: 13:00 dehumidifier while gateway offline -> not executed + email; NOT made up after recovery; family retry -> confirmed', () => {
  const s = setup({ start: at(12, 40) });
  s.sim.setEdgeOnline({ actor: 'owner', online: false });
  s.advanceTo(at(13, 1));
  assert.deepEqual({ r: run(s, 'dehum-on').result, why: run(s, 'dehum-on').reason }, { r: 'not_executed', why: 'GATEWAY_OFFLINE' });
  assert.ok(s.emails.some((e) => /13:00 Dehumidifier not done/u.test(e.subject)));
  s.sim.setEdgeOnline({ actor: 'owner', online: true });
  s.advanceTo(at(13, 20));
  assert.equal(run(s, 'dehum-on').result, 'not_executed', 'never made up automatically');
  assert.equal(s.sim.getState().devices.find((d) => d.id === 'dehumidifier').state.power, false);
  const r = s.g.retry({ runId: run(s, 'dehum-on').runId });
  assert.equal(r.ok, true); assert.equal(run(s, 'dehum-on').result, 'confirmed');
  assert.equal(s.sim.getState().devices.find((d) => d.id === 'dehumidifier').state.power, true);
  assert.equal(s.g.retry({ runId: run(s, 'dehum-on').runId }).code, 'RUN_NOT_RETRYABLE');
  assert.equal(s.g.retry({ runId: 'nope' }).code, 'RUN_UNKNOWN');
});

test('retry taps during an outage are refused without using up the make-up; after recovery the family can still do it', () => {
  const s = setup({ start: at(12, 40) });
  s.sim.setEdgeOnline({ actor: 'owner', online: false });
  s.advanceTo(at(13, 1));
  const id = run(s, 'dehum-on').runId;
  for (let i = 0; i < 5; i += 1) assert.equal(s.g.retry({ runId: id }).code, 'GATEWAY_OFFLINE');
  s.sim.setEdgeOnline({ actor: 'owner', online: true });
  s.advanceTo(at(13, 3));
  assert.equal(s.g.retry({ runId: id }).ok, true);
});

test('E4: simulated camera stops answering -> late after one missed 5-minute check, offline after two (one email); recovers', () => {
  const s = setup({ start: at(14, 0) });
  s.advanceTo(at(14, 1));
  s.g.setSimulatedCamera({ online: false });
  s.advanceTo(at(14, 6)); assert.equal(s.g.status().camera.state, 'late');
  s.advanceTo(at(14, 11)); assert.equal(s.g.status().camera.state, 'offline');
  s.advanceTo(at(14, 40)); assert.equal(s.kinds().filter((k) => k === 'offline:camera').length, 1);
  assert.ok(s.emails.some((e) => /Ring camera offline/u.test(e.subject)));
  s.g.setSimulatedCamera({ online: true });
  s.advanceTo(at(14, 46)); assert.equal(s.g.status().camera.state, 'online');
  assert.ok(s.emails.some((e) => /Ring camera back online/u.test(e.subject)));
});

test('E5: real Ring probe: expired token never raises a camera-offline alert; live online:false twice -> offline', async () => {
  let answer = { state: 'token_expired' };
  const s = setup({ start: at(15, 0), ringStatus: async () => answer });
  s.advanceTo(at(15, 1)); await s.g.probeRing();
  assert.equal(s.g.status().camera.source, 'simulated'); assert.equal(s.g.status().camera.ring, 'token_expired');
  assert.equal(s.kinds().some((k) => k.startsWith('offline')), false);
  answer = { state: 'online' };
  s.advanceTo(at(15, 7)); await s.g.probeRing();
  assert.equal(s.g.status().camera.source, 'ring'); assert.equal(s.g.status().camera.state, 'online');
  answer = { state: 'offline' };
  s.advanceTo(at(15, 13)); await s.g.probeRing(); assert.equal(s.g.status().camera.state, 'late');
  s.advanceTo(at(15, 19)); await s.g.probeRing(); assert.equal(s.g.status().camera.state, 'offline');
});

test('E9: unlock / disarm can never be a routine item', () => {
  const sim = createSimulator();
  for (const bad of [{ id: 'x', time: '08:00', deviceId: 'front_door', action: 'unlock' }, { id: 'y', time: '08:00', deviceId: 'camera', action: 'disarm' },
    { id: 'z', time: '25:00', deviceId: 'living_light', action: 'on' }]) {
    assert.throws(() => createGuardian({ simulator: sim, routine: [bad] }), /routine item not allowed/u);
  }
});

test('E11: a fast clock (2-minute steps) gives the same day as a 30-second clock; items before start are "not monitored", not run late', () => {
  const day = (step) => { const s = setup({ start: at(6, 58) }); s.advanceTo(at(22, 5), step); return s.g.status().routine.today.map((r) => r.result); };
  assert.deepEqual(day(120_000), day(30_000));
  assert.deepEqual(day(120_000), DEFAULT_ROUTINE.map(() => 'confirmed'));
  const late = setup({ start: at(15, 0) });
  late.advanceTo(at(15, 1));
  assert.equal(run(late, 'light-am-on').result, 'not_monitored');
  assert.equal(late.sim.getState().devices.find((d) => d.id === 'living_light').state.power, false);
});

test('unpaired routine device -> not executed with the simulator code (and an email); overall shows attention', () => {
  const s = setup({ pair: ['dehumidifier', 'air_conditioner', 'alarm_clock'] });
  s.advanceTo(at(7, 1));
  assert.equal(run(s, 'light-am-on').result, 'not_executed'); assert.match(run(s, 'light-am-on').reason, /PAIR/u);
  assert.equal(s.g.status().overall, 'attention'); assert.equal(s.emails.length, 1);
});

test('gateway flapping with short up-times: a reconnect reports a heartbeat at once, so brief blips never become offline alerts', () => {
  const s = setup({ start: at(10, 0) });
  s.advanceTo(at(10, 1));
  for (let i = 0; i < 40; i += 1) {
    s.sim.setEdgeOnline({ actor: 'owner', online: false }); s.advanceTo(s.clock() + 90_000, 10_000);
    s.sim.setEdgeOnline({ actor: 'owner', online: true }); s.advanceTo(s.clock() + 18_000, 6_000);
  }
  assert.equal(s.kinds().filter((k) => k === 'offline:gateway').length, 0);
  assert.equal(s.kinds().filter((k) => k === 'heartbeat_late:gateway').length, 0);
  assert.equal(s.emails.length, 0);
});

test('real Ring camera on a fast demo clock: judged on real time, so it is not "late" just because the demo clock raced ahead', async () => {
  let t = at(9, 50); let real = 1_000_000;
  const sim = createSimulator({ now: () => t });
  let answer = { state: 'online' };
  const g = createGuardian({ simulator: sim, clock: () => t, realClock: () => real, ringStatus: async () => answer });
  await g.probeRingNow();
  assert.equal(g.status().camera.source, 'ring'); assert.equal(g.status().camera.state, 'online');
  t += 60 * 60_000; real += 60_000; g.tick();          // x60: one real minute = one demo hour
  assert.equal(g.status().camera.state, 'online', 'one real minute after a real check is not late');
  real += 8 * 60_000; g.tick();                        // 9 real minutes without a successful real check -> late
  assert.equal(g.status().camera.state, 'late');
  answer = { state: 'online' }; await g.probeRingNow();
  assert.equal(g.status().camera.state, 'online');
});

test('door email: the remote-approval link is added only while a family phone is enabled; never a code or snapshot', () => {
  const sim = createSimulator({ now: () => at(9, 0) });
  const emails = [];
  const notifier = { enabled: true, publish: async (m) => { emails.push(m); return { sent: true }; }, status: () => ({ email: 'enabled' }) };
  let url = null;
  const g = createGuardian({ simulator: sim, clock: () => at(9, 0), notifier, familyUrl: () => url });
  const req = { requester: { kind: 'ring', name: 'Ring doorbell' } };
  g.noteDoor('requested', req);
  assert.doesNotMatch(emails[0].message, /Away from home/u);
  url = 'https://abc.execute-api.ap-southeast-1.amazonaws.com/staging/family';
  g.noteDoor('requested', req);
  assert.match(emails[1].message, /Away from home\? Answer on your enabled phone: https:\/\/abc\.execute-api\.[^ ]+\/family\n/u);
  assert.match(emails[1].message, /不在家？在已開通的手機上回覆：https:/u);
  assert.doesNotMatch(emails[1].message, /#code=/u);
  g.noteDoor('approved', { ...req, approver: 'Amy (remote)', receipt: { receiptId: 'r1' } });
  assert.doesNotMatch(emails[2].message, /Away from home/u, 'only the request email carries the link');
});
