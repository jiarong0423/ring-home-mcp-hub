// Other home devices: tiered AI permissions (src/agent_policy.mjs), robot vacuum reporting back, the real USB home gateway
// (src/usb_gateway.mjs, firmware/home_gateway) and the parent's button. Real simulator, fake clocks, fake serial ports.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createSimulator } from '../src/core.mjs';
import { createGuardian } from '../src/guardian.mjs';
import { decideAgentAction, describeAgentPolicy, AGENT_POLICY } from '../src/agent_policy.mjs';
import { createUsbGateway, parseGatewayLine, GATEWAY_ID } from '../src/usb_gateway.mjs';

const at = (hh, mm, ss = 0) => new Date(2026, 9, 16, hh, mm, ss, 0).getTime();
function setup({ start = at(9, 58), pair = ['living_light', 'robot_vacuum', 'air_conditioner'] } = {}) {
  let t = start; let real = 0;
  const sim = createSimulator({ now: () => t });
  for (const deviceId of pair) { const { code } = sim.beginPair({ actor: 'owner', deviceId }); sim.completePair({ actor: 'owner', deviceId, code }); }
  const emails = [];
  const notifier = { enabled: true, publish: async (m) => { emails.push(m); return { sent: true }; }, status: () => ({ email: 'enabled' }) };
  const g = createGuardian({ simulator: sim, clock: () => t, realClock: () => real, notifier, routine: [] });
  const advance = (ms, step = 30_000) => { const end = t + ms; while (t < end) { t = Math.min(end, t + step); real += step; sim.tick(); g.tick(); } };
  const advanceRealOnly = (ms) => { real += ms; g.tick(); };
  const advanceVirtualOnly = (ms) => { t += ms; sim.tick(); g.tick(); };
  const kinds = () => g.status().events.map((e) => e.kind).reverse();
  return { sim, g, emails, advance, advanceRealOnly, advanceVirtualOnly, kinds, startVacuum: () => sim.perform({ actor: 'owner', deviceId: 'robot_vacuum', action: 'start', origin: 'ui' }) };
}

test('agent policy: low-risk actions inside the family limits are allowed; door asks; disarm and out-of-limit settings are family-only', () => {
  const d = (deviceId, action, parameters, now = '10:00') => decideAgentAction({ deviceId, action, parameters, now });
  assert.equal(d('living_light', 'on').tier, 'allow');
  assert.equal(d('air_conditioner', 'set_temperature', { temperature: 26 }).allowed, true);
  assert.deepEqual([d('air_conditioner', 'set_temperature', { temperature: 18 }).reason, d('air_conditioner', 'set_temperature', { temperature: 30 }).reason],
    ['OUTSIDE_FAMILY_LIMITS', 'OUTSIDE_FAMILY_LIMITS']);
  assert.equal(d('air_conditioner', 'set_temperature', { temperature: '26' }).allowed, false, 'a number, not a string');
  assert.equal(d('dehumidifier', 'set_target_humidity', { humidity: 70 }).allowed, false);
  assert.equal(d('robot_vacuum', 'start', {}, '10:00').allowed, true);
  assert.equal(d('robot_vacuum', 'start', {}, '23:30').reason, 'OUTSIDE_ALLOWED_HOURS', 'no vacuuming at night');
  assert.equal(d('robot_vacuum', 'dock', {}, '23:30').allowed, true, 'sending it home is always fine');
  assert.equal(d('alarm_clock', 'set_alarm', { time: '07:00' }).allowed, true);
  assert.equal(d('alarm_clock', 'set_alarm', { time: '03:00' }).allowed, false);
  assert.equal(d('alarm_clock', 'clear_alarm').tier, 'family');
  assert.equal(d('camera', 'disarm').tier, 'family');
  assert.deepEqual([d('front_door', 'unlock').tier, d('front_door', 'unlock').reason], ['ask', 'FAMILY_APPROVAL_REQUIRED']);
  assert.equal(d('front_door', 'lock').allowed, true);
  assert.equal(d('microwave', 'on').allowed, false, 'unknown devices are never allowed');
  const p = describeAgentPolicy();
  assert.deepEqual(Object.keys(p).sort(), Object.keys(AGENT_POLICY).sort());
  p.air_conditioner.set_temperature.min = 0;
  assert.equal(AGENT_POLICY.air_conditioner.set_temperature.min, 24, 'the description is a copy');
});

test('vacuum: a run reports back once: done (back on the dock, with a receipt) after 40 min; no email', () => {
  const s = setup();
  assert.equal(s.startVacuum().status, 'simulated_applied');
  s.g.noteVacuumStart({ origin: 'console' });
  assert.equal(s.g.status().vacuum.running, true);
  s.advance(39 * 60_000);
  assert.equal(s.kinds().includes('vacuum_done'), false);
  s.advance(2 * 60_000);
  const done = s.g.status().events.find((e) => e.kind === 'vacuum_done');
  assert.ok(done && done.params.minutes >= 40 && /^[A-Za-z0-9_-]{8,12}$/u.test(done.params.receipt), JSON.stringify(done));
  assert.equal(s.sim.getState().devices.find((x) => x.id === 'robot_vacuum').state.mode, 'docked');
  assert.equal(s.g.status().vacuum.running, false);
  assert.deepEqual(s.emails, []);
});

test('vacuum: stuck -> one alert email with the minutes; gateway down at the end -> "cannot confirm", never assumed done', () => {
  const s = setup();
  s.startVacuum(); s.g.noteVacuumStart({ origin: 'ai_agent' });
  s.advance(12 * 60_000);
  assert.deepEqual(s.g.setVacuumFault({ fault: 'stuck' }), { ok: true });
  s.advance(60_000);
  assert.equal(s.kinds().filter((k) => k === 'vacuum_stuck').length, 1);
  assert.equal(s.emails.length, 1); assert.match(s.emails[0].subject, /Robot vacuum needs help/u);
  assert.deepEqual(s.g.setVacuumFault({ fault: 'stuck' }), { ok: false, code: 'VACUUM_NOT_RUNNING' });

  const s2 = setup();
  s2.startVacuum(); s2.g.noteVacuumStart({ origin: 'console' });
  s2.advance(30 * 60_000);
  s2.sim.setEdgeOnline({ actor: 'owner', online: false });
  s2.advance(15 * 60_000);
  assert.equal(s2.kinds().includes('vacuum_done'), false);
  assert.equal(s2.g.status().events.find((e) => e.kind === 'vacuum_unknown').params.reason, 'GATEWAY_OFFLINE');
  assert.equal(s2.g.setVacuumFault({ fault: 'melted' }).code, 'VACUUM_NOT_RUNNING');
});

test('parent button: short press = "I\'m OK" on the timeline (no email); long press = help (one email)', () => {
  const s = setup();
  s.g.noteButton({ press: 'short' });
  assert.equal(s.kinds().at(-1), 'parent_ok'); assert.equal(s.emails.length, 0);
  s.g.noteButton({ press: 'long' });
  assert.equal(s.kinds().at(-1), 'parent_help'); assert.equal(s.emails.length, 1);
  assert.match(s.emails[0].subject, /Help button pressed at home/u);
  assert.equal(s.g.noteButton({ press: 'triple' }), null);
});

test('real USB gateway: heartbeats on the REAL clock; a fast demo clock cannot age them; unplugged -> late 3 min, offline 5 min, one email', () => {
  const s = setup();
  s.g.noteUsbGateway({ beat: true });
  assert.equal(s.g.status().gateway.source, 'usb');
  s.advanceVirtualOnly(60 * 60_000);             // a 60x demo: one virtual hour, almost no real time
  assert.equal(s.g.status().gateway.state, 'online', 'virtual time does not age a real heartbeat');
  for (let i = 0; i < 10; i++) { s.g.noteUsbGateway({ beat: true }); s.advanceRealOnly(60_000); }
  s.g.noteUsbGateway({ beat: true });
  assert.equal(s.g.status().gateway.state, 'online');
  s.advanceRealOnly(2 * 60_000); assert.equal(s.g.status().gateway.state, 'online');
  s.advanceRealOnly(60_000 + 1); assert.equal(s.g.status().gateway.state, 'late');
  s.advanceRealOnly(2 * 60_000); assert.equal(s.g.status().gateway.state, 'offline');
  s.advanceRealOnly(10 * 60_000);
  assert.equal(s.kinds().filter((k) => k === 'offline').length, 1);
  assert.equal(s.emails.length, 1); assert.match(s.emails[0].subject, /Home gateway offline/u);
  s.g.noteUsbGateway({ beat: true });
  assert.equal(s.g.status().gateway.state, 'online');
  assert.equal(s.kinds().at(-1), 'recovered'); assert.equal(s.emails.length, 2);
});

test('usb lines: only small, well-formed JSON of the three known kinds is accepted', () => {
  assert.deepEqual(parseGatewayLine('{"t":"hello","id":"hmg-home-gateway","fw":"hmg-gw-1","chip":"esp32c3"}'), { t: 'hello', id: 'hmg-home-gateway', fw: 'hmg-gw-1' });
  assert.deepEqual(parseGatewayLine('{"t":"beat","n":3,"upMs":120000}'), { t: 'beat', n: 3 });
  assert.deepEqual(parseGatewayLine('{"t":"button","press":"long","n":1}'), { t: 'button', press: 'long', n: 1 });
  for (const bad of ['', 'hello', '[bike] button trigger=D2', '{"t":"button","press":"maybe","n":1}', '{"t":"beat","n":-1}', '{"t":"x"}', '{bad json', '{"t":"beat","n":1}' + ' '.repeat(300)]) {
    assert.equal(parseGatewayLine(bad), null, bad.slice(0, 40));
  }
});

function fakePorts() {
  const ports = new Map();
  return {
    ports,
    add(path, replyTo) {
      const p = { path, written: [], closed: false, data: null, end: null, replyTo };
      ports.set(path, p); return p;
    },
    list: () => [...ports.keys()],
    open: async (path) => {
      const p = ports.get(path); if (!p) throw new Error('gone');
      return {
        onData: (fn) => { p.data = fn; }, onEnd: (fn) => { p.end = fn; },
        write: (s) => { p.written.push(s); const r = p.replyTo?.(s); if (r) queueMicrotask(() => p.data?.(r)); },
        close: () => { p.closed = true; }
      };
    }
  };
}
const tick = () => new Promise((r) => setImmediate(r));

test('usb gateway: picks only the board that says hello as hmg-home-gateway; other boards are closed untouched; unplug is reported', async () => {
  const f = fakePorts();
  const other = f.add('/dev/cu.usbmodem1101', (s) => (s === '?' ? '[identity] role=bike id=B01\n' : null));
  const ours = f.add('/dev/cu.usbmodem2201', (s) => (s === '?' ? `{"t":"hello","id":"${GATEWAY_ID}","fw":"hmg-gw-1"}\n` : s === 'h' ? '{"t":"beat","n":1}\n' : null));
  const seen = [];
  const timers = [];
  const gw = createUsbGateway({ enabled: true, listPorts: f.list, openPort: f.open, helloTimeoutMs: 1000,
    setTimer: (fn, ms) => { timers.push({ fn, ms }); return timers.length; }, clearTimer: () => {},
    onHello: (h) => seen.push('hello:' + h.fw), onBeat: (b) => seen.push('beat:' + b.n), onButton: (b) => seen.push('button:' + b.press), onLost: () => seen.push('lost') });
  gw.start(); await tick(); await tick();
  assert.deepEqual(other.written, ['?'], 'only the identity question is sent to an unknown board');
  for (const t of timers.filter((x) => x.ms === 1000)) t.fn();   // its hello never comes -> closed
  assert.equal(other.closed, true);
  await gw.scanNow(); await tick(); await tick();
  assert.deepEqual(ours.written, ['?', 'h']);
  assert.deepEqual(seen, ['hello:hmg-gw-1', 'beat:1']);
  assert.equal(gw.status().connected, true);
  ours.data('{"t":"button","press":"short","n":1}\n{"t":"beat","n":2}\nnoise\n');
  assert.deepEqual(seen.slice(2), ['button:short', 'beat:2']);
  f.ports.delete(ours.path);
  await gw.scanNow();
  assert.equal(seen.at(-1), 'lost'); assert.equal(gw.status().connected, false);
  gw.stop();
});

test('usb gateway: off by default; a hello from a different id is refused', async () => {
  assert.equal(createUsbGateway({ listPorts: () => { throw new Error('must not scan'); } }).status().enabled, false);
  const f = fakePorts();
  const fake = f.add('/dev/cu.usbmodem9', (s) => (s === '?' ? '{"t":"hello","id":"someone-else","fw":"x"}\n' : null));
  const seen = [];
  const gw = createUsbGateway({ enabled: true, listPorts: f.list, openPort: f.open, setTimer: () => 0, clearTimer: () => {}, onHello: () => seen.push('hello') });
  gw.start(); await tick(); await tick();
  assert.equal(fake.closed, true); assert.deepEqual(seen, []); assert.equal(gw.status().connected, false);
  gw.stop();
});
