// Guardian evaluation: 30 simulated days on the real simulator + guardian (fake clock, fixed seed, no network).
// Random gateway blips / short drops / real outages and camera outages are injected; we measure what the family is told.
// Baseline for comparison: "alert on every missed heartbeat" (one alert per missed 60 s gateway beat / 5 min camera check).
// Usage: node scripts/eval_guardian.mjs [days=30] [seed=20261016]   -> prints a JSON summary and a Markdown table
import { createSimulator } from '../src/core.mjs';
import { createGuardian, DEFAULT_TIMING } from '../src/guardian.mjs';

const DAYS = Number(process.argv[2] ?? 30);
let seed = Number(process.argv[3] ?? 20261016);
const rand = () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };
const between = (a, b) => a + rand() * (b - a);
const MIN = 60_000;
const STEP = 30_000;

const start = new Date(2026, 9, 1, 0, 0, 0, 0).getTime();
let t = start; let real = 0;
const sim = createSimulator({ now: () => t });
for (const deviceId of ['living_light', 'dehumidifier', 'air_conditioner', 'alarm_clock']) {
  const { code } = sim.beginPair({ actor: 'owner', deviceId }); sim.completePair({ actor: 'owner', deviceId, code });
}
const emails = [];
const notifier = { enabled: true, publish: async (m) => { emails.push({ at: t, ...m }); return { sent: true }; }, status: () => ({ email: 'enabled' }) };
const ev = [];
const g = createGuardian({ simulator: sim, clock: () => t, realClock: () => real, notifier, onEvent: (e) => ev.push(e) });

// Fault plan: per day 0-3 gateway incidents (blip < 3 min, short 3-5 min, outage 5-120 min) and 0-1 camera outage.
const faults = [];
for (let d = 0; d < DAYS; d += 1) {
  const day0 = start + d * 24 * 60 * MIN;
  const n = Math.floor(rand() * 4);
  for (let i = 0; i < n; i += 1) {
    const kind = ['blip', 'blip', 'short', 'outage'][Math.floor(rand() * 4)];
    const len = kind === 'blip' ? between(0.3, 2.5) * MIN : kind === 'short' ? between(3.2, 4.8) * MIN : between(6, 120) * MIN;
    faults.push({ target: 'gateway', kind, from: day0 + between(1, 22) * 60 * MIN, len });
  }
  if (rand() < 0.4) faults.push({ target: 'camera', kind: 'outage', from: day0 + between(1, 22) * 60 * MIN, len: between(11, 90) * MIN });
  // once a week the gateway is down across a routine step (13:00 dehumidifier on), so missed steps are exercised too
  if (d % 7 === 3) faults.push({ target: 'gateway', kind: 'outage', from: day0 + (12 * 60 + 40) * MIN, len: between(30, 60) * MIN });
}
faults.sort((a, b) => a.from - b.from);
// Overlapping gateway incidents are merged into the first one (a gateway cannot be "more offline").
const plan = [];
for (const f of faults) { const last = plan.filter((p) => p.target === f.target).at(-1); if (last && f.from < last.from + last.len + 2 * MIN) continue; plan.push(f); }

const end = start + DAYS * 24 * 60 * MIN;
const active = { gateway: null, camera: null };
while (t < end) {
  t += STEP; real += STEP;
  for (const f of plan) {
    if (!f.started && t >= f.from) {
      f.started = true; active[f.target] = f;
      if (f.target === 'gateway') { sim.setEdgeOnline({ actor: 'owner', online: false }); g.noteGateway({ online: false }); } else g.setSimulatedCamera({ online: false });
    }
    if (f.started && !f.ended && t >= f.from + f.len) {
      f.ended = true; active[f.target] = null;
      if (f.target === 'gateway') { sim.setEdgeOnline({ actor: 'owner', online: true }); g.noteGateway({ online: true }); } else g.setSimulatedCamera({ online: true });
    }
  }
  if (!active.gateway) sim.heartbeat?.({ actor: 'owner' });
  sim.tick(); g.tick();
}

const at = (e) => Date.parse(e.at);
const found = (target, kind, from, until) => ev.find((e) => e.target === target && e.kind === kind && at(e) >= from && at(e) <= until);

const gw = plan.filter((p) => p.target === 'gateway');
const cam = plan.filter((p) => p.target === 'camera');
const outages = gw.filter((p) => p.kind === 'outage');
const shortDrops = gw.filter((p) => p.kind !== 'outage');
const detected = outages.map((o) => found('gateway', 'offline', o.from, o.from + o.len + 2 * MIN)).filter(Boolean);
const delays = outages.map((o) => { const e = found('gateway', 'offline', o.from, o.from + o.len + 2 * MIN); return e ? (at(e) - o.from) / MIN : null; }).filter((x) => x !== null);
const blips = gw.filter((p) => p.kind === 'blip');
const shorts = gw.filter((p) => p.kind === 'short');
const falseOffline = blips.filter((o) => found('gateway', 'offline', o.from, o.from + o.len + 1 * MIN)).length;
const shortAlerts = shorts.filter((o) => found('gateway', 'offline', o.from, o.from + o.len + 1 * MIN)).length;
const blipLate = blips.filter((o) => found('gateway', 'heartbeat_late', o.from, o.from + o.len + 1 * MIN)).length;
const camDetected = cam.filter((o) => found('camera', 'offline', o.from, o.from + o.len + 2 * MIN)).length;
const recovered = outages.filter((o) => found('gateway', 'recovered', o.from + o.len - MIN, o.from + o.len + 3 * MIN)).length;

const routine = ev.filter((e) => e.kind === 'routine_done' || e.kind === 'routine_missed');
const missed = routine.filter((e) => e.kind === 'routine_missed');
const naive = gw.reduce((a, o) => a + Math.floor(o.len / DEFAULT_TIMING.gatewayIntervalMs), 0)
  + cam.reduce((a, o) => a + Math.floor(o.len / DEFAULT_TIMING.cameraIntervalMs), 0);

const summary = {
  days: DAYS, seed: Number(process.argv[3] ?? 20261016),
  gateway: { incidents: gw.length, outages_over_5min: outages.length, detected: detected.length, detection_delay_min: { min: Math.min(...delays), max: Math.max(...delays) },
    blips_under_3min: blips.length, offline_alerts_from_blips: falseOffline, late_banners_from_blips: blipLate,
    drops_3_to_5min: shorts.length, offline_alerts_from_3_to_5min_drops: shortAlerts, recovered_notices: recovered },
  camera: { outages: cam.length, detected: camDetected },
  routine: { runs_with_a_result: routine.length, not_done_and_reported: missed.length,
    made_up_without_asking: ev.filter((e) => e.kind === 'routine_done' && missed.some((m) => m.params.scheduled === e.params.scheduled && Math.abs(at(m) - at(e)) < 2 * 60 * MIN && at(e) > at(m))).length },
  emails_sent: emails.length, naive_alerts_one_per_missed_heartbeat: naive
};
console.log(JSON.stringify(summary, null, 1));
console.log(`\n| Metric (${DAYS} simulated days, seed ${summary.seed}) | Result |\n|---|---|`);
console.log(`| Gateway outages over 5 min detected | ${detected.length} / ${outages.length} (alert ${summary.gateway.detection_delay_min.min.toFixed(1)}–${summary.gateway.detection_delay_min.max.toFixed(1)} min after it went quiet) |`);
console.log(`| "Offline" alerts from blips under 3 min (false alarms) | ${falseOffline} / ${blips.length} |`);
console.log(`| Drops of 3–5 min that crossed 5 min without a heartbeat (alerted, by design) | ${shortAlerts} / ${shorts.length} |`);
console.log(`| "Back online" notices after outages | ${recovered} / ${outages.length} |`);
console.log(`| Camera outages detected | ${camDetected} / ${cam.length} |`);
console.log(`| Routine steps that could not run, reported to the family | ${missed.length}; made up without the family asking: ${summary.routine.made_up_without_asking} |`);
console.log(`| Emails sent vs. "alert on every missed heartbeat" | ${emails.length} vs ${naive} |`);
