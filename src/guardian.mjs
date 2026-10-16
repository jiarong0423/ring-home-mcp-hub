// "Always-on guardian" for an older person living alone: low-frequency heartbeats for the Ring camera and the home gateway,
// proactive alerts only when something changes, and a daily routine that runs the devices on schedule instead of someone
// pressing buttons remotely. Every routine run ends in exactly one of: confirmed (receipt), not executed, or unknown.
// Missed runs are never made up silently; a family member decides with retry().
//
// Pure logic: the caller supplies the simulator, clocks, an optional Ring status probe and an optional notifier.

export const DEFAULT_ROUTINE = Object.freeze([
  { id: 'light-am-on', time: '07:00', deviceId: 'living_light', action: 'on' },
  { id: 'light-am-off', time: '09:00', deviceId: 'living_light', action: 'off' },
  { id: 'dehum-on', time: '13:00', deviceId: 'dehumidifier', action: 'on' },
  { id: 'dehum-off', time: '17:00', deviceId: 'dehumidifier', action: 'off' },
  { id: 'light-pm-on', time: '18:00', deviceId: 'living_light', action: 'on' },
  { id: 'alarm-set', time: '21:30', deviceId: 'alarm_clock', action: 'set_alarm', parameters: { time: '07:00' } },
  { id: 'ac-off', time: '22:00', deviceId: 'air_conditioner', action: 'off' },
  { id: 'light-pm-off', time: '22:00', deviceId: 'living_light', action: 'off' }
].map(Object.freeze));

export const DEFAULT_TIMING = Object.freeze({
  gatewayIntervalMs: 60_000,      // the home gateway reports once a minute while it is up
  gatewayLateMs: 3 * 60_000,      // no gateway heartbeat for 3 minutes -> "heartbeat late"
  gatewayOfflineMs: 5 * 60_000,   // 5 minutes -> "offline" (alert)
  cameraIntervalMs: 5 * 60_000,   // camera checked every 5 minutes
  cameraFailures: 2,              // two missed / failed checks in a row -> camera offline (alert)
  routineWindowMs: 60 * 60_000,   // a routine item older than this when first seen is "not monitored", never run late
  vacuumRunMs: 40 * 60_000        // a simulated cleaning run lasts 40 minutes on the guardian clock, then reports back
});

const DEVICE_NAMES = Object.freeze({
  living_light: ['Living room light', '客廳燈'], dehumidifier: ['Dehumidifier', '除濕機'], air_conditioner: ['Air conditioner', '冷氣'],
  alarm_clock: ['Alarm clock', '鬧鐘'], camera: ['Ring camera', 'Ring 攝影機'], gateway: ['Home gateway', '家中閘道'],
  front_door: ['Front door', '前門'], robot_vacuum: ['Robot vacuum', '掃地機'], home_button: ['Home button', '家中按鈕']
});
const ACTION_NAMES = Object.freeze({ on: ['on', '開'], off: ['off', '關'], set_alarm: ['set alarm', '設定鬧鐘'] });
const pad = (n) => String(n).padStart(2, '0');
const hhmm = (ms) => { const d = new Date(ms); return `${pad(d.getHours())}:${pad(d.getMinutes())}`; };
const dayKey = (ms) => { const d = new Date(ms); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`; };
const dueMs = (ms, time) => { const d = new Date(ms); const [h, m] = time.split(':').map(Number); d.setHours(h, m, 0, 0); return d.getTime(); };

export function createGuardian({ simulator, clock = Date.now, realClock = Date.now, routine = DEFAULT_ROUTINE, timing = DEFAULT_TIMING,
  ringStatus = null, notifier = null, maxEvents = 200, log = () => {}, onEvent = null, familyUrl = () => null }) {
  for (const item of routine) {   // unlock / disarm are never schedulable, here or in the simulator
    if ((item.deviceId === 'front_door' && item.action === 'unlock') || (item.deviceId === 'camera' && item.action === 'disarm')
      || !/^([01]\d|2[0-3]):[0-5]\d$/u.test(item.time)) throw new Error('routine item not allowed: ' + item.id);
  }
  const events = [];
  let seq = 0;
  const targets = {
    gateway: { state: 'online', lastHeartbeatMs: clock(), nextBeatMs: clock(), source: 'simulated', lastRealBeat: 0 },
    camera: { state: 'online', lastHeartbeatMs: clock(), source: 'simulated', failures: 0, simulatedOnline: true, nextCheckReal: 0,
      nextSimBeatMs: clock(), ring: 'not_configured' }
  };
  const runs = new Map();   // `${day}:${id}` -> run
  let vacuum = null;        // { startedAt, dueAt, origin, fault } while a cleaning run is in progress
  let currentDay = dayKey(clock());
  let ringInFlight = false;

  function emit(kind, severity, target, params, { email = false } = {}) {
    const at = clock();
    const event = Object.freeze({ id: ++seq, at: new Date(at).toISOString(), time: hhmm(at), kind, severity, target, params: Object.freeze({ ...params }) });
    events.push(event); if (events.length > maxEvents) events.shift();
    onEvent?.(event);   // full stream for evaluation / audit sinks (the UI keeps only the newest ones)
    if (email && notifier?.enabled) {
      const { subject, message } = emailFor(event);
      void notifier.publish({ subject, message });
    }
    return event;
  }
  function emailFor(e) {
    const [en, zh] = DEVICE_NAMES[e.target] ?? [e.target, e.target];
    const act = e.params.action ? (ACTION_NAMES[e.params.action] ?? [e.params.action, e.params.action]) : null;
    const lines = {
      offline: [`${en} offline`, `${e.time} ${en} is offline (last heartbeat ${e.params.lastHeartbeat}).`, `${e.time} ${zh}斷線（最後心跳 ${e.params.lastHeartbeat}）。`],
      recovered: [`${en} back online`, `${e.time} ${en} is back online.`, `${e.time} ${zh}已恢復。`],
      ring_token: ['Ring connection ended', `${e.time} The Ring connection ended (${e.params.reason}). Camera checks now show SIMULATED until a new Ring token is pasted on the admin phone.`, `${e.time} Ring 連線已結束（${e.params.reason}）。攝影機改顯示模擬，直到在管理員手機貼上新的 Ring token。`],
      routine_missed: [`${e.params.scheduled} ${en} not done`, `${e.params.scheduled} ${en} ${act?.[0]} was not done (${e.params.reason}). Open the console to retry.`,
        `${e.params.scheduled} ${zh}${act?.[1]}沒有完成（${e.params.reason}）。可在控制台補做。`],
      // No snapshot and no face hint ever go into an email; the admin looks on the paired phone.
      door_requested: e.params.requesterKind === 'ring' ? ['Someone rang the Ring doorbell', `${e.time} Someone rang the Ring doorbell. Look at the door snapshot and approve or deny on the admin phone within 60 s (door is SIMULATED).`,
        `${e.time} 有人按了 Ring 門鈴。請在 60 秒內到管理員手機看門口照片，再核准或拒絕（門鎖為模擬）。`] : ['Door unlock requested', `${e.time} "${e.params.requester}" asked to open the front door (SIMULATED). Approve or deny on the admin phone within 60 s.`,
        `${e.time}「${e.params.requester}」請求開前門（模擬）。請在 60 秒內到管理員手機核准或拒絕。`],
      door_approved: ['Door opened (SIMULATED)', `${e.time} The front door was opened (SIMULATED) for "${e.params.requester}", approved by "${e.params.approver}". Receipt ${e.params.receipt}.`,
        `${e.time} 前門已開（模擬），申請者「${e.params.requester}」，核准者「${e.params.approver}」。收據 ${e.params.receipt}。`],
      parent_help: ['Help button pressed at home', `${e.time} The help button at home was held down. Please call or check in now.`, `${e.time} 家中的求助按鈕被長按。請現在打電話或去看看。`],
      vacuum_stuck: ['Robot vacuum needs help', `${e.time} The robot vacuum stopped (${e.params.reason}) after ${e.params.minutes} min. It is SIMULATED; send it home from the console.`,
        `${e.time} 掃地機停住了（${e.params.reason}），已掃 ${e.params.minutes} 分鐘。掃地機為模擬，可在控制台叫它回充電座。`]
    }[e.kind] ?? [e.kind, e.kind, e.kind];
    // Away from home: a family phone enabled for remote approval answers on the relay page (the link carries no code or token).
    const remote = e.kind === 'door_requested' ? familyUrl() : null;
    if (remote) { lines[1] += ` Away from home? Answer on your enabled phone: ${remote}`; lines[2] += ` 不在家？在已開通的手機上回覆：${remote}`; }
    return { subject: `[Home MCP] ${lines[0]}`, message: `${lines[1]}\n${lines[2]}\n\nSimulated devices / Ring Playground test environment. 模擬設備／Ring Playground 測試環境。` };
  }

  // State changes only: online -> late (banner) -> offline (alert + email) -> online again (recovered + email).
  function transition(name, next, params) {
    const t = targets[name];
    if (t.state === next) return;
    const prev = t.state; t.state = next;
    const last = hhmm(t.lastHeartbeatMs);
    if (next === 'late') emit('heartbeat_late', 'warn', name, { lastHeartbeat: last, ...params });
    else if (next === 'offline') emit('offline', 'alert', name, { lastHeartbeat: last, ...params }, { email: true });
    else if (next === 'online') emit(prev === 'offline' ? 'recovered' : 'heartbeat_ok', 'info', name, { ...params }, { email: prev === 'offline' });
  }

  // The gateway's low-frequency heartbeat is modelled on the guardian clock (which may be accelerated for a demo): one beat
  // per interval while the simulated gateway is up. The simulator itself keeps real time, so codes and TTLs are unaffected.
  function checkGateway(now) {
    const g = targets.gateway;
    if (g.source === 'usb') {   // a real gateway on USB: real heartbeats, aged on the real clock (an accelerated demo cannot age them)
      const age = realClock() - g.lastRealBeat;
      transition('gateway', age >= timing.gatewayOfflineMs ? 'offline' : age >= timing.gatewayLateMs ? 'late' : 'online', { source: 'usb' });
      return;
    }
    const up = simulator.getState().edge.online === true;
    // A gateway reports right away when it reconnects, then every interval.
    if (up && g.wasUp === false) { g.lastHeartbeatMs = now; g.nextBeatMs = now + timing.gatewayIntervalMs; }
    g.wasUp = up;
    while (now >= g.nextBeatMs) { if (up) g.lastHeartbeatMs = g.nextBeatMs; g.nextBeatMs += timing.gatewayIntervalMs; }
    const age = now - g.lastHeartbeatMs;
    transition('gateway', age >= timing.gatewayOfflineMs ? 'offline' : age >= timing.gatewayLateMs ? 'late' : 'online');
  }

  function cameraVerdict(now) {
    const c = targets.camera;
    if (c.failures >= timing.cameraFailures) return 'offline';
    if (c.ring === 'webhook') return 'online';   // Ring itself reports offline / online; no status polling to age
    // Real Ring checks run on the real clock, so their age is judged on the real clock (a fast demo clock must not age them).
    const age = c.source === 'ring' && c.lastRealOk ? realClock() - c.lastRealOk : now - c.lastHeartbeatMs;
    if (c.failures >= 1 || age >= timing.cameraIntervalMs * 1.5) return 'late';
    return 'online';
  }
  function checkCamera(now) {
    const c = targets.camera;
    if (c.source === 'simulated') {
      while (now >= c.nextSimBeatMs) {          // one simulated status check per interval (virtual clock)
        if (c.simulatedOnline) { c.lastHeartbeatMs = c.nextSimBeatMs; c.failures = 0; } else c.failures += 1;
        c.nextSimBeatMs += timing.cameraIntervalMs;
      }
    }
    transition('camera', cameraVerdict(now));
  }
  // Real Ring status probe on the REAL clock (never accelerated): one GET /v1/devices/{id}/status per interval.
  async function probeRing() {
    const c = targets.camera;
    if (!ringStatus || ringInFlight || realClock() < c.nextCheckReal) return;
    ringInFlight = true; c.nextCheckReal = realClock() + timing.cameraIntervalMs;
    try {
      const r = await ringStatus();
      if (r.state === 'token_missing' && c.ring === 'webhook') return;   // webhook-driven state stays until a token allows polling
      if (r.state === 'token_missing' || r.state === 'token_expired') {
        // the real Ring link ended (30-minute Playground token): the family is told, never a silent switch to simulation
        if (c.source === 'ring') emit('ring_token', 'warn', 'camera', { reason: r.state }, { email: true });
        c.source = 'simulated'; c.ring = r.state; c.failures = 0; c.nextSimBeatMs = clock();
        return;
      }
      if (c.source !== 'ring') { c.source = 'ring'; c.failures = 0; emit('ring_live', 'info', 'camera', {}); }
      c.ring = 'live';
      if (r.state === 'online') { c.lastHeartbeatMs = clock(); c.lastRealOk = realClock(); c.failures = 0; } else c.failures += 1;
      transition('camera', cameraVerdict(clock()));
    } catch { if (c.source === 'ring') c.failures += 1; }
    finally { ringInFlight = false; }
  }

  function runItem(item, run) {
    const now = clock();
    run.attemptedAt = new Date(now).toISOString();
    if (targets.gateway.state !== 'online' || simulator.getState().edge.online !== true) return finish(item, run, 'not_executed', 'GATEWAY_OFFLINE');
    let result;
    try {
      result = simulator.perform({ actor: 'owner', deviceId: item.deviceId, action: item.action, parameters: item.parameters,
        origin: 'routine', immediateOnly: true });
    } catch (error) {
      return finish(item, run, 'not_executed', typeof error?.code === 'string' ? error.code : 'EXECUTION_FAILED');
    }
    if (result?.status === 'simulated_applied' && result.replayed !== true) {
      run.receiptId = typeof result.commandId === 'string' ? result.commandId.slice(0, 12) : null;
      return finish(item, run, 'confirmed', null);
    }
    if (result?.status === 'denied' || result?.status === 'not_applied') return finish(item, run, 'not_executed', result.code ?? 'NOT_APPLIED');
    return finish(item, run, 'unknown', 'NO_RECEIPT');
  }
  function finish(item, run, outcome, reason) {
    run.result = outcome; run.reason = reason;
    if (outcome === 'confirmed') emit('routine_done', 'info', item.deviceId, { scheduled: item.time, action: item.action, receipt: run.receiptId });
    else emit('routine_missed', 'alert', item.deviceId, { scheduled: item.time, action: item.action, reason }, { email: true });
    return run;
  }

  function checkRoutine(now) {
    const day = dayKey(now);
    if (day !== currentDay) { currentDay = day; for (const key of runs.keys()) if (!key.startsWith(day)) runs.delete(key); }
    for (const item of routine) {
      const key = `${day}:${item.id}`;
      if (runs.has(key)) continue;
      const due = dueMs(now, item.time);
      if (now < due) continue;
      const run = { runId: key, id: item.id, time: item.time, deviceId: item.deviceId, action: item.action, result: 'pending', reason: null, receiptId: null, retries: 0 };
      runs.set(key, run);
      if (now - due > timing.routineWindowMs) { run.result = 'not_monitored'; continue; }
      runItem(item, run);
    }
  }

  // A cleaning run ends in exactly one report: done (back on the dock, with a receipt), needs help (stuck / battery), or
  // cannot confirm (the gateway was down when it should have reported). Nothing is assumed finished.
  function checkVacuum(now) {
    if (!vacuum) return;
    const minutes = Math.max(1, Math.round((now - vacuum.startedAt) / 60_000));
    if (vacuum.fault) {
      emit('vacuum_stuck', 'alert', 'robot_vacuum', { reason: vacuum.fault, minutes }, { email: true });
      vacuum = null; return;
    }
    if (now < vacuum.dueAt) return;
    if (targets.gateway.state !== 'online' || simulator.getState().edge.online !== true) {
      emit('vacuum_unknown', 'warn', 'robot_vacuum', { reason: 'GATEWAY_OFFLINE', minutes }); vacuum = null; return;
    }
    let result = null;
    try { result = simulator.perform({ actor: 'owner', deviceId: 'robot_vacuum', action: 'dock', origin: 'routine', immediateOnly: true }); } catch { result = null; }
    if (result?.status === 'simulated_applied') emit('vacuum_done', 'info', 'robot_vacuum', { minutes, receipt: typeof result.commandId === 'string' ? result.commandId.slice(0, 12) : null });
    else emit('vacuum_unknown', 'warn', 'robot_vacuum', { reason: result?.code ?? 'NO_RECEIPT', minutes });
    vacuum = null;
  }

  function tick() {
    const now = clock();
    checkGateway(now);
    checkCamera(now);
    checkRoutine(now);
    checkVacuum(now);
    void probeRing();
  }

  // A family member chooses to make up a missed run. Same gates; never automatic.
  function retry({ runId }) {
    const run = runs.get(runId);
    if (!run) return { ok: false, code: 'RUN_UNKNOWN' };
    if (!['not_executed', 'unknown'].includes(run.result)) return { ok: false, code: 'RUN_NOT_RETRYABLE' };
    // Refused before anything is spent: a tap during an outage must not use up the family's make-up after recovery.
    if (targets.gateway.state !== 'online' || simulator.getState().edge.online !== true) return { ok: false, code: 'GATEWAY_OFFLINE' };
    if (run.retries >= 3) return { ok: false, code: 'RUN_RETRY_LIMIT' };
    run.retries += 1;
    const item = routine.find((r) => r.id === run.id);
    runItem(item, run);
    return { ok: run.result === 'confirmed', run: { ...run } };
  }
  // Event from the gateway itself (reconnect / disconnect), so a short up-time is never missed between ticks.
  function noteGateway({ online }) {
    const g = targets.gateway;
    if (online === true) { const now = clock(); g.lastHeartbeatMs = now; g.nextBeatMs = now + timing.gatewayIntervalMs; g.wasUp = true; }
    else g.wasUp = false;
  }
  // Ring's own device_offline / device_online webhook (pulled from the relay): the camera's state changes now, not at the next
  // 5-minute status check. Offline still goes through transition(), so the family gets the same single email.
  function noteRingDevice({ online }) {
    if (typeof online !== 'boolean') return { ok: false, code: 'INVALID_ARGUMENT' };
    const c = targets.camera;
    if (c.source !== 'ring') { c.source = 'ring'; c.ring = 'webhook'; }
    if (online) { c.failures = 0; c.lastHeartbeatMs = clock(); c.lastRealOk = realClock(); }
    else c.failures = Math.max(c.failures, timing.cameraFailures);
    transition('camera', online ? 'online' : 'offline');
    return { ok: true, state: c.state };
  }
  function setSimulatedCamera({ online }) {
    if (typeof online !== 'boolean') return { ok: false, code: 'INVALID_ARGUMENT' };
    targets.camera.simulatedOnline = online;
    return { ok: true, online };
  }

  // Door approval timeline (src/door_requests.mjs). Email only for "someone is asking" and "it was opened".
  const DOOR_KINDS = { requested: ['door_requested', 'warn', true], approved: ['door_approved', 'info', true], denied: ['door_denied', 'info', false],
    expired: ['door_expired', 'info', false], failed: ['door_failed', 'alert', false] };
  function noteDoor(kind, request) {
    const spec = DOOR_KINDS[kind];
    if (!spec) return null;
    return emit(spec[0], spec[1], 'front_door', { requester: request.requester?.name ?? '?', requesterKind: request.requester?.kind ?? null, approver: request.approver ?? null,
      receipt: request.receipt?.receiptId ?? null, reason: request.reason ?? null }, { email: spec[2] });
  }

  function noteDoorbellAgain() { return emit('doorbell_again', 'info', 'front_door', { requesterKind: 'ring' }); }

  // The real home gateway (ESP32-C3 on USB, src/usb_gateway.mjs): every heartbeat line counts, on the real clock.
  function noteUsbGateway({ beat }) {
    if (beat !== true) return { ok: false };
    const g = targets.gateway;
    g.source = 'usb'; g.lastRealBeat = realClock(); g.lastHeartbeatMs = clock();
    transition('gateway', 'online', { source: 'usb' });
    return { ok: true, state: g.state };
  }
  // The parent's button on the gateway: a short press says "I'm OK" (timeline), a long press asks for help (email).
  function noteButton({ press }) {
    if (press === 'long') return emit('parent_help', 'alert', 'home_button', { press }, { email: true });
    if (press === 'short') return emit('parent_ok', 'info', 'home_button', { press });
    return null;
  }
  // An AI agent tried something outside its limits (src/agent_policy.mjs). Nothing ran; the family can see it was asked.
  function noteAgentRefused({ deviceId, action, reason }) {
    return emit('agent_refused', 'info', DEVICE_NAMES[deviceId] ? deviceId : 'front_door', { action: String(action).slice(0, 32), reason: String(reason).slice(0, 40) });
  }
  // A cleaning run started (any origin: family, AI agent, schedule). Only one at a time; the last start wins.
  function noteVacuumStart({ origin }) {
    const now = clock();
    vacuum = { startedAt: now, dueAt: now + timing.vacuumRunMs, origin: String(origin ?? 'unknown').slice(0, 16), fault: null };
    emit('vacuum_started', 'info', 'robot_vacuum', { origin: vacuum.origin });
    return { ok: true };
  }
  // Demo / test only: make the running vacuum report a problem at the next tick.
  function setVacuumFault({ fault }) {
    if (!vacuum) return { ok: false, code: 'VACUUM_NOT_RUNNING' };
    if (!['stuck', 'battery_low'].includes(fault)) return { ok: false, code: 'INVALID_ARGUMENT' };
    vacuum.fault = fault; return { ok: true };
  }

  function status() {
    const now = clock();
    const today = routine.map((item) => {
      const run = runs.get(`${dayKey(now)}:${item.id}`);
      return { runId: `${dayKey(now)}:${item.id}`, time: item.time, deviceId: item.deviceId, action: item.action,
        result: run?.result ?? 'pending', reason: run?.reason ?? null, receiptId: run?.receiptId ?? null };
    });
    const problems = today.filter((r) => r.result === 'not_executed' || r.result === 'unknown').length
      + (targets.gateway.state !== 'online' ? 1 : 0) + (targets.camera.state !== 'online' ? 1 : 0);
    return {
      now: new Date(now).toISOString(), time: hhmm(now), overall: problems === 0 ? 'ok' : 'attention', attention: problems,
      gateway: { state: targets.gateway.state, lastHeartbeat: hhmm(targets.gateway.lastHeartbeatMs), source: targets.gateway.source },
      vacuum: vacuum ? { running: true, startedAt: hhmm(vacuum.startedAt), dueAt: hhmm(vacuum.dueAt), origin: vacuum.origin } : { running: false },
      camera: { state: targets.camera.state, lastHeartbeat: hhmm(targets.camera.lastHeartbeatMs), source: targets.camera.source,
        ring: targets.camera.ring, simulatedOnline: targets.camera.simulatedOnline },
      routine: { today, done: today.filter((r) => r.result === 'confirmed').length, total: today.length },
      events: events.slice(-40).reverse(),
      email: notifier ? notifier.status() : { email: 'disabled' }
    };
  }
  // A new Ring token was just handed over: check the real camera now instead of waiting for the next 5-minute slot.
  function probeRingNow() { targets.camera.nextCheckReal = 0; return probeRing(); }
  return Object.freeze({ tick, status, retry, setSimulatedCamera, noteGateway, noteRingDevice, probeRing, probeRingNow, noteDoor, noteDoorbellAgain,
    noteUsbGateway, noteButton, noteAgentRefused, noteVacuumStart, setVacuumFault });
}
