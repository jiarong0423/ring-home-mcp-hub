import { t } from './i18n-map.mjs';
// Guardian overview for family phones: one big line ("all normal" / "N things need attention"), camera, gateway and today's
// routine, a timeline of state changes, and a retry button for a missed run. It also notices when the hub itself stops
// answering (three failed polls in a row), because a dead hub cannot send anything. Text comes from public/i18n-map.mjs.
const el = id => document.getElementById(id);
const ports = () => globalThis.homeMcpSessionPorts;
const STATES = new Set(['online', 'late', 'offline']);
const RESULTS = new Set(['pending', 'confirmed', 'not_executed', 'unknown', 'not_monitored']);
let failures = 0;
let timer = null;
let speed = 1;

const deviceName = id => (['camera', 'gateway', 'home_button'].includes(id) ? t('guardian.target.' + id) : t('device.' + id + '.label'));
const actionName = (id, action) => t('device.' + id + '.action.' + action);
const item = (text, className) => { const li = document.createElement('li'); if (className) li.className = className; li.textContent = text; return li; };

function eventText(e) {
  const p = e.params ?? {};
  const asker = ['mcp', 'console', 'ring'].includes(p.requesterKind) ? t('door.via.' + p.requesterKind) : (p.requester ?? '?');
  const target = deviceName(e.target);
  switch (e.kind) {
    case 'offline': return t('guardian.event.offline', { target, last: p.lastHeartbeat ?? '—' });
    case 'heartbeat_late': return t('guardian.event.late', { target, last: p.lastHeartbeat ?? '—' });
    case 'recovered': return t('guardian.event.recovered', { target });
    case 'heartbeat_ok': return t('guardian.event.ok', { target });
    case 'routine_done': return t('guardian.event.routineDone', { at: p.scheduled, target, action: actionName(e.target, p.action) });
    case 'routine_missed': return t('guardian.event.routineMissed', { at: p.scheduled, target, action: actionName(e.target, p.action), reason: p.reason ?? '' });
    case 'ring_live': return t('guardian.event.ringLive');
    case 'ring_token': return t('guardian.event.ringToken');
    case 'door_requested': return t('guardian.event.doorRequested', { who: asker });
    case 'door_approved': return t('guardian.event.doorApproved', { who: asker, by: p.approver ?? '?', receipt: p.receipt ?? '—' });
    case 'door_denied': return t('guardian.event.doorDenied', { who: asker, by: p.approver ?? '?' });
    case 'door_expired': return t('guardian.event.doorExpired', { who: asker });
    case 'door_failed': return t('guardian.event.doorFailed', { reason: p.reason ?? '—' });
    case 'doorbell_again': return t('guardian.event.doorbellAgain');
    case 'parent_ok': return t('guardian.event.parentOk');
    case 'parent_help': return t('guardian.event.parentHelp');
    case 'vacuum_started': return t('guardian.event.vacuumStarted', { origin: p.origin ?? '—' });
    case 'vacuum_done': return t('guardian.event.vacuumDone', { minutes: p.minutes ?? '—', receipt: p.receipt ?? '—' });
    case 'vacuum_stuck': return t('guardian.event.vacuumStuck', { reason: p.reason ?? '—', minutes: p.minutes ?? '—' });
    case 'vacuum_unknown': return t('guardian.event.vacuumUnknown', { reason: p.reason ?? '—' });
    case 'agent_refused': return t('guardian.event.agentRefused', { target, action: actionName(e.target, p.action), reason: p.reason ?? '—' });
    default: return e.kind;
  }
}

function render(s) {
  speed = s.clock?.speed ?? 1;
  el('guardian-overall').dataset.state = s.overall;
  el('guardian-overall').textContent = s.overall === 'ok' ? t('guardian.allGood') : (s.attention === 1 ? t('guardian.attentionOne') : t('guardian.attention', { n: String(s.attention) }));
  el('guardian-clock').textContent = t(speed > 1 ? 'guardian.clockFast' : 'guardian.clock', { time: s.time, speed: String(speed) });
  const cam = STATES.has(s.camera.state) ? s.camera.state : 'offline';
  el('guardian-camera').textContent = t('guardian.state.' + cam);
  el('guardian-camera-note').textContent = t(s.camera.source === 'ring' ? 'guardian.cameraRing' : 'guardian.cameraSim', { last: s.camera.lastHeartbeat });
  const gw = STATES.has(s.gateway.state) ? s.gateway.state : 'offline';
  el('guardian-gateway').textContent = t('guardian.state.' + gw);
  el('guardian-gateway-note').textContent = t(s.gateway.source === 'usb' ? 'guardian.gatewayNoteUsb' : 'guardian.gatewayNote', { last: s.gateway.lastHeartbeat });
  el('guardian-routine').textContent = `${s.routine.done}/${s.routine.total}`;
  el('guardian-email').textContent = t('guardian.email.' + (['enabled', 'disabled', 'error', 'misconfigured'].includes(s.email?.email) ? s.email.email : 'disabled'));
  el('guardian-today').replaceChildren(...s.routine.today.map(r => {
    const result = RESULTS.has(r.result) ? r.result : 'unknown';
    const li = item(`${r.time}  ${deviceName(r.deviceId)} ${actionName(r.deviceId, r.action)} — ${t('guardian.result.' + result)}${r.reason ? ' (' + r.reason + ')' : ''}`, 'guardian-run');
    li.dataset.result = result;
    if (result === 'not_executed' || result === 'unknown') {
      const b = document.createElement('button'); b.type = 'button'; b.className = 'button small'; b.textContent = t('guardian.retry');
      b.addEventListener('click', async () => {
        b.disabled = true;
        try { await ports().request('/api/guardian/retry', 'POST', { runId: r.runId }); } catch (error) { el('guardian-email').textContent = t('guardian.retryFailed', { reason: error.code || 'ERROR' }); }
        await poll();
      });
      li.append(' ', b);
    }
    return li;
  }));
  el('guardian-events').replaceChildren(...(s.events.length ? s.events.slice(0, 20).map(e => {
    const li = item(`${e.time}  ${eventText(e)}`); li.dataset.severity = e.severity; return li;
  }) : [item(t('guardian.noEvents'))]));
}

async function poll() {
  if (!ports()?.role?.()) return;
  try {
    render(await ports().request('/api/guardian/status'));
    failures = 0;
  } catch (error) {
    if (error?.code === 'GUARDIAN_DISABLED') { el('guardian-panel').hidden = true; return; }
    failures += 1;
    if (failures >= 3) { el('guardian-overall').dataset.state = 'attention'; el('guardian-overall').textContent = t('guardian.hubUnreachable'); }
  }
}
function schedule() {
  clearTimeout(timer);
  if (!ports()?.role?.()) return;
  timer = setTimeout(async () => { await poll(); schedule(); }, speed > 1 ? 3000 : 30000);
}
// Daily care note on demand (admins): the hub writes it from today's log (Amazon Bedrock when configured, else a template)
// and emails it; the page shows the text and where it came from.
async function careNote() {
  const btn = el('guardian-care-note'); btn.disabled = true;
  el('guardian-care-note-source').textContent = t('careNote.writing');
  try {
    const r = await ports().request('/api/guardian/summary', 'POST', {});
    const box = el('guardian-care-note-text'); box.textContent = r.text; box.hidden = false;
    el('guardian-care-note-source').textContent = t(r.source === 'bedrock' ? 'careNote.fromBedrock' : 'careNote.fromTemplate', { reason: r.reason ?? '—' })
      + ' ' + t(r.emailed ? 'careNote.emailed' : 'careNote.notEmailed');
  } catch (error) { el('guardian-care-note-source').textContent = t('guardian.retryFailed', { reason: error.code || 'ERROR' }); }
  finally { btn.disabled = false; }
}
async function admin(path, body) {
  try { await ports().request(path, 'POST', body); } catch (error) { el('guardian-email').textContent = t('guardian.retryFailed', { reason: error.code || 'ERROR' }); }
  await poll();
}

const root = typeof document === 'undefined' ? null : el('guardian-panel');
if (root) {
  el('guardian-camera-off').addEventListener('click', () => admin('/api/guardian/camera', { online: false }));
  el('guardian-camera-on').addEventListener('click', () => admin('/api/guardian/camera', { online: true }));
  el('guardian-gateway-off').addEventListener('click', () => admin('/api/edge/online', { online: false }));
  el('guardian-gateway-on').addEventListener('click', () => admin('/api/edge/online', { online: true }));
  el('guardian-doorbell').addEventListener('click', () => admin('/api/door/doorbell-demo', {}));
  el('guardian-vacuum-stuck').addEventListener('click', () => admin('/api/guardian/vacuum-fault', { fault: 'stuck' }));
  el('guardian-care-note').addEventListener('click', () => { void careNote(); });
  globalThis.addEventListener('home-mcp-session-changed', () => { failures = 0; void poll().then(schedule); });
  globalThis.addEventListener('home-mcp-door-decided', () => { void poll(); });
}
