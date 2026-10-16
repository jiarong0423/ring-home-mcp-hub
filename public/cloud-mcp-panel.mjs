import { t } from './i18n-map.mjs';
// Cloud MCP (AWS) panel. Browser side holds no cloud secret: it never receives tokens, codes, the Mac key
// passphrase or account ids. The Cognito URL is shown as a link only (never opened automatically).
// All visible text comes from the mapping table (public/i18n-map.mjs); this module only picks keys.
const KEY_STATES = new Set(['ready', 'passphrase_missing', 'key_unlock_failed', 'key_identity_mismatch', 'identity_missing', 'state_dir_missing', 'state_dir_invalid']);
const ERROR_CODES = new Set(['AUTH_REQUIRED', 'SESSION_EXPIRED', 'CLOUD_PANEL_DISABLED', 'RING_OPERATOR_UNAVAILABLE', 'RING_OPERATOR_DENIED',
  'RING_OPERATOR_RATE_LIMIT', 'CLOUD_INTENT_REQUIRED', 'CLOUD_MCP_BUSY', 'MAC_KEY_NOT_READY', 'CALLBACK_URL_INVALID', 'CALLBACK_STATE_MISMATCH',
  'LOGIN_NOT_PENDING', 'LOGIN_EXPIRED', 'CALLBACK_NOT_STAGED', 'CLIPBOARD_UNAVAILABLE', 'CLOUD_AUTHORIZATION_CHANGED',
  'HOME_DEVICE_ACTION_NOT_ALLOWED', 'HOME_DEVICE_UNAVAILABLE']);
// Display list only; the server, the Mac launcher and the cloud each enforce the same allowlist independently.
const DEVICE_ACTIONS = [['living_light', 'on'], ['living_light', 'off'], ['air_conditioner', 'on'], ['air_conditioner', 'off'],
  ['dehumidifier', 'on'], ['dehumidifier', 'off'], ['robot_vacuum', 'start'], ['robot_vacuum', 'pause'], ['robot_vacuum', 'dock'],
  ['camera', 'arm'], ['front_door', 'lock']];
const deviceText = (deviceId, action) => ({ device: t('device.' + deviceId + '.label'), action: t('device.' + deviceId + '.action.' + action) });
const el = id => document.getElementById(id);
const ports = () => globalThis.cloudMcpPanelPorts;
const explain = code => ERROR_CODES.has(code) ? t('cloud.err.' + code) : (code?.startsWith?.('CALLBACK_LOGIN_ERROR') ? t('cloud.err.loginError') : t('cloud.err.other', { code: code || 'UNKNOWN' }));
// Server step lines arrive as stable codes { key: 'cloud.step.*', params } and are rendered through the table.
const STEP_PARAM = /^[A-Za-z0-9_.…-]{0,40}$/u;
function stepText(msg) {
  const key = typeof msg?.key === 'string' && /^cloud\.step\.[A-Za-z]{1,32}$/u.test(msg.key) ? msg.key : 'cloud.step.redacted';
  const params = {};
  if (msg?.params && typeof msg.params === 'object') {
    for (const [name, value] of Object.entries(msg.params)) if (/^[a-zA-Z]{1,16}$/u.test(name) && STEP_PARAM.test(String(value))) params[name] = String(value);
  }
  return t(key, params);
}
let busy = false;

function headers({ intent, operator, json }) {
  const h = { Accept: 'application/json' };
  const auth = ports()?.authorization?.();
  if (auth) h.Authorization = auth;
  if (intent) h['X-Cloud-MCP-Intent'] = intent;
  if (operator) h['X-Ring-Operator-Passcode'] = operator;
  if (json) h['Content-Type'] = 'application/json';
  return h;
}
async function api(path, { method = 'GET', intent, operator, body } = {}) {
  const response = await fetch(path, { method, headers: headers({ intent, operator, json: body !== undefined }),
    body: body === undefined ? undefined : JSON.stringify(body), credentials: 'same-origin', cache: 'no-store' });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    if (response.status === 401) ports()?.unauthorized?.();
    const error = new Error('HTTP ' + response.status); error.code = data.error || 'HTTP_' + response.status; throw error;
  }
  return response;
}
function takeOperator() {
  const field = el('cloud-operator-passcode');
  const value = field.value; field.value = '';
  return value;
}
function setBusy(value) {
  busy = value;
  for (const id of ['cloud-login', 'cloud-refresh', 'cloud-callback-submit', 'cloud-callback-clipboard', 'cloud-switch-on', 'cloud-switch-off', 'cloud-device-run', 'cloud-listen-run']) el(id).disabled = value;
}
async function guarded(fn) {
  if (busy) return;
  setBusy(true);
  try { await fn(); } finally { setBusy(false); }
}
function fmt(iso) { const d = new Date(iso); return Number.isNaN(d.getTime()) ? '—' : d.toLocaleTimeString(t('locale'), { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0'); }

async function refreshStatus() {
  if (!ports()?.authorization?.()) { el('cloud-mcp-status').textContent = t('cloud.err.AUTH_REQUIRED'); return; }
  try {
    const s = await (await api('/api/cloud-mcp/status')).json();
    const parts = [(KEY_STATES.has(s.key) ? t('cloud.key.' + s.key) : t('cloud.key.other', { key: s.key })) + (s.passphraseSource === 'env-test' ? t('cloud.key.testSource') : ''), t('cloud.status.mode')];
    parts.push(s.login?.pending ? t('cloud.status.loginPending', { at: fmt(s.login.expiresAt) }) : t('cloud.status.loginIdle'));
    parts.push(s.cloudSession?.active ? t('cloud.status.sessionActive', { at: fmt(s.cloudSession.expiresAt) })
      : s.callbackStaged ? t('cloud.status.callbackStaged') : t('cloud.status.callbackNone'));
    if (s.lastRun) parts.push(t('cloud.status.lastRun', { at: fmt(s.lastRun.at), result: s.lastRun.ok ? t('cloud.status.lastRunOk') : t('cloud.status.lastRunFail') }));
    el('cloud-mcp-status').textContent = parts.join(t('cloud.status.separator')) + t('cloud.status.end');
  } catch (error) { el('cloud-mcp-status').textContent = t('cloud.status.error', { reason: explain(error.code) }); }
}

async function login() {
  const operator = takeOperator();
  if (!operator) { el('cloud-login-output').textContent = t('cloud.needOperator'); return; }
  el('cloud-login-output').textContent = t('cloud.login.generating');
  try {
    const r = await (await api('/api/cloud-mcp/login-url', { method: 'POST', intent: 'login-url', operator })).json();
    const u = new URL(r.authorizeUrl);
    if (u.protocol !== 'https:' || !u.hostname.endsWith('.amazoncognito.com') || u.pathname !== '/oauth2/authorize') throw Object.assign(new Error('bad'), { code: 'LOGIN_URL_UNEXPECTED' });
    const out = el('cloud-login-output'); out.textContent = '';
    const a = document.createElement('a');
    a.href = u.href; a.target = '_blank'; a.rel = 'noopener noreferrer';
    a.textContent = t('cloud.login.link', { host: u.hostname });
    out.append(a, document.createTextNode(t('cloud.login.after', { at: fmt(r.expiresAt) })));
    el('cloud-callback-status').textContent = t('cloud.callback.initial');
    el('cloud-callback-fold').open = true;   // the next step is the callback; reveal it only now
  } catch (error) { el('cloud-login-output').textContent = t('cloud.login.failed', { reason: explain(error.code) }); }
  await refreshStatus();
}

async function stage(source) {
  const field = el('cloud-callback-url');
  const value = field.value; field.value = '';
  if (source === 'paste' && !value) { el('cloud-callback-status').textContent = t('cloud.callback.pasteFirst'); return; }
  try {
    const r = source === 'paste'
      ? await (await api('/api/cloud-mcp/callback', { method: 'POST', intent: 'callback', body: { callbackUrl: value } })).json()
      : await (await api('/api/cloud-mcp/callback-clipboard', { method: 'POST', intent: 'callback-clipboard' })).json();
    el('cloud-callback-status').textContent = t('cloud.callback.accepted', { source: r.source === 'clipboard' ? t('cloud.callback.sourceClipboard') : t('cloud.callback.sourcePaste'), at: fmt(r.expiresAt) });
  } catch (error) { el('cloud-callback-status').textContent = t('cloud.callback.rejected', { reason: explain(error.code) }); }
  await refreshStatus();
}

function addStep(at, text) {
  const li = document.createElement('li');
  const t = document.createElement('time'); t.dateTime = at; t.textContent = fmt(at);
  const span = document.createElement('span'); span.textContent = text;
  li.append(t, span); el('cloud-mcp-steps').append(li);
}

// Shared NDJSON stream reader for one cloud job; `render` turns the final result into the result line.
// The operator code is asked once per cloud login (login-url); actions reuse that login until it expires.
async function runJob({ path, intent, body, running, render }) {
  const result = el('cloud-mcp-result');
  el('cloud-mcp-steps').replaceChildren(); result.removeAttribute('data-ok');
  result.textContent = running;
  try {
    const response = await api(path, { method: 'POST', intent, body });
    const reader = response.body.getReader(); const decoder = new TextDecoder(); let buffer = ''; let final = null;
    for (;;) {
      const { value, done } = await reader.read();
      buffer += decoder.decode(value ?? new Uint8Array(), { stream: !done });
      let index;
      while ((index = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, index); buffer = buffer.slice(index + 1);
        if (!line) continue;
        const msg = JSON.parse(line);
        if (msg.type === 'step') addStep(msg.at, stepText(msg)); else final = msg;
      }
      if (done) break;
    }
    if (final?.type === 'result') {
      addStep(final.at, t('cloud.step.workerSummary', { status: final.worker.status, executed: final.worker.executed, mode: final.mode }));
      result.dataset.ok = String(final.ok);
      result.textContent = render(final, final.ok ? t('cloud.result.done') : t('cloud.result.notDone'));
    } else {
      result.dataset.ok = 'false';
      result.textContent = t('cloud.result.streamFailed', { code: final?.code || 'STREAM_ENDED' });
    }
  } catch (error) { result.dataset.ok = 'false'; result.textContent = t('cloud.result.notRun', { reason: explain(error.code) }); }
  await refreshStatus();
}
function runSwitch(enabled) {
  return runJob({ path: '/api/cloud-mcp/switch', intent: 'switch', body: { enabled }, running: t(enabled ? 'cloud.switch.runningOn' : 'cloud.switch.runningOff'),
    render: (final, verdict) => { const r = final.result;
      return t('cloud.result.line', { verdict, status: r.status, executed: r.executed, enabled: r.enabled, revision: r.revision, commandId: final.set.commandId, mode: final.mode }); } });
}
function runDevice() {
  const choice = DEVICE_ACTIONS[Number(el('cloud-device-command').value)];
  if (!choice) return Promise.resolve();
  const [deviceId, action] = choice; const names = deviceText(deviceId, action);
  return runJob({ path: '/api/cloud-mcp/device', intent: 'device', body: { deviceId, action }, running: t('cloud.device.running', names),
    render: (final, verdict) => { const r = final.result;
      return t('cloud.result.deviceLine', { verdict, status: r.status, executed: r.executed, device: r.deviceId ?? '—', action: r.action ?? '—',
        deviceStatus: r.deviceStatus ?? '—', commandId: final.set.commandId, mode: final.mode }) + (final.ok ? '' : t('cloud.result.deviceHint')); } });
}
// Waits for one command sent by an external MCP client (AI agent via the bridge); the result names what was applied.
function runListen() {
  return runJob({ path: '/api/cloud-mcp/listen', intent: 'listen', body: {}, running: t('cloud.listen.running'),
    render: (final, verdict) => { const r = final.result;
      if (final.worker.status === 'EMPTY') return t('cloud.result.listenEmpty');
      return t('cloud.result.deviceLine', { verdict, status: r.status, executed: r.executed, device: r.deviceId ?? '—', action: r.action ?? '—',
        deviceStatus: r.deviceStatus ?? '—', commandId: final.set.commandId ?? '—', mode: final.mode }) + (final.ok ? '' : t('cloud.result.deviceHint')); } });
}
function fillDeviceOptions() {
  const select = el('cloud-device-command');
  select.replaceChildren(...DEVICE_ACTIONS.map(([deviceId, action], index) => {
    const option = document.createElement('option'); option.value = String(index);
    option.textContent = t('cloud.device.option', deviceText(deviceId, action)); return option;
  }));
}

const root = typeof document === 'undefined' ? null : document.querySelector('[data-cloud-mcp-root]');
if (root) {
  el('cloud-login').addEventListener('click', () => guarded(login));
  el('cloud-refresh').addEventListener('click', () => guarded(refreshStatus));
  el('cloud-callback-submit').addEventListener('click', () => guarded(() => stage('paste')));
  el('cloud-callback-clipboard').addEventListener('click', () => guarded(() => stage('clipboard')));
  el('cloud-switch-on').addEventListener('click', () => guarded(() => runSwitch(true)));
  el('cloud-switch-off').addEventListener('click', () => guarded(() => runSwitch(false)));
  fillDeviceOptions();
  el('cloud-device-run').addEventListener('click', () => guarded(runDevice));
  el('cloud-listen-run').addEventListener('click', () => guarded(runListen));
  globalThis.addEventListener?.('wifi-permission-session-refresh', () => { void refreshStatus(); });
}
