import { t } from './i18n-map.mjs';
// Phone pairing UI. The phone keeps ONE long-lived device credential in localStorage and only ever trades it for a one-hour
// console session (the server rotates it on every trade). Pairing needs a one-time code AND the owner's "y" on the Mac terminal.
// All visible text comes from the mapping table (public/i18n-map.mjs).
const KEY = 'home-mcp-device-token';
const el = id => document.getElementById(id);
const ports = () => globalThis.homeMcpSessionPorts;
const store = {
  get() { try { return localStorage.getItem(KEY); } catch { return null; } },
  set(value) { try { localStorage.setItem(KEY, value); } catch { /* private mode: pairing still works for this tab */ } },
  clear() { try { localStorage.removeItem(KEY); } catch { /* ignore */ } }
};
const say = (id, key, params) => { el(id).textContent = t(key, params); };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
// Trusted phones stay signed in: the one-hour session is renewed in the background 5 minutes before it ends, and if it is
// lost anyway (server restart, sleep) the page opens again on its own from the stored credential.
let renewTimer = null;
let lastAutoOpen = 0;
let manualLogout = false;   // set by the Log out button; cleared on the next deliberate open
function scheduleRenew(expiresAt) {
  clearTimeout(renewTimer);
  const at = Date.parse(expiresAt);
  if (!Number.isFinite(at)) return;
  renewTimer = setTimeout(() => { void withTokenLock(renewLocked); }, Math.max(30_000, at - Date.now() - 5 * 60_000));
}
async function renewLocked() {
  const deviceToken = store.get();
  if (!deviceToken || !ports()?.role?.()) return;
  const r = await post('/api/phones/session', { deviceToken }).catch(() => null);
  if (!r) { scheduleRenew(new Date(Date.now() + 6 * 60_000).toISOString()); return; }   // offline: try again shortly
  if (!r.ok) { if (r.status === 401) store.clear(); return; }
  store.set(r.data.deviceToken);
  ports().renew(r.data.token);
  scheduleRenew(r.data.expiresAt);
}
async function post(path, body) {
  const response = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body), credentials: 'same-origin', cache: 'no-store' });
  const data = await response.json().catch(() => ({}));
  return { ok: response.ok, status: response.status, data };
}

// The server revokes a phone if a rotated-out credential is ever presented again, so every exchange on this phone runs under
// one browser lock and reads the stored credential inside it: a second tab then sees the already-rotated one.
function withTokenLock(run) {
  return navigator.locks?.request ? navigator.locks.request('home-mcp-device-token', run) : run();
}
// Door approval (public/door.mjs) proves this phone with its credential. Same lock; the rotated credential replaces the stored
// one whenever the server hands one back (also on a refusal); a revoked or unknown credential is dropped.
export function withDeviceCredential(run) {
  return withTokenLock(async () => {
    const deviceToken = store.get();
    if (!deviceToken) return { ok: false, status: 0, data: { error: 'NO_DEVICE_CREDENTIAL' } };
    const r = await run(deviceToken);
    if (typeof r?.data?.deviceToken === 'string') store.set(r.data.deviceToken);
    else if (['DEVICE_REVOKED', 'DEVICE_TOKEN_INVALID'].includes(r?.data?.error)) { store.clear(); renderUnlock(); }
    return r;
  });
}
function unlock() { return withTokenLock(unlockLocked); }
async function unlockLocked() {
  const deviceToken = store.get();
  if (!deviceToken) return false;
  say('phone-pair-status', 'phone.unlock.working');
  const r = await post('/api/phones/session', { deviceToken });
  if (!r.ok) {
    if (r.status === 401) store.clear();
    say('phone-pair-status', 'phone.unlock.failed', { reason: r.data.error || 'HTTP_' + r.status });
    renderUnlock();
    return false;
  }
  store.set(r.data.deviceToken);
  el('phone-pair-status').textContent = '';
  await ports().accept(r.data.token, { role: r.data.role, name: r.data.name });
  scheduleRenew(r.data.expiresAt);
  return true;
}

async function pair(event) {
  event.preventDefault();
  const code = el('phone-pair-code').value.replace(/[\s-]/gu, '');
  const name = el('phone-pair-name').value;
  const submit = el('phone-pair-submit'); submit.disabled = true;
  try {
    const r = await post('/api/phones/pair-request', { code, name });
    el('phone-pair-code').value = '';
    if (!r.ok) { say('phone-pair-status', 'phone.pair.failed', { reason: r.data.error || 'HTTP_' + r.status }); return; }
    // Tell the person exactly where to press, with the same two check digits the approver sees, and the time left.
    const waitKey = r.data.approver === 'mac' ? 'phone.pair.waitMac' : 'phone.pair.waitAdmin';
    say('phone-pair-status', waitKey, { check: r.data.check ?? '--', seconds: '120' });
    const until = Date.now() + 130_000;
    while (Date.now() < until) {
      await sleep(2000);
      const s = await post('/api/phones/pair-status', { requestId: r.data.requestId });
      if (s.ok && s.data.status === 'pending') { say('phone-pair-status', waitKey, { check: s.data.check ?? '--', seconds: String(s.data.secondsLeft ?? '') }); continue; }
      if (s.ok && s.data.status === 'approved') {
        store.set(s.data.deviceToken);
        say('phone-pair-status', 'phone.pair.approved');
        await unlock();
        return;
      }
      say('phone-pair-status', s.status === 403 ? 'phone.pair.rejected' : s.status === 410 ? 'phone.pair.timeout' : 'phone.pair.failed',
        { reason: s.data.error || 'HTTP_' + s.status });
      return;
    }
    say('phone-pair-status', 'phone.pair.timeout');
  } catch { say('phone-pair-status', 'phone.pair.failed', { reason: 'NETWORK' }); }
  finally { submit.disabled = false; }
}

function renderUnlock() { el('phone-unlock').hidden = !store.get(); }

// ---- Admin: family phones ----
async function addCode(role) {
  const out = el('phones-code');
  try {
    const r = await ports().request('/api/phones/pair-code', 'POST', { role });
    out.textContent = t('phones.code', { code: r.code.slice(0, 4) + ' ' + r.code.slice(4),
      role: t(role === 'admin' ? 'phones.roleAdmin' : 'phones.roleMember'), at: new Date(r.expiresAt).toLocaleTimeString(t('locale'), { hour12: false }) });
  } catch (error) { out.textContent = t('phones.failed', { reason: error.code || 'ERROR' }); }
}
async function renderPhones() {
  const list = el('phones-list');
  if (ports()?.role?.() !== 'admin') { list.replaceChildren(); return; }
  try {
    const { phones } = await ports().request('/api/phones', 'GET');
    const rows = phones.filter(p => p.active).map(p => {
      const li = document.createElement('li');
      const span = document.createElement('span');
      span.textContent = t('phones.item', { name: p.name, role: t(p.role === 'admin' ? 'phones.roleAdmin' : 'phones.roleMember'),
        at: new Date(p.lastUsedAt).toLocaleDateString(t('locale')) });
      const button = document.createElement('button');
      button.type = 'button'; button.className = 'button small'; button.textContent = t('phones.revoke');
      button.addEventListener('click', async () => {
        try { await ports().request('/api/phones/revoke', 'POST', { deviceId: p.deviceId }); el('phones-code').textContent = t('phones.revoked', { name: p.name }); }
        catch (error) { el('phones-code').textContent = t('phones.failed', { reason: error.code || 'ERROR' }); }
        await renderPhones();
      });
      li.append(span, button); return li;
    });
    if (!rows.length) { const li = document.createElement('li'); li.textContent = t('phones.empty'); rows.push(li); }
    list.replaceChildren(...rows);
  } catch (error) { el('phones-code').textContent = t('phones.failed', { reason: error.code || 'ERROR' }); }
}

// ---- Admin phone: approve a family phone (no computer needed). Checked every 3 s while this admin phone is open. ----
let pairTimer = null; let pairAdminPhone = true; let pairShown = null;
async function pollPairRequests() {
  if (ports()?.role?.() !== 'admin' || !pairAdminPhone) { el('pair-banner').hidden = true; return; }
  try {
    const { pending } = await ports().request('/api/phones/pending');
    const p = pending[0];
    if (!p) { el('pair-banner').hidden = true; pairShown = null; return; }
    if (pairShown !== p.approvalId) { pairShown = p.approvalId; el('pair-allow').disabled = false; el('pair-deny').disabled = false; }
    el('pair-banner-text').textContent = t('pairReq.title', { name: p.name, check: p.check, seconds: String(p.secondsLeft) });
    el('pair-banner').hidden = false;
  } catch (error) { if (error?.code === 'ADMIN_PHONE_REQUIRED') { pairAdminPhone = false; el('pair-banner').hidden = true; } }
}
function schedulePairPoll() {
  clearTimeout(pairTimer);
  if (ports()?.role?.() !== 'admin' || !pairAdminPhone) return;
  pairTimer = setTimeout(async () => { await pollPairRequests(); schedulePairPoll(); }, 3000);
}
async function decidePair(decision) {
  const approvalId = pairShown;
  if (!approvalId) return;
  el('pair-allow').disabled = true; el('pair-deny').disabled = true;
  try {
    const r = await withDeviceCredential((deviceToken) => ports().call('/api/phones/decide', { approvalId, decision, deviceToken }));
    el('pair-result').textContent = r.ok ? t(decision === 'approve' ? 'pairReq.allowed' : 'pairReq.denied', { name: r.data.name })
      : t('pairReq.failed', { reason: r.data.error || 'HTTP_' + r.status });
  } catch { el('pair-result').textContent = t('pairReq.failed', { reason: 'NETWORK' }); }
  finally { el('pair-banner').hidden = true; pairShown = null; await renderPhones(); }
}

const root = typeof document === 'undefined' ? null : el('phone-pair-form');
if (root) {
  root.addEventListener('submit', pair);
  el('phone-unlock').addEventListener('click', () => { manualLogout = false; void unlock(); });
  globalThis.addEventListener('home-mcp-manual-logout', () => { manualLogout = true; clearTimeout(renewTimer); });
  el('phones-add-member').addEventListener('click', () => { void addCode('member'); });
  el('phones-add-admin').addEventListener('click', () => { void addCode('admin'); });
  el('phones-refresh').addEventListener('click', () => { void renderPhones(); });
  el('pair-allow').addEventListener('click', () => { void decidePair('approve'); });
  el('pair-deny').addEventListener('click', () => { void decidePair('deny'); });
  globalThis.addEventListener('home-mcp-session-changed', () => { pairAdminPhone = true; void pollPairRequests().then(schedulePairPoll); });
  globalThis.addEventListener('home-mcp-session-changed', () => {
    renderUnlock(); void renderPhones();
    // Session gone but this phone is still trusted: open again by itself (at most once every 10 s, so no loop).
    if (!manualLogout && !ports()?.role?.() && store.get() && Date.now() - lastAutoOpen > 10_000) { lastAutoOpen = Date.now(); clearTimeout(renewTimer); void unlock(); }
  });
  renderUnlock();
  void unlock();
}
