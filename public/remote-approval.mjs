import { t } from './i18n-map.mjs';
// Remote approval card (admin PHONE only): get a one-time 10-minute link for the family relay page, open it on this phone
// or hand it to a family phone; list and remove enabled phones. The hub re-checks every remote answer with the phone's own key.
const el = id => document.getElementById(id);
const ports = () => globalThis.homeMcpSessionPorts;
const onPhone = () => document.body.dataset.via === 'phone' && ports()?.role?.() === 'admin';
let link = null;

function render(s) {
  const state = el('remote-state');
  if (!s.enabled) { state.textContent = t('remote.off'); state.dataset.state = 'attention'; el('remote-enable').disabled = true; return; }
  el('remote-enable').disabled = false;
  state.textContent = s.phones.length ? t('remote.on', { n: String(s.phones.length) }) : t('remote.none');
  state.dataset.state = s.phones.length ? 'ok' : 'attention';
  const list = el('remote-phones');
  list.replaceChildren(...s.phones.map((p) => {
    const li = document.createElement('li');
    const name = document.createElement('span'); name.textContent = p.name;
    const remove = document.createElement('button');
    remove.type = 'button'; remove.className = 'button small'; remove.textContent = t('remote.remove');
    remove.addEventListener('click', () => { void revoke(p.keyId); });
    li.append(name, remove);
    return li;
  }));
  if (s.lastError) el('remote-result').textContent = t('remote.unreachable');
}
async function poll() {
  if (!onPhone()) return;
  try { render(await ports().request('/api/relay/status')); } catch { /* next poll */ }
}
async function enable() {
  el('remote-enable').disabled = true;
  try {
    const r = await ports().request('/api/relay/enable', 'POST', {});
    link = r.url;
    el('remote-code').textContent = t('remote.code', { code: r.code, min: '10' });
    el('remote-open').href = r.url;
    el('remote-link').hidden = false;
    el('remote-result').textContent = '';
  } catch (error) { el('remote-result').textContent = t('remote.failed', { reason: error.code || 'ERROR' }); }
  finally { el('remote-enable').disabled = false; }
}
async function copy() {
  try { await navigator.clipboard.writeText(link); el('remote-result').textContent = t('remote.copied'); }
  catch { el('remote-result').textContent = t('remote.copyBlocked'); }
}
async function revoke(keyId) {
  try { render(await ports().request('/api/relay/revoke', 'POST', { keyId })); el('remote-result').textContent = t('remote.removed'); }
  catch (error) { el('remote-result').textContent = t('remote.failed', { reason: error.code || 'ERROR' }); }
}

const root = typeof document === 'undefined' ? null : el('remote-approval');
if (root) {
  el('remote-enable').addEventListener('click', () => { void enable(); });
  el('remote-copy').addEventListener('click', () => { void copy(); });
  // the link appears once; after a few minutes on screen it is hidden again (the code itself expires in 10 minutes)
  el('remote-open').addEventListener('click', () => { setTimeout(() => { el('remote-link').hidden = true; link = null; void poll(); }, 15_000); });
  globalThis.addEventListener('home-mcp-session-changed', () => { void poll(); });
  setInterval(() => { void poll(); }, 15_000);
}
