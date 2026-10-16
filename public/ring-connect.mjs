import { t } from './i18n-map.mjs';
// Ring connection card (admins): open the Ring Developer Playground, paste the 30-minute token into a masked field, Connect.
// The value is sent once to the hub (memory only), the field is cleared at once, and it is never shown or read back.
const el = id => document.getElementById(id);
const ports = () => globalThis.homeMcpSessionPorts;
let timer = null;

function render(s) {
  const box = el('ring-connect-state');
  let key = 'ringConnect.none'; let params = {};
  if (s.state === 'expired') key = 'ringConnect.expired';
  else if (s.state === 'offline_mode') key = 'ringConnect.offline';
  else if (s.state === 'live') {
    const min = Math.ceil((Date.parse(s.expiresAtEstimate) - Date.now()) / 60_000);
    key = min > 0 ? 'ringConnect.live' : 'ringConnect.liveOver'; params = { min: String(min) };
  }
  box.textContent = t(key, params);
  box.dataset.state = s.state === 'live' ? 'ok' : 'attention';
  el('ring-connect-clear').disabled = s.state === 'none';
  el('ring-connect-fold').open = s.state !== 'live';   // live: one line; otherwise the 1-2-3 steps are open
}
async function poll() {
  if (ports()?.role?.() !== 'admin') return;
  try { render(await ports().request('/api/ring/token-status')); } catch { /* shown on next poll */ }
}
function schedule() { clearTimeout(timer); if (ports()?.role?.() !== 'admin') return; timer = setTimeout(async () => { await poll(); schedule(); }, 15_000); }

async function connect(event) {
  event.preventDefault();
  const field = el('ring-connect-token');
  const token = field.value;
  field.value = '';                      // cleared before anything else happens
  if (!token.trim()) return;
  el('ring-connect-save').disabled = true;
  try { render(await ports().request('/api/ring/token', 'POST', { token })); el('ring-connect-result').textContent = t('ringConnect.saved'); }
  catch (error) { el('ring-connect-result').textContent = error instanceof TypeError ? t('ringConnect.unreachable') : t('ringConnect.failed', { reason: error.code || 'ERROR' }); }
  finally { el('ring-connect-save').disabled = false; }
}
// One tap instead of long-press: the browser reads the clipboard into the hidden field (on the user's tap; nothing displayed).
async function pasteFromClipboard() {
  try {
    const text = await navigator.clipboard.readText();
    el('ring-connect-token').value = text.trim();
    el('ring-connect-result').textContent = t('ringConnect.pasted');
  } catch { el('ring-connect-result').textContent = t('ringConnect.pasteBlocked'); el('ring-connect-token').focus(); }
}
async function disconnect() {
  try { render(await ports().request('/api/ring/token-clear', 'POST', {})); el('ring-connect-result').textContent = t('ringConnect.cleared'); }
  catch (error) { el('ring-connect-result').textContent = t('ringConnect.failed', { reason: error.code || 'ERROR' }); }
}

const root = typeof document === 'undefined' ? null : el('ring-connect');
if (root) {
  el('ring-connect-form').addEventListener('submit', connect);
  el('ring-connect-clear').addEventListener('click', () => { void disconnect(); });
  el('ring-connect-paste').addEventListener('click', () => { void pasteFromClipboard(); });
  globalThis.addEventListener('home-mcp-session-changed', () => { void poll().then(schedule); });
}
