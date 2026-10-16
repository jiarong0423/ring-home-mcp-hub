import { t } from './i18n-map.mjs';
import { withDeviceCredential } from './phone-pair.mjs';
// Door approval on the phone. The admin PHONE gets a banner (checked every 2 s) with the Ring door snapshot and Approve / Deny;
// deciding sends this phone's long-lived credential (src/door_requests.mjs + /api/door/decide), so a session token alone, e.g.
// one an AI agent holds, can never approve. Whoever asked follows their own request in one status line. Text: i18n-map.mjs.
const el = id => document.getElementById(id);
const ports = () => globalThis.homeMcpSessionPorts;
let pendingTimer = null;
let adminPhone = true;          // false once the server says this admin session is not a phone (desktop passcode)
let shown = null;               // requestId currently on the banner
let snapshotUrl = null;
let snapshotSource = null;
let deciding = false;

let mineTimer = null;
function mine(text, { keep = false } = {}) {   // an answered line is cleared after 20 s so an old result never lingers
  clearTimeout(mineTimer); el('door-mine').textContent = text;
  if (!keep && text) mineTimer = setTimeout(() => { el('door-mine').textContent = ''; }, 20_000);
}
function who(r) { return r.requester.kind === 'phone' ? r.requester.name : t('door.via.' + r.requester.kind); }
function clearSnapshot() {
  if (snapshotUrl) URL.revokeObjectURL(snapshotUrl);
  snapshotUrl = null; snapshotSource = null;
  el('door-snapshot').hidden = true; el('door-snapshot').removeAttribute('src');
}
function hide() { el('door-banner').hidden = true; shown = null; clearSnapshot(); void stopLive(); }

// Ring live view (WHEP, same offer as Ring's official sample): this browser makes the offer, the hub adds the Ring token and
// returns Ring's answer. Receive only: no microphone is opened. Ends when the request ends, on Stop, or at Ring's time limit.
let live = null;   // { pc, sessionId, timer }
async function stopLive() {
  const l = live; live = null;
  if (!l) return;
  clearTimeout(l.timer); l.pc.close();
  const v = el('door-live'); v.srcObject = null; v.hidden = true;
  el('door-live-toggle').textContent = t('door.liveStart');
  if (l.sessionId) await ports().request('/api/door/live-stop', 'POST', { sessionId: l.sessionId }).catch(() => {});
}
async function startLive() {
  if (live) { await stopLive(); el('door-live-note').textContent = ''; return; }
  const note = el('door-live-note'); note.textContent = t('door.liveConnecting');
  const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
  live = { pc, sessionId: null, timer: null };
  pc.addTransceiver('audio', { direction: 'sendrecv' });   // as in Ring's sample; no track is added, so nothing is sent
  pc.addTransceiver('video', { direction: 'recvonly' });
  pc.ontrack = (e) => { const v = el('door-live'); if (e.streams[0] && v.srcObject !== e.streams[0]) { v.srcObject = e.streams[0]; v.hidden = false; note.textContent = t('door.liveOn'); } };
  try {
    await pc.setLocalDescription(await pc.createOffer());
    await new Promise((done) => { if (pc.iceGatheringState === 'complete') return done(); const to = setTimeout(done, 3000);
      pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === 'complete') { clearTimeout(to); done(); } }; });
    const r = await ports().request('/api/door/live', 'POST', { sdp: pc.localDescription.sdp });
    if (live?.pc !== pc) return;   // stopped meanwhile
    live.sessionId = r.sessionId;
    live.timer = setTimeout(() => { void stopLive(); note.textContent = t('door.liveEnded'); }, r.maxSeconds * 1000);
    await pc.setRemoteDescription({ type: 'answer', sdp: r.sdp });
    el('door-live-toggle').textContent = t('door.liveStop');
  } catch (error) {
    if (live?.pc === pc) { live = null; pc.close(); }
    note.textContent = t('door.liveFailed', { reason: error?.code || 'ERROR' });
  }
}

async function loadSnapshot(p) {
  if (!p.snapshot?.ready) { el('door-snapshot-note').textContent = t('door.snapshotLoading'); return; }
  if (snapshotUrl && snapshotSource === p.snapshot.source) return;   // a stand-in is replaced once the Ring image arrives
  const shot = await ports().image('/api/door/snapshot').catch(() => null);
  if (!shot || shown !== p.requestId) return;
  if (snapshotUrl) URL.revokeObjectURL(snapshotUrl);
  snapshotUrl = URL.createObjectURL(shot.blob); snapshotSource = p.snapshot.source;
  const img = el('door-snapshot'); img.src = snapshotUrl; img.alt = t('door.snapshotAlt'); img.hidden = false;
  el('door-snapshot-note').textContent = shot.source === 'ring' ? t('door.snapshotRing')
    : p.snapshot.reason === 'no_recent_image' ? t('door.snapshotNoImage') : t('door.snapshotSim', { reason: p.snapshot.reason ?? '—' });
}
function faceText(h) {
  if (!h || h.state === 'pending') return t('faceHint.pending');
  if (h.state === 'match' || h.state === 'unknown') return h.faces.map(f => (f.match ? t('faceHint.looksLike', { name: f.name, score: f.score.toFixed(2) }) : t('faceHint.notEnrolled'))).join(' · ');
  return t('faceHint.' + (['no_face', 'no_image', 'disabled', 'error'].includes(h.state) ? h.state : 'error'));
}
function render(p) {
  if (!p) { if (!deciding) hide(); return; }
  if (shown !== p.requestId) { clearSnapshot(); void stopLive(); el('door-live-note').textContent = ''; shown = p.requestId; el('door-approve').disabled = false; el('door-deny').disabled = false; }
  el('door-banner').hidden = false;
  el('door-banner-text').textContent = p.requester.kind !== 'ring' ? t('door.pending', { who: who(p), seconds: String(p.secondsLeft) })
    : t(/person/iu.test(p.requester.name) ? 'door.pendingPerson' : 'door.pendingRing', { seconds: String(p.secondsLeft) });
  el('door-face-hint').textContent = faceText(p.faceHint);
  void loadSnapshot(p);
}

async function pollPending() {
  if (ports()?.role?.() !== 'admin' || !adminPhone) { hide(); return; }
  try { render((await ports().request('/api/door/pending')).pending); }
  catch (error) { if (error?.code === 'ADMIN_PHONE_REQUIRED' || error?.code === 'DOOR_APPROVAL_DISABLED') { adminPhone = false; hide(); } }
}
function schedule() {
  clearTimeout(pendingTimer);
  if (ports()?.role?.() !== 'admin' || !adminPhone) return;
  pendingTimer = setTimeout(async () => { await pollPending(); schedule(); }, 2000);
}

async function decide(decision) {
  const requestId = shown;
  if (!requestId || deciding) return;
  deciding = true; el('door-approve').disabled = true; el('door-deny').disabled = true;
  try {
    const r = await withDeviceCredential((deviceToken) => ports().call('/api/door/decide', { requestId, decision, deviceToken }));
    if (r.ok) {
      mine(t('door.decided.' + (['approved', 'denied', 'failed'].includes(r.data.status) ? r.data.status : 'failed'),
        { receipt: r.data.receipt?.receiptId ?? '—', reason: r.data.reason ?? '—' }));
    } else mine(t('door.decideFailed', { reason: r.data.error || 'HTTP_' + r.status }));
  } catch { mine(t('door.decideFailed', { reason: 'NETWORK' })); }
  finally { deciding = false; hide(); globalThis.dispatchEvent(new Event('home-mcp-door-decided')); await pollPending(); }
}

// Whoever asked (family phone or this console) follows the answer for up to 70 s.
async function follow(requestId) {
  const until = Date.now() + 70_000;
  while (Date.now() < until) {
    let s;
    try { s = await ports().request('/api/door/status', 'POST', { requestId }); } catch { return; }
    if (s.status === 'pending') mine(t('door.mine.pending', { seconds: String(s.secondsLeft) }), { keep: true });
    else {
      mine(t('door.mine.' + (['approved', 'denied', 'expired', 'failed'].includes(s.status) ? s.status : 'failed'),
        { by: s.approver ?? '—', reason: s.reason ?? '—' }));
      globalThis.dispatchEvent(new Event('home-mcp-door-decided'));
      return;
    }
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
}

const root = typeof document === 'undefined' ? null : el('door-banner');
if (root) {
  el('door-approve').addEventListener('click', () => { void decide('approve'); });
  el('door-deny').addEventListener('click', () => { void decide('deny'); });
  el('door-live-toggle').addEventListener('click', () => { void startLive(); });
  globalThis.addEventListener('home-mcp-door-asked', (event) => { void follow(event.detail?.requestId); });
  globalThis.addEventListener('home-mcp-session-changed', () => { adminPhone = true; hide(); el('door-mine').textContent = ''; void pollPending().then(schedule); });
}
