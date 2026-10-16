import { t } from './i18n-map.mjs';
// Face hints panel (admin phone only): enrol a person with a separate consent tick, list, delete one or everyone, and try a
// photo. Photos are shrunk on the phone and sent once; the hub keeps only an encrypted feature (src/face_hint.mjs).
const el = id => document.getElementById(id);
const ports = () => globalThis.homeMcpSessionPorts;
const say = (key, params) => { el('faces-result').textContent = t(key, params); };

// Shrink to at most 1024 px and re-encode as JPEG: smaller upload, and no camera metadata (location, device) leaves the phone.
async function photoBase64(file) {
  const bitmap = await createImageBitmap(file);
  const scale = Math.min(1, 1024 / Math.max(bitmap.width, bitmap.height));
  const canvas = document.createElement('canvas');
  canvas.width = Math.max(1, Math.round(bitmap.width * scale)); canvas.height = Math.max(1, Math.round(bitmap.height * scale));
  canvas.getContext('2d').drawImage(bitmap, 0, 0, canvas.width, canvas.height);
  bitmap.close?.();
  const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/jpeg', 0.88));
  const bytes = new Uint8Array(await blob.arrayBuffer());
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

async function render() {
  const panel = el('faces-panel');
  if (ports()?.role?.() !== 'admin') { panel.hidden = true; return; }
  let r;
  try { r = await ports().request('/api/faces'); }
  catch (error) { panel.hidden = true; if (error?.code !== 'ADMIN_PHONE_REQUIRED') say('faces.failed', { reason: error?.code || 'ERROR' }); return; }
  panel.hidden = false;
  el('faces-state').textContent = r.enabled ? t('faces.on', { n: String(r.people.length) }) : t('faces.off', { reason: r.reason });
  el('faces-form').hidden = !r.enabled; el('faces-check').disabled = !r.enabled; el('faces-delete-all').disabled = !r.enabled || !r.people.length;
  const rows = r.people.map(p => {
    const li = document.createElement('li');
    const span = document.createElement('span');
    span.textContent = t('faces.item', { name: p.name, at: new Date(p.enrolledAt).toLocaleDateString(t('locale')) });
    const b = document.createElement('button'); b.type = 'button'; b.className = 'button small'; b.textContent = t('faces.delete');
    b.addEventListener('click', async () => {
      try { const d = await ports().request('/api/faces/delete', 'POST', { id: p.id }); say('faces.deleted', { n: String(d.removed) }); }
      catch (error) { say('faces.failed', { reason: error.code || 'ERROR' }); }
      await render();
    });
    li.append(span, ' ', b); return li;
  });
  if (!rows.length) { const li = document.createElement('li'); li.textContent = t('faces.empty'); rows.push(li); }
  el('faces-list').replaceChildren(...rows);
}

async function enroll(event) {
  event.preventDefault();
  if (!el('faces-consent').checked) { say('faces.consentNeeded'); return; }
  const file = el('faces-photo').files?.[0];
  if (!file) return;
  const button = el('faces-enroll'); button.disabled = true; say('faces.working');
  try {
    const r = await ports().request('/api/faces/enroll', 'POST', { name: el('faces-name').value, consent: true, image: await photoBase64(file) });
    say('faces.enrolled', { name: r.name });
    el('faces-form').reset();
  } catch (error) { say('faces.failed', { reason: error.code || 'ERROR' }); }
  finally { button.disabled = false; await render(); }
}

async function check() {
  const file = el('faces-check').files?.[0];
  if (!file) return;
  say('faces.working');
  try {
    const { hint } = await ports().request('/api/faces/check', 'POST', { image: await photoBase64(file) });
    el('faces-result').textContent = hint.state === 'match' || hint.state === 'unknown'
      ? hint.faces.map(f => (f.match ? t('faceHint.looksLike', { name: f.name, score: f.score.toFixed(2) }) : t('faceHint.notEnrolled'))).join(' · ')
      : t('faceHint.' + (['no_face', 'no_image', 'disabled', 'error'].includes(hint.state) ? hint.state : 'error'));
  } catch (error) { say('faces.failed', { reason: error.code || 'ERROR' }); }
  finally { el('faces-check').value = ''; }
}

const root = typeof document === 'undefined' ? null : el('faces-panel');
if (root) {
  el('faces-form').addEventListener('submit', enroll);
  el('faces-check').addEventListener('change', () => { void check(); });
  el('faces-delete-all').addEventListener('click', async () => {
    if (!globalThis.confirm(t('faces.deleteAllConfirm'))) return;
    try { const d = await ports().request('/api/faces/delete', 'POST', { all: true }); say('faces.deleted', { n: String(d.removed) }); }
    catch (error) { say('faces.failed', { reason: error.code || 'ERROR' }); }
    await render();
  });
  globalThis.addEventListener('home-mcp-session-changed', () => { void render(); });
}
