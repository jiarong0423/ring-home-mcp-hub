// Remote-approval page for a family phone. The signing key is a WebCrypto ECDSA P-256 key created HERE, non-extractable,
// kept in this site's IndexedDB. Every request is signed; the cloud relays, the home hub verifies the signature again.
const el = (id) => document.getElementById(id);
const say = (text) => { el('status').textContent = text; };
const DB = 'home-mcp-family'; const STORE = 'keys';

function idb(mode, fn) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(DB, 1);
    open.onupgradeneeded = () => open.result.createObjectStore(STORE);
    open.onerror = () => reject(open.error);
    open.onsuccess = () => { const tx = open.result.transaction(STORE, mode); const req = fn(tx.objectStore(STORE)); tx.oncomplete = () => resolve(req?.result); tx.onerror = () => reject(tx.error); };
  });
}
const loadKey = () => idb('readonly', (s) => s.get('phone'));
const saveKey = (value) => idb('readwrite', (s) => s.put(value, 'phone'));

function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
}
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/u, '');
async function keyIdOf(jwk) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical({ crv: 'P-256', kty: 'EC', x: jwk.x, y: jwk.y })));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
async function call(op, payload, k) {
  const ts = Date.now(); const nonce = b64u(crypto.getRandomValues(new Uint8Array(18)));
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, k.privateKey, new TextEncoder().encode(canonical({ op, payload, keyId: k.keyId, ts, nonce })));
  const res = await fetch('relay/phone', { method: 'POST', headers: { 'content-type': 'application/json' }, cache: 'no-store',
    body: JSON.stringify({ op, payload, keyId: k.keyId, ts, nonce, signature: b64u(sig) }) });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(body.error || `HTTP ${res.status}`), { code: body.error || `HTTP_${res.status}` });
  return body;
}

async function enrol(code) {
  el('enrol').hidden = false;
  el('enable').onclick = async () => {
    const name = el('name').value.trim() || 'Family phone';
    el('enable').disabled = true;
    try {
      const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
      const { kty, crv, x, y } = await crypto.subtle.exportKey('jwk', pair.publicKey);
      const jwk = { kty, crv, x, y };
      const k = { privateKey: pair.privateKey, keyId: await keyIdOf(jwk), name };
      await call('register', { code, jwk, name }, k);
      await saveKey(k);
      history.replaceState(null, '', location.pathname);   // drop the one-time code from the address bar
      el('enrol').hidden = true;
      say(`Sent. The hub at home is confirming "${name}"… this takes a few seconds.`);
      setTimeout(loop, 4000);
    } catch (error) { el('enable').disabled = false; say(`Could not enable (${error.code || error.message}). Ask for a new code at home.`); }
  };
  say('One-time code received from your home hub.');
}

let shown = null;
async function loop() {
  const k = await loadKey();
  if (!k) { say('This phone is not enabled yet. At home, open the hub on your admin phone and choose "Enable remote approval".'); return; }
  try {
    const { request, result } = await call('pending', {}, k);
    if (request && !result) {
      shown = request.requestId;
      el('ask').hidden = false;
      el('ask-title').textContent = request.kind === 'ring' ? `Someone is at the door (${request.label}). Open it?` : `"${request.label}" asks to open the front door.`;
      el('ask-note').textContent = `${request.secondsLeft} s left.${request.hasSnapshot ? ' A Ring snapshot is on the admin phone at home.' : ''}`;
      say(`Enabled as "${k.name}". Waiting for your decision.`);
    } else {
      el('ask').hidden = true;
      say(result ? `Last request: ${result.status}${result.receiptId ? ` (receipt ${result.receiptId})` : ''}. Watching for new requests.` : `Enabled as "${k.name}". No one is asking to open the door.`);
    }
  } catch (error) {
    say(error.code === 'PHONE_NOT_ACTIVE' ? 'Not confirmed by the hub yet, or this phone was removed.' : `Cannot reach the relay (${error.code || 'network'}). Retrying…`);
  }
  setTimeout(loop, 3000);
}
async function decide(decision) {
  const k = await loadKey();
  if (!k || !shown) return;
  el('approve').disabled = el('deny').disabled = true;
  try { await call('decide', { requestId: shown, decision }, k); say(decision === 'approve' ? 'Approved. Waiting for the hub to open the door…' : 'Denied. The door stays locked.'); }
  catch (error) { say(`Not sent (${error.code || error.message}).`); }
  finally { el('approve').disabled = el('deny').disabled = false; el('ask').hidden = true; }
}
el('approve').onclick = () => decide('approve');
el('deny').onclick = () => decide('deny');
const code = new URLSearchParams(location.hash.slice(1)).get('code');
if (code && /^[A-Z2-9]{8}$/u.test(code)) void enrol(code); else void loop();
