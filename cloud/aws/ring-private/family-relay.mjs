// Family remote-approval relay (AWS_REMOTE_APPROVAL_PLAN_zh.md). The cloud is only a mailman:
//  - the home hub (Mac) talks to it with requests signed by its relay key (Ed25519, public key pinned at deploy time);
//  - a family phone talks to it with requests signed by a P-256 key that lives in that phone's browser (WebCrypto,
//    non-extractable) and that the hub activated after a one-time code shown on the admin phone at home;
//  - a decision ("approve"/"deny") is stored together with the phone's signature, and the hub verifies that signature
//    again itself before opening anything. The cloud holds no private key, so it cannot approve on anyone's behalf.
// Only a short text summary of a pending door request goes up; never a photo, a face hint or a Ring token.
// Storage is injected (getItem / putItem / updateItem style ports over the existing event table, deterministic keys).
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';

export class RelayError extends Error { constructor(status, code) { super(code); this.status = status; this.code = code; } }
const deny = (status, code) => { throw new RelayError(status, code); };
const sha = (value) => createHash('sha256').update(value).digest('hex');
const HEX = /^[a-f0-9]{64}$/u;
const B64U = /^[A-Za-z0-9_-]+$/u;
const MAX_SKEW_MS = 30_000;

// Canonical JSON (sorted keys) so both ends hash and sign exactly the same bytes.
export function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
}

// ---- phone keys (P-256, JWK public part only) ----
export function phoneKeyId(jwk) {
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string' ||
      !B64U.test(jwk.x) || !B64U.test(jwk.y) || jwk.x.length !== 43 || jwk.y.length !== 43 || 'd' in jwk) deny(400, 'PHONE_KEY_INVALID');
  return sha(canonical({ crv: 'P-256', kty: 'EC', x: jwk.x, y: jwk.y }));
}
// The phone signs canonical({ op, payload, keyId, ts, nonce }) with ECDSA P-256 / SHA-256 (WebCrypto raw r||s, 64 bytes).
export function verifyPhoneEnvelope(envelope, jwk, { now, maxSkewMs = MAX_SKEW_MS } = {}) {
  const e = envelope;
  if (!e || typeof e !== 'object' || typeof e.op !== 'string' || typeof e.keyId !== 'string' || !HEX.test(e.keyId) ||
      !Number.isSafeInteger(e.ts) || typeof e.nonce !== 'string' || !/^[A-Za-z0-9_-]{16,64}$/u.test(e.nonce) ||
      typeof e.signature !== 'string' || !B64U.test(e.signature) || e.payload === null || typeof e.payload !== 'object') deny(400, 'PHONE_ENVELOPE_INVALID');
  if (phoneKeyId(jwk) !== e.keyId) deny(403, 'PHONE_KEY_MISMATCH');
  if (Math.abs(now - e.ts) > maxSkewMs) deny(403, 'PHONE_ENVELOPE_STALE');
  const sig = Buffer.from(e.signature, 'base64url');
  if (sig.length !== 64) deny(403, 'PHONE_SIGNATURE_INVALID');
  let ok = false;
  try {
    const key = createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, format: 'jwk' });
    ok = cryptoVerify('sha256', Buffer.from(canonical({ op: e.op, payload: e.payload, keyId: e.keyId, ts: e.ts, nonce: e.nonce })), { key, dsaEncoding: 'ieee-p1363' }, sig);
  } catch { ok = false; }
  if (!ok) deny(403, 'PHONE_SIGNATURE_INVALID');
  return e;
}

// ---- hub (Mac) requests: Ed25519 over canonical({ schema, op, payloadSha256, nonce, issuedAt, expiresAt }) ----
export const MAC_SCHEMA = 'home-mcp-relay-mac-v1';
export function verifyMacEnvelope(envelope, publicKeySpki, { now }) {
  const e = envelope;
  if (!e || typeof e !== 'object' || e.claims === null || typeof e.claims !== 'object' || typeof e.signature !== 'string' || !B64U.test(e.signature)) deny(400, 'MAC_ENVELOPE_INVALID');
  const c = e.claims;
  if (c.schema !== MAC_SCHEMA || typeof c.op !== 'string' || typeof c.payloadSha256 !== 'string' || !HEX.test(c.payloadSha256) ||
      typeof c.nonce !== 'string' || !/^[A-Za-z0-9_-]{16,64}$/u.test(c.nonce) || !Number.isSafeInteger(c.issuedAt) || !Number.isSafeInteger(c.expiresAt) ||
      c.expiresAt <= c.issuedAt || c.expiresAt - c.issuedAt > 15_000) deny(400, 'MAC_ENVELOPE_INVALID');
  if (c.issuedAt > now + 5_000 || c.expiresAt <= now) deny(403, 'MAC_ENVELOPE_STALE');
  if (sha(canonical(e.payload ?? null)) !== c.payloadSha256) deny(403, 'MAC_PAYLOAD_MISMATCH');
  let ok = false;
  try {
    const key = createPublicKey({ key: Buffer.from(publicKeySpki, 'base64url'), format: 'der', type: 'spki' });
    ok = key.asymmetricKeyType === 'ed25519' && cryptoVerify(null, Buffer.from(canonical(c)), key, Buffer.from(e.signature, 'base64url'));
  } catch { ok = false; }
  if (!ok) deny(403, 'MAC_SIGNATURE_INVALID');
  return c;
}

// ---- the relay itself ----
const TTL = Object.freeze({ code: 10 * 60_000, registration: 10 * 60_000, request: 3 * 60_000, decision: 3 * 60_000, result: 10 * 60_000, nonce: 2 * 60_000 });
const LABEL = /^[\p{L}\p{N} ().,:'\-]{1,60}$/u;

export function createFamilyRelay({ store, macPublicKeySpki, clock = Date.now }) {
  if (!store || typeof store.get !== 'function' || typeof store.put !== 'function') throw new TypeError('relay store required');
  if (typeof macPublicKeySpki !== 'string' || !B64U.test(macPublicKeySpki)) throw new TypeError('relay mac key required');
  const expiry = (ms) => clock() + ms;
  const live = (item) => item && (!item.expiresAtMs || item.expiresAtMs > clock()) ? item : null;
  async function once(nonce) {   // replay guard for both sides
    const ok = await store.put({ pk: `relay:nonce:${sha(nonce)}`, expiresAtMs: expiry(TTL.nonce) }, { ifNotExists: true });
    if (!ok) deny(409, 'RELAY_REPLAY');
  }
  async function activePhone(keyId) {
    const phone = await store.get(`relay:phone:${keyId}`);
    if (!phone || phone.active !== true) deny(403, 'PHONE_NOT_ACTIVE');
    return phone;
  }

  async function mac(envelope) {
    const c = verifyMacEnvelope(envelope, macPublicKeySpki, { now: clock() });
    await once(c.nonce);
    const p = envelope.payload ?? {};
    switch (c.op) {
      case 'code': {   // one-time registration code (only its hash reaches the cloud)
        if (!HEX.test(p.codeSha256 ?? '')) deny(400, 'RELAY_ARGUMENT');
        await store.put({ pk: `relay:code:${p.codeSha256}`, used: false, expiresAtMs: expiry(TTL.code) });
        return { ok: true };
      }
      case 'activate': {
        if (!HEX.test(p.codeSha256 ?? '') || !HEX.test(p.phoneKeyId ?? '')) deny(400, 'RELAY_ARGUMENT');
        const reg = live(await store.get(`relay:phonereg:${p.codeSha256}`));
        if (!reg || reg.keyId !== p.phoneKeyId) deny(404, 'RELAY_REGISTRATION_UNKNOWN');
        await store.put({ pk: `relay:phone:${reg.keyId}`, jwk: reg.jwk, name: reg.name, active: true });
        return { ok: true, phoneKeyId: reg.keyId };
      }
      case 'revoke': {
        if (!HEX.test(p.phoneKeyId ?? '')) deny(400, 'RELAY_ARGUMENT');
        const phone = await store.get(`relay:phone:${p.phoneKeyId}`);
        if (phone) await store.put({ ...phone, active: false });
        return { ok: true };
      }
      case 'request': {   // the one pending door request, as text
        const r = p.request ?? {};
        if (typeof r.requestId !== 'string' || !/^[A-Za-z0-9_-]{16,64}$/u.test(r.requestId) || !['ring', 'mcp', 'phone', 'console'].includes(r.kind) ||
            typeof r.label !== 'string' || !LABEL.test(r.label) || !Number.isSafeInteger(r.expiresAtMs) || r.expiresAtMs <= clock() || r.expiresAtMs > clock() + TTL.request) deny(400, 'RELAY_ARGUMENT');
        await store.put({ pk: 'relay:request', requestId: r.requestId, kind: r.kind, label: r.label, hasSnapshot: r.hasSnapshot === true, expiresAtMs: r.expiresAtMs });
        return { ok: true };
      }
      case 'result': {
        if (typeof p.requestId !== 'string' || !['approved', 'denied', 'expired', 'failed'].includes(p.status)) deny(400, 'RELAY_ARGUMENT');
        await store.put({ pk: `relay:result:${p.requestId}`, status: p.status, receiptId: typeof p.receiptId === 'string' ? p.receiptId.slice(0, 16) : null, expiresAtMs: expiry(TTL.result) });
        return { ok: true };
      }
      case 'poll': {   // registrations waiting for activation, and the signed decision for the current request
        const out = { ok: true, registration: null, decision: null };
        if (HEX.test(p.codeSha256 ?? '')) { const reg = live(await store.get(`relay:phonereg:${p.codeSha256}`)); if (reg) out.registration = { keyId: reg.keyId, jwk: reg.jwk, name: reg.name }; }
        if (typeof p.requestId === 'string') { const d = live(await store.get(`relay:decision:${p.requestId}`)); if (d) out.decision = d.envelope; }
        return out;
      }
      default: deny(400, 'RELAY_OP_UNKNOWN');
    }
  }

  async function phone(envelope) {
    const now = clock();
    if (envelope?.op === 'register') {   // first contact: proves possession of the new key and spends the one-time code
      const p = envelope.payload ?? {};
      if (typeof p.code !== 'string' || !/^[A-Z2-9]{8}$/u.test(p.code) || typeof p.name !== 'string' || !LABEL.test(p.name)) deny(400, 'RELAY_ARGUMENT');
      const keyId = phoneKeyId(p.jwk);
      verifyPhoneEnvelope(envelope, p.jwk, { now });
      await once(envelope.nonce);
      const codeSha = sha(p.code);
      const code = live(await store.get(`relay:code:${codeSha}`));
      if (!code || code.used) deny(403, 'RELAY_CODE_INVALID');
      await store.put({ ...code, used: true });
      await store.put({ pk: `relay:phonereg:${codeSha}`, keyId, jwk: { kty: 'EC', crv: 'P-256', x: p.jwk.x, y: p.jwk.y }, name: p.name, expiresAtMs: expiry(TTL.registration) });
      return { ok: true, status: 'waiting_for_home' };
    }
    const keyId = typeof envelope?.keyId === 'string' && HEX.test(envelope.keyId) ? envelope.keyId : deny(400, 'PHONE_ENVELOPE_INVALID');
    const phoneRow = await activePhone(keyId);
    verifyPhoneEnvelope(envelope, phoneRow.jwk, { now });
    await once(envelope.nonce);
    const request = live(await store.get('relay:request'));
    if (envelope.op === 'pending') {
      const result = request ? live(await store.get(`relay:result:${request.requestId}`)) : null;
      return { ok: true, request: request ? { requestId: request.requestId, kind: request.kind, label: request.label, hasSnapshot: request.hasSnapshot,
        secondsLeft: Math.max(0, Math.ceil((request.expiresAtMs - now) / 1000)) } : null, result: result ? { status: result.status, receiptId: result.receiptId } : null };
    }
    if (envelope.op === 'decide') {
      const p = envelope.payload ?? {};
      if (!request || p.requestId !== request.requestId) deny(404, 'RELAY_REQUEST_UNKNOWN');
      if (!['approve', 'deny'].includes(p.decision)) deny(400, 'RELAY_ARGUMENT');
      const stored = { op: envelope.op, payload: { requestId: p.requestId, decision: p.decision }, keyId, ts: envelope.ts, nonce: envelope.nonce, signature: envelope.signature };
      const first = await store.put({ pk: `relay:decision:${p.requestId}`, envelope: stored, expiresAtMs: expiry(TTL.decision) }, { ifNotExists: true });
      if (!first) deny(409, 'RELAY_ALREADY_DECIDED');
      return { ok: true, status: 'sent_to_home' };
    }
    deny(400, 'RELAY_OP_UNKNOWN');
  }

  return Object.freeze({ mac, phone });
}

// In-memory store for tests and the offline demo (same semantics as the DynamoDB port).
export function createMemoryRelayStore() {
  const items = new Map();
  return Object.freeze({
    async get(pk) { const v = items.get(pk); return v ? structuredClone(v) : null; },
    async put(item, { ifNotExists = false } = {}) { if (ifNotExists && items.has(item.pk)) return false; items.set(item.pk, structuredClone(item)); return true; },
    size: () => items.size
  });
}
