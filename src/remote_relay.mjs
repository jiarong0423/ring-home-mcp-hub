// Home side of the family remote-approval relay (cloud: cloud/aws/ring-private/family-relay.mjs).
// The hub signs every call with its relay key (Ed25519, file 0600; public key pinned in the cloud stack), publishes the
// pending door request as text, polls for a decision, and re-verifies the phone's own signature with the phone key it
// stored at activation time before handing the decision to the door flow. A decision the cloud made up cannot pass.
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, randomInt, sign } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { canonical, MAC_SCHEMA, phoneKeyId, verifyPhoneEnvelope } from '../cloud/aws/ring-private/family-relay.mjs';

const sha = (value) => createHash('sha256').update(value).digest('hex');
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const CODE_TTL_MS = 10 * 60_000;

export function loadOrCreateRelayKey(path) {
  if (existsSync(path)) {
    const key = createPrivateKey(readFileSync(path));
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('relay key must be Ed25519');
    return key;
  }
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const { privateKey } = generateKeyPairSync('ed25519');
  writeFileSync(path, privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
  chmodSync(path, 0o600);
  return privateKey;
}
export const relayPublicKeySpki = (privateKey) => createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).toString('base64url');

export function createRemoteRelay({ base, privateKey, storePath, fetchImpl = fetch, clock = Date.now, onDecision = () => {}, log = () => {},
  sleep = (ms) => new Promise((r) => { const t = setTimeout(r, ms); t.unref?.(); }) }) {
  const url = new URL(base);
  if (url.protocol !== 'https:' && !(url.hostname === '127.0.0.1' && process.env.NODE_ENV === 'test')) throw new Error('relay base must be https');
  const root = url.href.replace(/\/$/u, '');
  let phones = existsSync(storePath) ? JSON.parse(readFileSync(storePath, 'utf8')).phones ?? [] : [];
  let pendingCode = null;           // { code, codeSha256, deviceId, expiresAtMs }
  let current = null;               // { requestId, expiresAtMs }
  let lastError = null;
  const persist = () => {
    mkdirSync(dirname(storePath), { recursive: true, mode: 0o700 });
    const tmp = `${storePath}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify({ schema: 'home-mcp-relay-phones-v1', phones }, null, 1), { mode: 0o600 });
    chmodSync(tmp, 0o600); renameSync(tmp, storePath);
  };

  async function call(op, payload) {
    const now = clock();
    const claims = { schema: MAC_SCHEMA, op, payloadSha256: sha(canonical(payload ?? null)), nonce: randomBytes(24).toString('base64url'), issuedAt: now, expiresAt: now + 15_000 };
    const signature = sign(null, Buffer.from(canonical(claims)), privateKey).toString('base64url');
    const res = await fetchImpl(`${root}/relay/mac`, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ claims, signature, payload }), signal: AbortSignal.timeout(5000) });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) { lastError = `${op} HTTP ${res.status} ${body.error ?? ''}`.trim(); throw Object.assign(new Error(lastError), { code: body.error ?? 'RELAY_HTTP', status: res.status }); }
    lastError = null;
    return body;
  }

  // Request and result must reach the family phone: retried on network errors and 5xx (stress test: 25 % injected 500s).
  // Each try is a fresh signed call (new nonce), so a retry is never a replay. 4xx is final.
  async function callRetry(op, payload) {
    for (let attempt = 0; ; attempt += 1) {
      try { return await call(op, payload); }
      catch (error) {
        const transient = error.status === undefined || error.status >= 500;   // network / timeout / 5xx
        if (!transient || attempt >= 2) throw error;
        await sleep(500 * (attempt + 1));
      }
    }
  }

  // Admin phone at home asks to "turn on remote approval": a one-time code, shown only on that screen.
  async function enable({ deviceId }) {
    let code = '';
    for (let i = 0; i < 8; i += 1) code += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
    const codeSha256 = sha(code);
    await call('code', { codeSha256 });
    pendingCode = { code, codeSha256, deviceId, expiresAtMs: clock() + CODE_TTL_MS };
    return { code, url: `${root}/family#code=${code}`, expiresAt: new Date(pendingCode.expiresAtMs).toISOString() };
  }

  async function tick() {
    if (pendingCode && clock() >= pendingCode.expiresAtMs) pendingCode = null;
    if (current && clock() > current.expiresAtMs + 5_000) current = null;   // the request ended at home; stop asking
    if (!pendingCode && !current) return { idle: true };
    const out = await call('poll', { ...(pendingCode ? { codeSha256: pendingCode.codeSha256 } : {}), ...(current ? { requestId: current.requestId } : {}) });
    if (pendingCode && out.registration) {
      const reg = out.registration;
      if (phoneKeyId(reg.jwk) !== reg.keyId) throw new Error('relay registration key mismatch');
      await call('activate', { codeSha256: pendingCode.codeSha256, phoneKeyId: reg.keyId });
      phones = [...phones.filter((p) => p.keyId !== reg.keyId), { keyId: reg.keyId, jwk: reg.jwk, name: reg.name, deviceId: pendingCode.deviceId, activatedAt: new Date(clock()).toISOString() }];
      persist();
      log(`remote approval: phone "${reg.name}" activated`);
      pendingCode = null;
    }
    if (current && out.decision) {
      const env = out.decision;
      const phone = phones.find((p) => p.keyId === env.keyId);
      try {
        if (!phone) throw new Error('unknown phone');
        // signed by the phone within the request's life; checked here with the key the HUB stored, not the cloud's copy
        verifyPhoneEnvelope(env, phone.jwk, { now: clock(), maxSkewMs: 3 * 60_000 });
        if (env.op !== 'decide' || env.payload.requestId !== current.requestId || !['approve', 'deny'].includes(env.payload.decision)) throw new Error('decision does not match');
      } catch (error) { log(`ERROR remote decision rejected: ${error.code ?? error.message}`); current = null; return { rejected: true }; }
      const requestId = current.requestId; current = null;
      onDecision({ requestId, decision: env.payload.decision, approver: `${phone.name} (remote)`, deviceId: phone.deviceId });
      return { decided: env.payload.decision };
    }
    return { waiting: true };
  }

  return Object.freeze({
    enable, tick,
    async publishRequest(r) { current = { requestId: r.requestId, expiresAtMs: r.expiresAtMs }; await callRetry('request', { request: r }); },
    async publishResult(r) { if (current?.requestId === r.requestId) current = null; await callRetry('result', r); },
    async revoke(keyId) { phones = phones.filter((p) => p.keyId !== keyId); persist(); await call('revoke', { phoneKeyId: keyId }); },
    status: () => ({ phones: phones.map(({ keyId, name, activatedAt }) => ({ keyId, name, activatedAt })), pendingCode: Boolean(pendingCode), waiting: Boolean(current), lastError })
  });
}
