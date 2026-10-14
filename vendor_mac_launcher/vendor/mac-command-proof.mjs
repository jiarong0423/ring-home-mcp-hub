import { createPublicKey, sign, verify, randomBytes, KeyObject } from 'node:crypto';
import { record, hash, receipt, text, time, deny, freeze } from './mac-command-contract.mjs';
export const MAC_PROOF_HEADER = 'x-ring-mac-proof';
const FIELDS = ['schema', 'keyId', 'ownerRef', 'associationRevision', 'operation', 'audience', 'tokenSha256', 'payloadSha256', 'nonce', 'issuedAt', 'expiresAt'];
export function macPublicKey(spki) {
  if (typeof spki !== 'string' || spki.length > 256 || !/^[A-Za-z0-9_-]+$/u.test(spki)) deny('MAC_PROOF_KEY');
  const bytes = Buffer.from(spki, 'base64url');
  if (bytes.toString('base64url') !== spki) deny('MAC_PROOF_KEY');
  let key; try { key = createPublicKey({ key: bytes, format: 'der', type: 'spki' }); } catch { deny('MAC_PROOF_KEY'); }
  if (key.asymmetricKeyType !== 'ed25519' || !key.export({ format: 'der', type: 'spki' }).equals(bytes)) deny('MAC_PROOF_KEY');
  return { key, keyId: hash(bytes) };
}
export function macProofPayload(operation, value) {
  if (operation === 'fetch') return record(value, []);
  if (operation === 'receipt') return receipt(value);
  deny('MAC_PROOF_OPERATION');
}
function audience(value) {
  let u; try { u = new URL(value); } catch { deny('MAC_PROOF_AUDIENCE'); }
  if (typeof value !== 'string' || u.protocol !== 'https:' || u.username || u.password || u.hash || u.search || u.href !== value || !u.pathname.endsWith('/mcp')) deny('MAC_PROOF_AUDIENCE');
  return value;
}
function claims(value) {
  const c = record(value, FIELDS);
  if (c.schema !== 'ring-mac-command-proof-v1' || typeof c.keyId !== 'string' || !/^[a-f0-9]{64}$/u.test(c.keyId) ||
      !Number.isSafeInteger(c.associationRevision) || c.associationRevision < 1 || !['fetch', 'receipt'].includes(c.operation) ||
      typeof c.tokenSha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(c.tokenSha256) || typeof c.payloadSha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(c.payloadSha256) ||
      typeof c.nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(c.nonce) || Buffer.from(c.nonce, 'base64url').toString('base64url') !== c.nonce) deny('MAC_PROOF_SCHEMA');
  text(c.ownerRef); audience(c.audience); time(c.issuedAt); time(c.expiresAt);
  if (c.expiresAt <= c.issuedAt || c.expiresAt > c.issuedAt + 15000) deny('MAC_PROOF_EXPIRY');
  return freeze(c);
}
export function parseMacProof(header) {
  if (typeof header !== 'string' || header.length > 4096 || !/^[A-Za-z0-9_-]+$/u.test(header)) deny('MAC_PROOF_REQUIRED');
  const bytes = Buffer.from(header, 'base64url'); if (bytes.toString('base64url') !== header) deny('MAC_PROOF_REQUIRED');
  let value; try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { deny('MAC_PROOF_REQUIRED'); }
  const p = record(value, ['claims', 'signature']); const c = claims(p.claims);
  if (typeof p.signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/u.test(p.signature) || Buffer.from(p.signature, 'base64url').toString('base64url') !== p.signature) deny('MAC_PROOF_SIGNATURE');
  return freeze({ claims: c, signature: p.signature });
}
export function verifyMacProof({ header, publicKeySpki, ownerRef, associationRevision, operation, audience: expectedAudience, token, payload, now }) {
  const p = parseMacProof(header); const c = p.claims; const key = macPublicKey(publicKeySpki); time(now);
  if (typeof token !== 'string' || token.length < 16 || c.keyId !== key.keyId || c.ownerRef !== ownerRef || c.associationRevision !== associationRevision ||
      c.operation !== operation || c.audience !== audience(expectedAudience) || c.tokenSha256 !== hash(token) ||
      c.payloadSha256 !== hash(JSON.stringify(macProofPayload(operation, payload))) || c.issuedAt > now + 5000 || c.expiresAt <= now ||
      !verify(null, Buffer.from(JSON.stringify(c)), key.key, Buffer.from(p.signature, 'base64url'))) deny('MAC_PROOF_DENIED');
  return c;
}
export function createMacCommandProofSigner({ privateKey, ownerRef, associationRevision, audience: target, clock = Date.now }) {
  if (!(privateKey instanceof KeyObject) || privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519' || typeof clock !== 'function') deny('MAC_PROOF_KEY');
  text(ownerRef); audience(target); if (!Number.isSafeInteger(associationRevision) || associationRevision < 1) deny('MAC_PROOF_SCHEMA');
  let resident = privateKey;
  const publicKeySpki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).toString('base64url');
  const keyId = macPublicKey(publicKeySpki).keyId;
  return Object.freeze({ keyId, publicKeySpki, ownerRef, associationRevision, audience: target,
    signRequest({ operation, token, payload }) {
      if (!resident || typeof token !== 'string' || token.length < 16) deny('MAC_PROOF_KEY');
      const now = time(clock());
      const c = claims({ schema: 'ring-mac-command-proof-v1', keyId, ownerRef, associationRevision, operation, audience: target,
        tokenSha256: hash(token), payloadSha256: hash(JSON.stringify(macProofPayload(operation, payload))), nonce: randomBytes(32).toString('base64url'), issuedAt: now, expiresAt: now + 15000 });
      return Buffer.from(JSON.stringify({ claims: c, signature: sign(null, Buffer.from(JSON.stringify(c)), resident).toString('base64url') })).toString('base64url');
    }, close() { resident = null; return { closed: true }; }
  });
}
