import { createCipheriv, createDecipheriv } from 'node:crypto';
import { types } from 'node:util';

const PURPOSE = 'RING_ACCOUNT_IDENTITY';
const FIELDS = Object.freeze(['version', 'purpose', 'keyId', 'encryptedDataKey', 'nonce', 'authTag', 'ciphertext']);

export class IdentityEnvelopeError extends Error {
  constructor(code) { super(code); this.name = 'IdentityEnvelopeError'; this.code = code; }
}
function deny(code) { throw new IdentityEnvelopeError(code); }
function exact(value, fields, code) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny(code);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== fields.length || fields.some(field => !Object.hasOwn(descriptors, field)) ||
        keys.some(key => typeof key !== 'string' || !fields.includes(key) || !Object.hasOwn(descriptors[key], 'value'))) deny(code);
    return Object.fromEntries(fields.map(field => [field, descriptors[field].value]));
  } catch (error) { if (error instanceof IdentityEnvelopeError) throw error; deny(code); }
}
function encoded(value, minimum, maximum) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) deny('IDENTITY_ENVELOPE_INVALID');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length < minimum || bytes.length > maximum || bytes.toString('base64url') !== value) deny('IDENTITY_ENVELOPE_INVALID');
  return bytes;
}
function context(value) {
  const data = exact(value, ['accountDigest', 'ownerRef', 'ownerEpoch', 'accountGeneration'], 'IDENTITY_ENVELOPE_CONTEXT');
  if (typeof data.accountDigest !== 'string' || !/^[0-9a-f]{64}$/.test(data.accountDigest) ||
      typeof data.ownerRef !== 'string' || !/^[A-Za-z][A-Za-z0-9._/@-]{2,255}$/.test(data.ownerRef) ||
      !Number.isSafeInteger(data.ownerEpoch) || data.ownerEpoch < 1 ||
      !Number.isSafeInteger(data.accountGeneration) || data.accountGeneration < 1) deny('IDENTITY_ENVELOPE_CONTEXT');
  return Object.freeze(data);
}
function encryptionContext(application, tableName, data) {
  return Object.freeze({
    application,
    table: tableName,
    purpose: PURPOSE,
    account_digest: data.accountDigest,
    owner_ref: data.ownerRef,
    owner_epoch: String(data.ownerEpoch),
    account_generation: String(data.accountGeneration)
  });
}
function aad(application, tableName, data) {
  return Buffer.from(JSON.stringify([application, tableName, PURPOSE, data.accountDigest, data.ownerRef,
    data.ownerEpoch, data.accountGeneration]), 'utf8');
}

export function createIdentityEnvelope(options) {
  const value = exact(options, ['generateDataKey', 'decryptDataKey', 'keyId', 'application', 'tableName', 'random'], 'IDENTITY_ENVELOPE_CONFIG');
  if (typeof value.generateDataKey !== 'function' || types.isProxy(value.generateDataKey) ||
      typeof value.decryptDataKey !== 'function' || types.isProxy(value.decryptDataKey) ||
      typeof value.random !== 'function' || types.isProxy(value.random) ||
      ![value.keyId, value.application, value.tableName].every(item => typeof item === 'string' && item.length >= 3 && item.length <= 255)) {
    deny('IDENTITY_ENVELOPE_CONFIG');
  }
  return Object.freeze({
    async seal(accountIdentifier, binding) {
      if (typeof accountIdentifier !== 'string' || accountIdentifier.length < 1 || accountIdentifier.length > 256 ||
          /[\x00-\x20\x7f]/.test(accountIdentifier)) deny('IDENTITY_ENVELOPE_INVALID');
      const current = context(binding);
      let response;
      try {
        response = await value.generateDataKey({ KeyId: value.keyId, KeySpec: 'AES_256',
          EncryptionContext: encryptionContext(value.application, value.tableName, current) });
      } catch { deny('IDENTITY_ENVELOPE_UNAVAILABLE'); }
      const plaintext = Buffer.from(response?.Plaintext ?? []);
      const wrapped = Buffer.from(response?.CiphertextBlob ?? []);
      if (plaintext.length !== 32 || wrapped.length < 1 || wrapped.length > 65_536) deny('IDENTITY_ENVELOPE_UNAVAILABLE');
      let nonce;
      try { nonce = Buffer.from(value.random(12)); } catch { plaintext.fill(0); deny('IDENTITY_ENVELOPE_UNAVAILABLE'); }
      if (nonce.length !== 12) { plaintext.fill(0); deny('IDENTITY_ENVELOPE_UNAVAILABLE'); }
      try {
        const cipher = createCipheriv('aes-256-gcm', plaintext, nonce);
        cipher.setAAD(aad(value.application, value.tableName, current));
        const ciphertext = Buffer.concat([cipher.update(accountIdentifier, 'utf8'), cipher.final()]);
        return Object.freeze({ version: 1, purpose: PURPOSE, keyId: value.keyId,
          encryptedDataKey: wrapped.toString('base64url'), nonce: nonce.toString('base64url'),
          authTag: cipher.getAuthTag().toString('base64url'), ciphertext: ciphertext.toString('base64url') });
      } catch { deny('IDENTITY_ENVELOPE_UNAVAILABLE'); }
      finally { plaintext.fill(0); }
    },
    async open(input, binding) {
      const envelope = exact(input, FIELDS, 'IDENTITY_ENVELOPE_INVALID');
      const current = context(binding);
      if (envelope.version !== 1 || envelope.purpose !== PURPOSE || envelope.keyId !== value.keyId) deny('IDENTITY_ENVELOPE_INVALID');
      const wrapped = encoded(envelope.encryptedDataKey, 1, 65_536);
      const nonce = encoded(envelope.nonce, 12, 12);
      const tag = encoded(envelope.authTag, 16, 16);
      const ciphertext = encoded(envelope.ciphertext, 1, 4096);
      let response;
      try { response = await value.decryptDataKey({ CiphertextBlob: wrapped, KeyId: value.keyId,
        EncryptionContext: encryptionContext(value.application, value.tableName, current) }); }
      catch { deny('IDENTITY_ENVELOPE_UNAVAILABLE'); }
      const plaintext = Buffer.from(response?.Plaintext ?? []);
      if (plaintext.length !== 32) deny('IDENTITY_ENVELOPE_UNAVAILABLE');
      try {
        const decipher = createDecipheriv('aes-256-gcm', plaintext, nonce);
        decipher.setAAD(aad(value.application, value.tableName, current));
        decipher.setAuthTag(tag);
        const output = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
        if (output.length < 1 || output.length > 256 || /[\x00-\x20\x7f]/.test(output)) deny('IDENTITY_ENVELOPE_INVALID');
        return output;
      } catch (error) { if (error instanceof IdentityEnvelopeError) throw error; deny('IDENTITY_ENVELOPE_CONTEXT'); }
      finally { plaintext.fill(0); }
    }
  });
}

export const IDENTITY_ENVELOPE_PURPOSE = PURPOSE;
