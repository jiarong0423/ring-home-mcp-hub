import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { ProtocolError, requireOpaque } from './protocol.mjs';

export const TOKEN_ENVELOPE_VERSION = 2;
export const TOKEN_ENVELOPE_LEGACY_VERSION = 1;
export const TOKEN_ENVELOPE_PURPOSE = 'RING_LINK_TOKENS';

const BASE64URL = /^[A-Za-z0-9_-]+$/;
const MAX_TOKEN_BYTES = 16_384;
const MAX_BLOB_BYTES = 65_536;
const LEGACY_PAYLOAD_KEYS = Object.freeze(['accountId', 'accessToken', 'refreshToken', 'tokenExpiresAt']);
const PAYLOAD_KEYS = Object.freeze([
  'accountId', 'accessToken', 'refreshToken', 'tokenExpiresAt', 'refreshTokenExpiresAt', 'rotation'
]);
const ENVELOPE_KEYS = Object.freeze([
  'schemaVersion',
  'purpose',
  'linkId',
  'revision',
  'encryptedDataKey',
  'nonce',
  'authTag',
  'ciphertext'
]);

function exactDataValues(value, required, optional = [], errorCode = 'token_envelope_invalid') {
  let descriptors;
  let prototype;
  let symbols;
  try {
    descriptors = Object.getOwnPropertyDescriptors(value);
    prototype = Object.getPrototypeOf(value);
    symbols = Object.getOwnPropertySymbols(value);
  } catch {
    throw new ProtocolError(errorCode);
  }
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(descriptors);
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      (prototype !== Object.prototype && prototype !== null) || symbols.length !== 0 ||
      required.some(key => !Object.hasOwn(descriptors, key)) || keys.some(key => !allowed.has(key)) ||
      keys.some(key => !Object.hasOwn(descriptors[key], 'value'))) {
    throw new ProtocolError(errorCode);
  }
  return Object.fromEntries(keys.map(key => [key, descriptors[key].value]));
}

function requirePositiveInteger(value, code = 'token_envelope_invalid') {
  if (!Number.isSafeInteger(value) || value < 1) throw new ProtocolError(code);
  return value;
}

function requireFutureEpoch(value) {
  if (!Number.isSafeInteger(value) || value < 1) throw new ProtocolError('token_payload_invalid');
  return value;
}

function decodeBlob(value, minimum, maximum = MAX_BLOB_BYTES) {
  if (typeof value !== 'string' || !BASE64URL.test(value)) throw new ProtocolError('token_envelope_invalid');
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length < minimum || decoded.length > maximum || decoded.toString('base64url') !== value) {
    throw new ProtocolError('token_envelope_invalid');
  }
  return decoded;
}

function encryptionContext({ application, tableName, linkId, revision, purpose, schemaVersion }) {
  return Object.freeze({
    app: application,
    table: tableName,
    schema_version: String(schemaVersion),
    purpose,
    link_id: linkId,
    revision: String(revision)
  });
}

function contextBytes(context) {
  return Buffer.from(JSON.stringify([
    context.app,
    context.table,
    context.schema_version,
    context.purpose,
    context.link_id,
    context.revision
  ]), 'utf8');
}

function requirePayload(payload, schemaVersion, revision) {
  const keys = schemaVersion === TOKEN_ENVELOPE_LEGACY_VERSION ? LEGACY_PAYLOAD_KEYS : PAYLOAD_KEYS;
  const values = exactDataValues(payload, keys, [], 'token_payload_invalid');
  try {
    requireOpaque(values.accountId, 256);
    requireOpaque(values.accessToken, MAX_TOKEN_BYTES);
    requireOpaque(values.refreshToken, MAX_TOKEN_BYTES);
  } catch {
    throw new ProtocolError('token_payload_invalid');
  }
  requireFutureEpoch(values.tokenExpiresAt);
  const normalized = {
    accountId: values.accountId,
    accessToken: values.accessToken,
    refreshToken: values.refreshToken,
    tokenExpiresAt: values.tokenExpiresAt
  };
  if (schemaVersion === TOKEN_ENVELOPE_VERSION) {
    requireFutureEpoch(values.refreshTokenExpiresAt);
    requirePositiveInteger(values.rotation, 'token_payload_invalid');
    if (values.refreshTokenExpiresAt <= values.tokenExpiresAt || values.rotation !== revision) {
      throw new ProtocolError('token_payload_invalid');
    }
    normalized.refreshTokenExpiresAt = values.refreshTokenExpiresAt;
    normalized.rotation = values.rotation;
  }
  return normalized;
}

function requireEnvelope(envelope, expected) {
  const values = exactDataValues(envelope, ENVELOPE_KEYS, [], 'token_envelope_context');
  if (![TOKEN_ENVELOPE_LEGACY_VERSION, TOKEN_ENVELOPE_VERSION].includes(values.schemaVersion) ||
      values.purpose !== expected.purpose ||
      values.linkId !== expected.linkId ||
      values.revision !== expected.revision) {
    throw new ProtocolError('token_envelope_context');
  }
  return {
    encryptedDataKey: decodeBlob(values.encryptedDataKey, 1),
    nonce: decodeBlob(values.nonce, 12, 12),
    authTag: decodeBlob(values.authTag, 16, 16),
    ciphertext: decodeBlob(values.ciphertext, 1)
  };
}

function keyFrom(value, errorCode) {
  let key;
  try {
    key = Buffer.from(value ?? []);
  } catch {
    throw new ProtocolError(errorCode);
  }
  if (key.length !== 32) {
    key.fill(0);
    throw new ProtocolError(errorCode);
  }
  return key;
}

export function createTokenEnvelope({
  generateDataKey,
  decryptDataKey,
  keyId,
  application = 'ring-private',
  tableName,
  random = randomBytes
} = {}) {
  if (typeof generateDataKey !== 'function' || typeof decryptDataKey !== 'function' ||
      typeof random !== 'function' || typeof keyId !== 'string' || keyId.length < 3 || keyId.length > 2048 ||
      typeof application !== 'string' || !/^[A-Za-z0-9_.-]{3,64}$/.test(application) ||
      typeof tableName !== 'string' || !/^[A-Za-z0-9_.-]{3,255}$/.test(tableName)) {
    throw new ProtocolError('token_envelope_config');
  }

  function expected(options) {
    const values = exactDataValues(options, ['linkId', 'revision'], ['purpose'], 'token_envelope_context');
    const { linkId, revision } = values;
    const purpose = values.purpose ?? TOKEN_ENVELOPE_PURPOSE;
    requireOpaque(linkId, 256);
    requirePositiveInteger(revision);
    if (purpose !== TOKEN_ENVELOPE_PURPOSE) throw new ProtocolError('token_envelope_context');
    return { linkId, revision, purpose };
  }

  return Object.freeze({
    async seal(payload, options) {
      const binding = expected(options);
      const { linkId, revision, purpose } = binding;
      let schemaVersion;
      try {
        const payloadKeys = Reflect.ownKeys(Object.getOwnPropertyDescriptors(payload));
        schemaVersion = payloadKeys.length === LEGACY_PAYLOAD_KEYS.length &&
          payloadKeys.every(key => typeof key === 'string' && LEGACY_PAYLOAD_KEYS.includes(key))
          ? TOKEN_ENVELOPE_LEGACY_VERSION
          : TOKEN_ENVELOPE_VERSION;
      } catch {
        throw new ProtocolError('token_payload_invalid');
      }
      const normalized = requirePayload(payload, schemaVersion, revision);
      const context = encryptionContext({ application, tableName, ...binding, schemaVersion });
      let response;
      try {
        response = await generateDataKey({
          KeyId: keyId,
          KeySpec: 'AES_256',
          EncryptionContext: context
        });
      } catch {
        throw new ProtocolError('token_envelope_unavailable');
      }
      let encryptedDataKey;
      try {
        encryptedDataKey = Buffer.from(response?.CiphertextBlob ?? []);
      } catch {
        throw new ProtocolError('token_envelope_unavailable');
      }
      if (encryptedDataKey.length === 0 || encryptedDataKey.length > MAX_BLOB_BYTES) {
        throw new ProtocolError('token_envelope_unavailable');
      }
      const key = keyFrom(response?.Plaintext, 'token_envelope_unavailable');
      try {
        const nonce = Buffer.from(random(12));
        if (nonce.length !== 12) throw new ProtocolError('token_envelope_config');
        const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
        cipher.setAAD(contextBytes(context));
        const ciphertext = Buffer.concat([
          cipher.update(JSON.stringify(normalized), 'utf8'),
          cipher.final()
        ]);
        return Object.freeze({
          schemaVersion,
          purpose,
          linkId,
          revision,
          encryptedDataKey: encryptedDataKey.toString('base64url'),
          nonce: nonce.toString('base64url'),
          authTag: cipher.getAuthTag().toString('base64url'),
          ciphertext: ciphertext.toString('base64url')
        });
      } catch (error) {
        if (error instanceof ProtocolError) throw error;
        throw new ProtocolError('token_envelope_invalid');
      } finally {
        key.fill(0);
      }
    },

    async open(envelope, options) {
      const binding = expected(options);
      const { linkId, revision, purpose } = binding;
      const decoded = requireEnvelope(envelope, binding);
      const schemaVersion = envelope.schemaVersion;
      const context = encryptionContext({ application, tableName, ...binding, schemaVersion });
      let response;
      try {
        response = await decryptDataKey({
          KeyId: keyId,
          CiphertextBlob: decoded.encryptedDataKey,
          EncryptionContext: context
        });
      } catch {
        throw new ProtocolError('token_envelope_unavailable');
      }
      const key = keyFrom(response?.Plaintext, 'token_envelope_unavailable');
      try {
        const decipher = createDecipheriv('aes-256-gcm', key, decoded.nonce, { authTagLength: 16 });
        decipher.setAAD(contextBytes(context));
        decipher.setAuthTag(decoded.authTag);
        const plaintext = Buffer.concat([decipher.update(decoded.ciphertext), decipher.final()]);
        if (plaintext.length > MAX_BLOB_BYTES) throw new ProtocolError('token_payload_invalid');
        let payload;
        try {
          payload = JSON.parse(plaintext.toString('utf8'));
        } catch {
          throw new ProtocolError('token_payload_invalid');
        }
        return Object.freeze(requirePayload(payload, schemaVersion, revision));
      } catch (error) {
        if (error instanceof ProtocolError) throw error;
        throw new ProtocolError('token_envelope_invalid');
      } finally {
        key.fill(0);
      }
    }
  });
}
