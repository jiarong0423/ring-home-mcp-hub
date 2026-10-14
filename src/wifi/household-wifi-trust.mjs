import { timingSafeEqual } from 'node:crypto';

const TRUST_SCHEMA = 'ring-b02-household-wifi-trust-v1';
const RECEIPT_SCHEMA = 'ring-b02-household-wifi-local-receipt-v1';
const PURPOSE = 'household-wifi-transport-trust';
const FINGERPRINT_VERSION = 'hmac-sha256-v1';

export class HouseholdWifiTrustError extends Error {
  constructor(code) {
    super(code);
    this.name = 'HouseholdWifiTrustError';
    this.code = code;
  }
}

function deny(code) {
  throw new HouseholdWifiTrustError(code);
}

function exact(value, keys, code) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny(code);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some(key => typeof key !== 'string' || !keys.includes(key)) ||
      keys.some(key => !Object.hasOwn(descriptors, key)) ||
      Object.values(descriptors).some(item => !item.enumerable || !Object.hasOwn(item, 'value'))) deny(code);
  return value;
}

function safeTime(value, code = 'B02_WIFI_TIME_DENIED') {
  if (!Number.isSafeInteger(value) || value <= 0 || value > 8_640_000_000_000_000) deny(code);
  return value;
}

function label(value, code) {
  if (typeof value !== 'string' || !/^[a-z][a-z0-9:._-]{2,127}$/.test(value)) deny(code);
  return value;
}

function generation(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value >= Number.MAX_SAFE_INTEGER) {
    deny('B02_WIFI_GENERATION_DENIED');
  }
  return value;
}

function keyedFingerprint(value) {
  if (typeof value !== 'string' || !/^wfk1\.[A-Za-z0-9_-]{43}$/.test(value)) {
    deny('B02_WIFI_FINGERPRINT_DENIED');
  }
  return value;
}

function evidence(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9:_-]{1,128}$/.test(value)) {
    deny('B02_WIFI_EVIDENCE_DENIED');
  }
  return value;
}

function sameFingerprint(left, right) {
  const first = Buffer.from(keyedFingerprint(left), 'utf8');
  const second = Buffer.from(keyedFingerprint(right), 'utf8');
  try { return timingSafeEqual(first, second); }
  finally { first.fill(0); second.fill(0); }
}

export function validateHouseholdWifiTrust(value, { allowRevoked = true } = {}) {
  const fields = exact(value, [
    'schema', 'version', 'purpose', 'active', 'revoked', 'householdId', 'generation',
    'fingerprintVersion', 'keyedFingerprint', 'verifiedAt', 'rotatedAt', 'revokedAt',
    'consentEvidence', 'secret'
  ], 'B02_WIFI_RECORD_DENIED');
  if (fields.schema !== TRUST_SCHEMA || fields.version !== 1 || fields.purpose !== PURPOSE ||
      typeof fields.active !== 'boolean' || typeof fields.revoked !== 'boolean' ||
      fields.active === fields.revoked || fields.secret !== null ||
      fields.fingerprintVersion !== FINGERPRINT_VERSION || (!allowRevoked && fields.revoked)) {
    deny('B02_WIFI_RECORD_DENIED');
  }
  const verifiedAt = safeTime(fields.verifiedAt);
  const rotatedAt = safeTime(fields.rotatedAt);
  if (rotatedAt < verifiedAt || (fields.revoked ? fields.revokedAt === null : fields.revokedAt !== null) ||
      (fields.revoked && safeTime(fields.revokedAt) < rotatedAt)) deny('B02_WIFI_TIME_DENIED');
  return Object.freeze({
    schema: TRUST_SCHEMA,
    version: 1,
    purpose: PURPOSE,
    active: fields.active,
    revoked: fields.revoked,
    householdId: label(fields.householdId, 'B02_WIFI_HOUSEHOLD_DENIED'),
    generation: generation(fields.generation),
    fingerprintVersion: FINGERPRINT_VERSION,
    keyedFingerprint: keyedFingerprint(fields.keyedFingerprint),
    verifiedAt,
    rotatedAt,
    revokedAt: fields.revokedAt,
    consentEvidence: evidence(fields.consentEvidence),
    secret: null
  });
}

export function createHouseholdWifiTrust(input) {
  const fields = exact(input, [
    'householdId', 'generation', 'keyedFingerprint', 'verifiedAt', 'rotatedAt', 'consentEvidence'
  ], 'B02_WIFI_INPUT_DENIED');
  return validateHouseholdWifiTrust({
    schema: TRUST_SCHEMA,
    version: 1,
    purpose: PURPOSE,
    active: true,
    revoked: false,
    householdId: fields.householdId,
    generation: fields.generation,
    fingerprintVersion: FINGERPRINT_VERSION,
    keyedFingerprint: fields.keyedFingerprint,
    verifiedAt: fields.verifiedAt,
    rotatedAt: fields.rotatedAt,
    revokedAt: null,
    consentEvidence: fields.consentEvidence,
    secret: null
  }, { allowRevoked: false });
}

export function rotateHouseholdWifiTrust(current, input) {
  const previous = validateHouseholdWifiTrust(current, { allowRevoked: false });
  const fields = exact(input, ['householdId', 'keyedFingerprint', 'rotatedAt', 'consentEvidence'],
    'B02_WIFI_ROTATION_DENIED');
  const rotatedAt = safeTime(fields.rotatedAt, 'B02_WIFI_ROTATION_DENIED');
  if (label(fields.householdId, 'B02_WIFI_ROTATION_DENIED') !== previous.householdId ||
      rotatedAt <= previous.rotatedAt || sameFingerprint(fields.keyedFingerprint, previous.keyedFingerprint)) {
    deny('B02_WIFI_ROTATION_DENIED');
  }
  return createHouseholdWifiTrust({
    householdId: previous.householdId,
    generation: previous.generation + 1,
    keyedFingerprint: fields.keyedFingerprint,
    verifiedAt: rotatedAt,
    rotatedAt,
    consentEvidence: fields.consentEvidence
  });
}

export function revokeHouseholdWifiTrust(current, input) {
  const previous = validateHouseholdWifiTrust(current, { allowRevoked: false });
  const fields = exact(input, ['revokedAt', 'consentEvidence'], 'B02_WIFI_REVOCATION_DENIED');
  const revokedAt = safeTime(fields.revokedAt, 'B02_WIFI_REVOCATION_DENIED');
  if (revokedAt <= previous.rotatedAt) deny('B02_WIFI_REVOCATION_DENIED');
  return validateHouseholdWifiTrust({
    ...previous,
    active: false,
    revoked: true,
    generation: previous.generation + 1,
    rotatedAt: revokedAt,
    revokedAt,
    consentEvidence: fields.consentEvidence,
    secret: null
  });
}

export function recognizeHouseholdWifi(input) {
  const fields = exact(input, ['trust', 'observedKeyedFingerprint', 'observedAt'], 'B02_WIFI_RECOGNITION_DENIED');
  const trust = validateHouseholdWifiTrust(fields.trust, { allowRevoked: false });
  const observedAt = safeTime(fields.observedAt, 'B02_WIFI_RECOGNITION_DENIED');
  if (observedAt < trust.verifiedAt || !sameFingerprint(fields.observedKeyedFingerprint, trust.keyedFingerprint)) {
    deny('B02_WIFI_RECOGNITION_DENIED');
  }
  return Object.freeze({
    schema: RECEIPT_SCHEMA,
    householdId: trust.householdId,
    trustGeneration: trust.generation,
    fingerprintVersion: FINGERPRINT_VERSION,
    keyedFingerprint: trust.keyedFingerprint,
    observedAt,
    transport: 'local-encrypted',
    secret: null
  });
}

export function validateLocalWifiReceipt(value, expectedHouseholdId) {
  const fields = exact(value, [
    'schema', 'householdId', 'trustGeneration', 'fingerprintVersion', 'keyedFingerprint',
    'observedAt', 'transport', 'secret'
  ], 'B02_WIFI_RECEIPT_DENIED');
  if (fields.schema !== RECEIPT_SCHEMA || fields.transport !== 'local-encrypted' || fields.secret !== null ||
      fields.fingerprintVersion !== FINGERPRINT_VERSION ||
      label(fields.householdId, 'B02_WIFI_RECEIPT_DENIED') !== expectedHouseholdId) deny('B02_WIFI_RECEIPT_DENIED');
  return Object.freeze({
    schema: RECEIPT_SCHEMA,
    householdId: fields.householdId,
    trustGeneration: generation(fields.trustGeneration),
    fingerprintVersion: FINGERPRINT_VERSION,
    keyedFingerprint: keyedFingerprint(fields.keyedFingerprint),
    observedAt: safeTime(fields.observedAt, 'B02_WIFI_RECEIPT_DENIED'),
    transport: 'local-encrypted',
    secret: null
  });
}

export const householdWifiTrustConstants = Object.freeze({
  trustSchema: TRUST_SCHEMA,
  receiptSchema: RECEIPT_SCHEMA,
  fingerprintVersion: FINGERPRINT_VERSION
});
