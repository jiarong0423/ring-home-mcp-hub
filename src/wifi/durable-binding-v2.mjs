const BINDING_SCHEMA = 'ring-b02-durable-telegram-binding-v2';
const BINDING_PURPOSE = 'telegram-owner-bot-binding';
const MIGRATION_SCHEMA = 'ring-b02-binding-v1-to-v2-migration-v1';
const ROLLBACK_SCHEMA = 'ring-b02-binding-v1-rollback-v1';
const PROVIDER_PROOF_SCHEMA = 'ring-b02-provider-binding-proof-v1';
const PENDING_SCHEMA = 'ring-b02-pending-telegram-binding-v2';
const LEGACY_SCHEMA = 'ring-b02-formal-owner-authority-v1';
const LEGACY_PURPOSE = 'telegram-owner-authority';
const MAX_GRANT_TTL_MS = 300_000;

export class DurableBindingError extends Error {
  constructor(code) {
    super(code);
    this.name = 'DurableBindingError';
    this.code = code;
  }
}

function deny(code) {
  throw new DurableBindingError(code);
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

function exactOptional(value, allowed, required, code) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny(code);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const actual = Reflect.ownKeys(value);
  if (actual.some(key => typeof key !== 'string' || !allowed.includes(key)) ||
      required.some(key => !Object.hasOwn(descriptors, key)) ||
      Object.values(descriptors).some(item => !item.enumerable || !Object.hasOwn(item, 'value'))) deny(code);
  return value;
}

function time(value, code = 'B02_BINDING_TIME_DENIED') {
  if (!Number.isSafeInteger(value) || value <= 0 || value > 8_640_000_000_000_000) deny(code);
  return value;
}

function identity(value, code = 'B02_BINDING_IDENTITY_DENIED') {
  if (typeof value !== 'string' || !/^[A-Za-z][A-Za-z0-9:_-]{2,127}$/.test(value)) deny(code);
  return value;
}

function evidence(value, code = 'B02_BINDING_EVIDENCE_DENIED') {
  if (typeof value !== 'string' || !/^[A-Za-z0-9:_-]{1,128}$/.test(value)) deny(code);
  return value;
}

function generation(value, code = 'B02_BINDING_GENERATION_DENIED') {
  if (!Number.isSafeInteger(value) || value < 1 || value >= Number.MAX_SAFE_INTEGER) deny(code);
  return value;
}

function revision(value, code = 'B02_BINDING_REVISION_DENIED') {
  if (!Number.isSafeInteger(value) || value < 1 || value >= Number.MAX_SAFE_INTEGER) deny(code);
  return value;
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

export function validateDurableBindingV2(value, { allowRevoked = true } = {}) {
  const fields = exact(value, [
    'schema', 'version', 'purpose', 'active', 'revoked', 'ownerId', 'botId',
    'generation', 'verifiedAt', 'rotatedAt', 'revokedAt', 'evidenceVersion', 'secret'
  ], 'B02_BINDING_FORMAT_DENIED');
  if (fields.schema !== BINDING_SCHEMA || fields.version !== 2 || fields.purpose !== BINDING_PURPOSE ||
      typeof fields.active !== 'boolean' || typeof fields.revoked !== 'boolean' ||
      fields.active === fields.revoked || fields.secret !== null || (!allowRevoked && fields.revoked)) {
    deny('B02_BINDING_FORMAT_DENIED');
  }
  const verifiedAt = time(fields.verifiedAt);
  const rotatedAt = time(fields.rotatedAt);
  if (rotatedAt < verifiedAt || (fields.revoked ? fields.revokedAt === null : fields.revokedAt !== null)) {
    deny('B02_BINDING_TIME_DENIED');
  }
  if (fields.revoked && (time(fields.revokedAt) < rotatedAt)) deny('B02_BINDING_TIME_DENIED');
  return deepFreeze({
    schema: BINDING_SCHEMA,
    version: 2,
    purpose: BINDING_PURPOSE,
    active: fields.active,
    revoked: fields.revoked,
    ownerId: identity(fields.ownerId),
    botId: identity(fields.botId),
    generation: generation(fields.generation),
    verifiedAt,
    rotatedAt,
    revokedAt: fields.revokedAt,
    evidenceVersion: evidence(fields.evidenceVersion),
    secret: null
  });
}

export function createDurableBindingV2(input) {
  const fields = exact(input, ['ownerId', 'botId', 'generation', 'verifiedAt', 'rotatedAt', 'evidenceVersion'],
    'B02_BINDING_INPUT_DENIED');
  return validateDurableBindingV2({
    schema: BINDING_SCHEMA,
    version: 2,
    purpose: BINDING_PURPOSE,
    active: true,
    revoked: false,
    ownerId: fields.ownerId,
    botId: fields.botId,
    generation: fields.generation,
    verifiedAt: fields.verifiedAt,
    rotatedAt: fields.rotatedAt,
    revokedAt: null,
    evidenceVersion: fields.evidenceVersion,
    secret: null
  }, { allowRevoked: false });
}

export function rotateDurableBindingV2(current, input) {
  const previous = validateDurableBindingV2(current, { allowRevoked: false });
  const fields = exact(input, ['ownerId', 'botId', 'verifiedAt', 'rotatedAt', 'evidenceVersion'],
    'B02_BINDING_ROTATION_DENIED');
  if (time(fields.verifiedAt) < previous.verifiedAt || time(fields.rotatedAt) <= previous.rotatedAt) {
    deny('B02_BINDING_ROTATION_DENIED');
  }
  if (identity(fields.ownerId) !== previous.ownerId || identity(fields.botId) !== previous.botId) {
    deny('B02_BINDING_ROTATION_DENIED');
  }
  return createDurableBindingV2({
    ownerId: fields.ownerId,
    botId: fields.botId,
    generation: previous.generation + 1,
    verifiedAt: fields.verifiedAt,
    rotatedAt: fields.rotatedAt,
    evidenceVersion: fields.evidenceVersion
  });
}

export function validateFreshTelegramProof(value, expected) {
  const proof = exact(value, [
    'schema', 'provider', 'purpose', 'ownerId', 'botId', 'verifiedAt', 'expiresAt', 'nonce', 'secret'
  ], 'B02_PROVIDER_PROOF_DENIED');
  const observedAt = time(expected.observedAt, 'B02_PROVIDER_PROOF_DENIED');
  const verifiedAt = time(proof.verifiedAt, 'B02_PROVIDER_PROOF_DENIED');
  const expiresAt = time(proof.expiresAt, 'B02_PROVIDER_PROOF_DENIED');
  if (proof.schema !== PROVIDER_PROOF_SCHEMA || proof.provider !== 'telegram' ||
      proof.purpose !== expected.purpose || proof.secret !== null ||
      identity(proof.ownerId, 'B02_PROVIDER_PROOF_DENIED') !== expected.ownerId ||
      identity(proof.botId, 'B02_PROVIDER_PROOF_DENIED') !== expected.botId ||
      verifiedAt > observedAt || observedAt >= expiresAt || expiresAt - verifiedAt > MAX_GRANT_TTL_MS ||
      observedAt - verifiedAt > MAX_GRANT_TTL_MS ||
      typeof proof.nonce !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(proof.nonce)) {
    deny('B02_PROVIDER_PROOF_DENIED');
  }
  return Object.freeze({ verifiedAt, expiresAt });
}

export function rebindDurableBindingV2(current, input) {
  const previous = validateDurableBindingV2(current, { allowRevoked: false });
  const fields = exact(input, [
    'ownerId', 'botId', 'observedAt', 'evidenceVersion', 'providerProof', 'grant'
  ], 'B02_BINDING_REBIND_DENIED');
  const observedAt = time(fields.observedAt, 'B02_BINDING_REBIND_DENIED');
  const ownerId = identity(fields.ownerId, 'B02_BINDING_REBIND_DENIED');
  const botId = identity(fields.botId, 'B02_BINDING_REBIND_DENIED');
  if (ownerId === previous.ownerId && botId === previous.botId) deny('B02_BINDING_REBIND_DENIED');
  validateFreshTelegramProof(fields.grant, {
    ownerId: previous.ownerId,
    botId: previous.botId,
    observedAt,
    purpose: 'binding-rebind'
  });
  const proof = validateFreshTelegramProof(fields.providerProof, {
    ownerId,
    botId,
    observedAt,
    purpose: 'binding-verification'
  });
  return createDurableBindingV2({
    ownerId,
    botId,
    generation: previous.generation + 1,
    verifiedAt: proof.verifiedAt,
    rotatedAt: observedAt,
    evidenceVersion: evidence(fields.evidenceVersion, 'B02_BINDING_REBIND_DENIED')
  });
}

export function revokeDurableBindingV2(current, input) {
  const previous = validateDurableBindingV2(current, { allowRevoked: false });
  const fields = exact(input, ['revokedAt', 'evidenceVersion'], 'B02_BINDING_REVOCATION_DENIED');
  const revokedAt = time(fields.revokedAt);
  if (revokedAt <= previous.rotatedAt) deny('B02_BINDING_REVOCATION_DENIED');
  return validateDurableBindingV2({
    ...previous,
    active: false,
    revoked: true,
    generation: previous.generation + 1,
    rotatedAt: revokedAt,
    revokedAt,
    evidenceVersion: fields.evidenceVersion,
    secret: null
  });
}

export function createBindingEnvelopeV2(input) {
  const fields = exact(input, ['revision', 'record'], 'B02_BINDING_ENVELOPE_DENIED');
  return deepFreeze({
    schema: BINDING_SCHEMA,
    revision: revision(fields.revision),
    record: validateDurableBindingV2(fields.record)
  });
}

export function migrateLegacyBindingV1(legacyValue, options) {
  const legacy = exact(legacyValue, ['schema', 'revision', 'record'], 'B02_MIGRATION_SOURCE_DENIED');
  const settings = exactOptional(options, ['botId', 'observedAt', 'evidenceVersion', 'providerProof'],
    ['botId', 'observedAt', 'evidenceVersion'], 'B02_MIGRATION_INPUT_DENIED');
  if (legacy.schema !== LEGACY_SCHEMA) deny('B02_MIGRATION_SOURCE_DENIED');
  const sourceRevision = revision(legacy.revision, 'B02_MIGRATION_SOURCE_DENIED');
  const source = exact(legacy.record, [
    'version', 'purpose', 'ownerId', 'ownerGeneration', 'revoked', 'expiresAt',
    'evidenceVersion', 'mode', 'secret'
  ], 'B02_MIGRATION_SOURCE_DENIED');
  if (source.version !== 1 || source.purpose !== LEGACY_PURPOSE || source.mode !== 'formal' ||
      typeof source.revoked !== 'boolean' || source.secret !== null ||
      !Number.isSafeInteger(source.expiresAt) || source.expiresAt <= 0) deny('B02_MIGRATION_SOURCE_DENIED');
  const observedAt = time(settings.observedAt, 'B02_MIGRATION_INPUT_DENIED');
  const ownerId = identity(source.ownerId, 'B02_MIGRATION_SOURCE_DENIED');
  const botId = identity(settings.botId, 'B02_MIGRATION_INPUT_DENIED');
  const base = createDurableBindingV2({
    ownerId,
    botId,
    generation: generation(source.ownerGeneration, 'B02_MIGRATION_SOURCE_DENIED'),
    verifiedAt: observedAt,
    rotatedAt: observedAt,
    evidenceVersion: evidence(settings.evidenceVersion, 'B02_MIGRATION_INPUT_DENIED')
  });
  const migrated = source.revoked ? validateDurableBindingV2({
    ...base,
    active: false,
    revoked: true,
    revokedAt: observedAt,
    secret: null
  }) : base;
  let verificationStatus = source.revoked ? 'revoked' : 'pending_verification';
  let candidate = source.revoked ? createBindingEnvelopeV2({ revision: sourceRevision, record: migrated }) : null;
  let pendingVerification = null;
  if (!source.revoked && Object.hasOwn(settings, 'providerProof') && settings.providerProof !== null) {
    validateFreshTelegramProof(settings.providerProof, {
      ownerId,
      botId,
      observedAt,
      purpose: 'legacy-migration'
    });
    verificationStatus = 'active';
    candidate = createBindingEnvelopeV2({ revision: sourceRevision, record: migrated });
  } else if (!source.revoked) {
    pendingVerification = deepFreeze({
      schema: PENDING_SCHEMA,
      ownerId,
      botId,
      generation: migrated.generation,
      observedAt,
      evidenceVersion: migrated.evidenceVersion,
      secret: null
    });
  }
  const rollbackArtifact = deepFreeze({
    schema: ROLLBACK_SCHEMA,
    sourceSchema: LEGACY_SCHEMA,
    sourceRevision,
    createdAt: observedAt,
    restoreObject: cloneJson(legacyValue),
    secret: null
  });
  return deepFreeze({
    schema: MIGRATION_SCHEMA,
    mode: 'isolated-object-only',
    verificationStatus,
    candidate,
    pendingVerification,
    rollbackArtifact
  });
}

export const durableBindingConstants = Object.freeze({
  bindingSchema: BINDING_SCHEMA,
  providerProofSchema: PROVIDER_PROOF_SCHEMA,
  maximumFreshProofTtlMs: MAX_GRANT_TTL_MS
});
