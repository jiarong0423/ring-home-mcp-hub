import { validateDurableBindingV2, validateFreshTelegramProof } from './durable-binding-v2.mjs';
import { validateHouseholdWifiTrust, validateLocalWifiReceipt } from './household-wifi-trust.mjs';

const GRANT_SCHEMA = 'ring-b02-mcp-entry-grant-v2';
const RECEIPT_SCHEMA = 'ring-b02-mcp-entry-consumption-v1';
const RING_REFERENCE_SCHEMA = 'ring-b02-ring-reference-v1';
const ENTRY_CONTEXT_SCHEMA = 'ring-b02-mcp-entry-context-v1';
const MAX_GRANT_TTL_MS = 300_000;

export class McpEntryAdmissionError extends Error {
  constructor(code) {
    super(code);
    this.name = 'McpEntryAdmissionError';
    this.code = code;
  }
}

function deny(code) {
  throw new McpEntryAdmissionError(code);
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

function safeTime(value, code = 'B02_MCP_ENTRY_TIME_DENIED') {
  if (!Number.isSafeInteger(value) || value <= 0 || value > 8_640_000_000_000_000) deny(code);
  return value;
}

function identity(value, code = 'B02_MCP_ENTRY_IDENTITY_DENIED') {
  if (typeof value !== 'string' || !/^[A-Za-z][A-Za-z0-9:_-]{2,127}$/.test(value)) deny(code);
  return value;
}

function label(value, code = 'B02_MCP_ENTRY_LABEL_DENIED') {
  if (typeof value !== 'string' || !/^[a-z][a-z0-9:._-]{2,127}$/.test(value)) deny(code);
  return value;
}

function positiveInteger(value, code) {
  if (!Number.isSafeInteger(value) || value < 1 || value >= Number.MAX_SAFE_INTEGER) deny(code);
  return value;
}

function nonce(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(value)) deny('B02_MCP_ENTRY_NONCE_DENIED');
  return value;
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function validateRingReference(value, { allowRevoked = false } = {}) {
  const fields = exact(value, [
    'schema', 'active', 'revoked', 'ownerId', 'householdId', 'revision',
    'rotatedAt', 'revokedAt', 'secret'
  ], 'B02_RING_REFERENCE_DENIED');
  if (fields.schema !== RING_REFERENCE_SCHEMA || typeof fields.active !== 'boolean' ||
      typeof fields.revoked !== 'boolean' || fields.active === fields.revoked || fields.secret !== null ||
      (!allowRevoked && fields.revoked) || (fields.revoked ? fields.revokedAt === null : fields.revokedAt !== null)) {
    deny('B02_RING_REFERENCE_DENIED');
  }
  const rotatedAt = safeTime(fields.rotatedAt, 'B02_RING_REFERENCE_DENIED');
  if (fields.revoked && safeTime(fields.revokedAt, 'B02_RING_REFERENCE_DENIED') < rotatedAt) {
    deny('B02_RING_REFERENCE_DENIED');
  }
  return deepFreeze({
    schema: RING_REFERENCE_SCHEMA,
    active: fields.active,
    revoked: fields.revoked,
    ownerId: identity(fields.ownerId, 'B02_RING_REFERENCE_DENIED'),
    householdId: label(fields.householdId, 'B02_RING_REFERENCE_DENIED'),
    revision: positiveInteger(fields.revision, 'B02_RING_REFERENCE_DENIED'),
    rotatedAt,
    revokedAt: fields.revokedAt,
    secret: null
  });
}

function validateEntryContext(value) {
  const fields = exact(value, ['schema', 'entryId', 'observedAt', 'secret'], 'B02_MCP_ENTRY_CONTEXT_DENIED');
  if (fields.schema !== ENTRY_CONTEXT_SCHEMA || fields.secret !== null) deny('B02_MCP_ENTRY_CONTEXT_DENIED');
  return deepFreeze({
    schema: ENTRY_CONTEXT_SCHEMA,
    entryId: label(fields.entryId, 'B02_MCP_ENTRY_CONTEXT_DENIED'),
    observedAt: safeTime(fields.observedAt, 'B02_MCP_ENTRY_CONTEXT_DENIED'),
    secret: null
  });
}

function validateTrustPackage(value, householdId) {
  const fields = exact(value, ['record', 'receipt'], 'B02_MCP_ENTRY_TRUST_DENIED');
  const record = validateHouseholdWifiTrust(fields.record, { allowRevoked: false });
  const receipt = validateLocalWifiReceipt(fields.receipt, householdId);
  if (record.householdId !== householdId || record.generation !== receipt.trustGeneration ||
      record.fingerprintVersion !== receipt.fingerprintVersion ||
      record.keyedFingerprint !== receipt.keyedFingerprint) deny('B02_MCP_ENTRY_TRUST_DENIED');
  return deepFreeze({
    householdId: receipt.householdId,
    trustGeneration: receipt.trustGeneration,
    fingerprintVersion: receipt.fingerprintVersion,
    keyedFingerprint: receipt.keyedFingerprint,
    observedAt: receipt.observedAt
  });
}

function validateGrant(value) {
  const fields = exact(value, [
    'schema', 'version', 'ownerId', 'botId', 'bindingGeneration', 'ringRevision',
    'householdId', 'scope', 'capability', 'purpose', 'path', 'trust', 'entryContext',
    'issuedAt', 'expiresAt', 'nonce', 'singleUse', 'secret'
  ], 'B02_MCP_ENTRY_GRANT_DENIED');
  if (fields.schema !== GRANT_SCHEMA || fields.version !== 2 || fields.singleUse !== true ||
      fields.secret !== null || !['local-encrypted', 'remote-encrypted'].includes(fields.path)) {
    deny('B02_MCP_ENTRY_GRANT_DENIED');
  }
  const issuedAt = safeTime(fields.issuedAt, 'B02_MCP_ENTRY_GRANT_DENIED');
  const expiresAt = safeTime(fields.expiresAt, 'B02_MCP_ENTRY_GRANT_DENIED');
  if (expiresAt <= issuedAt || expiresAt - issuedAt > MAX_GRANT_TTL_MS) deny('B02_MCP_ENTRY_TIME_DENIED');
  const householdId = label(fields.householdId, 'B02_MCP_ENTRY_GRANT_DENIED');
  let trust = null;
  if (fields.path === 'local-encrypted') {
    const local = exact(fields.trust, [
      'householdId', 'trustGeneration', 'fingerprintVersion', 'keyedFingerprint', 'observedAt'
    ], 'B02_MCP_ENTRY_TRUST_DENIED');
    if (local.householdId !== householdId || local.fingerprintVersion !== 'hmac-sha256-v1' ||
        typeof local.keyedFingerprint !== 'string' || !/^wfk1\.[A-Za-z0-9_-]{43}$/.test(local.keyedFingerprint)) {
      deny('B02_MCP_ENTRY_TRUST_DENIED');
    }
    trust = deepFreeze({
      householdId,
      trustGeneration: positiveInteger(local.trustGeneration, 'B02_MCP_ENTRY_TRUST_DENIED'),
      fingerprintVersion: 'hmac-sha256-v1',
      keyedFingerprint: local.keyedFingerprint,
      observedAt: safeTime(local.observedAt, 'B02_MCP_ENTRY_TRUST_DENIED')
    });
  } else if (fields.trust !== null) {
    deny('B02_MCP_ENTRY_TRUST_DENIED');
  }
  return deepFreeze({
    schema: GRANT_SCHEMA,
    version: 2,
    ownerId: identity(fields.ownerId, 'B02_MCP_ENTRY_GRANT_DENIED'),
    botId: identity(fields.botId, 'B02_MCP_ENTRY_GRANT_DENIED'),
    bindingGeneration: positiveInteger(fields.bindingGeneration, 'B02_MCP_ENTRY_GRANT_DENIED'),
    ringRevision: positiveInteger(fields.ringRevision, 'B02_MCP_ENTRY_GRANT_DENIED'),
    householdId,
    scope: label(fields.scope, 'B02_MCP_ENTRY_GRANT_DENIED'),
    capability: label(fields.capability, 'B02_MCP_ENTRY_GRANT_DENIED'),
    purpose: label(fields.purpose, 'B02_MCP_ENTRY_GRANT_DENIED'),
    path: fields.path,
    trust,
    entryContext: validateEntryContext(fields.entryContext),
    issuedAt,
    expiresAt,
    nonce: nonce(fields.nonce),
    singleUse: true,
    secret: null
  });
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

export function createMcpEntryAdmissionPort({ clock, sessionAuthority = null }) {
  if (typeof clock !== 'function') deny('B02_MCP_ENTRY_CLOCK_DENIED');
  const issued = new Map();
  const consumed = new Set();
  const sessionIssued = new Map();

  function issueGrant(input, session = null) {
    const fields = exact(input, [
      'binding', 'providerProof', 'ringReference', 'householdId', 'scope', 'capability',
      'purpose', 'path', 'wifiTrust', 'entryContext', 'nonce', 'expiresAt'
    ], 'B02_MCP_ENTRY_INPUT_DENIED');
    const now = safeTime(clock());
    const binding = validateDurableBindingV2(fields.binding, { allowRevoked: false });
    const householdId = label(fields.householdId);
    const ringReference = validateRingReference(fields.ringReference);
    if (ringReference.ownerId !== binding.ownerId || ringReference.householdId !== householdId) {
      deny('B02_MCP_ENTRY_BINDING_DENIED');
    }
    if (!['local-encrypted', 'remote-encrypted'].includes(fields.path)) deny('B02_MCP_ENTRY_PATH_DENIED');
    if (fields.path === 'local-encrypted') {
      if (fields.providerProof !== null) deny('B02_PROVIDER_PROOF_DENIED');
    } else {
      if (fields.wifiTrust !== null) deny('B02_MCP_ENTRY_TRUST_DENIED');
      if (session !== null) {
        if (fields.providerProof !== null || session.ownerId !== binding.ownerId || session.botId !== binding.botId ||
            session.bindingGeneration !== binding.generation || fields.expiresAt > session.expiresMonotonicMs) deny('B02_MCP_SESSION_BINDING_DENIED');
      } else validateFreshTelegramProof(fields.providerProof, {
        ownerId: binding.ownerId,
        botId: binding.botId,
        observedAt: now,
        purpose: 'mcp-admission'
      });
    }
    const entryContext = validateEntryContext(fields.entryContext);
    if (entryContext.observedAt > now || now - entryContext.observedAt > MAX_GRANT_TTL_MS) {
      deny('B02_MCP_ENTRY_CONTEXT_DENIED');
    }
    const expiresAt = safeTime(fields.expiresAt);
    if (expiresAt <= now || expiresAt - now > MAX_GRANT_TTL_MS) deny('B02_MCP_ENTRY_TIME_DENIED');
    const grantNonce = nonce(fields.nonce);
    if (issued.has(grantNonce)) deny('B02_MCP_ENTRY_NONCE_REUSE_DENIED');
    let trust = null;
    if (fields.path === 'local-encrypted') {
      trust = validateTrustPackage(fields.wifiTrust, householdId);
      if (trust.observedAt > now || now - trust.observedAt > MAX_GRANT_TTL_MS) deny('B02_MCP_ENTRY_TRUST_DENIED');
    }
    const grant = validateGrant({
      schema: GRANT_SCHEMA,
      version: 2,
      ownerId: binding.ownerId,
      botId: binding.botId,
      bindingGeneration: binding.generation,
      ringRevision: ringReference.revision,
      householdId,
      scope: fields.scope,
      capability: fields.capability,
      purpose: fields.purpose,
      path: fields.path,
      trust,
      entryContext,
      issuedAt: now,
      expiresAt,
      nonce: grantNonce,
      singleUse: true,
      secret: null
    });
    issued.set(grantNonce, grant);
    return grant;
  }

  function issueMcpEntryGrant(input) { return issueGrant(input); }

  function sessionSnapshot(input, method) {
    if (!sessionAuthority || typeof sessionAuthority[method] !== 'function') deny('B02_MCP_SESSION_AUTHORITY_DENIED');
    const session = exact(sessionAuthority[method]({ receipt: input.sessionReceipt, entryId: input.sessionEntryId,
      bootEpoch: input.sessionBootEpoch, scope: input.scope, capability: input.capability, purpose: input.purpose }),
      ['schema', 'ownerId', 'botId', 'bindingGeneration', 'bootEpoch', 'expiresMonotonicMs', 'scope', 'capability', 'purpose', 'entryId'],
      'B02_MCP_SESSION_RECEIPT_DENIED');
    if (session.schema !== 'validated-owner-session-v1' || session.bootEpoch !== input.sessionBootEpoch ||
        session.entryId !== input.sessionEntryId || session.scope !== input.scope || session.capability !== input.capability ||
        session.purpose !== input.purpose || !Number.isSafeInteger(session.expiresMonotonicMs) ||
        session.expiresMonotonicMs <= safeTime(clock())) deny('B02_MCP_SESSION_RECEIPT_DENIED');
    return session;
  }

  function issueSessionMcpEntryGrant(input) {
    const fields = exact(input, ['binding', 'ringReference', 'householdId', 'scope', 'capability', 'purpose', 'path',
      'wifiTrust', 'entryContext', 'nonce', 'expiresAt', 'sessionReceipt', 'sessionEntryId', 'sessionBootEpoch'], 'B02_MCP_SESSION_INPUT_DENIED');
    if (fields.path !== 'remote-encrypted' || fields.wifiTrust !== null) deny('B02_MCP_SESSION_INPUT_DENIED');
    const session = sessionSnapshot(fields, 'validateClaimedSessionReceipt');
    const { sessionReceipt, sessionEntryId, sessionBootEpoch, ...grantInput } = fields;
    const grant = issueGrant({ ...grantInput, providerProof: null,
      expiresAt: Math.min(fields.expiresAt, session.expiresMonotonicMs) }, session);
    sessionIssued.set(grant.nonce, Object.freeze({ receipt: sessionReceipt, entryId: sessionEntryId, bootEpoch: sessionBootEpoch }));
    return grant;
  }

  function consumeSessionMcpEntryGrant(input) {
    const fields = exact(input, ['grant', 'binding', 'ringReference', 'wifiTrust', 'sessionReceipt', 'sessionEntryId', 'sessionBootEpoch'],
      'B02_MCP_SESSION_INPUT_DENIED');
    const grant = validateGrant(fields.grant);
    if (grant.path !== 'remote-encrypted') deny('B02_MCP_SESSION_INPUT_DENIED');
    const source = sessionIssued.get(grant.nonce);
    if (!source || source.receipt !== fields.sessionReceipt || source.entryId !== fields.sessionEntryId ||
        source.bootEpoch !== fields.sessionBootEpoch || !sameJson(issued.get(grant.nonce), grant)) {
      deny('B02_MCP_SESSION_SOURCE_DENIED');
    }
    if (consumed.has(grant.nonce)) deny('B02_MCP_ENTRY_REPLAY_DENIED');
    const session = sessionSnapshot({ ...fields, scope: grant.scope, capability: grant.capability, purpose: grant.purpose }, 'finishSessionReceipt');
    if (session.ownerId !== grant.ownerId || session.botId !== grant.botId || session.bindingGeneration !== grant.bindingGeneration ||
        grant.expiresAt > session.expiresMonotonicMs) deny('B02_MCP_SESSION_BINDING_DENIED');
    return consumeGrant({ grant: fields.grant, binding: fields.binding, ringReference: fields.ringReference, wifiTrust: fields.wifiTrust });
  }

  function consumeMcpEntryGrant(input) {
    const fields = exact(input, ['grant', 'binding', 'ringReference', 'wifiTrust'], 'B02_MCP_ENTRY_CONSUME_DENIED');
    const grant = validateGrant(fields.grant);
    if (sessionIssued.has(grant.nonce)) deny('B02_MCP_SESSION_CONSUMER_REQUIRED');
    return consumeGrant(fields);
  }

  function consumeGrant(input) {
    const fields = exact(input, ['grant', 'binding', 'ringReference', 'wifiTrust'],
      'B02_MCP_ENTRY_CONSUME_DENIED');
    const now = safeTime(clock());
    const grant = validateGrant(fields.grant);
    if (now >= grant.expiresAt) deny('B02_MCP_ENTRY_EXPIRED');
    if (consumed.has(grant.nonce)) deny('B02_MCP_ENTRY_REPLAY_DENIED');
    const recorded = issued.get(grant.nonce);
    if (!recorded || !sameJson(recorded, grant)) deny('B02_MCP_ENTRY_UNKNOWN_GRANT_DENIED');
    const binding = validateDurableBindingV2(fields.binding, { allowRevoked: false });
    const ringReference = validateRingReference(fields.ringReference);
    if (binding.ownerId !== grant.ownerId || binding.botId !== grant.botId ||
        binding.generation !== grant.bindingGeneration || ringReference.ownerId !== grant.ownerId ||
        ringReference.householdId !== grant.householdId || ringReference.revision !== grant.ringRevision) {
      deny('B02_MCP_ENTRY_BINDING_DENIED');
    }
    if (grant.path === 'local-encrypted') {
      const currentTrust = validateHouseholdWifiTrust(fields.wifiTrust, { allowRevoked: false });
      if (currentTrust.householdId !== grant.trust.householdId ||
          currentTrust.generation !== grant.trust.trustGeneration ||
          currentTrust.fingerprintVersion !== grant.trust.fingerprintVersion ||
          currentTrust.keyedFingerprint !== grant.trust.keyedFingerprint) deny('B02_MCP_ENTRY_TRUST_DENIED');
    } else if (fields.wifiTrust !== null) {
      deny('B02_MCP_ENTRY_TRUST_DENIED');
    }
    consumed.add(grant.nonce);
    return deepFreeze({
      schema: RECEIPT_SCHEMA,
      accepted: true,
      nonce: grant.nonce,
      consumedAt: now,
      secret: null
    });
  }

  return Object.freeze({
    issueMcpEntryGrant,
    issueSessionMcpEntryGrant,
    consumeSessionMcpEntryGrant,
    consumeMcpEntryGrant,
    status() { return Object.freeze({ issuedCount: issued.size, consumedCount: consumed.size }); }
  });
}

export function createRingReference(input) {
  return validateRingReference(input);
}

export const mcpEntryAdmissionConstants = Object.freeze({
  grantSchema: GRANT_SCHEMA,
  consumptionSchema: RECEIPT_SCHEMA,
  ringReferenceSchema: RING_REFERENCE_SCHEMA,
  entryContextSchema: ENTRY_CONTEXT_SCHEMA,
  maximumGrantTtlMs: MAX_GRANT_TTL_MS
});
