import { types } from 'node:util';

const DIGEST = /^[0-9a-f]{64}$/;
const REF = /^[A-Za-z][A-Za-z0-9._/@-]{2,255}$/;
const SCOPE = /^[A-Za-z][A-Za-z0-9._:/@-]{2,255}$/;
const KMS_KEY_ARN = /^arn:(aws|aws-us-gov|aws-cn):kms:([a-z]{2}(?:-[a-z]+)+-[0-9]):[0-9]{12}:key\/(?:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}|mrk-[a-f0-9]{32})$/u;
function keyIdentifier(value) {
  if (typeof value !== 'string' || value.length > 255) return false;
  if (REF.test(value)) return true;
  const arn = KMS_KEY_ARN.exec(value);
  if (!arn) return false;
  const partition = arn[2].startsWith('cn-') ? 'aws-cn' : arn[2].startsWith('us-gov-') ? 'aws-us-gov' : 'aws';
  return arn[1] === partition;
}

export class DynamoIdentityAuthorityStoreError extends Error {
  constructor(code) {
    super(code);
    this.name = 'DynamoIdentityAuthorityStoreError';
    this.code = code;
  }
}

function deny(code) { throw new DynamoIdentityAuthorityStoreError(code); }

function exact(value, required, optional = [], code = 'AUTHORITY_INPUT_DENIED') {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny(code);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    const allowed = new Set([...required, ...optional]);
    if (required.some(key => !Object.hasOwn(descriptors, key)) ||
        keys.some(key => typeof key !== 'string' || !allowed.has(key) ||
          !Object.hasOwn(descriptors[key], 'value'))) deny(code);
    return Object.fromEntries(keys.map(key => [key, descriptors[key].value]));
  } catch (error) {
    if (error instanceof DynamoIdentityAuthorityStoreError) throw error;
    deny(code);
  }
}

function digest(value, code = 'AUTHORITY_INPUT_DENIED') {
  if (typeof value !== 'string' || !DIGEST.test(value)) deny(code);
  return value;
}

function reference(value, code = 'AUTHORITY_INPUT_DENIED') {
  if (typeof value !== 'string' || !REF.test(value)) deny(code);
  return value;
}

function positive(value, code = 'AUTHORITY_INPUT_DENIED') {
  if (!Number.isSafeInteger(value) || value < 1) deny(code);
  return value;
}

function scopes(value, code = 'AUTHORITY_INPUT_DENIED') {
  if (!Array.isArray(value) || types.isProxy(value) || value.length < 1 || value.length > 16) deny(code);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const result = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'string' ||
        !SCOPE.test(descriptor.value)) deny(code);
    result.push(descriptor.value);
  }
  if (Reflect.ownKeys(descriptors).some(key => key !== 'length' &&
      (typeof key !== 'string' || !/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length)) ||
      new Set(result).size !== result.length) deny(code);
  return Object.freeze(result);
}

function envelope(value) {
  const item = exact(value, ['version', 'purpose', 'keyId', 'encryptedDataKey', 'nonce', 'authTag', 'ciphertext']);
  if (item.version !== 1 || item.purpose !== 'RING_ACCOUNT_IDENTITY' ||
      !keyIdentifier(item.keyId)) deny('AUTHORITY_INPUT_DENIED');
  for (const field of ['encryptedDataKey', 'nonce', 'authTag', 'ciphertext']) {
    if (typeof item[field] !== 'string' || !/^[A-Za-z0-9_-]+$/.test(item[field])) deny('AUTHORITY_INPUT_DENIED');
  }
  if (Buffer.from(item.encryptedDataKey, 'base64url').length < 1 ||
      Buffer.from(item.nonce, 'base64url').length !== 12 || Buffer.from(item.authTag, 'base64url').length !== 16 ||
      Buffer.from(item.ciphertext, 'base64url').length < 1) deny('AUTHORITY_INPUT_DENIED');
  return Object.freeze(item);
}

function s(item, field, code = 'AUTHORITY_RECORD_DENIED') {
  const value = item?.[field]?.S;
  if (typeof value !== 'string' || value.length < 1) deny(code);
  return value;
}

function n(item, field, code = 'AUTHORITY_RECORD_DENIED') {
  const raw = item?.[field]?.N;
  if (typeof raw !== 'string' || !/^(0|[1-9][0-9]*)$/.test(raw)) deny(code);
  const value = Number(raw);
  if (!Number.isSafeInteger(value)) deny(code);
  return value;
}

function b(item, field, code = 'AUTHORITY_RECORD_DENIED') {
  const value = item?.[field]?.BOOL;
  if (typeof value !== 'boolean') deny(code);
  return value;
}

function list(item, field, code = 'AUTHORITY_RECORD_DENIED') {
  const value = item?.[field]?.L;
  if (!Array.isArray(value) || value.length < 1 || value.length > 16) deny(code);
  return scopes(value.map(entry => s({ value: entry }, 'value', code)), code);
}

function envelopeFrom(item) {
  const map = item?.account_identifier_envelope?.M;
  if (!map || typeof map !== 'object') deny('AUTHORITY_RECORD_DENIED');
  return envelope({
    version: n(map, 'version'), purpose: s(map, 'purpose'), keyId: s(map, 'key_id'),
    encryptedDataKey: s(map, 'encrypted_data_key'), nonce: s(map, 'nonce'),
    authTag: s(map, 'auth_tag'), ciphertext: s(map, 'ciphertext')
  });
}

function envelopeAttribute(value) {
  return { M: {
    version: { N: String(value.version) }, purpose: { S: value.purpose }, key_id: { S: value.keyId },
    encrypted_data_key: { S: value.encryptedDataKey }, nonce: { S: value.nonce },
    auth_tag: { S: value.authTag }, ciphertext: { S: value.ciphertext }
  } };
}

function safeErrorCode(error) {
  try {
    if (!error || !['object', 'function'].includes(typeof error) || types.isProxy(error)) return null;
    const descriptors = Object.getOwnPropertyDescriptors(error);
    for (const field of ['name', 'code']) {
      const descriptor = descriptors[field];
      if (descriptor && Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'string') {
        if (descriptor.value === 'ConditionalCheckFailedException' || descriptor.value === 'TransactionCanceledException') {
          return descriptor.value;
        }
      }
    }
    return null;
  } catch {
    return null;
  }
}

function conditional(error) {
  return safeErrorCode(error) !== null;
}

function authorityError(error) {
  try {
    return !types.isProxy(error) && error instanceof DynamoIdentityAuthorityStoreError;
  } catch {
    return false;
  }
}

function key(prefix, digestValue, suffix) {
  return { PK: { S: `${prefix}#${digest(digestValue)}` }, SK: { S: suffix } };
}

export function createDynamoIdentityAuthorityStore(options) {
  const value = exact(options, ['getItem', 'transactWrite', 'tableName'], ['clock']);
  if (typeof value.getItem !== 'function' || typeof value.transactWrite !== 'function' ||
      typeof value.tableName !== 'string' || !/^[A-Za-z0-9_.-]{3,255}$/.test(value.tableName) ||
      (value.clock !== undefined && typeof value.clock !== 'function')) deny('AUTHORITY_CONFIG');
  const clock = value.clock ?? Date.now;
  let lastNow = 0;

  function nowSeconds() {
    let milliseconds;
    try { milliseconds = clock(); } catch { deny('AUTHORITY_CLOCK_DENIED'); }
    if (!Number.isSafeInteger(milliseconds) || milliseconds < 0) deny('AUTHORITY_CLOCK_DENIED');
    const current = Math.floor(milliseconds / 1000);
    if (current < lastNow) deny('AUTHORITY_CLOCK_ROLLBACK');
    lastNow = current;
    return current;
  }

  async function read(Key) {
    try {
      const response = await value.getItem({ TableName: value.tableName, Key, ConsistentRead: true });
      return response?.Item ?? null;
    } catch (error) {
      if (authorityError(error)) throw error;
      deny('AUTHORITY_STORE_UNAVAILABLE');
    }
  }

  async function write(TransactItems) {
    try {
      const response = await value.transactWrite({ TransactItems });
      if (response === null || typeof response !== 'object') deny('AUTHORITY_OUTCOME_UNKNOWN');
      return response;
    } catch (error) {
      if (authorityError(error)) throw error;
      if (conditional(error)) deny('AUTHORITY_CONFLICT');
      deny('AUTHORITY_OUTCOME_UNKNOWN');
    }
  }

  const ownerKey = { PK: { S: 'OWNER#CURRENT' }, SK: { S: 'META' } };

  return Object.freeze({
    async createEnrollment(input) {
      const data = exact(input, ['nonceDigest', 'botDigest', 'botGeneration', 'enrollmentId', 'expiresAt']);
      const current = nowSeconds();
      digest(data.nonceDigest); digest(data.botDigest); positive(data.botGeneration); reference(data.enrollmentId);
      positive(data.expiresAt);
      if (data.expiresAt <= current || data.expiresAt - current > 300) deny('AUTHORITY_EXPIRED');
      await write([{ Put: {
        TableName: value.tableName,
        Item: { ...key('ENROLL', data.nonceDigest, 'STATE'), enrollment_id: { S: data.enrollmentId },
          status: { S: 'ISSUED' }, bot_digest: { S: data.botDigest }, bot_generation: { N: String(data.botGeneration) },
          created_at: { N: String(current) }, expires_at: { N: String(data.expiresAt) }, revision: { N: '1' } },
        ConditionExpression: 'attribute_not_exists(PK)'
      } }]);
      return Object.freeze({ enrollmentId: data.enrollmentId, expiresAt: data.expiresAt });
    },

    async admitOwner(input) {
      const data = exact(input, ['nonceDigest', 'updateDigest', 'botDigest', 'botGeneration', 'actorDigest',
        'chatDigest', 'actorRef', 'ownerRef', 'householdRef']);
      for (const field of ['nonceDigest', 'updateDigest', 'botDigest', 'actorDigest', 'chatDigest']) digest(data[field]);
      positive(data.botGeneration);
      for (const field of ['actorRef', 'ownerRef', 'householdRef']) reference(data[field]);
      const current = nowSeconds();
      const enrollment = await read(key('ENROLL', data.nonceDigest, 'STATE'));
      if (!enrollment || s(enrollment, 'status') !== 'ISSUED' || s(enrollment, 'bot_digest') !== data.botDigest ||
          n(enrollment, 'bot_generation') !== data.botGeneration || n(enrollment, 'expires_at') <= current) {
        deny('AUTHORITY_ENROLLMENT_DENIED');
      }
      await write([
        { Update: { TableName: value.tableName, Key: key('ENROLL', data.nonceDigest, 'STATE'),
          ConditionExpression: '#status = :issued AND bot_digest = :botDigest AND bot_generation = :botGeneration AND expires_at > :now AND revision = :revision',
          UpdateExpression: 'SET #status = :consumed, consumed_at = :now ADD revision :one',
          ExpressionAttributeNames: { '#status': 'status' }, ExpressionAttributeValues: {
            ':issued': { S: 'ISSUED' }, ':consumed': { S: 'CONSUMED' }, ':botDigest': { S: data.botDigest },
            ':botGeneration': { N: String(data.botGeneration) }, ':now': { N: String(current) },
            ':revision': { N: '1' }, ':one': { N: '1' }
          } } },
        { Put: { TableName: value.tableName, Item: { ...key('TGUPDATE', data.updateDigest, 'REPLAY'),
          consumed_at: { N: String(current) }, expires_at: { N: String(current + 86_400) } },
          ConditionExpression: 'attribute_not_exists(PK)' } },
        { Put: { TableName: value.tableName, Item: { ...ownerKey, owner_ref: { S: data.ownerRef },
          actor_ref: { S: data.actorRef }, household_ref: { S: data.householdRef }, owner_epoch: { N: '1' },
          actor_digest: { S: data.actorDigest }, chat_digest: { S: data.chatDigest }, bot_digest: { S: data.botDigest },
          bot_generation: { N: String(data.botGeneration) }, status: { S: 'ACTIVE' } },
          ConditionExpression: 'attribute_not_exists(PK)' } }
      ]);
      return Object.freeze({ actorRef: data.actorRef, ownerRef: data.ownerRef, householdRef: data.householdRef, ownerEpoch: 1 });
    },

    async issueSession(input) {
      const data = exact(input, ['ownerRef', 'ownerEpoch', 'grantId', 'grantDigest', 'grantGeneration', 'scopeRefs',
        'sessionId', 'sessionDigest', 'csrfDigest', 'sessionGeneration', 'sessionExpiresAt', 'idleExpiresAt', 'trustExpiresAt']);
      reference(data.ownerRef); positive(data.ownerEpoch); reference(data.grantId); digest(data.grantDigest);
      positive(data.grantGeneration); const scopeRefs = scopes(data.scopeRefs); reference(data.sessionId);
      digest(data.sessionDigest); digest(data.csrfDigest); positive(data.sessionGeneration);
      const current = nowSeconds();
      for (const field of ['sessionExpiresAt', 'idleExpiresAt', 'trustExpiresAt']) {
        positive(data[field]); if (data[field] <= current) deny('AUTHORITY_EXPIRED');
      }
      await write([
        { ConditionCheck: { TableName: value.tableName, Key: ownerKey,
          ConditionExpression: '#status = :active AND owner_ref = :ownerRef AND owner_epoch = :ownerEpoch',
          ExpressionAttributeNames: { '#status': 'status' }, ExpressionAttributeValues: { ':active': { S: 'ACTIVE' },
            ':ownerRef': { S: data.ownerRef }, ':ownerEpoch': { N: String(data.ownerEpoch) } } } },
        { Put: { TableName: value.tableName,
          Item: { PK: { S: `OWNER#${data.ownerRef}` }, SK: { S: `GRANT#${data.grantDigest}` },
            grant_id: { S: data.grantId }, grant_digest: { S: data.grantDigest },
            grant_generation: { N: String(data.grantGeneration) }, owner_epoch: { N: String(data.ownerEpoch) },
            scope_refs: { L: scopeRefs.map(scope => ({ S: scope })) }, expires_at: { N: String(data.trustExpiresAt) },
            revoked: { BOOL: false } }, ConditionExpression: 'attribute_not_exists(PK)' } },
        { Put: { TableName: value.tableName, Item: { ...key('SESSION', data.sessionDigest, 'META'),
          session_id: { S: data.sessionId }, session_generation: { N: String(data.sessionGeneration) },
          csrf_digest: { S: data.csrfDigest }, owner_ref: { S: data.ownerRef }, owner_epoch: { N: String(data.ownerEpoch) },
          grant_id: { S: data.grantId }, grant_digest: { S: data.grantDigest }, grant_generation: { N: String(data.grantGeneration) },
          session_expires_at: { N: String(data.sessionExpiresAt) }, idle_expires_at: { N: String(data.idleExpiresAt) },
          trust_expires_at: { N: String(data.trustExpiresAt) }, production_admitted: { BOOL: true }, revoked: { BOOL: false } },
          ConditionExpression: 'attribute_not_exists(PK)' } }
      ]);
      return Object.freeze({ sessionId: data.sessionId, sessionGeneration: data.sessionGeneration,
        grantId: data.grantId, grantGeneration: data.grantGeneration, ownerEpoch: data.ownerEpoch });
    },

    async projectAccount(input) {
      const data = exact(input, ['sessionDigest', 'ownerRef', 'ownerEpoch', 'grantDigest', 'grantGeneration',
        'accountDigest', 'accountGeneration', 'accountIdentifierEnvelope', 'expiresAt']);
      digest(data.sessionDigest); reference(data.ownerRef); positive(data.ownerEpoch); digest(data.grantDigest);
      positive(data.grantGeneration); digest(data.accountDigest); positive(data.accountGeneration);
      const protectedIdentifier = envelope(data.accountIdentifierEnvelope);
      const current = nowSeconds(); positive(data.expiresAt); if (data.expiresAt <= current) deny('AUTHORITY_EXPIRED');
      const sessionKey = key('SESSION', data.sessionDigest, 'META');
      await write([
        { ConditionCheck: { TableName: value.tableName, Key: ownerKey,
          ConditionExpression: '#status = :active AND owner_ref = :ownerRef AND owner_epoch = :ownerEpoch',
          ExpressionAttributeNames: { '#status': 'status' }, ExpressionAttributeValues: { ':active': { S: 'ACTIVE' },
            ':ownerRef': { S: data.ownerRef }, ':ownerEpoch': { N: String(data.ownerEpoch) } } } },
        { ConditionCheck: { TableName: value.tableName,
          Key: { PK: { S: `OWNER#${data.ownerRef}` }, SK: { S: `GRANT#${data.grantDigest}` } },
          ConditionExpression: 'grant_generation = :grantGeneration AND owner_epoch = :ownerEpoch AND revoked = :notRevoked AND expires_at > :now',
          ExpressionAttributeValues: { ':grantGeneration': { N: String(data.grantGeneration) },
            ':ownerEpoch': { N: String(data.ownerEpoch) }, ':notRevoked': { BOOL: false }, ':now': { N: String(current) } } } },
        { Update: { TableName: value.tableName, Key: sessionKey,
          ConditionExpression: 'owner_ref = :ownerRef AND owner_epoch = :ownerEpoch AND grant_digest = :grantDigest AND grant_generation = :grantGeneration AND revoked = :notRevoked AND attribute_not_exists(account_digest)',
          UpdateExpression: 'SET account_digest = :accountDigest, account_generation = :accountGeneration, projection_revision = :projectionRevision',
          ExpressionAttributeValues: { ':ownerRef': { S: data.ownerRef }, ':ownerEpoch': { N: String(data.ownerEpoch) },
            ':grantDigest': { S: data.grantDigest }, ':grantGeneration': { N: String(data.grantGeneration) },
            ':notRevoked': { BOOL: false }, ':accountDigest': { S: data.accountDigest },
            ':accountGeneration': { N: String(data.accountGeneration) }, ':projectionRevision': { N: '1' } } } },
        { Put: { TableName: value.tableName, Item: { ...key('ACCOUNT', data.accountDigest, 'IDENTITY'),
          account_digest: { S: data.accountDigest }, owner_ref: { S: data.ownerRef }, owner_epoch: { N: String(data.ownerEpoch) },
          identity_epoch: { N: String(data.ownerEpoch) },
          account_generation: { N: String(data.accountGeneration) }, projection_revision: { N: '1' },
          account_identifier_envelope: envelopeAttribute(protectedIdentifier), expires_at: { N: String(data.expiresAt) },
          revoked: { BOOL: false } }, ConditionExpression: 'attribute_not_exists(PK)' } }
      ]);
      return Object.freeze({ accountDigest: data.accountDigest, accountGeneration: data.accountGeneration,
        projectionRevision: 1, ownerEpoch: data.ownerEpoch, expiresAt: data.expiresAt });
    },

    async loadSessionAuthority(input) {
      const data = exact(input, ['sessionDigest', 'csrfDigest']);
      digest(data.sessionDigest); digest(data.csrfDigest);
      const current = nowSeconds();
      const session = await read(key('SESSION', data.sessionDigest, 'META'));
      if (!session || digest(s(session, 'csrf_digest')) !== data.csrfDigest || b(session, 'production_admitted') !== true ||
          b(session, 'revoked') || !session.account_digest) deny('AUTHORITY_SESSION_DENIED');
      const ownerRef = reference(s(session, 'owner_ref'));
      const ownerEpoch = positive(n(session, 'owner_epoch'));
      const grantDigest = digest(s(session, 'grant_digest'));
      const accountDigest = digest(s(session, 'account_digest'));
      const [owner, grant, account] = await Promise.all([
        read(ownerKey),
        read({ PK: { S: `OWNER#${ownerRef}` }, SK: { S: `GRANT#${grantDigest}` } }),
        read(key('ACCOUNT', accountDigest, 'IDENTITY'))
      ]);
      if (!owner || !grant || !account || s(owner, 'status') !== 'ACTIVE' || s(owner, 'owner_ref') !== ownerRef ||
          n(owner, 'owner_epoch') !== ownerEpoch || s(grant, 'grant_digest') !== grantDigest || b(grant, 'revoked') ||
          n(grant, 'owner_epoch') !== ownerEpoch || s(account, 'owner_ref') !== ownerRef || b(account, 'revoked') ||
          n(account, 'owner_epoch') !== ownerEpoch || s(account, 'account_digest') !== accountDigest) deny('AUTHORITY_SESSION_DENIED');
      const sessionGeneration = positive(n(session, 'session_generation'));
      const grantGeneration = positive(n(session, 'grant_generation'));
      const accountGeneration = positive(n(session, 'account_generation'));
      const projectionRevision = positive(n(session, 'projection_revision'));
      if (n(grant, 'grant_generation') !== grantGeneration || n(account, 'account_generation') !== accountGeneration ||
          n(account, 'projection_revision') !== projectionRevision) deny('AUTHORITY_SESSION_CHANGED');
      const deadlines = {
        sessionExpiresAt: positive(n(session, 'session_expires_at')),
        idleExpiresAt: positive(n(session, 'idle_expires_at')),
        trustExpiresAt: positive(n(session, 'trust_expires_at')),
        grantExpiresAt: positive(n(grant, 'expires_at')),
        accountExpiresAt: positive(n(account, 'expires_at'))
      };
      if (Object.values(deadlines).some(deadline => deadline <= current)) deny('AUTHORITY_EXPIRED');
      return Object.freeze({
        productionAdmitted: true, serverNow: current * 1000, ownerEpoch,
        sessionId: reference(s(session, 'session_id')), sessionGeneration,
        grantId: reference(s(session, 'grant_id')), grantGeneration,
        sessionExpiresAt: deadlines.sessionExpiresAt * 1000, idleExpiresAt: deadlines.idleExpiresAt * 1000,
        trustExpiresAt: Math.min(deadlines.trustExpiresAt, deadlines.grantExpiresAt, deadlines.accountExpiresAt) * 1000,
        actorRef: reference(s(owner, 'actor_ref')), ownerRef,
        householdRef: reference(s(owner, 'household_ref')), scopeRefs: list(grant, 'scope_refs'),
        accountDigest, accountGeneration, projectionRevision,
        accountIdentifierEnvelope: envelopeFrom(account), bindingExpiresAt: deadlines.accountExpiresAt * 1000
      });
    }
  });
}
