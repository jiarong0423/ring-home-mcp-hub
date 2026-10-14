import { randomUUID } from 'node:crypto';
import { ProtocolError, requireOpaque } from './protocol.mjs';
import {
  TOKEN_ENVELOPE_LEGACY_VERSION,
  TOKEN_ENVELOPE_PURPOSE,
  TOKEN_ENVELOPE_VERSION
} from './token-envelope.mjs';

const STATUS = Object.freeze({
  UNCLAIMED: 'UNCLAIMED',
  RESERVED: 'RESERVED',
  AWAITING: 'AWAITING',
  COMPLETED: 'COMPLETED',
  OUTCOME_UNKNOWN: 'OUTCOME_UNKNOWN'
});
const PROVIDER_PHASES = new Set(['POST', 'PATCH']);
const SHA256 = /^[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const CODE_STATES = new Set(['EXCHANGE_STARTED', 'UNCLAIMED', 'OUTCOME_UNKNOWN']);
const TOKEN_ENVELOPE_FIELDS = Object.freeze([
  'schemaVersion', 'purpose', 'linkId', 'revision',
  'encryptedDataKey', 'nonce', 'authTag', 'ciphertext'
]);

function exactDataValues(value, required, optional = [], errorCode = 'link_state_invalid') {
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
      required.some(key => !Object.hasOwn(descriptors, key)) ||
      keys.some(key => !allowed.has(key)) ||
      keys.some(key => !Object.hasOwn(descriptors[key], 'value'))) {
    throw new ProtocolError(errorCode);
  }
  return Object.fromEntries(keys.map(key => [key, descriptors[key].value]));
}

function requireDigest(value) {
  if (typeof value !== 'string' || !SHA256.test(value)) throw new ProtocolError('link_state_invalid');
  return value;
}

function requireStringList(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 16) throw new ProtocolError('link_state_invalid');
  let descriptors;
  let symbols;
  try {
    descriptors = Object.getOwnPropertyDescriptors(value);
    symbols = Object.getOwnPropertySymbols(value);
  } catch {
    throw new ProtocolError('link_state_invalid');
  }
  if (Object.keys(descriptors).some(key => key !== 'length' && !/^(0|[1-9][0-9]*)$/.test(key)) ||
      symbols.length !== 0) throw new ProtocolError('link_state_invalid');
  const result = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw new ProtocolError('link_state_invalid');
    try {
      requireOpaque(descriptor.value, 256);
    } catch {
      throw new ProtocolError('link_state_invalid');
    }
    result.push(descriptor.value);
  }
  if (new Set(result).size !== result.length) throw new ProtocolError('link_state_invalid');
  return result;
}

function conditionalFailure(error) {
  return error?.name === 'ConditionalCheckFailedException' || error?.code === 'ConditionalCheckFailedException';
}

function requireEpochSeconds(value, code = 'link_state_invalid') {
  if (!Number.isSafeInteger(value) || value < 1) throw new ProtocolError(code);
  return value;
}

function requireVersion(value) {
  if (!Number.isSafeInteger(value) || value < 1) throw new ProtocolError('link_state_invalid');
  return value;
}

function requirePhase(value) {
  if (!PROVIDER_PHASES.has(value)) throw new ProtocolError('link_state_invalid');
  return value;
}

function text(item, field) {
  const value = item?.[field]?.S;
  if (typeof value !== 'string' || value.length === 0) throw new ProtocolError('link_record_invalid');
  return value;
}

function number(item, field) {
  const source = item?.[field]?.N;
  if (typeof source !== 'string' || !/^(0|[1-9][0-9]*)$/.test(source)) throw new ProtocolError('link_record_invalid');
  const value = Number(source);
  if (!Number.isSafeInteger(value)) throw new ProtocolError('link_record_invalid');
  return value;
}

function publicRecord(item) {
  const id = text(item, 'link_id');
  const status = text(item, 'status');
  const version = number(item, 'revision');
  const identityEpoch = number(item, 'identity_epoch');
  const expiresAt = number(item, 'expires_at');
  if (!Object.values(STATUS).includes(status) || version < 1 ||
      (status === STATUS.UNCLAIMED ? identityEpoch < 0 : identityEpoch < 1) || expiresAt < 1) {
    throw new ProtocolError('link_record_invalid');
  }
  return Object.freeze({ id, status, version, identityEpoch, expiresAt });
}

function codeKey(codeDigest) {
  return { PK: { S: `CODE#${requireDigest(codeDigest)}` }, SK: { S: 'META' } };
}

function intakeKey(intakeId) {
  requireOpaque(intakeId, 128);
  return { PK: { S: `INTAKE#${intakeId}` }, SK: { S: 'STATE' } };
}

function exactEnvelope(value, expectedLinkId, expectedRevision) {
  const envelope = exactDataValues(value, TOKEN_ENVELOPE_FIELDS, [], 'token_envelope_invalid');
  if (![TOKEN_ENVELOPE_LEGACY_VERSION, TOKEN_ENVELOPE_VERSION].includes(envelope.schemaVersion) ||
      envelope.purpose !== TOKEN_ENVELOPE_PURPOSE || envelope.linkId !== expectedLinkId ||
      !Number.isSafeInteger(envelope.revision) || envelope.revision < 1 ||
      (expectedRevision !== undefined && envelope.revision !== expectedRevision)) {
    throw new ProtocolError('token_envelope_invalid');
  }
  const limits = {
    encryptedDataKey: [1, 65_536],
    nonce: [12, 12],
    authTag: [16, 16],
    ciphertext: [1, 65_536]
  };
  for (const field of Object.keys(limits)) {
    const encoded = envelope[field];
    if (typeof encoded !== 'string' || !BASE64URL.test(encoded)) {
      throw new ProtocolError('token_envelope_invalid');
    }
    const decoded = Buffer.from(encoded, 'base64url');
    const [minimum, maximum] = limits[field];
    if (decoded.length < minimum || decoded.length > maximum || decoded.toString('base64url') !== encoded) {
      throw new ProtocolError('token_envelope_invalid');
    }
  }
  return envelope;
}

function sameEnvelope(left, right) {
  return TOKEN_ENVELOPE_FIELDS.every(field => left[field] === right[field]);
}

function envelopeAttribute(envelope) {
  return { M: {
    schema_version: { N: String(envelope.schemaVersion) },
    purpose: { S: envelope.purpose },
    link_id: { S: envelope.linkId },
    revision: { N: String(envelope.revision) },
    encrypted_data_key: { S: envelope.encryptedDataKey },
    nonce: { S: envelope.nonce },
    auth_tag: { S: envelope.authTag },
    ciphertext: { S: envelope.ciphertext }
  } };
}

function envelopeFromAttribute(attribute, expectedLinkId) {
  const map = attribute?.M;
  if (!map || typeof map !== 'object') throw new ProtocolError('link_record_invalid');
  return Object.freeze(exactEnvelope({
    schemaVersion: number(map, 'schema_version'),
    purpose: text(map, 'purpose'),
    linkId: text(map, 'link_id'),
    revision: number(map, 'revision'),
    encryptedDataKey: text(map, 'encrypted_data_key'),
    nonce: text(map, 'nonce'),
    authTag: text(map, 'auth_tag'),
    ciphertext: text(map, 'ciphertext')
  }, expectedLinkId));
}

function privateRecord(item) {
  const record = publicRecord(item);
  const accountDigest = text(item, 'account_digest');
  requireDigest(accountDigest);
  return Object.freeze({
    ...record,
    accountDigest,
    tokenEnvelope: envelopeFromAttribute(item?.token_envelope, record.id)
  });
}

function key(linkId) {
  requireOpaque(linkId, 256);
  return { PK: { S: `LINK#${linkId}` }, SK: { S: 'STATE' } };
}

function accountKey(accountDigest) {
  if (typeof accountDigest !== 'string' || !SHA256.test(accountDigest)) {
    throw new ProtocolError('link_state_invalid');
  }
  return { PK: { S: `ACCOUNT#${accountDigest}` }, SK: { S: 'IDENTITY' } };
}

function currentAccountCheck(accountDigest, currentEpoch, now, accountGeneration, projectionRevision) {
  const generationPins = accountGeneration === undefined ? {} : {
    ':accountGeneration': { N: String(requireVersion(accountGeneration)) },
    ':projectionRevision': { N: String(requireVersion(projectionRevision)) }
  };
  return {
    TableName: null,
    Key: accountKey(accountDigest),
    ConditionExpression: 'identity_epoch = :currentEpoch AND revoked = :notRevoked AND expires_at > :now' +
      (accountGeneration === undefined ? '' : ' AND account_generation = :accountGeneration AND projection_revision = :projectionRevision'),
    ExpressionAttributeValues: {
      ':currentEpoch': { N: String(requireVersion(currentEpoch)) },
      ':notRevoked': { BOOL: false },
      ':now': { N: String(requireEpochSeconds(now, 'link_clock')) },
      ...generationPins
    }
  };
}

function baseValues({ expectedVersion, currentEpoch, now }) {
  return {
    ':expectedVersion': { N: String(requireVersion(expectedVersion)) },
    ':currentEpoch': { N: String(requireVersion(currentEpoch)) },
    ':now': { N: String(requireEpochSeconds(now, 'link_clock')) },
    ':one': { N: '1' }
  };
}

function sanitizedResult(linkId, status, version, providerPhase) {
  return Object.freeze({
    id: linkId,
    status,
    version,
    providerPhase
  });
}

export function createDynamoLinkStore({
  query,
  getItem,
  transactWrite,
  tableName,
  indexName = 'GSI1',
  clock = () => Date.now(),
  createIntakeId = randomUUID,
  maxExchangeSeconds = 300,
  maxUnclaimedSeconds = 600,
  maxCandidates = 25,
  maxQueryPages = 2
} = {}) {
  if (typeof query !== 'function' || typeof getItem !== 'function' || typeof transactWrite !== 'function' ||
      typeof clock !== 'function' || typeof createIntakeId !== 'function' ||
      typeof tableName !== 'string' || !/^[A-Za-z0-9_.-]{3,255}$/.test(tableName) ||
      typeof indexName !== 'string' || !/^[A-Za-z0-9_.-]{3,255}$/.test(indexName) ||
      !Number.isSafeInteger(maxExchangeSeconds) || maxExchangeSeconds < 30 || maxExchangeSeconds > 600 ||
      !Number.isSafeInteger(maxUnclaimedSeconds) || maxUnclaimedSeconds < 30 || maxUnclaimedSeconds > 3_600 ||
      !Number.isSafeInteger(maxCandidates) || maxCandidates < 1 || maxCandidates > 100 ||
      !Number.isSafeInteger(maxQueryPages) || maxQueryPages < 1 || maxQueryPages > 10) {
    throw new ProtocolError('link_store_config');
  }

  function nowSeconds() {
    const milliseconds = clock();
    if (!Number.isSafeInteger(milliseconds) || milliseconds < 0) throw new ProtocolError('link_clock');
    return Math.floor(milliseconds / 1000);
  }

  async function writeTransaction(linkUpdate, accountDigest, currentEpoch, now, unavailableCode = 'link_store_unavailable', pins = {}) {
    const account = currentAccountCheck(accountDigest, currentEpoch, now, pins.accountGeneration, pins.projectionRevision);
    account.TableName = tableName;
    try {
      return await transactWrite({
        TransactItems: [
          { Update: linkUpdate },
          { ConditionCheck: account }
        ]
      });
    } catch (error) {
      if (conditionalFailure(error)) throw new ProtocolError('link_conflict');
      throw new ProtocolError(unavailableCode);
    }
  }

  async function readItem(keyValue, unavailableCode = 'link_store_unavailable') {
    try {
      const response = await getItem({ TableName: tableName, Key: keyValue, ConsistentRead: true });
      return response?.Item ?? null;
    } catch {
      throw new ProtocolError(unavailableCode);
    }
  }

  async function queryUnclaimed(now, includePrivate) {
    requireEpochSeconds(now, 'link_clock');
    const records = [];
    let exclusiveStartKey;
    for (let page = 0; page < maxQueryPages; page += 1) {
      const remaining = maxCandidates - records.length;
      if (remaining < 1) throw new ProtocolError('unclaimed_limit');
      let response;
      try {
        response = await query({
          TableName: tableName,
          IndexName: indexName,
          KeyConditionExpression: '#gsiPk = :unclaimed',
          ExpressionAttributeNames: { '#gsiPk': 'GSI1PK' },
          ExpressionAttributeValues: { ':unclaimed': { S: STATUS.UNCLAIMED } },
          ProjectionExpression: includePrivate
            ? 'link_id, #status, revision, identity_epoch, expires_at, account_digest, token_envelope'
            : 'link_id, #status, revision, identity_epoch, expires_at',
          Limit: remaining,
          ConsistentRead: false,
          ...(exclusiveStartKey ? { ExclusiveStartKey: exclusiveStartKey } : {})
        });
      } catch {
        throw new ProtocolError('link_store_unavailable');
      }
      if (!Array.isArray(response?.Items)) throw new ProtocolError('link_store_unavailable');
      if (response.Items.length > remaining) throw new ProtocolError('unclaimed_limit');
      for (const item of response.Items) {
        const record = includePrivate ? privateRecord(item) : publicRecord(item);
        if (record.status !== STATUS.UNCLAIMED) throw new ProtocolError('link_record_invalid');
        if (record.expiresAt > now) records.push(record);
      }
      exclusiveStartKey = response.LastEvaluatedKey;
      if (!exclusiveStartKey) return Object.freeze(records);
    }
    throw new ProtocolError('unclaimed_limit');
  }

  async function readIntake(intakeId) {
    const item = await readItem(intakeKey(intakeId), 'code_store_unavailable');
    if (!item) throw new ProtocolError('code_conflict');
    const storedIntakeId = text(item, 'intake_id');
    const codeDigest = text(item, 'code_digest');
    const bodyDigest = text(item, 'body_digest');
    const status = text(item, 'status');
    const exchangeDeadline = number(item, 'exchange_deadline');
    const revision = number(item, 'revision');
    const accountDigest = status === 'UNCLAIMED' ? text(item, 'account_digest') : undefined;
    if (storedIntakeId !== intakeId || !SHA256.test(codeDigest) || !SHA256.test(bodyDigest) ||
        (accountDigest !== undefined && !SHA256.test(accountDigest)) || !CODE_STATES.has(status) ||
        exchangeDeadline < 1 || revision < 1) throw new ProtocolError('code_record_invalid');
    return { intakeId, codeDigest, bodyDigest, accountDigest, status, exchangeDeadline, revision };
  }

  async function readCode(codeDigest) {
    const item = await readItem(codeKey(codeDigest), 'code_store_unavailable');
    if (!item) throw new ProtocolError('code_conflict');
    const intakeId = text(item, 'intake_id');
    const bodyDigest = text(item, 'body_digest');
    const status = text(item, 'status');
    const exchangeDeadline = number(item, 'exchange_deadline');
    const revision = number(item, 'revision');
    const accountDigest = status === 'UNCLAIMED' ? text(item, 'account_digest') : undefined;
    if (!SHA256.test(bodyDigest) || (accountDigest !== undefined && !SHA256.test(accountDigest)) ||
        !CODE_STATES.has(status) || exchangeDeadline < 1 || revision < 1) {
      throw new ProtocolError('code_record_invalid');
    }
    return { intakeId, bodyDigest, accountDigest, status, exchangeDeadline, revision };
  }

  async function readCommittedLink(intakeId) {
    const item = await readItem(key(intakeId), 'code_store_unavailable');
    if (!item) throw new ProtocolError('code_conflict');
    const record = privateRecord(item);
    if (record.status !== STATUS.UNCLAIMED) throw new ProtocolError('code_conflict');
    return record;
  }

  async function writeUnknown({ linkId, accountDigest, expectedVersion, currentEpoch, now, phase, reason }) {
    const values = {
      ':currentEpoch': { N: String(requireVersion(currentEpoch)) },
      ':now': { N: String(requireEpochSeconds(now, 'link_clock')) },
      ':reserved': { S: STATUS.RESERVED },
      ':awaiting': { S: STATUS.AWAITING },
      ':unknown': { S: STATUS.OUTCOME_UNKNOWN },
      ':phase': { S: `${phase}_UNKNOWN` },
      ':journal': { L: [{ M: {
        phase: { S: phase },
        result: { S: 'OUTCOME_UNKNOWN' },
        reason: { S: reason },
        at: { N: String(now) }
      } }] },
      ':empty': { L: [] },
      ':one': { N: '1' }
    };
    values[':expectedVersion'] = { N: String(requireVersion(expectedVersion)) };
    values[':startedVersion'] = { N: String(expectedVersion + 1) };
    try {
      await writeTransaction({
        TableName: tableName,
        Key: key(linkId),
        ConditionExpression: 'identity_epoch = :currentEpoch AND expires_at > :now AND (revision = :expectedVersion OR revision = :startedVersion) AND (#status = :reserved OR #status = :awaiting)',
        UpdateExpression: 'SET #status = :unknown, provider_phase = :phase, provider_journal = list_append(if_not_exists(provider_journal, :empty), :journal), updated_at = :now ADD revision :one',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: values,
      }, accountDigest, currentEpoch, now);
    } catch {
      throw new ProtocolError('link_store_unavailable');
    }
  }

  return Object.freeze({
    async listUnclaimed(now = nowSeconds()) {
      return queryUnclaimed(now, false);
    },

    async listUnclaimedForMatch(now = nowSeconds()) {
      return queryUnclaimed(now, true);
    },

    async beginCodeExchange(input) {
      const values = exactDataValues(input, ['codeDigest', 'receivedAt', 'bodyDigest', 'exchangeDeadline']);
      const codeDigest = requireDigest(values.codeDigest);
      const bodyDigest = requireDigest(values.bodyDigest);
      const receivedAt = requireEpochSeconds(values.receivedAt, 'code_state_invalid');
      const exchangeDeadline = requireEpochSeconds(values.exchangeDeadline, 'code_state_invalid');
      const current = nowSeconds();
      if (receivedAt < current - 5 || receivedAt > current + 5 || exchangeDeadline <= receivedAt ||
          exchangeDeadline - receivedAt > maxExchangeSeconds) throw new ProtocolError('code_expired');
      let intakeId;
      try {
        intakeId = createIntakeId();
        requireOpaque(intakeId, 128);
      } catch {
        throw new ProtocolError('link_store_config');
      }
      const common = {
        intake_id: { S: intakeId },
        body_digest: { S: bodyDigest },
        status: { S: 'EXCHANGE_STARTED' },
        received_at: { N: String(receivedAt) },
        exchange_deadline: { N: String(exchangeDeadline) },
        expires_at: { N: String(exchangeDeadline) },
        revision: { N: '1' }
      };
      try {
        await transactWrite({
          TransactItems: [
            { Put: {
              TableName: tableName,
              Item: { ...codeKey(codeDigest), ...common },
              ConditionExpression: 'attribute_not_exists(PK)'
            } },
            { Put: {
              TableName: tableName,
              Item: { ...intakeKey(intakeId), ...common, code_digest: { S: codeDigest } },
              ConditionExpression: 'attribute_not_exists(PK)'
            } }
          ]
        });
        return Object.freeze({ intakeId, status: 'EXCHANGE_STARTED', duplicate: false, safeDuplicate: false, mayCallProvider: true });
      } catch (error) {
        if (!conditionalFailure(error)) throw new ProtocolError('code_store_unavailable');
      }
      const existing = await readCode(codeDigest);
      if (existing.bodyDigest !== bodyDigest) throw new ProtocolError('code_conflict');
      if (existing.exchangeDeadline <= current) throw new ProtocolError('code_expired');
      if (existing.status === 'UNCLAIMED') {
        const committed = await readCommittedLink(existing.intakeId);
        if (committed.expiresAt <= current) throw new ProtocolError('link_expired');
        return Object.freeze({ intakeId: existing.intakeId, status: 'UNCLAIMED', duplicate: true, safeDuplicate: true, mayCallProvider: false });
      }
      if (existing.status === 'EXCHANGE_STARTED') throw new ProtocolError('code_exchange_in_progress');
      if (existing.status === 'OUTCOME_UNKNOWN') throw new ProtocolError('code_outcome_unknown');
      throw new ProtocolError('code_conflict');
    },

    async commitUnclaimed(input) {
      const values = exactDataValues(input, ['intakeId', 'bodyDigest', 'accountDigest', 'exchangeDeadline', 'tokenEnvelope', 'linkExpiresAt']);
      const intakeId = values.intakeId;
      const bodyDigest = requireDigest(values.bodyDigest);
      const accountDigest = requireDigest(values.accountDigest);
      const exchangeDeadline = requireEpochSeconds(values.exchangeDeadline, 'code_state_invalid');
      const envelope = exactEnvelope(values.tokenEnvelope, intakeId, 1);
      const linkExpiresAt = requireEpochSeconds(values.linkExpiresAt, 'link_state_invalid');
      const current = nowSeconds();
      if (linkExpiresAt <= current || linkExpiresAt - current > maxUnclaimedSeconds) throw new ProtocolError('link_expired');
      const intake = await readIntake(intakeId);
      if (intake.bodyDigest !== bodyDigest || intake.exchangeDeadline !== exchangeDeadline) throw new ProtocolError('code_conflict');
      if (intake.exchangeDeadline <= current) throw new ProtocolError('code_expired');
      if (intake.status === 'UNCLAIMED') {
        const committed = await readCommittedLink(intakeId);
        if (committed.expiresAt <= current || intake.accountDigest !== accountDigest || committed.accountDigest !== accountDigest ||
            !sameEnvelope(committed.tokenEnvelope, envelope)) throw new ProtocolError('code_conflict');
        return Object.freeze({ intakeId, status: 'UNCLAIMED', version: 1, duplicate: true, safeDuplicate: true });
      }
      if (intake.status === 'OUTCOME_UNKNOWN') throw new ProtocolError('code_outcome_unknown');
      if (intake.status !== 'EXCHANGE_STARTED') throw new ProtocolError('code_conflict');
      const gsiSort = `${String(linkExpiresAt).padStart(16, '0')}#${intakeId}`;
      try {
        await transactWrite({
          TransactItems: [
            { Update: {
              TableName: tableName,
              Key: intakeKey(intakeId),
              ConditionExpression: '#status = :started AND revision = :revision AND intake_id = :intakeId AND body_digest = :bodyDigest AND exchange_deadline = :exchangeDeadline AND exchange_deadline > :now AND attribute_not_exists(account_digest)',
              UpdateExpression: 'SET #status = :unclaimed, account_digest = :accountDigest, updated_at = :now ADD revision :one',
              ExpressionAttributeNames: { '#status': 'status' },
              ExpressionAttributeValues: {
                ':started': { S: 'EXCHANGE_STARTED' }, ':unclaimed': { S: 'UNCLAIMED' },
                ':revision': { N: String(intake.revision) }, ':intakeId': { S: intakeId },
                ':bodyDigest': { S: bodyDigest }, ':accountDigest': { S: accountDigest },
                ':exchangeDeadline': { N: String(exchangeDeadline) }, ':now': { N: String(current) }, ':one': { N: '1' }
              }
            } },
            { Update: {
              TableName: tableName,
              Key: codeKey(intake.codeDigest),
              ConditionExpression: '#status = :started AND intake_id = :intakeId AND body_digest = :bodyDigest AND exchange_deadline = :exchangeDeadline AND exchange_deadline > :now AND attribute_not_exists(account_digest)',
              UpdateExpression: 'SET #status = :unclaimed, link_id = :intakeId, account_digest = :accountDigest, updated_at = :now ADD revision :one',
              ExpressionAttributeNames: { '#status': 'status' },
              ExpressionAttributeValues: {
                ':started': { S: 'EXCHANGE_STARTED' }, ':unclaimed': { S: 'UNCLAIMED' },
                ':intakeId': { S: intakeId }, ':bodyDigest': { S: bodyDigest },
                ':accountDigest': { S: accountDigest }, ':exchangeDeadline': { N: String(exchangeDeadline) },
                ':now': { N: String(current) }, ':one': { N: '1' }
              }
            } },
            { Put: {
              TableName: tableName,
              Item: {
                ...key(intakeId), link_id: { S: intakeId }, status: { S: STATUS.UNCLAIMED },
                revision: { N: '1' }, identity_epoch: { N: '0' }, expires_at: { N: String(linkExpiresAt) },
                account_digest: { S: accountDigest }, token_envelope: envelopeAttribute(envelope),
                token_revision: { N: '1' },
                GSI1PK: { S: STATUS.UNCLAIMED }, GSI1SK: { S: gsiSort }
              },
              ConditionExpression: 'attribute_not_exists(PK)'
            } }
          ]
        });
      } catch (error) {
        if (conditionalFailure(error)) throw new ProtocolError('code_conflict');
        throw new ProtocolError('code_store_unavailable');
      }
      return Object.freeze({ intakeId, status: 'UNCLAIMED', version: 1, duplicate: false, safeDuplicate: false });
    },

    async rotateTokenEnvelope(input) {
      const values = exactDataValues(input, [
        'linkId', 'accountDigest', 'expectedLinkVersion', 'expectedTokenRevision', 'tokenEnvelope'
      ]);
      const linkId = values.linkId;
      try { requireOpaque(linkId, 256); } catch { throw new ProtocolError('link_state_invalid'); }
      const accountDigest = requireDigest(values.accountDigest);
      const expectedLinkVersion = requireVersion(values.expectedLinkVersion);
      const expectedTokenRevision = requireVersion(values.expectedTokenRevision);
      if (expectedTokenRevision >= Number.MAX_SAFE_INTEGER) throw new ProtocolError('link_state_invalid');
      const nextTokenRevision = expectedTokenRevision + 1;
      const envelope = exactEnvelope(values.tokenEnvelope, linkId, nextTokenRevision);
      const current = nowSeconds();
      const update = {
        TableName: tableName,
        Key: key(linkId),
        ConditionExpression: '#status = :reserved AND revision = :expectedLinkVersion AND account_digest = :accountDigest AND expires_at > :now AND token_envelope.revision = :expectedTokenRevision AND (attribute_not_exists(token_revision) OR token_revision = :expectedTokenRevision)',
        UpdateExpression: 'SET token_envelope = :tokenEnvelope, token_revision = :nextTokenRevision, updated_at = :now',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: {
          ':reserved': { S: STATUS.RESERVED },
          ':expectedLinkVersion': { N: String(expectedLinkVersion) },
          ':accountDigest': { S: accountDigest },
          ':now': { N: String(current) },
          ':expectedTokenRevision': { N: String(expectedTokenRevision) },
          ':nextTokenRevision': { N: String(nextTokenRevision) },
          ':tokenEnvelope': envelopeAttribute(envelope)
        }
      };
      try {
        await transactWrite({ TransactItems: [{ Update: update }] });
        return Object.freeze({ id: linkId, tokenRevision: nextTokenRevision, duplicate: false });
      } catch (error) {
        if (!conditionalFailure(error)) throw new ProtocolError('token_rotation_outcome_unknown');
      }
      let currentRecord;
      try {
        const item = await readItem(key(linkId));
        if (item) currentRecord = privateRecord(item);
      } catch {
        throw new ProtocolError('token_rotation_outcome_unknown');
      }
      if (currentRecord?.status === STATUS.RESERVED && currentRecord.version === expectedLinkVersion &&
          currentRecord.accountDigest === accountDigest &&
          currentRecord.tokenEnvelope.revision === nextTokenRevision &&
          sameEnvelope(currentRecord.tokenEnvelope, envelope)) {
        return Object.freeze({ id: linkId, tokenRevision: nextTokenRevision, duplicate: true });
      }
      throw new ProtocolError('token_rotation_conflict');
    },

    async markCodeOutcomeUnknown(input) {
      const values = exactDataValues(input, ['intakeId'], ['reason']);
      const intakeId = values.intakeId;
      const reason = values.reason ?? 'EXCHANGE_RESULT_AMBIGUOUS';
      if (typeof reason !== 'string' || !/^[A-Z0-9_]{3,64}$/.test(reason)) throw new ProtocolError('code_state_invalid');
      const intake = await readIntake(intakeId);
      if (intake.status === 'UNCLAIMED') {
        return Object.freeze({ intakeId, status: 'UNCLAIMED', duplicate: true, safeDuplicate: true, retryAllowed: false });
      }
      if (intake.status === 'OUTCOME_UNKNOWN') {
        return Object.freeze({ intakeId, status: 'OUTCOME_UNKNOWN', duplicate: true, safeDuplicate: false, retryAllowed: false });
      }
      const current = nowSeconds();
      try {
        await transactWrite({
          TransactItems: [
            { Update: {
              TableName: tableName,
              Key: intakeKey(intakeId),
              ConditionExpression: '#status = :started AND revision = :revision',
              UpdateExpression: 'SET #status = :unknown, outcome_reason = :reason, updated_at = :now ADD revision :one',
              ExpressionAttributeNames: { '#status': 'status' },
              ExpressionAttributeValues: {
                ':started': { S: 'EXCHANGE_STARTED' }, ':unknown': { S: 'OUTCOME_UNKNOWN' },
                ':reason': { S: reason }, ':revision': { N: String(intake.revision) },
                ':now': { N: String(current) }, ':one': { N: '1' }
              }
            } },
            { Update: {
              TableName: tableName,
              Key: codeKey(intake.codeDigest),
              ConditionExpression: '#status = :started AND intake_id = :intakeId',
              UpdateExpression: 'SET #status = :unknown, outcome_reason = :reason, updated_at = :now ADD revision :one',
              ExpressionAttributeNames: { '#status': 'status' },
              ExpressionAttributeValues: {
                ':started': { S: 'EXCHANGE_STARTED' }, ':unknown': { S: 'OUTCOME_UNKNOWN' },
                ':intakeId': { S: intakeId }, ':reason': { S: reason },
                ':now': { N: String(current) }, ':one': { N: '1' }
              }
            } }
          ]
        });
      } catch (error) {
        if (conditionalFailure(error)) throw new ProtocolError('code_conflict');
        throw new ProtocolError('code_store_unavailable');
      }
      return Object.freeze({ intakeId, status: 'OUTCOME_UNKNOWN', duplicate: false, safeDuplicate: false, retryAllowed: false });
    },

    async reserveClaim(input) {
      const values = exactDataValues(input, [
        'linkId', 'actorRef', 'ownerRef', 'householdRef', 'scopeRefs', 'accountDigest',
        'expectedVersion', 'currentEpoch', 'expiresAt'
      ], ['accountGeneration', 'projectionRevision']);
      const { linkId, actorRef, ownerRef, householdRef, expectedVersion, currentEpoch, expiresAt } = values;
      for (const reference of [actorRef, ownerRef, householdRef]) {
        try { requireOpaque(reference, 256); } catch { throw new ProtocolError('link_state_invalid'); }
      }
      const scopeRefs = requireStringList(values.scopeRefs);
      const accountDigest = requireDigest(values.accountDigest);
      if ((values.accountGeneration === undefined) !== (values.projectionRevision === undefined)) {
        throw new ProtocolError('link_state_invalid');
      }
      const accountPins = values.accountGeneration === undefined ? {} : {
        accountGeneration: requireVersion(values.accountGeneration),
        projectionRevision: requireVersion(values.projectionRevision)
      };
      requireEpochSeconds(expiresAt);
      const now = nowSeconds();
      if (expiresAt <= now) throw new ProtocolError('link_expired');
      const writeValues = {
        ...baseValues({ expectedVersion, currentEpoch, now }),
        ':unclaimed': { S: STATUS.UNCLAIMED },
        ':reserved': { S: STATUS.RESERVED },
        ':notStarted': { S: 'NOT_STARTED' },
        ':actorRef': { S: actorRef },
        ':ownerRef': { S: ownerRef },
        ':householdRef': { S: householdRef },
        ':scopeRefs': { L: scopeRefs.map(scopeRef => ({ S: scopeRef })) },
        ':accountDigest': { S: accountDigest },
        ':unboundEpoch': { N: '0' },
        ...(accountPins.accountGeneration === undefined ? {} : {
          ':accountGeneration': { N: String(accountPins.accountGeneration) },
          ':projectionRevision': { N: String(accountPins.projectionRevision) }
        })
      };
      await writeTransaction({
        TableName: tableName,
        Key: key(linkId),
        ConditionExpression: '#status = :unclaimed AND revision = :expectedVersion AND identity_epoch = :unboundEpoch AND account_digest = :accountDigest AND expires_at > :now',
        UpdateExpression: 'SET #status = :reserved, actor_ref = :actorRef, owner_ref = :ownerRef, household_ref = :householdRef, scope_refs = :scopeRefs, identity_epoch = :currentEpoch, provider_phase = :notStarted, updated_at = :now' +
          (accountPins.accountGeneration === undefined ? '' : ', account_generation = :accountGeneration, projection_revision = :projectionRevision') +
          ' REMOVE GSI1PK, GSI1SK ADD revision :one',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: writeValues,
      }, accountDigest, currentEpoch, now, 'link_store_unavailable', accountPins);
      return sanitizedResult(linkId, STATUS.RESERVED, expectedVersion + 1, 'NOT_STARTED');
    },

    async beginProviderPhase({ linkId, accountDigest, phase, expectedVersion, currentEpoch, expiresAt } = {}) {
      requirePhase(phase);
      requireEpochSeconds(expiresAt);
      const now = nowSeconds();
      if (expiresAt <= now) throw new ProtocolError('link_expired');
      const expectedStatus = phase === 'POST' ? STATUS.RESERVED : STATUS.AWAITING;
      const expectedProviderPhase = phase === 'POST' ? 'NOT_STARTED' : 'POST_SUCCEEDED';
      const started = `${phase}_STARTED`;
      const values = {
        ...baseValues({ expectedVersion, currentEpoch, now }),
        ':expectedStatus': { S: expectedStatus },
        ':expectedProviderPhase': { S: expectedProviderPhase },
        ':started': { S: started },
        ':journal': { L: [{ M: {
          phase: { S: phase },
          result: { S: 'STARTED' },
          at: { N: String(now) }
        } }] },
        ':empty': { L: [] }
      };
      try {
        await writeTransaction({
          TableName: tableName,
          Key: key(linkId),
          ConditionExpression: '#status = :expectedStatus AND provider_phase = :expectedProviderPhase AND revision = :expectedVersion AND identity_epoch = :currentEpoch AND expires_at > :now',
          UpdateExpression: 'SET provider_phase = :started, provider_journal = list_append(if_not_exists(provider_journal, :empty), :journal), updated_at = :now ADD revision :one',
          ExpressionAttributeNames: { '#status': 'status' },
          ExpressionAttributeValues: values,
        }, accountDigest, currentEpoch, now);
      } catch (error) {
        if (conditionalFailure(error) || error?.code === 'link_conflict') throw new ProtocolError('link_conflict');
        await writeUnknown({ linkId, accountDigest, expectedVersion, currentEpoch, now, phase, reason: 'STARTED_WRITE_AMBIGUOUS' });
        throw new ProtocolError('provider_outcome_unknown');
      }
      return sanitizedResult(linkId, expectedStatus, expectedVersion + 1, started);
    },

    async finishProviderPhase({ linkId, accountDigest, phase, expectedVersion, currentEpoch, expiresAt } = {}) {
      requirePhase(phase);
      requireEpochSeconds(expiresAt);
      const now = nowSeconds();
      if (expiresAt <= now) throw new ProtocolError('link_expired');
      const expectedStatus = phase === 'POST' ? STATUS.RESERVED : STATUS.AWAITING;
      const nextStatus = phase === 'POST' ? STATUS.AWAITING : STATUS.COMPLETED;
      const started = `${phase}_STARTED`;
      const succeeded = `${phase}_SUCCEEDED`;
      const values = {
        ...baseValues({ expectedVersion, currentEpoch, now }),
        ':expectedStatus': { S: expectedStatus },
        ':nextStatus': { S: nextStatus },
        ':started': { S: started },
        ':succeeded': { S: succeeded },
        ':journal': { L: [{ M: {
          phase: { S: phase },
          result: { S: 'SUCCEEDED' },
          at: { N: String(now) }
        } }] },
        ':empty': { L: [] }
      };
      try {
        await writeTransaction({
          TableName: tableName,
          Key: key(linkId),
          ConditionExpression: '#status = :expectedStatus AND provider_phase = :started AND revision = :expectedVersion AND identity_epoch = :currentEpoch AND expires_at > :now',
          UpdateExpression: 'SET #status = :nextStatus, provider_phase = :succeeded, provider_journal = list_append(if_not_exists(provider_journal, :empty), :journal), updated_at = :now ADD revision :one',
          ExpressionAttributeNames: { '#status': 'status' },
          ExpressionAttributeValues: values,
        }, accountDigest, currentEpoch, now);
      } catch (error) {
        if (conditionalFailure(error) || error?.code === 'link_conflict') throw new ProtocolError('link_conflict');
        await writeUnknown({ linkId, accountDigest, expectedVersion, currentEpoch, now, phase, reason: 'RESULT_WRITE_AMBIGUOUS' });
        throw new ProtocolError('provider_outcome_unknown');
      }
      return sanitizedResult(linkId, nextStatus, expectedVersion + 1, succeeded);
    },

    async markOutcomeUnknown({ linkId, accountDigest, phase, expectedVersion, currentEpoch, reason = 'PROVIDER_RESULT_AMBIGUOUS' } = {}) {
      requirePhase(phase);
      if (!/^[A-Z0-9_]{3,64}$/.test(reason)) throw new ProtocolError('link_state_invalid');
      const now = nowSeconds();
      await writeUnknown({ linkId, accountDigest, expectedVersion, currentEpoch, now, phase, reason });
      return sanitizedResult(linkId, STATUS.OUTCOME_UNKNOWN, null, `${phase}_UNKNOWN`);
    }
  });
}
