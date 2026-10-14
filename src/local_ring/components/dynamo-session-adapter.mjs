import { createHash } from 'node:crypto';

const HEX = /^[a-f0-9]{64}$/;
const TABLE = /^[A-Za-z0-9_.-]{3,255}$/;
const AUTH_TYPES = Object.freeze({
  pk: 'S', status: 'S', created_at: 'N', expires_at: 'N', ttl_delete_after: 'N',
  state_digest: 'S', browser_correlation_digest: 'S', oidc_nonce_digest: 'S',
  pkce_verifier_ciphertext: 'S', ring_nonce_time_ciphertext: 'S',
  reservation_ref: 'S', reserved_at: 'N', consumed_at: 'N'
});
const SESSION_TYPES = Object.freeze({
  pk: 'S', owner_subject_ref: 'S', version: 'N', status: 'S', created_at: 'N',
  last_seen_at: 'N', absolute_expires_at: 'N', idle_expires_at: 'N',
  revoked_at: 'N', csrf_ref: 'S', ttl_delete_after: 'N'
});

export class DynamoSessionAdapterError extends Error {
  constructor(code) {
    super(code);
    this.name = 'DynamoSessionAdapterError';
    this.code = code;
  }
}

function fail(code) { throw new DynamoSessionAdapterError(code); }
function sec(value) { return Number.isSafeInteger(value) && value >= 0; }
function isSessionVersion(value) {
  return Number.isSafeInteger(value) && value >= 1 && value < Number.MAX_SAFE_INTEGER;
}
function nextSessionVersion(value) {
  if (!isSessionVersion(value)) fail('invalid_session_row');
  const nextVersion = value + 1;
  if (!isSessionVersion(nextVersion)) fail('invalid_session_row');
  return nextVersion;
}
function plain(value, allowed, code) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) fail(code);
  const result = {};
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || (allowed && !allowed.includes(key))) fail(code);
    const desc = Object.getOwnPropertyDescriptor(value, key);
    if (!desc || !Object.hasOwn(desc, 'value')) fail(code);
    result[key] = desc.value;
  }
  return result;
}
function need(value, fields, code) {
  if (fields.some(field => !Object.hasOwn(value, field))) fail(code);
}
function digest(value) { return typeof value === 'string' && HEX.test(value); }
function name(value) { return typeof value === 'string' && TABLE.test(value) && !value.includes('*'); }
function safeText(value, max = 16384) {
  return typeof value === 'string' && value.length > 0 && value.length <= max &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}
function avString(value) { return { S: value }; }
function avNumber(value) { return { N: String(value) }; }
function key(pk) {
  if (!digest(pk)) fail('invalid_key');
  return { pk: avString(pk) };
}
function decision(decisionNow, lowerBound) {
  if (typeof decisionNow !== 'function') fail('clock_unavailable');
  let current;
  try { current = decisionNow(); } catch { fail('clock_unavailable'); }
  if (!sec(current) || current < lowerBound) fail('clock_unavailable');
  return current;
}
function authRow(value) {
  const row = plain(value, Object.keys(AUTH_TYPES), 'invalid_auth_row');
  need(row, ['pk','status','created_at','expires_at','ttl_delete_after','state_digest',
    'browser_correlation_digest','oidc_nonce_digest','pkce_verifier_ciphertext',
    'ring_nonce_time_ciphertext'], 'invalid_auth_row');
  if (![row.pk,row.state_digest,row.browser_correlation_digest,row.oidc_nonce_digest]
    .every(digest) || row.pk !== row.state_digest ||
    !safeText(row.pkce_verifier_ciphertext) ||
    !safeText(row.ring_nonce_time_ciphertext) ||
    !sec(row.created_at) || !sec(row.expires_at) || !sec(row.ttl_delete_after) ||
    row.expires_at <= row.created_at || row.expires_at > row.created_at + 300 ||
    row.ttl_delete_after !== row.expires_at + 604800 ||
    !['pending','exchanging','consumed'].includes(row.status)) fail('invalid_auth_row');
  if (row.status === 'pending' && (row.reservation_ref !== undefined ||
      row.reserved_at !== undefined || row.consumed_at !== undefined)) fail('invalid_auth_row');
  if (row.status === 'exchanging' && (!digest(row.reservation_ref) ||
      !sec(row.reserved_at) || row.reserved_at < row.created_at ||
      row.reserved_at >= row.expires_at || row.consumed_at !== undefined)) {
    fail('invalid_auth_row');
  }
  if (row.status === 'consumed' && (!digest(row.reservation_ref) ||
      !sec(row.reserved_at) || !sec(row.consumed_at) ||
      row.reserved_at < row.created_at || row.reserved_at >= row.expires_at ||
      row.consumed_at < row.reserved_at || row.consumed_at >= row.expires_at)) {
    fail('invalid_auth_row');
  }
  return row;
}
function sessionRow(value) {
  const row = plain(value, Object.keys(SESSION_TYPES), 'invalid_session_row');
  need(row, ['pk','owner_subject_ref','version','status','created_at','last_seen_at',
    'absolute_expires_at','idle_expires_at','csrf_ref','ttl_delete_after'],
    'invalid_session_row');
  if (![row.pk,row.owner_subject_ref,row.csrf_ref].every(digest) ||
      !isSessionVersion(row.version) ||
      ![row.created_at,row.last_seen_at,row.absolute_expires_at,row.idle_expires_at,
        row.ttl_delete_after].every(sec) ||
      row.absolute_expires_at !== row.created_at + 3600 ||
      row.last_seen_at < row.created_at ||
      row.idle_expires_at > Math.min(row.last_seen_at + 900, row.absolute_expires_at) ||
      row.ttl_delete_after !== row.absolute_expires_at + 604800 ||
      !['active','revoked'].includes(row.status)) fail('invalid_session_row');
  if (row.status === 'active' && row.revoked_at !== undefined) fail('invalid_session_row');
  if (row.status === 'revoked' && (!sec(row.revoked_at) ||
      row.revoked_at < row.created_at || row.revoked_at >= row.absolute_expires_at)) {
    fail('invalid_session_row');
  }
  return row;
}

function encode(row, types) {
  const result = {};
  for (const [field, type] of Object.entries(types)) {
    if (row[field] !== undefined) result[field] = type === 'S' ?
      avString(row[field]) : avNumber(row[field]);
  }
  return result;
}
function decode(item, types, validation) {
  const source = plain(item, Object.keys(types), 'malformed_read');
  const row = {};
  for (const [field, av] of Object.entries(source)) {
    const attribute = plain(av, [types[field]], 'malformed_read');
    need(attribute, [types[field]], 'malformed_read');
    if (Object.keys(attribute).length !== 1) fail('malformed_read');
    if (types[field] === 'S') {
      if (!safeText(attribute.S)) fail('malformed_read');
      row[field] = attribute.S;
    } else {
      if (typeof attribute.N !== 'string' || !/^(0|[1-9][0-9]*)$/.test(attribute.N)) {
        fail('malformed_read');
      }
      const number = Number(attribute.N);
      if (!sec(number)) fail('malformed_read');
      row[field] = number;
    }
  }
  try { return validation(row); } catch { fail('malformed_read'); }
}

export function encodeAuthItem(row) { return encode(authRow(row), AUTH_TYPES); }
export function encodeSessionItem(row) { return encode(sessionRow(row), SESSION_TYPES); }
export function decodeAuthItem(item) { return decode(item, AUTH_TYPES, authRow); }
export function decodeSessionItem(item) { return decode(item, SESSION_TYPES, sessionRow); }

function checkTable(tableName) { if (!name(tableName)) fail('invalid_config'); }
function checkTime(now) { if (!sec(now)) fail('invalid_time'); }
function tokenFor(request) {
  return createHash('sha256').update(JSON.stringify(request), 'utf8').digest('hex').slice(0, 32);
}

export function planPutTransaction({ tableName, row, now }) {
  checkTable(tableName); checkTime(now);
  const value = authRow(row);
  if (value.status !== 'pending' || value.expires_at <= now) fail('invalid_auth_row');
  return { TableName: tableName, Item: encodeAuthItem(value),
    ConditionExpression: 'attribute_not_exists(#pk)',
    ExpressionAttributeNames: { '#pk': 'pk' } };
}

export function planReserveTransaction({ tableName, pk, reservationRef,
  expectedExpiresAt, expectedRow, now }) {
  checkTable(tableName); key(pk); checkTime(now);
  const current = authRow(expectedRow);
  if (!digest(reservationRef) || !sec(expectedExpiresAt) || expectedExpiresAt <= now) {
    fail('invalid_reservation');
  }
  if (current.pk !== pk || current.status !== 'pending' ||
      current.expires_at !== expectedExpiresAt) fail('invalid_reservation');
  return { TableName: tableName, Key: key(pk),
    ConditionExpression: 'attribute_exists(#pk) AND #status = :pending AND #created = :created AND #expires = :expected AND #ttl = :ttl AND #expires > :now AND attribute_not_exists(#reservation) AND attribute_not_exists(#consumed)',
    UpdateExpression: 'SET #status = :exchanging, #reservation = :reservationRef, #reservedAt = :now',
    ExpressionAttributeNames: { '#pk': 'pk', '#status': 'status', '#expires': 'expires_at',
      '#created': 'created_at', '#ttl': 'ttl_delete_after',
      '#reservation': 'reservation_ref', '#reservedAt': 'reserved_at',
      '#consumed': 'consumed_at' },
    ExpressionAttributeValues: { ':pending': avString('pending'),
      ':exchanging': avString('exchanging'), ':expected': avNumber(expectedExpiresAt),
      ':created': avNumber(current.created_at), ':ttl': avNumber(current.ttl_delete_after),
      ':now': avNumber(now), ':reservationRef': avString(reservationRef) } };
}

export function planFinalizeTransaction({ authTableName, sessionTableName, pk,
  reservationRef, expectedRow, sessionRow: proposedSession, now }) {
  checkTable(authTableName); checkTable(sessionTableName); key(pk); checkTime(now);
  if (!digest(reservationRef)) fail('invalid_finalization');
  const current = authRow(expectedRow);
  if (current.pk !== pk || current.status !== 'exchanging' ||
      current.reservation_ref !== reservationRef || current.expires_at <= now) {
    fail('invalid_finalization');
  }
  const next = sessionRow(proposedSession);
  if (next.status !== 'active' || next.version !== 1 ||
      next.absolute_expires_at <= now || next.idle_expires_at <= now ||
      (authTableName === sessionTableName && next.pk === pk)) fail('invalid_finalization');
  const request = { TransactItems: [
    { Update: { TableName: authTableName, Key: key(pk),
      ConditionExpression: 'attribute_exists(#pk) AND #status = :exchanging AND #reservation = :reservationRef AND #created = :created AND #expires = :expected AND #ttl = :ttl AND #expires > :now AND attribute_not_exists(#consumed)',
      UpdateExpression: 'SET #status = :consumedStatus, #consumed = :now',
      ExpressionAttributeNames: { '#pk': 'pk', '#status': 'status',
        '#reservation': 'reservation_ref', '#expires': 'expires_at',
        '#created': 'created_at', '#ttl': 'ttl_delete_after',
        '#consumed': 'consumed_at' },
      ExpressionAttributeValues: { ':exchanging': avString('exchanging'),
        ':reservationRef': avString(reservationRef), ':now': avNumber(now),
        ':created': avNumber(current.created_at),
        ':expected': avNumber(current.expires_at),
        ':ttl': avNumber(current.ttl_delete_after),
        ':consumedStatus': avString('consumed') } } },
    { Put: { TableName: sessionTableName, Item: encodeSessionItem(next),
      ConditionExpression: 'attribute_not_exists(#pk)',
      ExpressionAttributeNames: { '#pk': 'pk' } } }
  ] };
  return { ...request, ClientRequestToken: tokenFor(request) };
}

function sessionCondition(expected, now) {
  return {
    ConditionExpression: 'attribute_exists(#pk) AND #status = :active AND #version = :version AND #owner = :owner AND #created = :created AND #absolute = :absoluteExpected AND #idle = :idleExpected AND #absolute > :now AND #idle > :now AND attribute_not_exists(#revoked)',
    ExpressionAttributeNames: { '#pk': 'pk', '#status': 'status', '#version': 'version',
      '#owner': 'owner_subject_ref', '#created': 'created_at',
      '#absolute': 'absolute_expires_at', '#idle': 'idle_expires_at',
      '#revoked': 'revoked_at' },
    ExpressionAttributeValues: { ':active': avString('active'),
      ':version': avNumber(expected.version), ':owner': avString(expected.owner_subject_ref),
      ':created': avNumber(expected.created_at),
      ':absoluteExpected': avNumber(expected.absolute_expires_at),
      ':idleExpected': avNumber(expected.idle_expires_at), ':now': avNumber(now) }
  };
}

export function planTouchSession({ tableName, pk, expectedVersion, expectedRow, now,
  idleSeconds }) {
  checkTable(tableName); key(pk); checkTime(now);
  const current = sessionRow(expectedRow);
  if (current.pk !== pk || current.version !== expectedVersion ||
      current.status !== 'active' || idleSeconds !== 900 ||
      current.absolute_expires_at <= now || current.idle_expires_at <= now) {
    fail('invalid_session_row');
  }
  const next = { ...current, version: nextSessionVersion(current.version), last_seen_at: now,
    idle_expires_at: Math.min(now + idleSeconds, current.absolute_expires_at) };
  const condition = sessionCondition(current, now);
  return { request: { TableName: tableName, Key: key(pk),
    ConditionExpression: condition.ConditionExpression,
    UpdateExpression: 'SET #version = :nextVersion, #lastSeen = :now, #idle = :nextIdle',
    ExpressionAttributeNames: { ...condition.ExpressionAttributeNames,
      '#lastSeen': 'last_seen_at' },
    ExpressionAttributeValues: { ...condition.ExpressionAttributeValues,
      ':nextVersion': avNumber(next.version), ':nextIdle': avNumber(next.idle_expires_at) } },
  nextRow: next };
}

export function planRotateSession({ tableName, pk, expectedVersion, expectedRow,
  newRow, now, idleSeconds }) {
  checkTable(tableName); key(pk); checkTime(now);
  const current = sessionRow(expectedRow);
  const nextVersion = nextSessionVersion(current.version);
  const replacement = sessionRow(newRow);
  if (current.pk !== pk || current.version !== expectedVersion ||
      current.status !== 'active' || replacement.pk === pk ||
      replacement.status !== 'active' || replacement.version !== nextVersion ||
      replacement.created_at !== current.created_at ||
      replacement.absolute_expires_at !== current.absolute_expires_at ||
      replacement.owner_subject_ref !== current.owner_subject_ref ||
      idleSeconds !== 900 || current.absolute_expires_at <= now ||
      current.idle_expires_at <= now) fail('invalid_session_row');
  const next = { ...replacement, last_seen_at: now,
    idle_expires_at: Math.min(now + idleSeconds, current.absolute_expires_at) };
  const condition = sessionCondition(current, now);
  const request = { TransactItems: [
    { Update: { TableName: tableName, Key: key(pk),
      ConditionExpression: condition.ConditionExpression,
      UpdateExpression: 'SET #status = :revokedStatus, #version = :nextVersion, #revoked = :now',
      ExpressionAttributeNames: condition.ExpressionAttributeNames,
      ExpressionAttributeValues: { ...condition.ExpressionAttributeValues,
        ':revokedStatus': avString('revoked'),
        ':nextVersion': avNumber(nextVersion) } } },
    { Put: { TableName: tableName, Item: encodeSessionItem(next),
      ConditionExpression: 'attribute_not_exists(#pk)',
      ExpressionAttributeNames: { '#pk': 'pk' } } }
  ] };
  return { request: { ...request, ClientRequestToken: tokenFor(request) }, nextRow: next };
}

export function planRevokeSession({ tableName, pk, expectedVersion, expectedRow, now }) {
  checkTable(tableName); key(pk); checkTime(now);
  const current = sessionRow(expectedRow);
  if (current.pk !== pk || current.version !== expectedVersion ||
      current.status !== 'active' || current.absolute_expires_at <= now ||
      current.idle_expires_at <= now) fail('invalid_session_row');
  const nextVersion = nextSessionVersion(current.version);
  const condition = sessionCondition(current, now);
  return { TableName: tableName, Key: key(pk),
    ConditionExpression: condition.ConditionExpression,
    UpdateExpression: 'SET #status = :revokedStatus, #version = :nextVersion, #revoked = :now',
    ExpressionAttributeNames: condition.ExpressionAttributeNames,
    ExpressionAttributeValues: { ...condition.ExpressionAttributeValues,
      ':revokedStatus': avString('revoked'),
      ':nextVersion': avNumber(nextVersion) } };
}

function dataProperty(value, field, inherited = false) {
  let current = value;
  for (let depth = 0; depth < 5; depth += 1) {
    if (current === null || (typeof current !== 'object' &&
        typeof current !== 'function')) return { found: false };
    const descriptor = Object.getOwnPropertyDescriptor(current, field);
    if (descriptor) {
      if (!Object.hasOwn(descriptor, 'value')) return { found: false };
      return { found: true, value: descriptor.value };
    }
    if (!inherited) return { found: false };
    current = Object.getPrototypeOf(current);
  }
  return { found: false };
}

function knownConflict(error, operation, itemCount) {
  try {
    const name = dataProperty(error, 'name', true);
    if (!name.found || typeof name.value !== 'string') return false;
    if (operation !== 'TransactWriteItems') {
      return name.value === 'ConditionalCheckFailedException';
    }
    if (name.value !== 'TransactionCanceledException') return false;
    const reasons = dataProperty(error, 'CancellationReasons');
    if (!reasons.found || !Array.isArray(reasons.value)) return false;
    const length = dataProperty(reasons.value, 'length');
    if (!length.found || length.value !== itemCount) return false;
    let conditional = false;
    for (let index = 0; index < itemCount; index += 1) {
      const reason = dataProperty(reasons.value, String(index));
      if (!reason.found) return false;
      const code = dataProperty(reason.value, 'Code');
      if (!code.found) return false;
      if (code.value === 'ConditionalCheckFailed') conditional = true;
      else if (code.value !== 'None') return false;
    }
    return conditional;
  } catch {
    return false;
  }
}

export function createDynamoSessionAdapter({ getItem, authTableName, sessionTableName,
  mode = 'guarded', offlineExecute } = {}) {
  if (typeof getItem !== 'function' || !name(authTableName) || !name(sessionTableName) ||
      !['guarded','offline_fixture'].includes(mode) ||
      (mode === 'offline_fixture' && typeof offlineExecute !== 'function') ||
      (mode === 'guarded' && offlineExecute !== undefined)) fail('invalid_config');
  const read = async (tableName, pk, decoder) => {
    const request = { TableName: tableName, Key: key(pk), ConsistentRead: true };
    let response;
    try { response = await getItem(request); } catch { fail('read_unavailable'); }
    const output = plain(response, ['Item','$metadata','ConsumedCapacity'], 'malformed_read');
    if (!Object.hasOwn(output, 'Item')) return null;
    const row = decoder(output.Item);
    if (row.pk !== pk) fail('malformed_read');
    return row;
  };
  const execute = async (operation, request, decisionNow, lowerBound, deadlineGuards) => {
    decision(decisionNow, lowerBound);
    if (mode === 'guarded') fail('commit_clock_unavailable');
    let result;
    try { result = await offlineExecute({ operation, request, decisionNow,
      deadlineGuards }); }
    catch (error) {
      if (knownConflict(error, operation, request.TransactItems?.length)) return false;
      fail('outcome_unknown');
    }
    plain(result, [], 'outcome_unknown');
    return true;
  };
  const mutationGate = () => {
    if (mode === 'guarded') fail('commit_clock_unavailable');
  };
  return Object.freeze({
    async putTransaction(row, { decisionNow } = {}) {
      mutationGate();
      const value = authRow(row);
      const now = decision(decisionNow, value.created_at);
      const request = planPutTransaction({ tableName: authTableName, row: value, now });
      return execute('PutItem', request, decisionNow, now,
        [{ kind: 'auth', expiresAt: value.expires_at }]);
    },
    async getTransaction(pk) { return read(authTableName, pk, decodeAuthItem); },
    async reserveTransaction({ pk, reservationRef, now, expectedExpiresAt,
      originalRingDeadline, decisionNow }) {
      mutationGate();
      key(pk); checkTime(now);
      if (!sec(originalRingDeadline) || originalRingDeadline <= now) fail('invalid_reservation');
      const current = await read(authTableName, pk, decodeAuthItem);
      if (!current || current.status !== 'pending' ||
          current.expires_at !== expectedExpiresAt) return false;
      const request = planReserveTransaction({ tableName: authTableName, pk,
        reservationRef, expectedExpiresAt, expectedRow: current, now });
      return execute('UpdateItem', request, decisionNow, now,
        [{ kind: 'auth', expiresAt: expectedExpiresAt },
          { kind: 'ring', expiresAt: originalRingDeadline }]);
    },
    async finalizeTransaction({ pk, reservationRef, now, originalRingDeadline,
      verifiedIdentityExpiresAt, sessionRow: proposedSession, decisionNow }) {
      mutationGate();
      key(pk); checkTime(now);
      if (!sec(originalRingDeadline) || !sec(verifiedIdentityExpiresAt) ||
          originalRingDeadline <= now || verifiedIdentityExpiresAt <= now) {
        fail('invalid_finalization');
      }
      const current = await read(authTableName, pk, decodeAuthItem);
      if (!current || current.status !== 'exchanging' ||
          current.reservation_ref !== reservationRef) return false;
      const session = sessionRow(proposedSession);
      const request = planFinalizeTransaction({ authTableName, sessionTableName,
        pk, reservationRef, expectedRow: current, sessionRow: session, now });
      return execute('TransactWriteItems', request, decisionNow, now,
        [{ kind: 'auth', expiresAt: current.expires_at },
          { kind: 'ring', expiresAt: originalRingDeadline },
          { kind: 'identity', expiresAt: verifiedIdentityExpiresAt },
          { kind: 'session_absolute', expiresAt: session.absolute_expires_at },
          { kind: 'session_idle', expiresAt: session.idle_expires_at }]);
    },
    async getSession(pk) { return read(sessionTableName, pk, decodeSessionItem); },
    async touchSession({ pk, expectedVersion, now, idleSeconds, decisionNow }) {
      mutationGate();
      key(pk); checkTime(now);
      const current = await read(sessionTableName, pk, decodeSessionItem);
      if (!current || current.status !== 'active' ||
          current.version !== expectedVersion) return null;
      const { request, nextRow } = planTouchSession({ tableName: sessionTableName,
        pk, expectedVersion, expectedRow: current, now, idleSeconds });
      const result = await execute('UpdateItem', request, decisionNow, now,
        [{ kind: 'session_absolute', expiresAt: current.absolute_expires_at },
          { kind: 'session_idle', expiresAt: current.idle_expires_at }]);
      return result ? nextRow : null;
    },
    async rotateSession({ pk, expectedVersion, now, newRow, idleSeconds,
      decisionNow }) {
      mutationGate();
      key(pk); checkTime(now);
      const current = await read(sessionTableName, pk, decodeSessionItem);
      if (!current || current.status !== 'active' ||
          current.version !== expectedVersion) return null;
      const { request, nextRow } = planRotateSession({ tableName: sessionTableName,
        pk, expectedVersion, expectedRow: current, newRow, now, idleSeconds });
      const result = await execute('TransactWriteItems', request, decisionNow, now,
        [{ kind: 'session_absolute', expiresAt: current.absolute_expires_at },
          { kind: 'session_idle', expiresAt: current.idle_expires_at }]);
      return result ? nextRow : null;
    },
    async revokeSession({ pk, expectedVersion, now, decisionNow }) {
      mutationGate();
      key(pk); checkTime(now);
      const current = await read(sessionTableName, pk, decodeSessionItem);
      if (!current || current.status !== 'active' ||
          current.version !== expectedVersion) return false;
      const request = planRevokeSession({ tableName: sessionTableName,
        pk, expectedVersion, expectedRow: current, now });
      return execute('UpdateItem', request, decisionNow, now,
        [{ kind: 'session_absolute', expiresAt: current.absolute_expires_at },
          { kind: 'session_idle', expiresAt: current.idle_expires_at }]);
    }
  });
}
