import { createHmac, timingSafeEqual } from 'node:crypto';
import { ProtocolError, requireOpaque } from './protocol.mjs';

const DEFAULT_TTL_SECONDS = 604_800;
const MAX_BODY_BYTES = 65_536;
const HEX_SHA256 = /^[0-9a-f]{64}$/;

function digest(key, domain, value) {
  return createHmac('sha256', key).update(domain, 'utf8').update(Buffer.from([0])).update(value).digest('hex');
}

function sameDigest(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string' ||
      !HEX_SHA256.test(left) || !HEX_SHA256.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

function isConditionalFailure(error) {
  return error?.name === 'ConditionalCheckFailedException' || error?.code === 'ConditionalCheckFailedException';
}

function requireItem(item) {
  const accountDigest = item?.account_digest?.S;
  const bodyDigest = item?.body_digest?.S;
  if (typeof accountDigest !== 'string' || !HEX_SHA256.test(accountDigest) ||
      typeof bodyDigest !== 'string' || !HEX_SHA256.test(bodyDigest)) {
    throw new ProtocolError('ledger_conflict');
  }
  return { accountDigest, bodyDigest };
}

function operationOptions(value) {
  if (value === undefined) return Object.freeze({ signal: undefined });
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value) ||
        Reflect.ownKeys(value).some(key => key !== 'signal') ||
        typeof AbortSignal === 'undefined' || !(value.signal instanceof AbortSignal)) {
      throw new ProtocolError('ledger_config');
    }
    return Object.freeze({ signal: value.signal });
  } catch (error) {
    if (error instanceof ProtocolError) throw error;
    throw new ProtocolError('ledger_config');
  }
}

export function createDynamoEventLedger({
  putItem,
  getItem,
  tableName,
  hashKey,
  clock = () => Date.now(),
  ttlSeconds = DEFAULT_TTL_SECONDS
} = {}) {
  if (typeof putItem !== 'function' || typeof getItem !== 'function' ||
      typeof tableName !== 'string' || !/^[A-Za-z0-9_.-]{3,255}$/.test(tableName) ||
      !(typeof hashKey === 'string' || Buffer.isBuffer(hashKey)) ||
      Buffer.byteLength(hashKey) < 32 || Buffer.byteLength(hashKey) > 4096 ||
      typeof clock !== 'function' || !Number.isSafeInteger(ttlSeconds) ||
      ttlSeconds < 3600 || ttlSeconds > 2_592_000) {
    throw new ProtocolError('ledger_config');
  }
  const digestKey = Buffer.from(hashKey);

  function identity(requestId, accountId, rawBody) {
    requireOpaque(requestId, 256);
    requireOpaque(accountId, 256);
    if (!Buffer.isBuffer(rawBody) || rawBody.length === 0 || rawBody.length > MAX_BODY_BYTES) {
      throw new ProtocolError('invalid_webhook');
    }
    return {
      pk: digest(digestKey, 'ring-request-id', requestId),
      accountDigest: digest(digestKey, 'ring-account-id', accountId),
      bodyDigest: digest(digestKey, 'ring-raw-body', rawBody)
    };
  }

  async function readIdentity(value, options) {
    let item;
    try {
      const result = await getItem(
        { TableName: tableName, Key: { pk: { S: value.pk } }, ConsistentRead: true },
        options.signal === undefined ? undefined : { signal: options.signal }
      );
      item = result?.Item;
    } catch {
      throw new ProtocolError('ledger_unavailable');
    }
    if (!item) return false;
    const existing = requireItem(item);
    if (!sameDigest(existing.accountDigest, value.accountDigest) || !sameDigest(existing.bodyDigest, value.bodyDigest)) {
      throw new ProtocolError('event_conflict');
    }
    return true;
  }

  return Object.freeze({
    async lookupWebhook(requestId, accountId, rawBody, optionsValue) {
      const options = operationOptions(optionsValue);
      const value = identity(requestId, accountId, rawBody);
      return { duplicate: await readIdentity(value, options) };
    },
    async acceptWebhook(requestId, accountId, rawBody, optionsValue) {
      const options = operationOptions(optionsValue);
      const value = identity(requestId, accountId, rawBody);
      const now = clock();
      if (!Number.isSafeInteger(now) || now < 0) throw new ProtocolError('ledger_clock');
      const expiresAt = Math.floor(now / 1000) + ttlSeconds;
      if (!Number.isSafeInteger(expiresAt)) throw new ProtocolError('ledger_clock');

      try {
        await putItem({
          TableName: tableName,
          Item: {
            pk: { S: value.pk },
            account_digest: { S: value.accountDigest },
            body_digest: { S: value.bodyDigest },
            expires_at: { N: String(expiresAt) }
          },
          ConditionExpression: 'attribute_not_exists(pk)'
        }, options.signal === undefined ? undefined : { signal: options.signal });
        return { duplicate: false };
      } catch (error) {
        if (!isConditionalFailure(error)) throw new ProtocolError('ledger_unavailable');
      }

      if (!await readIdentity(value, options)) throw new ProtocolError('ledger_conflict');
      return { duplicate: true };
    }
  });
}
