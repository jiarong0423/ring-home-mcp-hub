import { createHmac, timingSafeEqual } from 'node:crypto';
import { ProtocolError, requireOpaque } from './protocol.mjs';

const HEX_SHA256 = /^[0-9a-f]{64}$/;
const POSITIVE_INTEGER = /^[1-9][0-9]*$/;
const NONNEGATIVE_INTEGER = /^(0|[1-9][0-9]*)$/;

function sameHash(left, right) {
  if (typeof left !== 'string' || !HEX_SHA256.test(left)) return false;
  return timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

function parseNumber(value, pattern) {
  if (typeof value !== 'string' || !pattern.test(value)) throw new ProtocolError('linked_record_invalid');
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new ProtocolError('linked_record_invalid');
  return parsed;
}

function operationOptions(value) {
  if (value === undefined) return Object.freeze({ signal: undefined });
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value) ||
        Reflect.ownKeys(value).some(key => key !== 'signal') ||
        typeof AbortSignal === 'undefined' || !(value.signal instanceof AbortSignal)) {
      throw new ProtocolError('linked_authorizer_config');
    }
    return Object.freeze({ signal: value.signal });
  } catch (error) {
    if (error instanceof ProtocolError) throw error;
    throw new ProtocolError('linked_authorizer_config');
  }
}

export function createDynamoLinkedDeviceAuthorizer({
  getItem,
  tableName,
  hashKey,
  clock = () => Date.now()
} = {}) {
  if (typeof getItem !== 'function' || typeof tableName !== 'string' ||
      !/^[A-Za-z0-9_.-]{3,255}$/.test(tableName) ||
      !(typeof hashKey === 'string' || Buffer.isBuffer(hashKey)) ||
      Buffer.byteLength(hashKey) < 32 || Buffer.byteLength(hashKey) > 4096 ||
      typeof clock !== 'function') {
    throw new ProtocolError('linked_authorizer_config');
  }
  const digestKey = Buffer.from(hashKey);

  return Object.freeze({
    async isLinkedDevice(accountId, deviceId, optionsValue) {
      const options = operationOptions(optionsValue);
      requireOpaque(accountId, 256);
      requireOpaque(deviceId, 256);
      const pk = createHmac('sha256', digestKey)
        .update('ring-linked-device\0', 'utf8')
        .update(JSON.stringify([accountId, deviceId]), 'utf8')
        .digest('hex');
      let item;
      try {
        const result = await getItem(
          { TableName: tableName, Key: { pk: { S: pk } }, ConsistentRead: true },
          options.signal === undefined ? undefined : { signal: options.signal }
        );
        item = result?.Item;
      } catch {
        throw new ProtocolError('linked_store_unavailable');
      }
      if (!item) return false;
      if (!sameHash(item.pk?.S, pk) || typeof item.status?.S !== 'string' ||
          typeof item.revoked?.BOOL !== 'boolean') {
        throw new ProtocolError('linked_record_invalid');
      }
      const grantVersion = parseNumber(item.grant_version?.N, POSITIVE_INTEGER);
      const expiresAt = parseNumber(item.expires_at?.N, NONNEGATIVE_INTEGER);
      const now = clock();
      if (!Number.isSafeInteger(now) || now < 0) throw new ProtocolError('linked_clock_unavailable');
      if (grantVersion < 1) throw new ProtocolError('linked_record_invalid');
      return item.status.S === 'completed' && item.revoked.BOOL === false &&
        expiresAt > Math.floor(now / 1000);
    }
  });
}
