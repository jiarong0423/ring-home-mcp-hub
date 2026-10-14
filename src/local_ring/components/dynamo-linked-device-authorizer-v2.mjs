import { timingSafeEqual } from 'node:crypto';
import { ProtocolError } from './protocol.mjs';
import { deriveLinkedDeviceKey, requireLinkedHashKey } from './linked-device-key.mjs';

const TABLE_NAME = /^[A-Za-z0-9_.-]{3,255}$/;
const HEX_SHA256 = /^[0-9a-f]{64}$/;
const POSITIVE_INTEGER = /^[1-9][0-9]*$/;
const NONNEGATIVE_INTEGER = /^(0|[1-9][0-9]*)$/;

function sameKey(value, expected) {
  return typeof value === 'string' && HEX_SHA256.test(value) &&
    timingSafeEqual(Buffer.from(value, 'hex'), Buffer.from(expected, 'hex'));
}

function storedNumber(value, pattern) {
  if (typeof value !== 'string' || !pattern.test(value)) {
    throw new ProtocolError('linked_record_invalid');
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new ProtocolError('linked_record_invalid');
  return parsed;
}

function nowMilliseconds(clock) {
  let value;
  try {
    value = clock();
  } catch {
    throw new ProtocolError('linked_clock_unavailable');
  }
  if (!Number.isSafeInteger(value) || value < 0) throw new ProtocolError('linked_clock_unavailable');
  return value;
}

export function createDynamoLinkedDeviceAuthorizerV2({
  getItem,
  tableName,
  hashKey,
  accountAuthority,
  clock = () => Date.now()
} = {}) {
  if (typeof getItem !== 'function' || typeof tableName !== 'string' ||
      !TABLE_NAME.test(tableName) || typeof accountAuthority?.isCurrent !== 'function' ||
      typeof clock !== 'function') {
    throw new ProtocolError('linked_authorizer_config');
  }
  const key = requireLinkedHashKey(hashKey);
  const isCurrent = accountAuthority.isCurrent;

  return Object.freeze({
    async isLinkedDevice(accountId, deviceId) {
      const pk = deriveLinkedDeviceKey(accountId, deviceId, key);
      let item;
      try {
        const result = await getItem({
          TableName: tableName,
          Key: { pk: { S: pk } },
          ConsistentRead: true
        });
        item = result?.Item;
      } catch {
        throw new ProtocolError('linked_store_unavailable');
      }
      if (!item) return false;
      if (!sameKey(item.pk?.S, pk) || typeof item.status?.S !== 'string' ||
          typeof item.revoked?.BOOL !== 'boolean') {
        throw new ProtocolError('linked_record_invalid');
      }
      const grantVersion = storedNumber(item.grant_version?.N, POSITIVE_INTEGER);
      const expiresAt = storedNumber(item.expires_at?.N, NONNEGATIVE_INTEGER);
      const accountEpoch = storedNumber(item.account_epoch?.N, POSITIVE_INTEGER);
      const now = nowMilliseconds(clock);
      if (item.status.S !== 'completed' || item.revoked.BOOL !== false ||
          expiresAt <= Math.floor(now / 1000)) return false;
      let current;
      try {
        current = await isCurrent.call(accountAuthority, accountId, accountEpoch);
      } catch {
        throw new ProtocolError('linked_account_authority_unavailable');
      }
      if (typeof current !== 'boolean') {
        throw new ProtocolError('linked_account_authority_invalid');
      }
      const decisionTime = nowMilliseconds(clock);
      return current && decisionTime >= now && expiresAt > Math.floor(decisionTime / 1000);
    }
  });
}
