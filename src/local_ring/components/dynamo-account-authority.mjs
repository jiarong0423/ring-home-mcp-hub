import { createHmac, timingSafeEqual } from 'node:crypto';
import { ProtocolError, requireOpaque } from './protocol.mjs';
import { deriveLinkedEvidenceDigest, requireLinkedHashKey } from './linked-device-key.mjs';

const TABLE_NAME = /^[A-Za-z0-9_.-]{3,255}$/;
const ATTRIBUTE_NAME = /^[A-Za-z][A-Za-z0-9_]*$/;
const NUMBER = /^(0|[1-9][0-9]*)$/;
const HEX_SHA256 = /^[0-9a-f]{64}$/;
const RESERVED_ATTRIBUTES = new Set([
  'pk', 'status', 'revoked', 'account_epoch', 'integration_ref', 'expires_at',
  'revoked_at', 'removal_ref'
]);

function nowSeconds(clock) {
  const value = clock();
  if (!Number.isSafeInteger(value) || value < 0) throw new ProtocolError('account_authority_clock_unavailable');
  return Math.floor(value / 1000);
}

function nowMilliseconds(clock) {
  let value;
  try {
    value = clock();
  } catch {
    throw new ProtocolError('account_authority_clock_unavailable');
  }
  if (!Number.isSafeInteger(value) || value < 0) throw new ProtocolError('account_authority_clock_unavailable');
  return value;
}

function epoch(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value >= Number.MAX_SAFE_INTEGER) {
    throw new ProtocolError('account_authority_epoch_invalid');
  }
  return value;
}

function storedNumber(value, positive = false) {
  if (typeof value !== 'string' || !NUMBER.test(value)) {
    throw new ProtocolError('account_authority_record_invalid');
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || (positive && parsed < 1)) {
    throw new ProtocolError('account_authority_record_invalid');
  }
  return parsed;
}

function sameDigest(value, expected) {
  return typeof value === 'string' && HEX_SHA256.test(value) &&
    timingSafeEqual(Buffer.from(value, 'hex'), Buffer.from(expected, 'hex'));
}

export function deriveAccountAuthorityKey(accountId, hashKey) {
  requireOpaque(accountId, 256);
  const key = requireLinkedHashKey(hashKey);
  return createHmac('sha256', key)
    .update('ring-account-authority\0', 'utf8')
    .update(accountId, 'utf8')
    .digest('hex');
}

function parseItem(item, pk, ttlAttributeName) {
  if (!sameDigest(item?.pk?.S, pk) || typeof item?.revoked?.BOOL !== 'boolean') {
    throw new ProtocolError('account_authority_record_invalid');
  }
  const currentEpoch = storedNumber(item.account_epoch?.N, true);
  if (typeof item.integration_ref?.S !== 'string' || !HEX_SHA256.test(item.integration_ref.S)) {
    throw new ProtocolError('account_authority_record_invalid');
  }
  if (item.status?.S === 'active' && item.revoked.BOOL === false) {
    if (item.removal_ref !== undefined || item.revoked_at !== undefined ||
        item[ttlAttributeName] !== undefined) {
      throw new ProtocolError('account_authority_record_invalid');
    }
    return {
      status: 'active', currentEpoch, integrationRef: item.integration_ref.S,
      expiresAt: storedNumber(item.expires_at?.N)
    };
  }
  if (item.status?.S === 'revoked' && item.revoked.BOOL === true) {
    if (item.expires_at !== undefined || item[ttlAttributeName] !== undefined ||
        !HEX_SHA256.test(item.removal_ref?.S ?? '')) {
      throw new ProtocolError('account_authority_record_invalid');
    }
    storedNumber(item.revoked_at?.N);
    return {
      status: 'revoked', currentEpoch, integrationRef: item.integration_ref.S,
      removalRef: item.removal_ref.S
    };
  }
  throw new ProtocolError('account_authority_record_invalid');
}

export function createDynamoAccountAuthority({
  getItem,
  updateItem,
  tableName,
  hashKey,
  ttlAttributeName,
  clock = () => Date.now()
} = {}) {
  if (typeof getItem !== 'function' || typeof updateItem !== 'function' ||
      typeof tableName !== 'string' || !TABLE_NAME.test(tableName) ||
      typeof ttlAttributeName !== 'string' || !ATTRIBUTE_NAME.test(ttlAttributeName) ||
      RESERVED_ATTRIBUTES.has(ttlAttributeName) ||
      typeof clock !== 'function') {
    throw new ProtocolError('account_authority_config');
  }
  const key = requireLinkedHashKey(hashKey);

  async function read(accountKey) {
    let result;
    try {
      result = await getItem({
        TableName: tableName,
        Key: { pk: { S: accountKey } },
        ConsistentRead: true
      });
    } catch {
      throw new ProtocolError('account_authority_store_unavailable');
    }
    if (!result?.Item) return null;
    return parseItem(result.Item, accountKey, ttlAttributeName);
  }

  return Object.freeze({
    async isCurrent(accountId, expectedEpoch) {
      const accountKey = deriveAccountAuthorityKey(accountId, key);
      epoch(expectedEpoch);
      const startedAt = nowMilliseconds(clock);
      const item = await read(accountKey);
      const now = nowMilliseconds(clock);
      return now >= startedAt && item?.status === 'active' &&
        item.currentEpoch === expectedEpoch && item.expiresAt > Math.floor(now / 1000);
    },

    async revokeAccount(accountId, expectedEpoch, expectedIntegrationRef, removalId) {
      const accountKey = deriveAccountAuthorityKey(accountId, key);
      epoch(expectedEpoch);
      requireOpaque(expectedIntegrationRef, 256);
      requireOpaque(removalId, 256);
      const now = nowSeconds(clock);
      const nextEpoch = expectedEpoch + 1;
      const integrationRef = deriveLinkedEvidenceDigest('integration', expectedIntegrationRef, key);
      const removalRef = deriveLinkedEvidenceDigest('account-removal', removalId, key);
      const names = {
        '#status': 'status', '#revoked': 'revoked', '#epoch': 'account_epoch',
        '#integrationRef': 'integration_ref',
        '#expires': 'expires_at', '#revokedAt': 'revoked_at', '#removalRef': 'removal_ref'
      };
      names['#ttl'] = ttlAttributeName;
      try {
        await updateItem({
          TableName: tableName,
          Key: { pk: { S: accountKey } },
          ConditionExpression: '#status = :active AND #revoked = :false AND #epoch = :expected AND #integrationRef = :integrationRef AND attribute_not_exists(#ttl) AND attribute_not_exists(#removalRef) AND attribute_not_exists(#revokedAt)',
          UpdateExpression: 'SET #status = :revokedStatus, #revoked = :true, #epoch = :next, #revokedAt = :now, #removalRef = :removalRef REMOVE #expires, #ttl',
          ExpressionAttributeNames: names,
          ExpressionAttributeValues: {
            ':active': { S: 'active' }, ':false': { BOOL: false },
            ':expected': { N: String(expectedEpoch) }, ':integrationRef': { S: integrationRef },
            ':now': { N: String(now) },
            ':revokedStatus': { S: 'revoked' }, ':true': { BOOL: true },
            ':next': { N: String(nextEpoch) }, ':removalRef': { S: removalRef }
          },
          ReturnValues: 'NONE'
        });
        return Object.freeze({ status: 'revoked', accountEpoch: nextEpoch, duplicate: false });
      } catch (error) {
        if (error?.name !== 'ConditionalCheckFailedException' &&
            error?.code !== 'ConditionalCheckFailedException') {
          throw new ProtocolError('account_authority_store_unavailable');
        }
      }
      const item = await read(accountKey);
      if (item?.status === 'revoked' && item.currentEpoch === nextEpoch &&
          sameDigest(item.integrationRef, integrationRef) &&
          sameDigest(item.removalRef, removalRef)) {
        return Object.freeze({ status: 'revoked', accountEpoch: nextEpoch, duplicate: true });
      }
      throw new ProtocolError('account_authority_conflict');
    }
  });
}
