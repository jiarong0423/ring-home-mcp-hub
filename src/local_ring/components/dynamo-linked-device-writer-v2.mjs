import { ProtocolError, requireOpaque } from './protocol.mjs';
import { deriveAccountAuthorityKey } from './dynamo-account-authority.mjs';
import { deriveLinkedDeviceKey, deriveLinkedEvidenceDigest, requireLinkedHashKey } from './linked-device-key.mjs';

const TABLE_NAME = /^[A-Za-z0-9_.-]{3,255}$/;
const ATTRIBUTE_NAME = /^[A-Za-z][A-Za-z0-9_]*$/;
const CLAIM_FIELDS = new Set([
  'claimId', 'accountId', 'deviceId', 'partnerActorId', 'partnerSessionId',
  'ringAccountLookupId', 'ringDeviceDiscoveryId', 'integrationRef',
  'accountEpoch', 'createdAt', 'expiresAt', 'claimExpiresAt', 'sessionExpiresAt'
]);
const RESERVED_TABLE_ATTRIBUTES = new Set([
  'pk', 'status', 'revoked', 'account_epoch', 'integration_ref', 'expires_at',
  'revoked_at', 'removal_ref', 'account_ref', 'device_ref', 'actor_ref',
  'session_ref', 'account_lookup_ref', 'discovery_ref', 'created_at',
  'session_expires_at', 'link_expires_at', 'consumed_at', 'grant_version',
  'claim_ref', 'revoker_ref', 'revoke_session_ref', 'revocation_ref'
]);

function boundedId(value) {
  requireOpaque(value, 256);
  if (value.trim().length === 0) throw new ProtocolError('pair_claim_invalid');
  return value;
}

function exactFields(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) ||
      Reflect.ownKeys(value).length !== fields.size ||
      Reflect.ownKeys(value).some(key => !fields.has(key))) {
    throw new ProtocolError('pair_claim_invalid');
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.values(descriptors).some(descriptor => !Object.hasOwn(descriptor, 'value'))) {
    throw new ProtocolError('pair_claim_invalid');
  }
  return Object.fromEntries(Object.entries(descriptors).map(([name, descriptor]) => [name, descriptor.value]));
}

function positiveEpoch(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value >= Number.MAX_SAFE_INTEGER) {
    throw new ProtocolError('pair_claim_invalid');
  }
  return value;
}

function seconds(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new ProtocolError('pair_claim_invalid');
  return value;
}

function nowSeconds(clock) {
  let value;
  try {
    value = clock();
  } catch {
    throw new ProtocolError('pair_clock_unavailable');
  }
  if (!Number.isSafeInteger(value) || value < 0) throw new ProtocolError('pair_clock_unavailable');
  return Math.floor(value / 1000);
}

function evidence(domain, value, key) {
  return deriveLinkedEvidenceDigest(domain, boundedId(value), key);
}

export function createDynamoLinkedDeviceWriterV2({
  transactWriteItems,
  resolveVerifiedClaim,
  accountTableName,
  pairTableName,
  claimTableName,
  hashKey,
  ttlAttributeName,
  lifetimePolicy,
  clock = () => Date.now()
} = {}) {
  if (typeof transactWriteItems !== 'function' || typeof resolveVerifiedClaim !== 'function' ||
      ![accountTableName, pairTableName, claimTableName].every(name =>
        typeof name === 'string' && TABLE_NAME.test(name)) ||
      typeof ttlAttributeName !== 'string' || !ATTRIBUTE_NAME.test(ttlAttributeName) ||
      RESERVED_TABLE_ATTRIBUTES.has(ttlAttributeName) ||
      typeof lifetimePolicy?.validateAccountLink !== 'function' ||
      typeof clock !== 'function') {
    throw new ProtocolError('pair_writer_config');
  }
  const key = requireLinkedHashKey(hashKey);

  return Object.freeze({
    async createCompletedLink(input) {
      const request = exactFields(input, new Set(['claimId']));
      const claimId = boundedId(request.claimId);
      let context;
      try {
        context = await resolveVerifiedClaim(claimId);
      } catch {
        throw new ProtocolError('pair_claim_unavailable');
      }
      const now = nowSeconds(clock);
      context = exactFields(context, CLAIM_FIELDS);
      if (boundedId(context.claimId) !== claimId) throw new ProtocolError('pair_claim_invalid');
      for (const field of [
        'accountId', 'deviceId', 'partnerActorId', 'partnerSessionId',
        'ringAccountLookupId', 'ringDeviceDiscoveryId', 'integrationRef'
      ]) boundedId(context[field]);
      positiveEpoch(context.accountEpoch);
      for (const field of ['createdAt', 'expiresAt', 'claimExpiresAt', 'sessionExpiresAt']) {
        seconds(context[field]);
      }
      if (context.createdAt > now || context.expiresAt <= now ||
          context.claimExpiresAt <= now || context.sessionExpiresAt <= now) {
        throw new ProtocolError('pair_claim_expired');
      }
      const link = lifetimePolicy.validateAccountLink({
        status: 'completed', createdAt: context.createdAt,
        expiresAt: context.expiresAt, accountEpoch: context.accountEpoch
      }, now);
      if (link?.status !== 'completed' || link.createdAt !== context.createdAt ||
          link.expiresAt !== context.expiresAt || link.accountEpoch !== context.accountEpoch) {
        throw new ProtocolError('pair_link_policy_invalid');
      }

      const accountKey = deriveAccountAuthorityKey(context.accountId, key);
      const pairKey = deriveLinkedDeviceKey(context.accountId, context.deviceId, key);
      const claimKey = evidence('link-claim-key', claimId, key);
      const locations = [
        [accountTableName, accountKey], [claimTableName, claimKey], [pairTableName, pairKey]
      ].map(([table, pk]) => `${table}\0${pk}`);
      if (new Set(locations).size !== 3) throw new ProtocolError('pair_writer_config');

      const refs = {
        account: accountKey,
        device: pairKey,
        actor: evidence('actor', context.partnerActorId, key),
        session: evidence('session', context.partnerSessionId, key),
        lookup: evidence('account-lookup', context.ringAccountLookupId, key),
        discovery: evidence('device-discovery', context.ringDeviceDiscoveryId, key),
        integration: evidence('integration', context.integrationRef, key),
        claim: evidence('claim', claimId, key)
      };
      const transaction = {
        TransactItems: [
          {
            ConditionCheck: {
              TableName: accountTableName,
              Key: { pk: { S: accountKey } },
              ConditionExpression: '#status = :active AND #revoked = :false AND #epoch = :epoch AND #integration = :integration AND #expires > :now AND #expires >= :pairExpires AND attribute_not_exists(#ttl) AND attribute_not_exists(#removal) AND attribute_not_exists(#revokedAt)',
              ExpressionAttributeNames: {
                '#status': 'status', '#revoked': 'revoked', '#epoch': 'account_epoch',
                '#integration': 'integration_ref', '#expires': 'expires_at',
                '#ttl': ttlAttributeName, '#removal': 'removal_ref', '#revokedAt': 'revoked_at'
              },
              ExpressionAttributeValues: {
                ':active': { S: 'active' }, ':false': { BOOL: false },
                ':epoch': { N: String(context.accountEpoch) },
                ':integration': { S: refs.integration }, ':now': { N: String(now) },
                ':pairExpires': { N: String(context.expiresAt) }
              }
            }
          },
          {
            Update: {
              TableName: claimTableName,
              Key: { pk: { S: claimKey } },
              ConditionExpression: '#status = :pending AND #account = :account AND #device = :device AND #actor = :actor AND #session = :session AND #lookup = :lookup AND #discovery = :discovery AND #integration = :integration AND #epoch = :epoch AND #created = :created AND #expires = :claimExpires AND #sessionExpires = :sessionExpires AND #linkExpires = :pairExpires AND #expires > :now AND #sessionExpires > :now AND attribute_not_exists(#ttl) AND attribute_not_exists(#consumedAt)',
              UpdateExpression: 'SET #status = :consumed, #consumedAt = :now',
              ExpressionAttributeNames: {
                '#status': 'status', '#account': 'account_ref', '#device': 'device_ref',
                '#actor': 'actor_ref', '#session': 'session_ref',
                '#lookup': 'account_lookup_ref', '#discovery': 'discovery_ref',
                '#integration': 'integration_ref', '#epoch': 'account_epoch',
                '#created': 'created_at', '#expires': 'expires_at',
                '#sessionExpires': 'session_expires_at', '#linkExpires': 'link_expires_at',
                '#consumedAt': 'consumed_at', '#ttl': ttlAttributeName
              },
              ExpressionAttributeValues: {
                ':pending': { S: 'pending' }, ':account': { S: refs.account },
                ':device': { S: refs.device }, ':actor': { S: refs.actor },
                ':session': { S: refs.session }, ':lookup': { S: refs.lookup },
                ':discovery': { S: refs.discovery }, ':integration': { S: refs.integration },
                ':epoch': { N: String(context.accountEpoch) },
                ':created': { N: String(context.createdAt) },
                ':claimExpires': { N: String(context.claimExpiresAt) },
                ':sessionExpires': { N: String(context.sessionExpiresAt) },
                ':pairExpires': { N: String(context.expiresAt) },
                ':now': { N: String(now) }, ':consumed': { S: 'consumed' }
              }
            }
          },
          {
            Put: {
              TableName: pairTableName,
              Item: {
                pk: { S: pairKey }, status: { S: 'completed' },
                revoked: { BOOL: false }, grant_version: { N: '1' },
                account_epoch: { N: String(context.accountEpoch) },
                expires_at: { N: String(context.expiresAt) },
                created_at: { N: String(context.createdAt) },
                actor_ref: { S: refs.actor }, session_ref: { S: refs.session },
                account_lookup_ref: { S: refs.lookup }, discovery_ref: { S: refs.discovery },
                integration_ref: { S: refs.integration }, claim_ref: { S: refs.claim }
              },
              ConditionExpression: 'attribute_not_exists(#pk)',
              ExpressionAttributeNames: { '#pk': 'pk' }
            }
          }
        ]
      };
      try {
        await transactWriteItems(transaction);
      } catch (error) {
        if (error?.name === 'TransactionCanceledException' ||
            error?.code === 'TransactionCanceledException' ||
            error?.name === 'ConditionalCheckFailedException' ||
            error?.code === 'ConditionalCheckFailedException') {
          throw new ProtocolError('pair_transaction_conflict');
        }
        throw new ProtocolError('pair_transaction_outcome_unknown');
      }
      const afterCommit = (() => {
        try {
          return nowSeconds(clock);
        } catch {
          throw new ProtocolError('pair_postcommit_clock_unknown');
        }
      })();
      if (afterCommit < now) throw new ProtocolError('pair_postcommit_clock_unknown');
      if (afterCommit >= context.expiresAt || afterCommit >= context.claimExpiresAt ||
          afterCommit >= context.sessionExpiresAt) {
        throw new ProtocolError('pair_postcommit_expired');
      }
      return Object.freeze({ status: 'completed', grantVersion: 1, accountEpoch: context.accountEpoch });
    }
  });
}
