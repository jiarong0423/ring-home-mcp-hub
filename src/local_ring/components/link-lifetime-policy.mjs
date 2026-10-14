import { ProtocolError, requireOpaque } from './protocol.mjs';

const LINK_FIELDS = new Set(['status', 'createdAt', 'expiresAt', 'accountEpoch']);
const CREDENTIAL_FIELDS = new Set(['accessTokenExpiresAt', 'refreshTokenExpiresAt']);
const GRANT_FIELDS = new Set([
  'actorId', 'homeId', 'deviceId', 'action', 'parameters', 'grantVersion',
  'createdAt', 'expiresAt', 'accountEpoch'
]);
const TOMBSTONE_FIELDS = new Set(['status', 'revokedAt', 'accountEpoch', 'retention']);

function exactFields(value, fields, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== fields.size ||
      Object.keys(value).some(key => !fields.has(key))) {
    throw new ProtocolError(code);
  }
}

function epoch(value, code, allowZero = true) {
  if (!Number.isSafeInteger(value) || value < (allowZero ? 0 : 1)) {
    throw new ProtocolError(code);
  }
  return value;
}

function boundedIdentity(value) {
  try {
    requireOpaque(value, 256);
  } catch {
    throw new ProtocolError('action_grant_invalid');
  }
  if (value.trim().length === 0) throw new ProtocolError('action_grant_invalid');
  return value;
}

function emptyLightParameters(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) ||
      Reflect.ownKeys(value).length !== 0) {
    throw new ProtocolError('action_grant_invalid');
  }
}

function boundedLifetime(createdAt, expiresAt, maxAgeSeconds, nowSeconds, code) {
  epoch(createdAt, code);
  epoch(expiresAt, code);
  epoch(nowSeconds, code);
  if (createdAt > nowSeconds || expiresAt <= nowSeconds ||
      expiresAt <= createdAt || expiresAt - createdAt > maxAgeSeconds) {
    throw new ProtocolError(code);
  }
}

export function createLinkLifetimePolicy({ maxLinkAgeSeconds, maxActionGrantSeconds } = {}) {
  epoch(maxLinkAgeSeconds, 'link_policy_config', false);
  epoch(maxActionGrantSeconds, 'link_policy_config', false);

  function validateAccountLink(link, nowSeconds) {
    exactFields(link, LINK_FIELDS, 'account_link_invalid');
    if (link.status !== 'completed') throw new ProtocolError('account_link_invalid');
    epoch(link.accountEpoch, 'account_link_invalid', false);
    boundedLifetime(link.createdAt, link.expiresAt, maxLinkAgeSeconds, nowSeconds, 'account_link_invalid');
    return Object.freeze({
      status: link.status,
      createdAt: link.createdAt,
      expiresAt: link.expiresAt,
      accountEpoch: link.accountEpoch
    });
  }

  return Object.freeze({
    validateAccountLink,

    validateCredentialMetadata(metadata) {
      exactFields(metadata, CREDENTIAL_FIELDS, 'credential_metadata_invalid');
      epoch(metadata.accessTokenExpiresAt, 'credential_metadata_invalid', false);
      epoch(metadata.refreshTokenExpiresAt, 'credential_metadata_invalid', false);
      return Object.freeze({
        accessTokenExpiresAt: metadata.accessTokenExpiresAt,
        refreshTokenExpiresAt: metadata.refreshTokenExpiresAt
      });
    },

    validateActionGrant(grant, {
      link, currentAccountEpoch, currentGrantVersion,
      expectedActorId, expectedHomeId, expectedDeviceId, nowSeconds
    } = {}) {
      exactFields(grant, GRANT_FIELDS, 'action_grant_invalid');
      if (grant.action !== 'living_light.on' || grant.deviceId !== 'living_light') {
        throw new ProtocolError('action_grant_invalid');
      }
      for (const field of ['actorId', 'homeId', 'deviceId']) boundedIdentity(grant[field]);
      boundedIdentity(expectedActorId);
      boundedIdentity(expectedHomeId);
      boundedIdentity(expectedDeviceId);
      if (grant.actorId !== expectedActorId || grant.homeId !== expectedHomeId ||
          grant.deviceId !== expectedDeviceId) throw new ProtocolError('action_grant_binding_mismatch');
      emptyLightParameters(grant.parameters);
      epoch(grant.grantVersion, 'action_grant_invalid', false);
      epoch(currentGrantVersion, 'action_grant_invalid', false);
      if (grant.grantVersion !== currentGrantVersion) throw new ProtocolError('action_grant_version_mismatch');
      epoch(grant.accountEpoch, 'action_grant_invalid', false);
      epoch(currentAccountEpoch, 'action_grant_invalid', false);
      if (grant.accountEpoch !== currentAccountEpoch) throw new ProtocolError('action_grant_epoch_mismatch');
      const activeLink = validateAccountLink(link, nowSeconds);
      if (activeLink.accountEpoch !== currentAccountEpoch) throw new ProtocolError('action_grant_epoch_mismatch');
      boundedLifetime(grant.createdAt, grant.expiresAt, maxActionGrantSeconds, nowSeconds, 'action_grant_invalid');
      if (grant.createdAt < activeLink.createdAt || grant.expiresAt > activeLink.expiresAt) {
        throw new ProtocolError('action_grant_invalid');
      }
      return Object.freeze({
        actorId: grant.actorId,
        homeId: grant.homeId,
        deviceId: grant.deviceId,
        action: grant.action,
        parameters: Object.freeze({}),
        grantVersion: grant.grantVersion,
        createdAt: grant.createdAt,
        expiresAt: grant.expiresAt,
        accountEpoch: grant.accountEpoch
      });
    },

    validateRevocationTombstone(tombstone) {
      exactFields(tombstone, TOMBSTONE_FIELDS, 'tombstone_invalid');
      if (tombstone.status !== 'revoked' || tombstone.retention !== 'non_ttl') {
        throw new ProtocolError('tombstone_invalid');
      }
      epoch(tombstone.revokedAt, 'tombstone_invalid');
      epoch(tombstone.accountEpoch, 'tombstone_invalid', false);
      return Object.freeze({
        status: tombstone.status,
        revokedAt: tombstone.revokedAt,
        accountEpoch: tombstone.accountEpoch,
        retention: tombstone.retention
      });
    }
  });
}
