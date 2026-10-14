import { createHash, createHmac, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { createSessionMachine } from './components/session-machine.mjs';
import { createOidcJwtVerifier } from './components/oidc-jwt-verifier.mjs';
import { createDynamoSessionAdapter } from './components/dynamo-session-adapter.mjs';
import { createOfflineDynamoFixture } from './components/offline-dynamo-fixture.mjs';
import { createDynamoAccountAuthority, deriveAccountAuthorityKey } from './components/dynamo-account-authority.mjs';
import { createDynamoLinkedDeviceAuthorizerV2 } from './components/dynamo-linked-device-authorizer-v2.mjs';
import { createDynamoLinkedDeviceWriterV2 } from './components/dynamo-linked-device-writer-v2.mjs';
import { deriveLinkedDeviceKey, deriveLinkedEvidenceDigest } from './components/linked-device-key.mjs';
import { createLinkLifetimePolicy } from './components/link-lifetime-policy.mjs';
import { parseSignedAppIntegrationRemoved } from './components/app-integration-removal.mjs';
import { createLocalLifecycleStore } from './lifecycle-store.mjs';

const ISSUER = 'https://local-generated-issuer.invalid/pool';
const CLIENT = 'local-generated-client';
const SUBJECT = 'local-generated-owner';
const ORIGIN = 'https://local-generated-app.invalid';
const AUTH_TABLE = 'LocalAuthTable';
const SESSION_TABLE = 'LocalSessionTable';

export class LocalIdentityError extends Error {
  constructor(code) {
    super(code);
    this.name = 'LocalIdentityError';
    this.code = code;
  }
}

function fail(code) { throw new LocalIdentityError(code); }

/** Generated in-process identity and Ring provenance only; no provider or credential loader exists. */
export function createLocalIdentityBinding({ now = () => Date.now() } = {}) {
  if (typeof now !== 'function') fail('LOCAL_CLOCK_UNKNOWN');
  let lastObserved = -1;
  const milliseconds = () => {
    let value;
    try { value = now(); } catch { fail('LOCAL_CLOCK_UNKNOWN'); }
    if (!Number.isSafeInteger(value) || value < 0 || value > 8_640_000_000_000_000 - 3_600_000) fail('LOCAL_CLOCK_UNKNOWN');
    if (value < lastObserved) fail('LOCAL_CLOCK_REGRESSED');
    lastObserved = value;
    return value;
  };
  const seconds = () => Math.floor(milliseconds() / 1000);
  const createdMs = milliseconds();
  const ringConfig = Object.freeze({ enabled: true, accountId: 'local-generated-account',
    sourceId: 'local-generated-source', sourceType: 'devices', homeId: 'local-generated-home',
    grantVersion: '1', expiresAtMs: createdMs + 3_600_000 });
  const secret = randomBytes(32);
  const hashKey = randomBytes(32);
  const signingKey = randomBytes(32).toString('base64url');
  const digest = (purpose, value) => createHmac('sha256', secret)
    .update(purpose, 'utf8').update('\0', 'utf8').update(value, 'utf8').digest('hex');
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const publicJwk = { ...publicKey.export({ format: 'jwk' }), kid: 'local-generated-key',
    alg: 'RS256', use: 'sig', key_ops: ['verify'] };
  const jwksUri = `${ISSUER}/.well-known/jwks.json`;
  const jwt = payload => {
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: publicJwk.kid, typ: 'JWT' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const input = `${header}.${body}`;
    return `${input}.${sign('RSA-SHA256', Buffer.from(input, 'ascii'), privateKey).toString('base64url')}`;
  };
  const sessionFixture = createOfflineDynamoFixture();
  const sessionStore = createDynamoSessionAdapter({ getItem: sessionFixture.getItem,
    authTableName: AUTH_TABLE, sessionTableName: SESSION_TABLE,
    mode: 'offline_fixture', offlineExecute: sessionFixture.offlineExecute });
  const verifier = createOidcJwtVerifier({ issuer: ISSUER, clientId: CLIENT, ownerSubject: SUBJECT,
    jwksUri, maxJwksAgeSeconds: 3600, clock: seconds,
    loadPinnedJwks: async () => ({ jwksUri, snapshotVersion: 1,
      fetchedAtSeconds: Math.floor(createdMs / 1000),
      expiresAtSeconds: Math.floor(ringConfig.expiresAtMs / 1000), keys: [publicJwk] }) });
  const seals = new Map();
  const auditEvents = [];
  let pendingExchange = null;
  const machine = createSessionMachine({ clock: seconds, randomBytes, digest, store: sessionStore,
    seal: async ({ purpose, plaintext }) => {
      if (seals.size >= 2) fail('LOCAL_LINK_FAILED');
      const ref = randomBytes(32).toString('hex');
      seals.set(ref, { purpose, plaintext });
      return ref;
    },
    open: async ({ purpose, ciphertext }) => {
      const saved = seals.get(ciphertext);
      if (!saved || saved.purpose !== purpose) fail('LOCAL_LINK_FAILED');
      return saved.plaintext;
    },
    exchangeCode: async ({ code, codeVerifier, redirectUri, clientId }) => {
      const exchange = pendingExchange;
      if (!exchange || exchange.used || code !== exchange.code || clientId !== CLIENT ||
          redirectUri !== `${ORIGIN}/auth/callback` ||
          createHash('sha256').update(codeVerifier, 'utf8').digest('base64url') !== exchange.codeChallenge) fail('LOCAL_LINK_FAILED');
      exchange.used = true;
      const at = seconds();
      return { idToken: jwt({ iss: ISSUER, aud: CLIENT, sub: SUBJECT,
        exp: Math.min(at + 300, Math.floor(ringConfig.expiresAtMs / 1000)),
        iat: at, token_use: 'id', nonce: exchange.oidcNonce }) };
    },
    verifyIdentity: verifier.verifyIdentity,
    audit: event => {
      if (auditEvents.length < 16) auditEvents.push(Object.freeze({ event: event.event, code: event.code }));
    },
    config: { issuer: ISSUER, clientId: CLIENT, ownerSubject: SUBJECT, origin: ORIGIN,
      redirectUri: `${ORIGIN}/auth/callback`, authTransactionSeconds: 300,
      sessionAbsoluteSeconds: 3600, sessionIdleSeconds: 900, ringNonceSeconds: 600,
      cleanupLagSeconds: 604800 } });
  const lifecycle = createLocalLifecycleStore({ now: milliseconds });
  const policy = createLinkLifetimePolicy({ maxLinkAgeSeconds: 3600, maxActionGrantSeconds: 3600 });
  const authority = createDynamoAccountAuthority({ getItem: lifecycle.getItem, updateItem: lifecycle.updateItem,
    tableName: 'localAccounts', hashKey, ttlAttributeName: 'ttl_delete_after', clock: milliseconds });
  const authorizer = createDynamoLinkedDeviceAuthorizerV2({ getItem: lifecycle.getItem,
    tableName: 'localLinks', hashKey, accountAuthority: authority, clock: milliseconds });
  const claims = new Map();
  const writer = createDynamoLinkedDeviceWriterV2({ transactWriteItems: lifecycle.transactWriteItems,
    resolveVerifiedClaim: async claimId => {
      if (!claims.has(claimId)) fail('LOCAL_LINK_FAILED');
      return claims.get(claimId);
    }, accountTableName: 'localAccounts', pairTableName: 'localLinks', claimTableName: 'localClaims',
    hashKey, ttlAttributeName: 'ttl_delete_after', lifetimePolicy: policy, clock: milliseconds });
  let identity = 'unlinked';
  let attemptedLink = false;
  let generation = 0;
  let accountEpoch = 0;
  let session = null;
  let link = null;
  let grant = null;
  let integrationRef = null;
  let removalId = null;
  let completedLink = false;

  const deadline = () => session && link && grant
    ? Math.min(session.idleExpiresAt, session.expiresAt, link.expiresAt, grant.expiresAt) * 1000
    : 0;
  const requireAuthenticated = () => {
    if (identity === 'revoked') fail('LOCAL_IDENTITY_REVOKED');
    if (identity === 'logged_out') fail('LOCAL_IDENTITY_LOGGED_OUT');
    if (identity !== 'authenticated' || !completedLink) fail('LOCAL_IDENTITY_UNLINKED');
    const at = milliseconds();
    if (at >= deadline() || at >= ringConfig.expiresAtMs) fail('LOCAL_IDENTITY_EXPIRED');
    return at;
  };
  const status = () => {
    let authorized = false;
    try {
      const at = milliseconds();
      authorized = identity === 'authenticated' && completedLink && at < deadline() && at < ringConfig.expiresAtMs;
    } catch { authorized = false; }
    const countSession = table => [...sessionFixture.rows.keys()].filter(key => key.startsWith(`${table}\0`)).length;
    return Object.freeze({ mode: 'local_simulation', identity, linked: completedLink && identity !== 'revoked',
      authorized, accountEpoch, grantExpiresAt: grant ? grant.expiresAt * 1000 : null,
      retained: Object.freeze({ ...lifecycle.counts(), contexts: countSession(AUTH_TABLE),
        sessions: countSession(SESSION_TABLE), sealedReferences: seals.size, auditEvents: auditEvents.length }) });
  };

  const linkAccount = async () => {
    if (identity === 'revoked') fail('LOCAL_IDENTITY_REVOKED');
    if (identity === 'logged_out') fail('LOCAL_IDENTITY_LOGGED_OUT');
    if (attemptedLink) fail('LOCAL_IDENTITY_ALREADY_LINKED');
    attemptedLink = true;
    const stamp = ++generation;
    try {
      const started = milliseconds();
      if (started >= ringConfig.expiresAtMs) fail('LOCAL_IDENTITY_EXPIRED');
      const begun = await machine.begin({ ringNonce: randomBytes(32).toString('base64url'), ringTimeSeconds: Math.floor(started / 1000) });
      pendingExchange = { code: randomBytes(32).toString('base64url'), codeChallenge: begun.codeChallenge,
        oidcNonce: begun.oidcNonce, used: false };
      const callback = await machine.callback({ state: begun.state, browserCorrelation: begun.browserCorrelation,
        code: pendingExchange.code });
      const sessionId = /^__Host-ring_session=([A-Za-z0-9_-]{43});/.exec(callback.cookie)?.[1];
      if (!sessionId) fail('LOCAL_LINK_FAILED');
      const authenticated = await machine.authorize({ sessionId, version: callback.version });
      const row = await sessionStore.getSession(digest('app-session', sessionId));
      if (!row || authenticated.authenticated !== true || stamp !== generation) fail('LOCAL_LINK_FAILED');
      session = { sessionId, version: callback.version, csrfToken: callback.csrfToken,
        expiresAt: row.absolute_expires_at, idleExpiresAt: row.idle_expires_at };
      const createdAt = seconds();
      const expiresAt = Math.min(Math.floor(ringConfig.expiresAtMs / 1000), session.expiresAt);
      if (expiresAt <= createdAt) fail('LOCAL_LINK_FAILED');
      integrationRef = randomBytes(32).toString('base64url');
      const claimId = randomBytes(32).toString('base64url');
      // Lookup and discovery evidence are generated provenance, never official Ring acceptance.
      const context = Object.freeze({ claimId, accountId: ringConfig.accountId, deviceId: ringConfig.sourceId,
        partnerActorId: 'owner', partnerSessionId: sessionId,
        ringAccountLookupId: `generated-lookup-${randomBytes(16).toString('hex')}`,
        ringDeviceDiscoveryId: `generated-discovery-${randomBytes(16).toString('hex')}`,
        integrationRef, accountEpoch: 1, createdAt, expiresAt,
        claimExpiresAt: Math.min(createdAt + 300, session.idleExpiresAt), sessionExpiresAt: session.idleExpiresAt });
      const evidence = (domain, value) => deriveLinkedEvidenceDigest(domain, value, hashKey);
      const accountKey = deriveAccountAuthorityKey(ringConfig.accountId, hashKey);
      const deviceKey = deriveLinkedDeviceKey(ringConfig.accountId, ringConfig.sourceId, hashKey);
      lifecycle.seed('localAccounts', { pk: { S: accountKey }, status: { S: 'active' }, revoked: { BOOL: false },
        account_epoch: { N: '1' }, integration_ref: { S: evidence('integration', integrationRef) }, expires_at: { N: String(expiresAt) } });
      lifecycle.seed('localClaims', { pk: { S: evidence('link-claim-key', claimId) }, status: { S: 'pending' },
        account_ref: { S: accountKey }, device_ref: { S: deviceKey }, actor_ref: { S: evidence('actor', context.partnerActorId) },
        session_ref: { S: evidence('session', context.partnerSessionId) }, account_lookup_ref: { S: evidence('account-lookup', context.ringAccountLookupId) },
        discovery_ref: { S: evidence('device-discovery', context.ringDeviceDiscoveryId) }, integration_ref: { S: evidence('integration', integrationRef) },
        account_epoch: { N: '1' }, created_at: { N: String(createdAt) }, expires_at: { N: String(context.claimExpiresAt) },
        session_expires_at: { N: String(context.sessionExpiresAt) }, link_expires_at: { N: String(expiresAt) } });
      claims.set(claimId, context);
      await writer.createCompletedLink({ claimId });
      if (stamp !== generation || !(await authority.isCurrent(ringConfig.accountId, 1))) fail('LOCAL_LINK_FAILED');
      link = Object.freeze({ status: 'completed', createdAt, expiresAt, accountEpoch: 1 });
      grant = Object.freeze({ actorId: 'owner', homeId: ringConfig.homeId, deviceId: 'living_light',
        action: 'living_light.on', parameters: Object.freeze({}), grantVersion: 1,
        createdAt, expiresAt: Math.min(expiresAt, session.idleExpiresAt), accountEpoch: 1 });
      accountEpoch = 1;
      completedLink = true;
      identity = 'authenticated';
      await authorize();
      return status();
    } catch (error) {
      if (identity === 'authenticated') {
        identity = 'unlinked';
        completedLink = false;
      }
      if (error instanceof LocalIdentityError) throw error;
      fail('LOCAL_LINK_FAILED');
    } finally {
      pendingExchange = null;
    }
  };

  const authorize = async () => {
    requireAuthenticated();
    const stamp = generation;
    try {
      await machine.authorize({ sessionId: session.sessionId, version: session.version });
      if (!(await authorizer.isLinkedDevice(ringConfig.accountId, ringConfig.sourceId))) fail('LOCAL_IDENTITY_DENIED');
      const pk = deriveLinkedDeviceKey(ringConfig.accountId, ringConfig.sourceId, hashKey);
      const stored = (await lifecycle.getItem({ TableName: 'localLinks', Key: { pk: { S: pk } }, ConsistentRead: true })).Item;
      if (!stored || stored.status.S !== 'completed' || stored.revoked.BOOL !== false ||
          stored.grant_version.N !== String(grant.grantVersion) || stored.account_epoch.N !== String(accountEpoch)) fail('LOCAL_IDENTITY_DENIED');
      policy.validateActionGrant(grant, { link, currentAccountEpoch: accountEpoch,
        currentGrantVersion: Number(stored.grant_version.N), expectedActorId: 'owner', expectedHomeId: ringConfig.homeId,
        expectedDeviceId: 'living_light', nowSeconds: seconds() });
      await machine.authorize({ sessionId: session.sessionId, version: session.version });
      if (!(await authority.isCurrent(ringConfig.accountId, accountEpoch))) fail('LOCAL_IDENTITY_DENIED');
      requireAuthenticated();
      if (generation !== stamp) fail('LOCAL_IDENTITY_DENIED');
      return Object.freeze({ actorId: 'owner', accountId: ringConfig.accountId, sourceId: ringConfig.sourceId,
        homeId: ringConfig.homeId, grantVersion: '1', accountEpoch, expiresAtMs: Math.min(deadline(), ringConfig.expiresAtMs) });
    } catch (error) {
      try { requireAuthenticated(); } catch (localError) { throw localError; }
      if (error instanceof LocalIdentityError) throw error;
      fail('LOCAL_IDENTITY_DENIED');
    }
  };

  const remove = async () => {
    if (!completedLink || !integrationRef) fail('LOCAL_IDENTITY_UNLINKED');
    ++generation;
    identity = 'revoked';
    try {
      const occurredAt = milliseconds();
      removalId ??= randomBytes(32).toString('base64url');
      const rawBody = Buffer.from(JSON.stringify({ meta: { version: '1.1', request_id: removalId,
        account_id: ringConfig.accountId, time: new Date(occurredAt).toISOString() },
        data: { id: removalId, type: 'app_integration_removed', attributes: {
          source_type: 'users', source: ringConfig.accountId, timestamp: occurredAt } } }));
      const signature = `sha256=${createHmac('sha256', signingKey).update(rawBody).digest('hex')}`;
      const verified = parseSignedAppIntegrationRemoved({ rawBody, signature, signingKey });
      if (verified.accountId !== ringConfig.accountId || verified.requestId !== removalId) fail('LOCAL_REMOVAL_FAILED');
      const result = await authority.revokeAccount(verified.accountId, 1, integrationRef, verified.requestId);
      accountEpoch = result.accountEpoch;
      const account = lifecycle.inspect('localAccounts', deriveAccountAuthorityKey(ringConfig.accountId, hashKey));
      policy.validateRevocationTombstone({ status: account.status.S, revokedAt: Number(account.revoked_at.N),
        accountEpoch: Number(account.account_epoch.N), retention: 'non_ttl' });
      return status();
    } catch (error) {
      if (error instanceof LocalIdentityError) throw error;
      fail('LOCAL_REMOVAL_FAILED');
    }
  };

  const logout = async () => {
    if (!session || !completedLink || identity === 'logged_out' || identity === 'revoked') return status();
    ++generation;
    if (identity !== 'revoked') identity = 'logged_out';
    try {
      await machine.logout({ sessionId: session.sessionId, version: session.version,
        origin: ORIGIN, csrfToken: session.csrfToken });
      return status();
    } catch (error) {
      if (error instanceof LocalIdentityError) throw error;
      fail('LOCAL_LOGOUT_FAILED');
    }
  };

  return Object.freeze({ link: linkAccount, authorize, remove, logout, status, ringConfig });
}
