import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { createLocalIdentityBinding } from '../src/local_ring/identity-binding.mjs';
import { createLocalLifecycleStore } from '../src/local_ring/lifecycle-store.mjs';
import { createSessionMachine } from '../src/local_ring/components/session-machine.mjs';
import { createCognitoResourceBoundAccessTokenVerifier, createOidcAccessTokenVerifier,
  createOidcJwtVerifier } from '../src/local_ring/components/oidc-jwt-verifier.mjs';
import { createDynamoSessionAdapter } from '../src/local_ring/components/dynamo-session-adapter.mjs';
import { createOfflineDynamoFixture } from '../src/local_ring/components/offline-dynamo-fixture.mjs';
import { createDynamoLinkedDeviceWriterV2 } from '../src/local_ring/components/dynamo-linked-device-writer-v2.mjs';
import { createDynamoAccountAuthority, deriveAccountAuthorityKey } from '../src/local_ring/components/dynamo-account-authority.mjs';
import { deriveLinkedDeviceKey, deriveLinkedEvidenceDigest } from '../src/local_ring/components/linked-device-key.mjs';
import { createLinkLifetimePolicy } from '../src/local_ring/components/link-lifetime-policy.mjs';

const START = 2_100_000_000_123;
const rejects = (fn, code) => assert.rejects(fn, error => error.code === code);
function binding() {
  const clock = { value: START };
  const identity = createLocalIdentityBinding({ now: () => clock.value });
  return { identity, clock };
}

test('LI01 unlinked generated identity has no authorization or history', async () => {
  const { identity } = binding();
  assert.equal(identity.status().mode, 'local_simulation');
  assert.equal(identity.status().identity, 'unlinked');
  assert.equal(identity.status().authorized, false);
  assert.equal(identity.status().retained.contexts, 0);
  await rejects(() => identity.authorize(), 'LOCAL_IDENTITY_UNLINKED');
});

test('LI02 real strict-v1 callback and atomic generated claim bind one fixed light grant', async () => {
  const { identity } = binding();
  const status = await identity.link();
  assert.equal(status.identity, 'authenticated');
  assert.equal(status.authorized, true);
  assert.deepEqual(status.retained, { accounts: 1, claims: 1, links: 1, tombstones: 0,
    contexts: 1, sessions: 1, sealedReferences: 2, auditEvents: 2 });
  const allowed = await identity.authorize();
  assert.deepEqual(allowed, { actorId: 'owner', accountId: 'local-generated-account',
    sourceId: 'local-generated-source', homeId: 'local-generated-home', grantVersion: '1',
    accountEpoch: 1, expiresAtMs: Math.floor(START / 1000) * 1000 + 900_000 });
  assert.equal(Object.isFrozen(allowed), true);
  assert.equal(Object.isFrozen(identity.ringConfig), true);
});

test('LI03 coarse status omits credentials, aliases and signed payloads', async () => {
  const { identity } = binding();
  await identity.link();
  const status = identity.status();
  assert.deepEqual(Object.keys(status).sort(), ['accountEpoch', 'authorized', 'grantExpiresAt', 'identity', 'linked', 'mode', 'retained']);
  assert.doesNotMatch(JSON.stringify(status), /local-generated|csrf|nonce|cookie|idToken|privateKey|signature|accountId|sourceId/);
  assert.equal(Object.isFrozen(status.retained), true);
});

test('LI04 a repeated or concurrent link cannot reuse a claim or mint another session', async () => {
  const { identity } = binding();
  const results = await Promise.allSettled([identity.link(), identity.link()]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(results.find(result => result.status === 'rejected').reason.code, 'LOCAL_IDENTITY_ALREADY_LINKED');
  const counts = identity.status().retained;
  await rejects(() => identity.link(), 'LOCAL_IDENTITY_ALREADY_LINKED');
  assert.deepEqual(identity.status().retained, counts);
});

test('LI05 strict-v1 logout blocks future actions and retains session/context history', async () => {
  const { identity } = binding();
  await identity.link();
  await identity.logout();
  assert.equal(identity.status().identity, 'logged_out');
  assert.equal(identity.status().authorized, false);
  assert.equal(identity.status().retained.contexts, 1);
  assert.equal(identity.status().retained.sessions, 1);
  await rejects(() => identity.authorize(), 'LOCAL_IDENTITY_LOGGED_OUT');
  await rejects(() => identity.link(), 'LOCAL_IDENTITY_LOGGED_OUT');
});

test('LI06 signed removal advances account epoch and retains a non-TTL tombstone', async () => {
  const { identity } = binding();
  await identity.link();
  await identity.remove();
  const status = identity.status();
  assert.equal(status.identity, 'revoked');
  assert.equal(status.linked, false);
  assert.equal(status.accountEpoch, 2);
  assert.equal(status.retained.tombstones, 1);
  assert.equal(status.retained.claims, 1);
  assert.equal(status.retained.links, 1);
  await rejects(() => identity.authorize(), 'LOCAL_IDENTITY_REVOKED');
  await rejects(() => identity.link(), 'LOCAL_IDENTITY_REVOKED');
  await identity.remove();
  assert.equal(identity.status().accountEpoch, 2);
  assert.deepEqual(identity.status().retained, status.retained);
});

test('LI07 exact idle/grant deadline denies without deleting retained history', async () => {
  const { identity, clock } = binding();
  await identity.link();
  const deadline = (await identity.authorize()).expiresAtMs;
  clock.value = deadline - 1;
  await identity.authorize();
  clock.value = deadline;
  await rejects(() => identity.authorize(), 'LOCAL_IDENTITY_EXPIRED');
  assert.equal(identity.status().authorized, false);
  assert.equal(identity.status().retained.sessions, 1);
  assert.equal(identity.status().retained.links, 1);
});

test('LI08 expiry during an authorization await rejects the decision', async () => {
  const { identity, clock } = binding();
  await identity.link();
  const deadline = (await identity.authorize()).expiresAtMs;
  const pending = identity.authorize();
  queueMicrotask(() => { clock.value = deadline; });
  await rejects(() => pending, 'LOCAL_IDENTITY_EXPIRED');
});

test('LI09 removal intent during authorization cannot return an allow decision', async () => {
  const { identity } = binding();
  await identity.link();
  const pending = identity.authorize();
  const removed = identity.remove();
  await rejects(() => pending, 'LOCAL_IDENTITY_REVOKED');
  await removed;
  assert.equal(identity.status().retained.tombstones, 1);
});

test('LI10 regressing or unavailable clock fails closed', async () => {
  const { identity, clock } = binding();
  await identity.link();
  clock.value = START - 1;
  await rejects(() => identity.authorize(), 'LOCAL_CLOCK_REGRESSED');
  assert.equal(identity.status().authorized, false);
  assert.throws(() => createLocalIdentityBinding({ now: () => NaN }), error => error.code === 'LOCAL_CLOCK_UNKNOWN');
});

function lifecycleHarness({ beforeCommit } = {}) {
  const clock = { value: START };
  const key = randomBytes(32);
  const context = { claimId: 'generated-claim', accountId: 'generated-account', deviceId: 'generated-source',
    partnerActorId: 'owner', partnerSessionId: 'generated-session', ringAccountLookupId: 'generated-lookup',
    ringDeviceDiscoveryId: 'generated-discovery', integrationRef: 'generated-integration', accountEpoch: 1,
    createdAt: Math.floor(START / 1000), expiresAt: Math.floor(START / 1000) + 3600,
    claimExpiresAt: Math.floor(START / 1000) + 300, sessionExpiresAt: Math.floor(START / 1000) + 900 };
  let hook;
  const store = createLocalLifecycleStore({ now: () => clock.value, beforeCommit: async operation => {
    if (beforeCommit) await beforeCommit({ ...operation, clock, context, store, authority });
    if (hook) await hook(operation);
  } });
  const ref = (domain, value) => deriveLinkedEvidenceDigest(domain, value, key);
  const accountPk = deriveAccountAuthorityKey(context.accountId, key);
  const claimPk = ref('link-claim-key', context.claimId);
  const linkPk = deriveLinkedDeviceKey(context.accountId, context.deviceId, key);
  store.seed('localAccounts', { pk: { S: accountPk }, status: { S: 'active' }, revoked: { BOOL: false },
    account_epoch: { N: '1' }, integration_ref: { S: ref('integration', context.integrationRef) }, expires_at: { N: String(context.expiresAt) } });
  store.seed('localClaims', { pk: { S: claimPk }, status: { S: 'pending' }, account_ref: { S: accountPk }, device_ref: { S: linkPk },
    actor_ref: { S: ref('actor', context.partnerActorId) }, session_ref: { S: ref('session', context.partnerSessionId) },
    account_lookup_ref: { S: ref('account-lookup', context.ringAccountLookupId) }, discovery_ref: { S: ref('device-discovery', context.ringDeviceDiscoveryId) },
    integration_ref: { S: ref('integration', context.integrationRef) }, account_epoch: { N: '1' },
    created_at: { N: String(context.createdAt) }, expires_at: { N: String(context.claimExpiresAt) },
    session_expires_at: { N: String(context.sessionExpiresAt) }, link_expires_at: { N: String(context.expiresAt) } });
  const authority = createDynamoAccountAuthority({ getItem: store.getItem, updateItem: store.updateItem,
    tableName: 'localAccounts', hashKey: key, ttlAttributeName: 'ttl_delete_after', clock: () => clock.value });
  const writer = createDynamoLinkedDeviceWriterV2({ transactWriteItems: store.transactWriteItems,
    resolveVerifiedClaim: async claimId => claimId === context.claimId ? context : null,
    accountTableName: 'localAccounts', pairTableName: 'localLinks', claimTableName: 'localClaims',
    hashKey: key, ttlAttributeName: 'ttl_delete_after',
    lifetimePolicy: createLinkLifetimePolicy({ maxLinkAgeSeconds: 3600, maxActionGrantSeconds: 3600 }), clock: () => clock.value });
  return { store, clock, context, writer, authority, accountPk, claimPk, linkPk,
    setHook: value => { hook = value; } };
}

test('LI11 transaction consumes the exact claim once and retains consumed history', async () => {
  const fx = lifecycleHarness();
  await fx.writer.createCompletedLink({ claimId: fx.context.claimId });
  assert.equal(fx.store.inspect('localClaims', fx.claimPk).status.S, 'consumed');
  const before = fx.store.inspect('localLinks', fx.linkPk);
  await rejects(() => fx.writer.createCompletedLink({ claimId: fx.context.claimId }), 'pair_transaction_conflict');
  assert.deepEqual(fx.store.inspect('localLinks', fx.linkPk), before);
  assert.equal(fx.store.counts().claims, 1);
});

test('LI12 claim expiry at atomic commit causes no consumption or partial link', async () => {
  const fx = lifecycleHarness({ beforeCommit: ({ operation, clock, context }) => {
    if (operation === 'TransactWriteItems') clock.value = context.claimExpiresAt * 1000;
  } });
  await rejects(() => fx.writer.createCompletedLink({ claimId: fx.context.claimId }), 'pair_transaction_conflict');
  assert.equal(fx.store.inspect('localClaims', fx.claimPk).status.S, 'pending');
  assert.equal(fx.store.inspect('localLinks', fx.linkPk), null);
  assert.equal(fx.store.inspect('localAccounts', fx.accountPk).status.S, 'active');
});

test('LI13 account revocation at commit prevents a late claim from resurrecting a link', async () => {
  const fx = lifecycleHarness();
  fx.setHook(async ({ operation }) => {
    if (operation === 'TransactWriteItems') await fx.authority.revokeAccount(fx.context.accountId, 1, fx.context.integrationRef, 'generated-removal');
  });
  await rejects(() => fx.writer.createCompletedLink({ claimId: fx.context.claimId }), 'pair_transaction_conflict');
  const account = fx.store.inspect('localAccounts', fx.accountPk);
  assert.equal(account.status.S, 'revoked');
  assert.equal(account.account_epoch.N, '2');
  assert.equal(account.expires_at, undefined);
  assert.equal(account.ttl_delete_after, undefined);
  assert.equal(fx.store.inspect('localClaims', fx.claimPk).status.S, 'pending');
  assert.equal(fx.store.inspect('localLinks', fx.linkPk), null);
  assert.throws(() => fx.store.seed('localAccounts', account), /local_lifecycle_request_invalid/);
});

test('LI14 lifecycle transport rejects unknown tables, weak reads and transaction grammar', async () => {
  const fx = lifecycleHarness();
  const counts = fx.store.counts();
  await rejects(() => fx.store.getItem({ TableName: 'foreignTable', Key: { pk: { S: fx.accountPk } }, ConsistentRead: true }), 'local_lifecycle_request_invalid');
  await rejects(() => fx.store.getItem({ TableName: 'localAccounts', Key: { pk: { S: fx.accountPk } }, ConsistentRead: false }), 'local_lifecycle_request_invalid');
  await rejects(() => fx.store.transactWriteItems({ TransactItems: [{ Delete: {} }] }), 'local_lifecycle_request_invalid');
  assert.deepEqual(fx.store.counts(), counts);
});

const ISSUER = 'https://generated-test-issuer.invalid/pool';
const CLIENT = 'generated-test-client';
const OWNER = 'generated-test-owner';
const ORIGIN = 'https://generated-test-app.invalid';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'generated-test-key', alg: 'RS256', use: 'sig', key_ops: ['verify'] };
function sessionHarness({ transform } = {}) {
  const current = Math.floor(START / 1000);
  const fixture = createOfflineDynamoFixture();
  const store = createDynamoSessionAdapter({ getItem: fixture.getItem, authTableName: 'TestLocalAuth',
    sessionTableName: 'TestLocalSessions', mode: 'offline_fixture', offlineExecute: fixture.offlineExecute });
  const secret = randomBytes(32);
  const digest = (purpose, value) => createHmac('sha256', secret).update(`${purpose}:${value}`).digest('hex');
  const seals = new Map();
  let nonce;
  let exchanges = 0;
  const verifier = createOidcJwtVerifier({ issuer: ISSUER, clientId: CLIENT, ownerSubject: OWNER,
    jwksUri: `${ISSUER}/.well-known/jwks.json`, maxJwksAgeSeconds: 3600, clock: () => current,
    loadPinnedJwks: async () => ({ jwksUri: `${ISSUER}/.well-known/jwks.json`, snapshotVersion: 1,
      fetchedAtSeconds: current, expiresAtSeconds: current + 300, keys: [jwk] }) });
  const machine = createSessionMachine({ clock: () => current, randomBytes, digest, store,
    seal: async ({ purpose, plaintext }) => {
      const ref = randomBytes(32).toString('hex'); seals.set(ref, { purpose, plaintext }); return ref;
    },
    open: async ({ purpose, ciphertext }) => {
      const saved = seals.get(ciphertext); assert.equal(saved.purpose, purpose); return saved.plaintext;
    },
    exchangeCode: async () => {
      exchanges++;
      const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: jwk.kid, typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ iss: ISSUER, aud: CLIENT, sub: OWNER,
        exp: current + 300, iat: current, token_use: 'id', nonce })).toString('base64url');
      const input = `${header}.${payload}`;
      let idToken = `${input}.${sign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url')}`;
      if (transform) idToken = transform(idToken);
      return { idToken };
    },
    verifyIdentity: verifier.verifyIdentity, audit: () => {},
    config: { issuer: ISSUER, clientId: CLIENT, ownerSubject: OWNER, origin: ORIGIN,
      redirectUri: `${ORIGIN}/auth/callback`, authTransactionSeconds: 300, sessionAbsoluteSeconds: 3600,
      sessionIdleSeconds: 900, ringNonceSeconds: 600, cleanupLagSeconds: 604800 } });
  return { machine, fixture, digest,
    async begin() { const begun = await machine.begin({ ringNonce: randomBytes(32).toString('base64url'), ringTimeSeconds: current }); nonce = begun.oidcNonce; return begun; },
    get exchanges() { return exchanges; } };
}

test('LI15 tampered JWT payload cannot mint a session', async () => {
  const fx = sessionHarness({ transform: token => {
    const parts = token.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    payload.sub = 'generated-other-owner';
    return `${parts[0]}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${parts[2]}`;
  } });
  const begun = await fx.begin();
  await rejects(() => fx.machine.callback({ state: begun.state, browserCorrelation: begun.browserCorrelation, code: 'generated-code' }), 'identity_invalid');
  assert.equal([...fx.fixture.rows.keys()].filter(key => key.startsWith('TestLocalSessions\0')).length, 0);
});

test('LI16 callback replay and forged Origin/CSRF cannot create or mutate another session', async () => {
  const fx = sessionHarness();
  const begun = await fx.begin();
  const request = { state: begun.state, browserCorrelation: begun.browserCorrelation, code: 'generated-code' };
  const result = await fx.machine.callback(request);
  const sessionId = /^__Host-ring_session=([^;]+)/.exec(result.cookie)[1];
  const pk = fx.digest('app-session', sessionId);
  const baseline = fx.fixture.inspect('TestLocalSessions', pk);
  await rejects(() => fx.machine.callback(request), 'reservation_conflict');
  assert.equal(fx.exchanges, 1);
  await rejects(() => fx.machine.logout({ sessionId, version: 1, origin: 'https://wrong.invalid', csrfToken: result.csrfToken }), 'origin_csrf_invalid');
  await rejects(() => fx.machine.logout({ sessionId, version: 1, origin: ORIGIN, csrfToken: randomBytes(32).toString('base64url') }), 'origin_csrf_invalid');
  assert.deepEqual(fx.fixture.inspect('TestLocalSessions', pk), baseline);
  await fx.machine.logout({ sessionId, version: 1, origin: ORIGIN, csrfToken: result.csrfToken });
  await rejects(() => fx.machine.authorize({ sessionId, version: 1 }), 'session_invalid');
  assert.equal(fx.fixture.inspect('TestLocalSessions', pk).status.S, 'revoked');
});

const RESOURCE = 'https://generated-resource.invalid/mcp';
const ACCESS_AUDIENCE = 'generated-mcp-audience';
const ACCESS_SCOPES = ['mcp:tools:list', 'mcp:tools:call'];

function signAccessToken(claims = {}, typ = 'at+jwt') {
  const current = Math.floor(START / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: jwk.kid, typ })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ iss: ISSUER, aud: ACCESS_AUDIENCE,
    resource: RESOURCE, sub: OWNER, scope: ACCESS_SCOPES.join(' '), token_use: 'access',
    exp: current + 300, iat: current, ...claims })).toString('base64url');
  const input = `${header}.${payload}`;
  return `${input}.${sign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url')}`;
}

function accessVerifier({ current = Math.floor(START / 1000), snapshotExpiresAt = current + 300 } = {}) {
  return createOidcAccessTokenVerifier({ issuer: ISSUER, resource: RESOURCE,
    audience: ACCESS_AUDIENCE, requiredScopes: ACCESS_SCOPES,
    jwksUri: `${ISSUER}/.well-known/jwks.json`, maxJwksAgeSeconds: 3600,
    maximumTokenLifetimeSeconds: 300, clock: () => current,
    loadPinnedJwks: async () => ({ jwksUri: `${ISSUER}/.well-known/jwks.json`, snapshotVersion: 1,
      fetchedAtSeconds: current, expiresAtSeconds: snapshotExpiresAt, keys: [jwk] }) });
}

test('LI17 resource-server access-token profile verifies only its fixed issuer resource audience and scope', async () => {
  const current = Math.floor(START / 1000);
  const claims = await accessVerifier({ current }).verifyAccessToken({ accessToken: signAccessToken() });
  assert.deepEqual(claims, { verified: true, tokenUse: 'access', sub: OWNER, iss: ISSUER,
    aud: ACCESS_AUDIENCE, resource: RESOURCE, scope: ACCESS_SCOPES,
    exp: current + 300, iat: current });
  assert.equal(Object.isFrozen(claims), true);
  assert.equal(Object.isFrozen(claims.scope), true);
});

test('LI18 resource-server access-token profile denies wrong issuer audience resource or scope', async () => {
  for (const changes of [
    { iss: 'https://wrong-issuer.invalid/pool' },
    { aud: 'wrong-audience' },
    { resource: 'https://wrong-resource.invalid/mcp' },
    { scope: 'mcp:tools:list' },
    { scope: 'mcp:tools:list mcp:tools:call mcp:admin' }
  ]) {
    await rejects(() => accessVerifier().verifyAccessToken({ accessToken: signAccessToken(changes) }),
      'access_invalid');
  }
});

test('LI19 resource-server profile rejects ID-token confusion expiry and excessive lifetime', async () => {
  const current = Math.floor(START / 1000);
  await rejects(() => accessVerifier({ current }).verifyAccessToken({ accessToken:
    signAccessToken({ token_use: 'id', nonce: 'generated-nonce' }, 'JWT') }), 'jwt_invalid');
  await rejects(() => accessVerifier({ current }).verifyAccessToken({ accessToken:
    signAccessToken({ exp: current }) }), 'access_invalid');
  await rejects(() => accessVerifier({ current }).verifyAccessToken({ accessToken:
    signAccessToken({ exp: current + 301 }) }), 'access_invalid');
});

test('LI20 resource-server profile fails closed on stale pinned JWKS', async () => {
  const current = Math.floor(START / 1000);
  await rejects(() => accessVerifier({ current, snapshotExpiresAt: current }).verifyAccessToken({
    accessToken: signAccessToken() }), 'jwks_stale');
});

const COGNITO_CLIENT = 'generated-cognito-app-client';

function signCognitoAccessToken(claims = {}, headerClaims = {}) {
  const current = Math.floor(START / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: jwk.kid, typ: 'JWT',
    ...headerClaims })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ iss: ISSUER, client_id: COGNITO_CLIENT,
    aud: RESOURCE, sub: OWNER, scope: ACCESS_SCOPES.join(' '), token_use: 'access',
    exp: current + 300, iat: current, ...claims })).toString('base64url');
  const input = `${header}.${payload}`;
  return `${input}.${sign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url')}`;
}

function cognitoAccessVerifier({ current = Math.floor(START / 1000),
  snapshotExpiresAt = current + 300 } = {}) {
  return createCognitoResourceBoundAccessTokenVerifier({ issuer: ISSUER,
    clientId: COGNITO_CLIENT, resource: RESOURCE, requiredScopes: ACCESS_SCOPES,
    jwksUri: `${ISSUER}/.well-known/jwks.json`, maxJwksAgeSeconds: 3600,
    maximumTokenLifetimeSeconds: 300, clock: () => current,
    loadPinnedJwks: async () => ({ jwksUri: `${ISSUER}/.well-known/jwks.json`,
      snapshotVersion: 1, fetchedAtSeconds: current, expiresAtSeconds: snapshotExpiresAt,
      keys: [jwk] }) });
}

test('LI21 Cognito resource-bound profile accepts signed JWT with absent or JWT typ', async () => {
  const current = Math.floor(START / 1000);
  for (const typ of [undefined, 'JWT']) {
    const claims = await cognitoAccessVerifier({ current }).verifyAccessToken({
      accessToken: signCognitoAccessToken({}, { typ }) });
    assert.deepEqual(claims, { verified: true, tokenUse: 'access', sub: OWNER, iss: ISSUER,
      aud: RESOURCE, resource: RESOURCE, scope: ACCESS_SCOPES,
      exp: current + 300, iat: current });
    assert.equal(Object.isFrozen(claims), true);
    assert.equal(Object.isFrozen(claims.scope), true);
    assert.equal(Object.hasOwn(claims, 'clientId'), false);
  }
});

test('LI22 Cognito profile rejects at+jwt and every other explicit typ', async () => {
  for (const typ of ['at+jwt', 'application/at+jwt', 'JOSE']) {
    await rejects(() => cognitoAccessVerifier().verifyAccessToken({
      accessToken: signCognitoAccessToken({}, { typ }) }), 'jwt_invalid');
  }
});

test('LI23 Cognito profile requires exact client_id and aud resource and rejects legacy resource-only tokens', async () => {
  for (const changes of [
    { iss: 'https://wrong-issuer.invalid/pool' },
    { client_id: undefined },
    { client_id: 'wrong-client' },
    { aud: undefined },
    { aud: 'wrong-audience' },
    { aud: ACCESS_AUDIENCE, client_id: undefined, resource: RESOURCE }
  ]) {
    await rejects(() => cognitoAccessVerifier().verifyAccessToken({
      accessToken: signCognitoAccessToken(changes) }), 'access_invalid');
  }
});

test('LI24 Cognito profile requires access token_use and the exact full scope set', async () => {
  for (const changes of [
    { token_use: 'id' },
    { token_use: undefined },
    { scope: 'mcp:tools:list' },
    { scope: 'mcp:tools:list mcp:tools:call mcp:admin' }
  ]) {
    await rejects(() => cognitoAccessVerifier().verifyAccessToken({
      accessToken: signCognitoAccessToken(changes) }), 'access_invalid');
  }
});

test('LI25 Cognito profile rejects expired, future and over-300-second tokens', async () => {
  const current = Math.floor(START / 1000);
  for (const changes of [
    { exp: current },
    { iat: current + 1, exp: current + 300 },
    { nbf: current + 1 },
    { exp: current + 301 }
  ]) {
    await rejects(() => cognitoAccessVerifier({ current }).verifyAccessToken({
      accessToken: signCognitoAccessToken(changes) }), 'access_invalid');
  }
});

test('LI26 Cognito profile rejects non-RS256 algorithms and unknown kid', async () => {
  for (const headerClaims of [
    { alg: 'none' },
    { alg: 'HS256' },
    { kid: 'generated-unknown-key' }
  ]) {
    await rejects(() => cognitoAccessVerifier().verifyAccessToken({
      accessToken: signCognitoAccessToken({}, headerClaims) }), 'jwt_invalid');
  }
  const signed = signCognitoAccessToken();
  const parts = signed.split('.');
  parts[2] = `${parts[2][0] === 'A' ? 'B' : 'A'}${parts[2].slice(1)}`;
  await rejects(() => cognitoAccessVerifier().verifyAccessToken({
    accessToken: parts.join('.') }), 'jwt_invalid');
});

test('LI27 Cognito profile fails closed on stale pinned JWKS', async () => {
  const current = Math.floor(START / 1000);
  await rejects(() => cognitoAccessVerifier({ current, snapshotExpiresAt: current })
    .verifyAccessToken({ accessToken: signCognitoAccessToken() }), 'jwks_stale');
});
