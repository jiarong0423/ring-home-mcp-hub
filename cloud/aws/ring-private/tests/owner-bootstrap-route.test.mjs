import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { lookupFormalVerifiedLogin } from '../../../../src/formal-runtime/request-authorization-policy.mjs';
import { createMcpRestComposition, parseNonsecretMcpEnvironment, parseRestV1McpEvent } from '../mcp-rest-composition.mjs';
import { createCloudOwnerBootstrap, OWNER_RENEWAL_APPROVAL_SCHEMA } from '../cloud-owner-bootstrap.mjs';
import { digest, identityEnvelope, createFakeTable, approvalFixture, sha256, ACCOUNT_ID } from './owner-bootstrap-fixture.mjs';

process.env.NODE_ENV = 'test';
const { handler, installMcpRuntimeFactoryForTest, restoreProductionRuntimeForTest } = await import('../handler.mjs');

const now = 1_800_000_000;
const nowMs = now * 1000;
const issuer = 'https://generated-cognito.invalid/pool';
const resource = 'https://generated-mcp.invalid/mcp';
const clientId = 'generated-public-client';
const scopes = [`${resource}/tools.list`, `${resource}/tools.call`];
const RING_TOKEN = 'ring.playground-token_SECRET-123';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'generated-key', alg: 'RS256', use: 'sig', key_ops: ['verify'] };
const environment = () => ({ RING_MCP_STATE: 'enabled', RING_MCP_ISSUER: issuer, RING_MCP_PUBLIC_CLIENT_ID: clientId, RING_MCP_RESOURCE_URI: resource,
  RING_MCP_REQUIRED_SCOPES: JSON.stringify(scopes), RING_MCP_MAX_TOKEN_LIFETIME_SECONDS: '300', RING_MCP_MAX_JWKS_AGE_SECONDS: '300',
  RING_MCP_EXPECTED_API_ID: 'generated-api', RING_MCP_EXPECTED_STAGE: 'staging' });
function token(claims = {}) {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: jwk.kid, typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ iss: issuer, client_id: clientId, aud: resource, sub: 'generated-owner', scope: scopes.join(' '),
    token_use: 'access', iat: now, exp: now + 300, ...claims })).toString('base64url');
  return `${header}.${payload}.${sign('RSA-SHA256', Buffer.from(`${header}.${payload}`), privateKey).toString('base64url')}`;
}
function event({ method = 'POST', body = { ringAccessToken: RING_TOKEN }, rawBody, headers = {}, auth = true, contentType = 'application/json', base64 = false } = {}) {
  const selected = { ...(contentType ? { 'content-type': contentType } : {}), ...(auth ? { authorization: `Bearer ${token()}` } : {}), ...headers };
  let encoded = rawBody !== undefined ? rawBody : body === null ? null : JSON.stringify(body);
  if (base64 && encoded !== null) encoded = Buffer.from(encoded).toString('base64');
  return { resource: '/owner/bootstrap', path: '/owner/bootstrap', httpMethod: method, headers: { ...selected },
    multiValueHeaders: Object.fromEntries(Object.entries(selected).map(([k, v]) => [k, [v]])),
    queryStringParameters: null, multiValueQueryStringParameters: null, pathParameters: null, stageVariables: null,
    requestContext: { apiId: 'generated-api', stage: 'staging', httpMethod: method, resourcePath: '/owner/bootstrap', path: '/staging/owner/bootstrap' },
    body: encoded, isBase64Encoded: base64 };
}
function composition(ownerBootstrapService) {
  const calls = [];
  return { calls, runtime: createMcpRestComposition({ config: parseNonsecretMcpEnvironment(environment()),
    loadPinnedJwks: async () => ({ jwksUri: `${issuer}/.well-known/jwks.json`, snapshotVersion: 1, fetchedAtSeconds: now, expiresAtSeconds: now + 300, keys: [jwk] }),
    clockSeconds: () => now,
    trustedTransportEvidencePort: { productionAdmitted: true, async resolve() { calls.push('tls'); return { productionAdmitted: true, encrypted: true, protocol: 'TLSv1.3', evidenceId: 'generated-tls' }; } },
    formalMcpApplicationPort: { productionAdmitted: true, async handle() { throw new Error('mcp application must not run for /owner/bootstrap'); } },
    ownerBootstrapService }) };
}
const ctx = { apiId: 'generated-api', stage: 'staging' };

test('POST /owner/bootstrap parses as its own exact-match route; other methods, bodies and content types are refused', () => {
  assert.equal(parseRestV1McpEvent(event(), ctx).route, 'owner-bootstrap');
  assert.equal(parseRestV1McpEvent(event({ contentType: 'application/json; charset=utf-8' }), ctx).route, 'owner-bootstrap');
  assert.equal(parseRestV1McpEvent(event({ base64: true }), ctx).route, 'owner-bootstrap');
  for (const method of ['GET', 'HEAD', 'OPTIONS', 'PUT', 'DELETE', 'PATCH']) assert.throws(() => parseRestV1McpEvent(event({ method }), ctx), /mcp_rest_denied/, method);
  for (const bad of [event({ contentType: 'text/plain' }), event({ contentType: null }), event({ contentType: 'application/x-www-form-urlencoded' }), event({ body: null }),
    event({ body: {} }), event({ body: { ringAccessToken: RING_TOKEN, extra: 1 } }), event({ body: { token: RING_TOKEN } }), event({ body: { ringAccessToken: 5 } }),
    event({ body: { ringAccessToken: '' } }), event({ body: { ringAccessToken: 'x'.repeat(8193) } }), event({ body: { ringAccessToken: 'has space' } }),
    event({ body: { ringAccessToken: ['a'] } }), event({ rawBody: '[]' }), event({ rawBody: '"x"' }), event({ rawBody: 'null' }), event({ rawBody: '{' }),
    event({ rawBody: '{"ringAccessToken":"a","ringAccessToken":"b","x":1}' })]) {
    assert.throws(() => parseRestV1McpEvent(bad, ctx), /mcp_rest_denied/);
  }
  assert.equal(parseRestV1McpEvent(event({ body: { ringAccessToken: 'x'.repeat(8192) } }), ctx).route, 'owner-bootstrap');
  const withQuery = event(); withQuery.queryStringParameters = { a: 'b' };
  assert.throws(() => parseRestV1McpEvent(withQuery, ctx), /mcp_rest_denied/);
  const slash = event(); slash.path = slash.resource = '/owner/bootstrap/'; slash.requestContext.resourcePath = '/owner/bootstrap/'; slash.requestContext.path = '/staging/owner/bootstrap/';
  assert.throws(() => parseRestV1McpEvent(slash, ctx), /mcp_rest_denied/);
});

test('bearer is verified first: missing, malformed, expired, wrong audience or wrong scopes never reach the service', async () => {
  const seen = [];
  const { runtime } = composition({ async ensureWithRingToken(input) { assert.ok(lookupFormalVerifiedLogin(input)); seen.push([input.actor.subject, input.ringAccessToken]); return { bootstrapped: true }; } });
  const ok = await runtime.handle(event());
  assert.equal(ok.statusCode, 200);
  assert.deepEqual(JSON.parse(ok.body), { status: 'owner_bootstrapped' });
  assert.deepEqual(seen, [['generated-owner', RING_TOKEN]]);
  for (const e of [event({ auth: false }), event({ headers: { authorization: 'Bearer malformed.token.value' } }),
    event({ headers: { authorization: `Bearer ${token({ exp: now - 1 })}` } }), event({ headers: { authorization: `Bearer ${token({ aud: 'https://other.invalid/mcp' })}` } }),
    event({ headers: { authorization: `Bearer ${token({ scope: scopes[0] })}` } }), event({ headers: { authorization: `Basic ${Buffer.from('a:b').toString('base64')}` } })]) {
    const response = await runtime.handle(e);
    assert.ok([401, 403].includes(response.statusCode), String(response.statusCode));
    assert.equal(response.body.includes(RING_TOKEN), false);
  }
  assert.equal(seen.length, 1);
});

test('every post-authorization failure has the identical status and body; only success differs; nothing is echoed', async () => {
  const failures = [
    async () => { throw new TypeError('owner_bootstrap_ring_denied'); }, async () => { throw new TypeError('owner_bootstrap_locked'); },
    async () => { throw new Error('dynamodb exploded ' + RING_TOKEN); }, async () => ({ bootstrapped: false, reason: 'owner_exists' }),
    async () => undefined, async () => null, async () => ({ bootstrapped: 'yes' }), async () => ({ renewed: 'yes' }), async () => ({ renewed: false, bootstrapped: false }), async () => { throw Object.assign(new Error('x'), { status: 401, code: 'B02_FORMAL_SECRET' }); }];
  const bodies = new Set(); const statuses = new Set();
  for (const impl of failures) {
    const { runtime } = composition({ ensureWithRingToken: impl });
    const response = await runtime.handle(event());
    bodies.add(response.body); statuses.add(response.statusCode);
    assert.equal(response.body.includes(RING_TOKEN), false);
  }
  assert.equal(bodies.size, 1); assert.equal(statuses.size, 1);
  assert.deepEqual(JSON.parse([...bodies][0]), { error: 'mcp_rest_denied' });
  assert.equal([...statuses][0], 400);
});

test('state off: composition without a service is blocked after authorization; the Lambda gate answers 503 before any runtime is built', async () => {
  const { runtime } = composition(null);
  assert.equal((await runtime.handle(event())).statusCode, 503);
  Object.assign(process.env, { RING_BACKEND_STATE: 'enabled', RING_MCP_STATE: 'enabled', RING_MCP_EXPECTED_API_ID: 'generated-api', RING_MCP_EXPECTED_STAGE: 'staging' });
  delete process.env.RING_OWNER_BOOTSTRAP_STATE;
  restoreProductionRuntimeForTest();
  let constructed = 0; const handled = [];
  installMcpRuntimeFactoryForTest(() => { constructed += 1; return { async handle(e) { handled.push(`${e.httpMethod} ${e.path}`); return { statusCode: 200, headers: { 'content-type': 'application/json' }, body: '{}' }; } }; });
  try {
    for (const state of [undefined, 'blocked', 'ENABLED', 'enabled ', '']) {
      if (state === undefined) delete process.env.RING_OWNER_BOOTSTRAP_STATE; else process.env.RING_OWNER_BOOTSTRAP_STATE = state;
      const response = await handler(event());
      assert.equal(response.statusCode, 503);
      assert.deepEqual(JSON.parse(response.body), { status: 'not_configured' });
    }
    assert.equal(constructed, 0);
    process.env.RING_OWNER_BOOTSTRAP_STATE = 'enabled';
    assert.equal((await handler(event())).statusCode, 200);
    assert.deepEqual(handled, ['POST /owner/bootstrap']);
    // the other MCP routes are unaffected by this switch
    delete process.env.RING_OWNER_BOOTSTRAP_STATE;
    const other = event({ body: {} }); other.path = other.resource = '/mac/commands/fetch'; other.requestContext.resourcePath = '/mac/commands/fetch'; other.requestContext.path = '/staging/mac/commands/fetch';
    assert.equal((await handler(other)).statusCode, 200);
    // MCP master switch off also blocks it
    process.env.RING_OWNER_BOOTSTRAP_STATE = 'enabled';
    process.env.RING_MCP_STATE = 'blocked';
    assert.equal((await handler(event())).statusCode, 503);
    process.env.RING_MCP_STATE = 'enabled';
    // malformed events are rejected by preflight even when enabled; other methods are not routes at all
    const bad = event(); bad.requestContext.apiId = 'wrong-api';
    assert.equal((await handler(bad)).statusCode, 400);
    assert.equal((await handler(event({ body: { ringAccessToken: RING_TOKEN, extra: 1 } }))).statusCode, 400);
    for (const method of ['GET', 'HEAD', 'OPTIONS']) assert.equal((await handler(event({ method }))).statusCode, 404, method);
  } finally { restoreProductionRuntimeForTest(); for (const k of ['RING_BACKEND_STATE', 'RING_MCP_STATE', 'RING_OWNER_BOOTSTRAP_STATE', 'RING_MCP_EXPECTED_API_ID', 'RING_MCP_EXPECTED_STAGE']) delete process.env[k]; }
});

test('integration: route -> real bootstrap with a fake Ring client creates the owner once; wrong Ring account, replay and lockout are generic denials; logs stay clean', async () => {
  const logs = [];
  const original = { info: console.info, log: console.log, warn: console.warn, error: console.error, debug: console.debug };
  for (const name of Object.keys(original)) console[name] = (...a) => logs.push(a.map(x => typeof x === 'string' ? x : JSON.stringify(x)).join(' '));
  const results = [];
  try {
    const table = createFakeTable();
    const approval = approvalFixture({ issuer, resource, scopes, cognitoSub: 'generated-owner', issuedAt: nowMs - 60000, notAfter: nowMs + 3600000, expiresAt: nowMs + 7200000 });
    let ringId = ACCOUNT_ID;
    const ringCalls = [];
    const bootstrap = createCloudOwnerBootstrap({ getItem: table.getItem, transactWrite: table.transactWrite, tableName: 'ring-test-link', digest, identityEnvelope,
      profile: { issuer, resource, scopes }, approvalSha256: approval.sha, clock: () => nowMs, loadApproval: async () => approval.bytes,
      ringTokenClient: { async getAccountId(t) { ringCalls.push(t); return ringId; } } });
    const { runtime } = composition(bootstrap);
    ringId = 'a-different-ring-account';
    const wrong = await runtime.handle(event());
    results.push(wrong);
    assert.equal(wrong.statusCode, 400);
    assert.equal(table.get('OWNER#CURRENT', 'META'), undefined);
    ringId = ACCOUNT_ID;
    const ok = await runtime.handle(event());
    results.push(ok);
    assert.equal(ok.statusCode, 200); assert.deepEqual(JSON.parse(ok.body), { status: 'owner_bootstrapped' });
    assert.ok(table.get('OWNER#CURRENT', 'META'));
    const replay = await runtime.handle(event());
    results.push(replay);
    assert.equal(replay.statusCode, 400);
    assert.equal(replay.body, wrong.body);
    assert.equal(ringCalls.length, 2, 'once the owner exists Ring is not contacted again');
    // lockout through the route: a fresh table, three wrong tokens, then the right one is refused with the same generic body
    const t2 = createFakeTable(); let id2 = 'nope'; let calls2 = 0;
    const b2 = createCloudOwnerBootstrap({ getItem: t2.getItem, transactWrite: t2.transactWrite, tableName: 'ring-test-link', digest, identityEnvelope,
      profile: { issuer, resource, scopes }, approvalSha256: approval.sha, clock: () => nowMs, loadApproval: async () => approval.bytes,
      ringTokenClient: { async getAccountId() { calls2 += 1; return id2; } } });
    const r2 = composition(b2).runtime;
    for (let i = 0; i < 3; i += 1) assert.equal((await r2.handle(event())).body, wrong.body);
    id2 = ACCOUNT_ID;
    const locked = await r2.handle(event());
    results.push(locked);
    assert.equal(locked.statusCode, 400); assert.equal(locked.body, wrong.body);
    assert.equal(calls2, 3); assert.equal(t2.get('OWNER#CURRENT', 'META'), undefined);
  } finally { Object.assign(console, original); }
  const everything = [...logs, ...results.map(r => JSON.stringify(r))].join('\n');
  for (const secret of [RING_TOKEN, ACCOUNT_ID, sha256(ACCOUNT_ID), 'owner/fixture', 'generated-owner']) assert.equal(everything.includes(secret), false, secret);
});

test('integration: once the owner exists, the SAME route with a renewal approval extends the association (200 owner_renewed); replay and the old bootstrap approval stay generic denials', async () => {
  const table = createFakeTable();
  const boot = approvalFixture({ issuer, resource, scopes, cognitoSub: 'generated-owner', issuedAt: nowMs - 60000, notAfter: nowMs + 3600000, expiresAt: nowMs + 7200000 });
  const ring = { calls: 0, async getAccountId() { ring.calls += 1; return ACCOUNT_ID; } };
  const make = bytes => composition(createCloudOwnerBootstrap({ getItem: table.getItem, transactWrite: table.transactWrite, tableName: 'ring-test-link', digest, identityEnvelope,
    profile: { issuer, resource, scopes }, approvalSha256: sha256(bytes), clock: () => nowMs, loadApproval: async () => bytes, ringTokenClient: ring })).runtime;
  const bootRoute = make(boot.bytes);
  assert.deepEqual(JSON.parse((await bootRoute.handle(event())).body), { status: 'owner_bootstrapped' });
  const denied = await bootRoute.handle(event({ body: { ringAccessToken: 'ring.other-token_SECRET-1' } }));
  assert.equal(denied.statusCode, 400);
  const renewal = Buffer.from(JSON.stringify({ schema: OWNER_RENEWAL_APPROVAL_SCHEMA, mode: 'renew', issuer, resource, cognitoSub: 'generated-owner',
    ringAccountIdSha256: sha256(ACCOUNT_ID), bootstrapApprovalSha256: boot.sha, ownerRef: 'owner/fixture', ownerEpoch: 1, associationRevision: 1, accountGeneration: 1,
    ringScopeRefs: ['ring.read', 'ring.link'], scopes, issuedAt: nowMs - 60000, notAfter: nowMs + 3600000, expiresAt: nowMs + 72000000 }));
  const renewRoute = make(renewal);
  const ok = await renewRoute.handle(event({ body: { ringAccessToken: 'ring.renew-token_SECRET-2' } }));
  assert.equal(ok.statusCode, 200); assert.deepEqual(JSON.parse(ok.body), { status: 'owner_renewed' });
  const subjectDigest = await digest('oauth-subject', `${issuer}\0generated-owner`);
  const association = table.get(`OAUTH#${subjectDigest}`, 'RING_ASSOCIATION');
  assert.equal(association.expires_at.N, String(Math.floor((nowMs + 72000000) / 1000))); assert.equal(association.revision.N, '1');
  const replay = await renewRoute.handle(event({ body: { ringAccessToken: 'ring.renew-token_SECRET-3' } }));
  assert.equal(replay.statusCode, 400); assert.equal(replay.body, denied.body);
  assert.equal(ring.calls, 2, 'Ring is contacted once for bootstrap and once for the renewal');
});
