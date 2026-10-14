import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { lookupFormalVerifiedLogin } from '../../../../src/formal-runtime/request-authorization-policy.mjs';
import { createMcpRestComposition, parseNonsecretMcpEnvironment, parseRestV1McpEvent, MAC_ENROLLMENT_APPROVAL_FILE } from '../mcp-rest-composition.mjs';
import { createMacEnrollmentInstaller } from '../mac-command-proof-authority.mjs';
import { COMMAND_TABLE, hash } from '../../../../src/formal-runtime/mac-command-contract.mjs';
import { memoryDynamo } from './mac-command-proof-fixture.mjs';

process.env.NODE_ENV = 'test';
const { handler, installMcpRuntimeFactoryForTest, restoreProductionRuntimeForTest } = await import('../handler.mjs');

const now = 1_800_000_000;
const issuer = 'https://generated-cognito.invalid/pool';
const resource = 'https://generated-mcp.invalid/mcp';
const clientId = 'generated-public-client';
const scopes = [`${resource}/tools.list`, `${resource}/tools.call`];
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
function enrollEvent({ method = 'POST', body = null, headers = {}, auth = true } = {}) {
  const selected = { ...(body === null ? {} : { 'content-type': 'application/json' }), ...(auth ? { authorization: `Bearer ${token()}` } : {}), ...headers };
  const encoded = body === null ? null : JSON.stringify(body);
  return { resource: '/mac/enroll', path: '/mac/enroll', httpMethod: method, headers: { ...selected },
    multiValueHeaders: Object.fromEntries(Object.entries(selected).map(([k, v]) => [k, [v]])),
    queryStringParameters: null, multiValueQueryStringParameters: null, pathParameters: null, stageVariables: null,
    requestContext: { apiId: 'generated-api', stage: 'staging', httpMethod: method, resourcePath: '/mac/enroll', path: '/staging/mac/enroll' },
    body: encoded, isBase64Encoded: false };
}
function composition(macEnrollmentService) {
  const calls = [];
  return { calls, runtime: createMcpRestComposition({ config: parseNonsecretMcpEnvironment(environment()),
    loadPinnedJwks: async () => ({ jwksUri: `${issuer}/.well-known/jwks.json`, snapshotVersion: 1, fetchedAtSeconds: now, expiresAtSeconds: now + 300, keys: [jwk] }),
    clockSeconds: () => now,
    trustedTransportEvidencePort: { productionAdmitted: true, async resolve() { calls.push('tls'); return { productionAdmitted: true, encrypted: true, protocol: 'TLSv1.3', evidenceId: 'generated-tls' }; } },
    formalMcpApplicationPort: { productionAdmitted: true, async handle() { throw new Error('mcp application must not run for /mac/enroll'); } },
    macEnrollmentService }) };
}

test('POST /mac/enroll parses as its own route; GET and a populated body are refused', () => {
  const ctx = { apiId: 'generated-api', stage: 'staging' };
  assert.equal(parseRestV1McpEvent(enrollEvent(), ctx).route, 'mac-enroll');
  assert.equal(parseRestV1McpEvent(enrollEvent({ body: {} }), ctx).route, 'mac-enroll');
  assert.throws(() => parseRestV1McpEvent(enrollEvent({ method: 'GET' }), ctx), /mcp_rest_denied/);
  assert.equal(MAC_ENROLLMENT_APPROVAL_FILE, 'mac-enrollment-approval-v1.json');
});

test('/mac/enroll needs a verified bearer on the same request; bad or missing bearer never reaches the service', async () => {
  const seen = [];
  const { runtime } = composition({ async enroll(input) { assert.ok(lookupFormalVerifiedLogin(input)); seen.push(input.actor.subject); return { installed: true }; } });
  assert.equal((await runtime.handle(enrollEvent())).statusCode, 200);
  assert.deepEqual(seen, ['generated-owner']);
  for (const e of [enrollEvent({ auth: false }), enrollEvent({ headers: { authorization: 'Bearer malformed.token.value' } }),
    enrollEvent({ headers: { authorization: `Bearer ${token({ exp: now - 1 })}` } }), enrollEvent({ headers: { authorization: `Bearer ${token({ aud: 'https://other.invalid/mcp' })}` } }),
    enrollEvent({ headers: { authorization: `Bearer ${token({ scope: scopes[0] })}` } })]) {
    const response = await runtime.handle(e);
    assert.ok([401, 403].includes(response.statusCode), String(response.statusCode));
  }
  assert.equal(seen.length, 1);
});

test('/mac/enroll takes no request data: {} and null body are accepted, anything else is refused before the service', async () => {
  let calls = 0;
  const { runtime } = composition({ async enroll() { calls += 1; return { installed: true }; } });
  assert.equal((await runtime.handle(enrollEvent({ body: {} }))).statusCode, 200);
  assert.equal((await runtime.handle(enrollEvent({ body: null }))).statusCode, 200);
  for (const body of [{ approval: 'x' }, { ownerRef: 'owner-a' }, { publicKeySpki: 'AAAA' }]) assert.equal((await runtime.handle(enrollEvent({ body }))).statusCode, 400);
  assert.equal(calls, 2);
});

test('state off: composition without an enrollment service is blocked after authorization; the Lambda gate blocks before the runtime is built', async () => {
  const { runtime } = composition(null);
  assert.equal((await runtime.handle(enrollEvent())).statusCode, 503);
  Object.assign(process.env, { RING_BACKEND_STATE: 'enabled', RING_MCP_STATE: 'enabled', RING_MCP_EXPECTED_API_ID: 'generated-api', RING_MCP_EXPECTED_STAGE: 'staging' });
  delete process.env.RING_MAC_ENROLLMENT_STATE;
  restoreProductionRuntimeForTest();
  let constructed = 0; const handled = [];
  installMcpRuntimeFactoryForTest(() => { constructed += 1; return { async handle(event) { handled.push(`${event.httpMethod} ${event.path}`); return { statusCode: 200, headers: { 'content-type': 'application/json' }, body: '{}' }; } }; });
  try {
    for (const state of [undefined, 'blocked', 'ENABLED', 'enabled ']) {
      if (state === undefined) delete process.env.RING_MAC_ENROLLMENT_STATE; else process.env.RING_MAC_ENROLLMENT_STATE = state;
      const response = await handler(enrollEvent());
      assert.equal(response.statusCode, 503);
      assert.deepEqual(JSON.parse(response.body), { status: 'not_configured' });
    }
    assert.equal(constructed, 0);
    process.env.RING_MAC_ENROLLMENT_STATE = 'enabled';
    assert.equal((await handler(enrollEvent())).statusCode, 200);
    assert.deepEqual(handled, ['POST /mac/enroll']);
    // The other MCP routes are not affected by the enrollment switch.
    delete process.env.RING_MAC_ENROLLMENT_STATE;
    const other = enrollEvent({ body: {} }); other.path = other.resource = '/mac/commands/fetch'; other.requestContext.resourcePath = '/mac/commands/fetch'; other.requestContext.path = '/staging/mac/commands/fetch';
    assert.equal((await handler(other)).statusCode, 200);
    // A malformed enrollment event is rejected by preflight even when enabled.
    process.env.RING_MAC_ENROLLMENT_STATE = 'enabled';
    const bad = enrollEvent(); bad.requestContext.apiId = 'wrong-api';
    assert.equal((await handler(bad)).statusCode, 400);
    const get = enrollEvent({ method: 'GET' });
    assert.equal((await handler(get)).statusCode, 404);
  } finally { restoreProductionRuntimeForTest(); for (const k of ['RING_BACKEND_STATE', 'RING_MCP_STATE', 'RING_MAC_ENROLLMENT_STATE', 'RING_MCP_EXPECTED_API_ID', 'RING_MCP_EXPECTED_STAGE']) delete process.env[k]; }
});

test('idempotent: the first call installs the pinned approval, a replay is rejected by the conditional write and changes nothing', async () => {
  const keys = generateKeyPairSync('ed25519');
  const spki = keys.publicKey.export({ format: 'der', type: 'spki' });
  const clockMs = 1_800_000_000_000;
  const approval = Buffer.from(JSON.stringify({ schema: 'ring-mac-enrollment-approval-v1', ownerRef: 'generated-owner-ref', associationRevision: 1, keyId: hash(spki),
    publicKeySpki: spki.toString('base64url'), expectedRevision: 0, revision: 1, expiresAt: clockMs + 3600_000 }));
  const db = memoryDynamo();
  const installer = createMacEnrollmentInstaller({ ports: db.ports, tableName: COMMAND_TABLE, approvalSha256: hash(approval), clock: () => clockMs,
    authorize: async () => ({ ownerRef: 'generated-owner-ref', associationRevision: 1, assertCurrent: () => true }) });
  let reads = 0;
  const service = { async enroll({ request, actor }) { reads += 1; return installer.install({ request, actor, approvalBytes: approval }); } };
  const { runtime } = composition(service);
  const first = await runtime.handle(enrollEvent());
  assert.equal(first.statusCode, 200);
  assert.equal(JSON.parse(first.body).installed, true);
  assert.equal(db.rows.size, 1);
  const snapshot = JSON.stringify([...db.rows.entries()]);
  const replay = await runtime.handle(enrollEvent());
  assert.notEqual(replay.statusCode, 200);
  assert.equal(reads, 2);
  assert.equal(JSON.stringify([...db.rows.entries()]), snapshot);
  assert.equal(JSON.stringify([first.body, replay.body]).includes(spki.toString('base64url')), false);
  // Wrong-hash approval bytes are refused by the installer itself.
  const tampered = createMacEnrollmentInstaller({ ports: memoryDynamo().ports, tableName: COMMAND_TABLE, approvalSha256: 'f'.repeat(64), clock: () => clockMs,
    authorize: async () => ({ ownerRef: 'generated-owner-ref', associationRevision: 1, assertCurrent: () => true }) });
  await assert.rejects(tampered.install({ request: {}, actor: {}, approvalBytes: approval }), /MAC_ENROLLMENT_APPROVAL/);
});
