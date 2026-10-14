import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { lookupFormalVerifiedLogin } from '../../../../src/formal-runtime/request-authorization-policy.mjs';
import {
  createDisabledProductionMcpRuntime,
  createMcpRestComposition,
  parseNonsecretMcpEnvironment,
  parseRestV1McpEvent
} from '../mcp-rest-composition.mjs';

const now = 1_800_000_000;
const issuer = 'https://generated-cognito.invalid/pool';
const resource = 'https://generated-mcp.invalid/mcp';
const clientId = 'generated-public-client';
const scopes = [`${resource}/tools.list`, `${resource}/tools.call`];
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'generated-key', alg: 'RS256', use: 'sig', key_ops: ['verify'] };

function environment(overrides = {}) {
  return {
    RING_MCP_STATE: 'enabled',
    RING_MCP_ISSUER: issuer,
    RING_MCP_PUBLIC_CLIENT_ID: clientId,
    RING_MCP_RESOURCE_URI: resource,
    RING_MCP_REQUIRED_SCOPES: JSON.stringify(scopes),
    RING_MCP_MAX_TOKEN_LIFETIME_SECONDS: '300',
    RING_MCP_MAX_JWKS_AGE_SECONDS: '300',
    RING_MCP_EXPECTED_API_ID: 'generated-api',
    RING_MCP_EXPECTED_STAGE: 'staging',
    ...overrides
  };
}

function token(claims = {}, typ = 'JWT') {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: jwk.kid, typ })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ iss: issuer, client_id: clientId, aud: resource,
    sub: 'generated-owner', scope: scopes.join(' '), token_use: 'access', iat: now, exp: now + 300,
    ...claims })).toString('base64url');
  const input = `${header}.${payload}`;
  return `${input}.${sign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url')}`;
}

const meta = {
  'io.modelcontextprotocol/protocolVersion': '2026-07-28',
  'io.modelcontextprotocol/clientInfo': { name: 'rest-test', version: '1.0.0' },
  'io.modelcontextprotocol/clientCapabilities': {}
};

function event({ path = '/mcp', method = path === '/mcp' ? 'POST' : 'GET', body,
  headers = {}, base64 = false } = {}) {
  const envelope = body ?? { jsonrpc: '2.0', id: 7, method: 'tools/list', params: { _meta: meta } };
  const selected = method === 'POST' ? {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    'mcp-protocol-version': '2026-07-28',
    'mcp-method': envelope.method ?? 'tools/list',
    authorization: `Bearer ${token()}`,
    ...headers
  } : { ...headers };
  const encoded = method === 'POST' ? JSON.stringify(envelope) : null;
  return {
    resource: path,
    path,
    httpMethod: method,
    headers: { ...selected },
    multiValueHeaders: Object.fromEntries(Object.entries(selected).map(([key, value]) => [key, [value]])),
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    pathParameters: null,
    stageVariables: null,
    requestContext: { apiId: 'generated-api', stage: 'staging', httpMethod: method,
      resourcePath: path, path: `/staging${path}` },
    body: method === 'POST' && base64 ? Buffer.from(encoded).toString('base64') : encoded,
    isBase64Encoded: method === 'POST' && base64
  };
}

function ports({ tls = true, calls = [] } = {}) {
  return {
    trustedTransportEvidencePort: { productionAdmitted: true, async resolve() {
      calls.push('tls');
      if (!tls) throw new Error('denied');
      return { productionAdmitted: true, encrypted: true, protocol: 'TLSv1.3', evidenceId: 'generated-tls' };
    } },
    formalMcpApplicationPort: { productionAdmitted: true, async handle(input) {
      calls.push(['application', input.routeId, input.actor.subject, input.transport.protocol]);
      return { jsonrpc: '2.0', id: input.envelope.id, result: { tools: [] } };
    } }
  };
}

function composition(options = {}) {
  const calls = options.calls ?? [];
  return { calls, runtime: createMcpRestComposition({
    config: parseNonsecretMcpEnvironment(environment()),
    loadPinnedJwks: async () => { calls.push('jwks'); return { jwksUri: `${issuer}/.well-known/jwks.json`,
      snapshotVersion: 1, fetchedAtSeconds: now, expiresAtSeconds: now + 300, keys: [jwk] }; },
    clockSeconds: () => now,
    ...ports({ tls: options.tls, calls }),
    macCommandService: options.macCommandService ?? null
  }) };
}

test('Mac routes bind real verified login to the same request; invalid or expired bearer never reaches service', async () => {
  const handled = [];
  const macCommandService = {
    async fetch(input) {
      assert.ok(lookupFormalVerifiedLogin(input));
      handled.push('fetch');
      return { status: 'EMPTY' };
    },
    async receipt(input) {
      assert.ok(lookupFormalVerifiedLogin(input));
      handled.push(input.receipt.commandId);
      return { status: 'SUCCEEDED', commandId: input.receipt.commandId };
    }
  };
  const { runtime } = composition({ macCommandService });
  assert.equal((await runtime.handle(event({path: '/mac/commands/fetch', method: 'POST', body: {}}))).statusCode, 200);
  assert.equal((await runtime.handle(event({path: '/mac/commands/receipt', method: 'POST', body: {commandId: 'generated-command'}}))).statusCode, 200);
  for (const headers of [{authorization: 'Bearer malformed.token.value'}, {authorization: 'Bearer ' + token({exp: now - 1})}]) {
    assert.equal((await runtime.handle(event({path: '/mac/commands/fetch', method: 'POST', body: {}, headers}))).statusCode, 401);
  }
  assert.equal((await runtime.handle(event({path: '/mac/commands/fetch', method: 'POST', body: {owner: 'injected'}}))).statusCode, 400);
  assert.deepEqual(handled, ['fetch', 'generated-command']);
});

test('nonsecret environment is default blocked and enabled only by the exact bounded contract', () => {
  assert.deepEqual(parseNonsecretMcpEnvironment({}), { state: 'blocked' });
  const config = parseNonsecretMcpEnvironment(environment());
  assert.equal(config.state, 'enabled');
  assert.deepEqual(config.requiredScopes, scopes);
  assert.equal(config.maximumTokenLifetimeSeconds, 300);
  for (const overrides of [
    { RING_MCP_STATE: 'active' },
    { RING_MCP_ISSUER: 'http://issuer.invalid' },
    { RING_MCP_RESOURCE_URI: 'https://generated-mcp.invalid/other' },
    { RING_MCP_REQUIRED_SCOPES: JSON.stringify([scopes[0]]) },
    { RING_MCP_MAX_TOKEN_LIFETIME_SECONDS: '301' }
  ]) assert.throws(() => parseNonsecretMcpEnvironment(environment(overrides)), /mcp_config_denied/);
});

test('REST v1 parser accepts JSON and canonical base64 then rejects v2, conflicts, query and bounds', () => {
  assert.equal(parseRestV1McpEvent(event(), { apiId: 'generated-api', stage: 'staging' }).route, 'mcp');
  assert.equal(parseRestV1McpEvent(event({ base64: true }), { apiId: 'generated-api', stage: 'staging' }).route, 'mcp');
  for (const mutate of [
    value => { value.requestContext.http = { method: 'POST' }; },
    value => { value.queryStringParameters = {}; },
    value => { value.multiValueHeaders.authorization = ['one', 'two']; },
    value => { value.multiValueHeaders.authorization = ['Bearer conflicting.token.value']; },
    value => { value.body = 'x'.repeat(65537); },
    value => { value.unexpected = true; }
  ]) {
    const value = event();
    mutate(value);
    assert.throws(() => parseRestV1McpEvent(value, { apiId: 'generated-api', stage: 'staging' }), /mcp_rest_denied/);
  }
});

test('metadata is TLS-gated, exact, nonsecret and never loads JWKS or calls application', async () => {
  const { runtime, calls } = composition();
  const response = await runtime.handle(event({ path: '/.well-known/oauth-protected-resource' }));
  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), {
    resource,
    authorization_servers: [issuer],
    scopes_supported: scopes,
    bearer_methods_supported: ['header']
  });
  assert.deepEqual(calls, ['tls']);
  assert.equal(response.headers['cache-control'], 'no-store');
});

test('valid Cognito access request delegates once with server-validated actor and transport', async () => {
  const { runtime, calls } = composition();
  const response = await runtime.handle(event());
  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), { jsonrpc: '2.0', id: 7, result: { tools: [] } });
  assert.deepEqual(calls, ['tls', 'jwks', ['application', 'tools/list', 'generated-owner', 'TLSv1.3']]);
});

test('TLS, bearer and Cognito claim failures deny before application delegation', async () => {
  const deniedTls = composition({ tls: false });
  assert.equal((await deniedTls.runtime.handle(event())).statusCode, 403);
  assert.deepEqual(deniedTls.calls, ['tls']);
  for (const claims of [
    { iss: 'https://wrong.invalid/pool' },
    { client_id: 'wrong-client' },
    { aud: 'https://wrong.invalid/mcp' },
    { scope: scopes[0] },
    { token_use: 'id' },
    { exp: now },
    { exp: now + 301 }
  ]) {
    const fx = composition();
    const request = event();
    const value = `Bearer ${token(claims)}`;
    request.headers.authorization = value;
    request.multiValueHeaders.authorization = [value];
    assert.equal((await fx.runtime.handle(request)).statusCode, 401);
    assert.equal(fx.calls.some(call => Array.isArray(call) && call[0] === 'application'), false);
  }
});

test('forwarded claims and missing production ports fail closed without application fallback', async () => {
  const fx = composition();
  const request = event({ headers: { 'x-forwarded-proto': 'https' } });
  assert.equal((await fx.runtime.handle(request)).statusCode, 403);
  assert.equal(fx.calls.some(call => Array.isArray(call) && call[0] === 'application'), false);
  assert.throws(() => createMcpRestComposition({ config: parseNonsecretMcpEnvironment(environment()),
    loadPinnedJwks: async () => ({}), clockSeconds: () => now }), /mcp_ports_missing/);
  const blocked = createMcpRestComposition({ config: { state: 'blocked' } });
  assert.equal((await blocked.handle(new Proxy({}, { get() { throw new Error('must-not-read'); } }))).statusCode, 503);
});

test('production factory remains disabled without constructing credentials, JWKS or application ports', async () => {
  const previous = process.env.RING_MCP_STATE;
  try {
    process.env.RING_MCP_STATE = 'blocked';
    const runtime = createDisabledProductionMcpRuntime();
    assert.equal((await runtime.handle(new Proxy({}, { get() { throw new Error('must-not-read'); } }))).statusCode, 503);
  } finally {
    if (previous === undefined) delete process.env.RING_MCP_STATE;
    else process.env.RING_MCP_STATE = previous;
  }
});


test('C4 policy-attestation stays qualified with null negotiated protocol and direct TLS still denies forwarded', async () => {
  const calls = [];
  const base = ports({ calls });
  base.trustedTransportEvidencePort = { productionAdmitted: true, transportEvidenceKind: 'apigateway-rest-policy-v1',
    async resolve() { return { productionAdmitted: true, encrypted: true, kind: 'apigateway-rest-policy-v1',
      negotiatedProtocol: null, minimumTlsVersion: 'TLSv1.2', evidenceId: 'generated-policy',
      rootDecisionSha256: 'a'.repeat(64), deploymentEvidenceSha256: 'b'.repeat(64) }; } };
  base.formalMcpApplicationPort = { productionAdmitted: true, async handle(input) {
    assert.equal(input.transport.negotiatedProtocol, null);
    assert.equal(input.transport.minimumTlsVersion, 'TLSv1.2');
    assert.equal(Object.hasOwn(input.transport, 'protocol'), false);
    return { jsonrpc: '2.0', id: input.envelope.id, result: { tools: [] } };
  } };
  const runtime = createMcpRestComposition({ config: parseNonsecretMcpEnvironment(environment()),
    loadPinnedJwks: async () => ({ jwksUri: issuer + '/.well-known/jwks.json', snapshotVersion: 1,
      fetchedAtSeconds: now, expiresAtSeconds: now + 300, keys: [jwk] }), clockSeconds: () => now, ...base });
  assert.equal((await runtime.handle(event())).statusCode, 200);
  assert.equal((await runtime.handle(event({ headers: { forwarded: 'proto=https' } }))).statusCode, 403);
});
