import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { createPinnedCognitoJwksLoader, loadAdmittedMcpProductionPorts,
  FORMAL_MCP_ADMISSION_PATH, FORMAL_MCP_LAYER_MODULE } from '../mcp-production-ports.mjs';
import { createMcpRestComposition, createProductionMcpRuntime, parseNonsecretMcpEnvironment } from '../mcp-rest-composition.mjs';
import { createFormalMcpProfile, createFormalRouteSet } from '../../../../src/formal-runtime/server-composition.mjs';

process.env.NODE_ENV = 'test';
const issuer = 'https://cognito-idp.us-east-1.amazonaws.com/generated_pool';
const resource = 'https://mcp.generated.invalid/mcp';
const clientId = 'generated-public-client';
const scopes = [resource + '/tools.list', resource + '/tools.call'];
const now = 1800000000;
const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'generated', alg: 'RS256', use: 'sig' };
const sha = value => createHash('sha256').update(value).digest('hex');
function httpFixture(options = {}) {
  const effects = { calls: 0, destroyed: 0, options: null, url: null };
  return { effects, requestImpl(url, requestOptions, callback) {
    effects.calls++; effects.options = requestOptions; effects.url = url;
    const request = new EventEmitter();
    request.destroy = () => { effects.destroyed++; };
    request.end = () => {
      if (options.hang) return;
      queueMicrotask(() => {
        const response = new EventEmitter();
        response.statusCode = options.status ?? 200;
        response.socket = { encrypted: true, authorized: options.authorized ?? true,
          getProtocol: () => options.protocol ?? 'TLSv1.3' };
        response.headers = { 'content-type': options.contentType ?? 'application/json',
          'cache-control': 'max-age=60', ...(options.headers ?? {}) };
        response.destroy = () => { effects.destroyed++; };
        callback(response);
        if (options.aborted) { response.emit('aborted'); return; }
        const body = options.bytes ?? Buffer.from(JSON.stringify(options.document ?? { keys: [jwk] }));
        response.emit('data', body);
        response.emit('end');
      });
    };
    return request;
  } };
}
const loader = (fixture, extra = {}) => createPinnedCognitoJwksLoader({ issuer,
  maxJwksAgeSeconds: 300, clockSeconds: () => now, requestImpl: fixture.requestImpl, ...extra });

test('JWKS construction is inert; pinned authenticated GET singleflights and caches', async () => {
  const fixture = httpFixture(); const value = loader(fixture);
  assert.equal(fixture.effects.calls, 0);
  const [a, b] = await Promise.all([value.loadPinnedJwks({ jwksUri: issuer + '/.well-known/jwks.json' }),
    value.loadPinnedJwks({ jwksUri: issuer + '/.well-known/jwks.json' })]);
  assert.equal(a, b); assert.equal(fixture.effects.calls, 1);
  assert.equal(a.snapshotVersion, 1); assert.equal(a.expiresAtSeconds, now + 60);
  assert.equal((await value.loadPinnedJwks({ jwksUri: a.jwksUri })), a);
  assert.equal(fixture.effects.options.rejectUnauthorized, true);
  assert.equal(fixture.effects.options.minVersion, 'TLSv1.2');
  assert.equal(fixture.effects.options.agent, false);
  assert.deepEqual(await value.close(), { closed: true, inFlight: 0 });
  await assert.rejects(value.loadPinnedJwks({ jwksUri: a.jwksUri }), /jwks_uri_denied/);
});
test('JWKS denies alternate issuer or URI without request', async () => {
  const fixture = httpFixture();
  for (const bad of ['http://cognito-idp.us-east-1.amazonaws.com/pool', issuer + '?x=1',
    'https://cognito-idp.us-east-1.amazonaws.com.evil.invalid/pool']) assert.throws(() => loader(fixture, { issuer: bad }), /cognito_issuer_denied/);
  const value = loader(fixture);
  await assert.rejects(value.loadPinnedJwks({ jwksUri: 'https://attacker.invalid/jwks' }), /jwks_uri_denied/);
  assert.equal(fixture.effects.calls, 0); await value.close();
});
test('Cognito public kid equals/slash/plus parity matches the existing verifier', async () => {
  const fixture = httpFixture({ document: { keys: ['public=', 'public/key', 'public+key'].map(kid => ({ ...jwk, kid })) } });
  const value = loader(fixture);
  assert.deepEqual((await value.loadPinnedJwks({ jwksUri: issuer + '/.well-known/jwks.json' })).keys.map(k => k.kid),
    ['public=', 'public/key', 'public+key']);
  await value.close();
});
test('JWKS refuses redirect, unverified certificate, old TLS and compressed response', async () => {
  for (const options of [{ status: 302, headers: { location: issuer } }, { authorized: false },
    { protocol: 'TLSv1.1' }, { headers: { 'content-encoding': 'gzip' } }, { contentType: 'text/html' }]) {
    const fixture = httpFixture(options); const value = loader(fixture);
    await assert.rejects(value.loadPinnedJwks({ jwksUri: issuer + '/.well-known/jwks.json' }), /jwks_fetch_denied/);
    assert.equal(fixture.effects.calls, 1); await value.close();
  }
});
test('JWKS refuses bounded-body violations, malformed UTF8/JSON, private key and duplicate kid', async () => {
  for (const options of [{ bytes: Buffer.alloc(65537) }, { bytes: Buffer.from([255]) },
    { bytes: Buffer.from('{') }, { document: { keys: [{ ...jwk, d: 'private' }] } },
    { document: { keys: [jwk, jwk] } }, { headers: { 'content-length': '65537' } },
    { headers: { 'content-length': '1' } }, { aborted: true }]) {
    const fixture = httpFixture(options); const value = loader(fixture);
    await assert.rejects(value.loadPinnedJwks({ jwksUri: issuer + '/.well-known/jwks.json' }), /jwks_fetch_denied/);
    await value.close();
  }
});
test('JWKS timeout and close cancel active request and leave no inflight operation', async () => {
  const fixture = httpFixture({ hang: true }); const value = loader(fixture, { timeoutMs: 5 });
  await assert.rejects(value.loadPinnedJwks({ jwksUri: issuer + '/.well-known/jwks.json' }), /jwks_fetch_denied/);
  assert.ok(fixture.effects.destroyed > 0); await value.close();
  const other = loader(httpFixture({ hang: true }));
  const pending = other.loadPinnedJwks({ jwksUri: issuer + '/.well-known/jwks.json' });
  const rejection = assert.rejects(pending, /jwks_fetch_denied/);
  assert.deepEqual(await other.close(), { closed: true, inFlight: 0 }); await rejection;
});
test('JWKS cache expiry refreshes version; clock reversal refuses stale cache', async () => {
  let clock = now; const fixture = httpFixture(); const value = loader(fixture, { clockSeconds: () => clock });
  const uri = { jwksUri: issuer + '/.well-known/jwks.json' };
  assert.equal((await value.loadPinnedJwks(uri)).snapshotVersion, 1);
  clock += 61; assert.equal((await value.loadPinnedJwks(uri)).snapshotVersion, 2);
  clock--; await assert.rejects(value.loadPinnedJwks(uri), /jwks_clock_regressed/); await value.close();
});

function fixture(extra = {}) {
  const counts = { reads: 0, imports: 0, factories: 0, source: 0, context: 0, grants: 0,
    consumes: 0, lists: 0, executes: 0, closed: 0, sourceRequests: [], contextInputs: [], dispatchInputs: [] };
  const moduleBytes = Buffer.from('generated-fixture-layer-not-production-evidence');
  const admission = { schema: 'ring-mcp-gateway-admission-v1', decision: 'ADMITTED_GATEWAY_DEPLOYMENT',
    rootDecisionSha256: sha('generated-root-decision'), layerModuleSha256: sha(moduleBytes),
    oauth: { issuer, clientId, resource, requiredScopes: scopes, maximumTokenLifetimeSeconds: 300, maxJwksAgeSeconds: 300 }, gateway: {
      apiId: 'generated-api', stage: 'teststage', domainName: 'mcp.generated.invalid', deploymentId: 'generated-deployment',
      resourceUri: resource, minimumTlsVersion: 'TLSv1.2', tlsPolicyEvidenceSha256: sha('generated-policy'),
      deploymentEvidenceSha256: sha('generated-deployment-evidence'), executeApiEndpointDisabled: true } };
  if (extra.native) {
    const nativeResource = 'https://a1b2c3d4e5.execute-api.us-east-1.amazonaws.com/teststage/mcp';
    admission.oauth.resource = nativeResource;
    admission.oauth.requiredScopes = [nativeResource + '/tools.list', nativeResource + '/tools.call'];
    Object.assign(admission.gateway, { apiId: 'a1b2c3d4e5', deploymentId: 'abc123',
      domainName: 'a1b2c3d4e5.execute-api.us-east-1.amazonaws.com', resourceUri: nativeResource,
      executeApiEndpointDisabled: false, endpointType: 'REGIONAL', region: 'us-east-1',
      securityPolicy: 'SecurityPolicy_TLS13_1_2_2021_06', endpointAccessMode: 'STRICT', apiStatus: 'AVAILABLE' });
  }
  if (extra.admission) extra.admission(admission);
  const admissionBytes = Buffer.from(JSON.stringify(admission));
  const environment = { RING_MCP_STATE: 'enabled', RING_MCP_ISSUER: issuer, RING_MCP_PUBLIC_CLIENT_ID: clientId,
    RING_MCP_RESOURCE_URI: extra.native ? admission.oauth.resource : resource,
    RING_MCP_REQUIRED_SCOPES: JSON.stringify(extra.native ? admission.oauth.requiredScopes : scopes),
    RING_MCP_MAX_TOKEN_LIFETIME_SECONDS: '300', RING_MCP_MAX_JWKS_AGE_SECONDS: '300',
    RING_MCP_EXPECTED_API_ID: extra.native ? 'a1b2c3d4e5' : 'generated-api', RING_MCP_EXPECTED_STAGE: 'teststage',
    RING_MCP_ADMISSION_SHA256: sha(admissionBytes) };
  const clock = { monotonicNowMs: () => 1000 };
  const bootEpoch = { digest: sha('generated-boot') };
  const generatedSessionReceipt = Object.freeze({ fixture: 'synthetic-consumer-only' });
  const runtime = { status: () => ({ state: extra.notReady ? 'DISABLED' : 'READY' }),
    async issueMcpEntry() { counts.grants++; return { generated: true }; },
    async consumeMcpEntry() { counts.consumes++; return { generated: true }; },
    async close() { counts.closed++; } };
  const actualProfile = createFormalMcpProfile({ runtime, bootEpoch, clock, ports: {
    formalCapabilityPort: { async list(options) { counts.lists++; return { tools: [], ...options }; },
      async execute(input) { counts.executes++; assert.equal(input.capability, 'ring.test'); return { content: [] }; } },
    remoteEntryPort: { async consumeSealedIntent({ intentHandle }) {
      assert.equal(intentHandle, 'server-owned-generated-intent');
      return { productionAdmitted: true, singleUse: true, path: 'remote-encrypted', purpose: 'mcp-entry',
        bootEpoch: bootEpoch.digest, scope: 'mcp', capability: 'ring.test', entryId: 'generated-entry',
        issuedMonotonicMs: 1000, wifiTrust: null, sessionReceipt: generatedSessionReceipt };
    } } } });
  const profile = Object.freeze({ profile: actualProfile.profile, configured: actualProfile.configured,
    get ready() { return actualProfile.ready; }, list: actualProfile.list,
    async call(envelope, context) { counts.dispatchInputs.push(envelope); return actualProfile.call(envelope, context); },
    close: actualProfile.close });
  const assembly = { mode: extra.demo ? 'DEMO' : 'FORMAL', profile, routeSet: createFormalRouteSet(),
    close: async () => profile.close() };
  const http = httpFixture();
  const dependencies = { async readRootLayerFile(path) {
    counts.reads++;
    assert.ok([FORMAL_MCP_ADMISSION_PATH, '/opt/ring-b02/formal-mcp-ports.mjs'].includes(path));
    return path === FORMAL_MCP_ADMISSION_PATH ? admissionBytes : extra.badModule ? Buffer.from('changed') : moduleBytes;
  }, async importer(path) {
    counts.imports++; assert.equal(path, FORMAL_MCP_LAYER_MODULE);
    return { async createRingB02FormalMcpSeam() { counts.factories++; return { assembly,
      formalContextPort: { async resolve(input) { counts.context++; counts.contextInputs.push(input);
        assert.equal(input.actor.subject, 'generated-owner');
        if (extra.contextCheck) await extra.contextCheck(input);
        return { source: extra.localContext ? 'local' : 'remote', serverContext: { intentHandle: 'server-owned-generated-intent' } }; },
        async close() { counts.closed++; } },
      invocationSourcePort: { async verifyInvocation({ event, invocationContext, admissionSha256 }) {
        counts.source++; counts.sourceRequests.push([event, invocationContext]);
        return { source: 'aws-apigateway-rest-lambda', event: extra.spoofSource ? { ...event } : event,
          invocationContext, admissionSha256 };
      }, async close() { counts.closed++; } }, ...(extra.malformedSource ? { invocationSourcePort: {
        verifyInvocation: null, async close() { counts.closed++; } } } : {}),
      ...(extra.malformedContext ? { formalContextPort: { resolve: null, async close() { counts.closed++; } } } : {}) }; } };
  }, requestImpl: http.requestImpl };
  return { environment, dependencies, counts, http, config: parseNonsecretMcpEnvironment(environment) };
}
function jwt(subject = 'generated-owner') {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: jwk.kid, typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ iss: issuer, client_id: clientId, aud: resource, sub: subject,
    scope: scopes.join(' '), token_use: 'access', iat: now, exp: now + 300 })).toString('base64url');
  return header + '.' + payload + '.' + sign('RSA-SHA256', Buffer.from(header + '.' + payload), privateKey).toString('base64url');
}
function event(method = 'tools/list', extra = {}) {
  const params = { _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28',
    'io.modelcontextprotocol/clientInfo': { name: 'generated-test', version: '1' },
    'io.modelcontextprotocol/clientCapabilities': {} },
    ...(method === 'tools/call' ? { name: 'ring.test', arguments: {} } : {}) };
  const body = { jsonrpc: '2.0', id: 1, method, params };
  const headers = { 'content-type': 'application/json', accept: 'application/json, text/event-stream',
    'mcp-protocol-version': '2026-07-28', 'mcp-method': method, authorization: 'Bearer ' + jwt(),
    ...(method === 'tools/call' ? { 'mcp-name': 'ring.test' } : {}), ...extra };
  return { resource: '/mcp', path: '/mcp', httpMethod: 'POST', headers,
    multiValueHeaders: Object.fromEntries(Object.entries(headers).map(([name, value]) => [name, [value]])),
    queryStringParameters: null, multiValueQueryStringParameters: null, pathParameters: null, stageVariables: null,
    requestContext: { apiId: 'generated-api', stage: 'teststage', deploymentId: 'generated-deployment',
      domainName: 'mcp.generated.invalid', protocol: 'HTTP/1.1', extendedRequestId: 'generated-request',
      resourcePath: '/mcp', path: '/teststage/mcp', httpMethod: 'POST' },
    body: JSON.stringify(body), isBase64Encoded: false };
}
const invocation = () => ({ functionVersion: 'generated-version', awsRequestId: 'generated-lambda-request' });
async function composition(fx) {
  const ports = await loadAdmittedMcpProductionPorts({ config: fx.config, clockSeconds: () => now, testDependencies: fx.dependencies });
  return { ports, runtime: createMcpRestComposition({ config: fx.config, ...ports }) };
}
test('disabled production factory never opens or imports layer, fetches JWKS, or opens runtime', async () => {
  const fx = fixture();
  const runtime = await createProductionMcpRuntime({ environment: { RING_MCP_STATE: 'blocked' }, testDependencies: fx.dependencies });
  assert.equal((await runtime.handle({})).statusCode, 503);
  assert.equal(fx.counts.reads + fx.counts.imports + fx.counts.grants + fx.http.effects.calls, 0);
});
test('production fixed-layer admission needs digest, immutable bytes and matching root deployment', async () => {
  const fx = fixture();
  await assert.rejects(loadAdmittedMcpProductionPorts({ config: { ...fx.config, admissionSha256: null }, testDependencies: fx.dependencies }), /mcp_admission_pin_missing/);
  await assert.rejects(loadAdmittedMcpProductionPorts({ config: { ...fx.config, admissionSha256: sha('wrong') }, testDependencies: fx.dependencies }), /mcp_admission_pin_denied/);
  for (const change of [a => { a.gateway.minimumTlsVersion = 'TLSv1.0'; },
    a => { a.gateway.executeApiEndpointDisabled = false; }, a => { a.gateway.deploymentId = ''; },
    a => { a.gateway.resourceUri = 'https://wrong.invalid/mcp'; }]) {
    const altered = fixture({ admission: change });
    await assert.rejects(composition(altered), /mcp_gateway_admission_denied|mcp_production_input_denied/); assert.equal(altered.counts.factories, 0);
  }
  const bad = fixture({ badModule: true }); await assert.rejects(composition(bad), /mcp_layer_pin_denied/);
  assert.equal(bad.counts.imports, 0);
});
test('FORMAL bridge rejects demo assembly and refuses fixture dependencies in production', async () => {
  const fx = fixture({ demo: true }); await assert.rejects(composition(fx), /mcp_formal_assembly_missing/);
  assert.equal(fx.counts.closed, 3);
  const old = process.env.NODE_ENV;
  try { process.env.NODE_ENV = 'production'; await assert.rejects(composition(fixture()), /mcp_test_dependency_denied/); }
  finally { process.env.NODE_ENV = old; }
});
test('root-pinned OAuth contract rejects environment substitution before importing the layer', async () => {
  for (const change of [{ issuer: 'https://cognito-idp.us-east-1.amazonaws.com/other_pool' },
    { clientId: 'other-public-client' }, { resource: 'https://other.generated.invalid/mcp' },
    { requiredScopes: [...scopes].reverse() }, { maximumTokenLifetimeSeconds: 299 },
    { maxJwksAgeSeconds: 299 }]) {
    const fx = fixture();
    await assert.rejects(loadAdmittedMcpProductionPorts({ config: { ...fx.config, ...change },
      clockSeconds: () => now, testDependencies: fx.dependencies }), /mcp_gateway_admission_denied/);
    assert.equal(fx.counts.imports + fx.counts.factories + fx.counts.grants + fx.http.effects.calls, 0);
  }
});
test('returned seam cleanup closes each owned assembly/context/source exactly once on constructor failure', async () => {
  for (const extra of [{ malformedSource: true }, { malformedContext: true },
    { admission: a => { a.oauth.issuer = 'https://cognito.untrusted.invalid/pool'; } }]) {
    const fx = fixture(extra);
    if (extra.admission) fx.config = { ...fx.config, issuer: 'https://cognito.untrusted.invalid/pool' };
    await assert.rejects(composition(fx));
    assert.equal(fx.counts.closed, 3); assert.equal(fx.counts.grants + fx.http.effects.calls, 0);
  }
});
test('gateway normalization ignores forwarded claims only after same-event/context provenance', async () => {
  const fx = fixture(); const { ports, runtime } = await composition(fx);
  assert.equal(fx.http.effects.calls, 0); assert.equal(fx.counts.grants, 0);
  const e = event('tools/list', { 'x-forwarded-proto': 'http', 'x-forwarded-host': 'attacker.invalid',
    'x-forwarded-for': 'generated-untrusted', forwarded: 'proto=http;host=attacker.invalid' });
  const ctx = invocation(); const reply = await runtime.handle(e, ctx);
  assert.equal(reply.statusCode, 200); assert.equal(fx.counts.lists, 1);
  assert.equal(fx.counts.grants, 0); assert.equal(fx.counts.context, 0);
  assert.equal(fx.counts.sourceRequests[0][0], e); assert.equal(fx.counts.sourceRequests[0][1], ctx);
  assert.ok(Object.hasOwn(e.headers, 'forwarded')); assert.ok(Object.hasOwn(e.multiValueHeaders, 'forwarded'));
  await assert.rejects(ports.trustedTransportEvidencePort.resolve({ request: { headers: {} } }), /mcp_gateway_request_denied/);
  await ports.close(); assert.equal(fx.counts.closed, 3);
});
test('gateway forged source and context/deployment/protocol mismatches precede JWT/application', async () => {
  for (const change of [e => { e.requestContext.apiId = 'wrong'; }, e => { e.requestContext.deploymentId = 'wrong'; },
    e => { e.requestContext.domainName = 'attacker.invalid'; }, e => { e.requestContext.protocol = 'TLSv1.2'; },
    e => { delete e.requestContext.extendedRequestId; }]) {
    const fx = fixture(); const { ports, runtime } = await composition(fx); const e = event(); change(e);
    assert.notEqual((await runtime.handle(e, invocation())).statusCode, 200);
    assert.equal(fx.http.effects.calls + fx.counts.lists + fx.counts.grants, 0); await ports.close();
  }
  const fx = fixture({ spoofSource: true }); const { ports, runtime } = await composition(fx);
  assert.notEqual((await runtime.handle(event('tools/list', { 'x-forwarded-proto': 'https' }), invocation())).statusCode, 200);
  assert.equal(fx.http.effects.calls + fx.counts.lists + fx.counts.grants, 0); await ports.close();
});
test('gateway evidence is policy-attested with null negotiated protocol and identity-branded request', async () => {
  const fx = fixture(); const { ports } = await composition(fx); const e = event();
  const prepared = await ports.trustedTransportEvidencePort.prepareEvent({ event: e, invocationContext: invocation() });
  const request = Object.freeze({ headers: Object.freeze({}) });
  ports.trustedTransportEvidencePort.bindRequest({ event: prepared, request });
  const proof = await ports.trustedTransportEvidencePort.resolve({ request });
  assert.equal(proof.negotiatedProtocol, null); assert.equal(proof.minimumTlsVersion, 'TLSv1.2');
  assert.equal(proof.kind, 'apigateway-rest-policy-v1'); assert.equal(Object.hasOwn(proof, 'protocol'), false);
  assert.throws(() => ports.trustedTransportEvidencePort.bindRequest({ event: { ...prepared }, request: {} }));
  await ports.close(); await assert.rejects(ports.trustedTransportEvidencePort.resolve({ request }));
});
test('tools/call dispatches existing formal profile and server-owned remote context once', async () => {
  const fx = fixture(); const { ports, runtime } = await composition(fx);
  const reply = await runtime.handle(event('tools/call'), invocation());
  assert.equal(reply.statusCode, 200); assert.equal(JSON.parse(reply.body).result.resultType, 'complete');
  assert.deepEqual([fx.counts.context, fx.counts.grants, fx.counts.consumes, fx.counts.executes], [1, 1, 1, 1]);
  await ports.close();
});
test('not-ready FORMAL profile or local context cannot fabricate remote admission', async () => {
  for (const extra of [{ notReady: true }, { localContext: true }]) {
    const fx = fixture(extra); const { ports, runtime } = await composition(fx);
    assert.notEqual((await runtime.handle(event('tools/call'), invocation())).statusCode, 200);
    assert.equal(fx.counts.grants + fx.counts.consumes + fx.counts.executes, 0); await ports.close();
  }
});

function contextBindingEvent(era = 'modern', options = {}) {
  const value = event('tools/call');
  const body = JSON.parse(value.body);
  body.id = options.id ?? 'generated-rpc';
  body.params.name = options.name ?? 'ring.test';
  body.params.arguments = options.arguments ?? { nested: { mode: 'allowed' }, items: [1, 2] };
  if (era === 'legacy') {
    delete body.params._meta;
    value.headers['mcp-protocol-version'] = '2025-11-25';
    delete value.headers['mcp-method'];
    delete value.headers['mcp-name'];
  } else value.headers['mcp-name'] = body.params.name;
  if (options.subject) value.headers.authorization = 'Bearer ' + jwt(options.subject);
  value.multiValueHeaders = Object.fromEntries(Object.entries(value.headers).map(([name, item]) => [name, [item]]));
  value.body = JSON.stringify(body);
  return value;
}
const noDispatchEffects = fx => assert.deepEqual(
  [fx.counts.grants, fx.counts.consumes, fx.counts.executes, fx.counts.dispatchInputs.length], [0, 0, 0, 0]);

test('context binding: modern accepted command reaches context and dispatch as one exact object', async () => {
  const fx = fixture(); const { ports, runtime } = await composition(fx);
  assert.equal((await runtime.handle(contextBindingEvent(), invocation())).statusCode, 200);
  const input = fx.counts.contextInputs[0];
  assert.deepEqual(Object.keys(input).sort(), ['actor', 'effectiveEnvelope', 'request', 'validatedWire']);
  assert.equal(input.actor.subject, 'generated-owner');
  assert.equal(input.actor.authority, 'oauth-access-token');
  assert.equal(input.validatedWire.era, 'MODERN_STATELESS');
  assert.deepEqual(input.effectiveEnvelope, { jsonrpc: '2.0', id: 'generated-rpc', method: 'tools/call',
    params: { name: 'ring.test', arguments: { nested: { mode: 'allowed' }, items: [1, 2] } } });
  assert.equal(fx.counts.dispatchInputs[0], input.effectiveEnvelope);
  assert.equal(input.effectiveEnvelope.params.arguments, input.validatedWire.request.params.arguments);
  assert.equal(fx.counts.context, 1);
  assert.deepEqual([fx.counts.grants, fx.counts.consumes, fx.counts.executes], [1, 1, 1]);
  await ports.close();
});

test('context binding: modern and legacy preserve equivalent id capability and arguments', async () => {
  const accepted = [];
  for (const era of ['modern', 'legacy']) {
    const fx = fixture(); const { ports, runtime } = await composition(fx);
    assert.equal((await runtime.handle(contextBindingEvent(era), invocation())).statusCode, 200);
    const input = fx.counts.contextInputs[0];
    assert.equal(fx.counts.dispatchInputs[0], input.effectiveEnvelope);
    assert.equal(Object.hasOwn(input.effectiveEnvelope.params, '_meta'), false);
    if (era === 'legacy') assert.equal(input.effectiveEnvelope, input.validatedWire.request);
    accepted.push(input.effectiveEnvelope);
    await ports.close();
  }
  assert.deepEqual(accepted[0], accepted[1]);
});

test('context binding: context cannot mutate request actor wire or nested dispatch payload', async () => {
  const fx = fixture({ contextCheck(input) {
    for (const value of [input, input.request, input.request.headers, input.actor, input.actor.scopes,
      input.validatedWire, input.validatedWire.request, input.effectiveEnvelope,
      input.effectiveEnvelope.params, input.effectiveEnvelope.params.arguments,
      input.effectiveEnvelope.params.arguments.nested, input.effectiveEnvelope.params.arguments.items]) {
      assert.equal(Object.isFrozen(value), true);
    }
    for (const [object, key, replacement] of [[input, 'request', {}], [input.actor, 'subject', 'other'],
      [input.request.headers, 'authorization', 'Bearer other'], [input.validatedWire, 'era', 'LEGACY_HANDSHAKE'],
      [input.effectiveEnvelope, 'id', 'other'], [input.effectiveEnvelope.params, 'name', 'ring.other'],
      [input.effectiveEnvelope.params.arguments.nested, 'mode', 'other'],
      [input.effectiveEnvelope.params.arguments.items, '0', 99]]) {
      assert.equal(Reflect.set(object, key, replacement), false);
    }
  } });
  const { ports, runtime } = await composition(fx);
  assert.equal((await runtime.handle(contextBindingEvent(), invocation())).statusCode, 200);
  assert.equal(fx.counts.dispatchInputs[0], fx.counts.contextInputs[0].effectiveEnvelope);
  assert.equal(fx.counts.dispatchInputs[0].params.arguments.nested.mode, 'allowed');
  assert.equal(fx.counts.dispatchInputs[0].id, 'generated-rpc');
  await ports.close();
});

test('context binding: context denial precedes remote consumption grants and execution', async () => {
  const fx = fixture({ contextCheck() { throw new TypeError('generated_context_denied'); } });
  const { ports, runtime } = await composition(fx);
  assert.notEqual((await runtime.handle(contextBindingEvent(), invocation())).statusCode, 200);
  assert.equal(fx.counts.context, 1); noDispatchEffects(fx);
  await ports.close(); assert.equal(fx.counts.closed, 3);
});

test('context binding: another verified OAuth actor does not replace current fixture authority', async () => {
  const fx = fixture(); const { ports, runtime } = await composition(fx);
  assert.notEqual((await runtime.handle(contextBindingEvent('modern', { subject: 'other-generated-owner' }), invocation())).statusCode, 200);
  assert.equal(fx.counts.context, 1); noDispatchEffects(fx);
  await ports.close();
});

test('context binding: copied request lacks the server transport brand before context', async () => {
  const fx = fixture(); const { ports, runtime } = await composition(fx);
  assert.equal((await runtime.handle(contextBindingEvent(), invocation())).statusCode, 200);
  const input = fx.counts.contextInputs[0];
  await assert.rejects(ports.formalMcpApplicationPort.handle({ routeId: 'tools/call',
    request: { ...input.request }, actor: input.actor, wire: input.validatedWire,
    envelope: input.effectiveEnvelope }), /mcp_gateway_request_denied/);
  assert.equal(fx.counts.context, 1);
  assert.deepEqual([fx.counts.grants, fx.counts.consumes, fx.counts.executes], [1, 1, 1]);
  await ports.close();
});

test('context binding: substituted capability is visible to the context gate before grant', async () => {
  const fx = fixture({ contextCheck(input) { assert.equal(input.effectiveEnvelope.params.name, 'ring.test'); } });
  const { ports, runtime } = await composition(fx);
  assert.notEqual((await runtime.handle(contextBindingEvent('modern', { name: 'ring.other' }), invocation())).statusCode, 200);
  assert.equal(fx.counts.context, 1); noDispatchEffects(fx); await ports.close();
});

test('context binding: substituted arguments are visible to the context gate before grant', async () => {
  const fx = fixture({ contextCheck(input) {
    assert.deepEqual(input.effectiveEnvelope.params.arguments, { nested: { mode: 'allowed' }, items: [1, 2] });
  } });
  const { ports, runtime } = await composition(fx);
  assert.notEqual((await runtime.handle(contextBindingEvent('modern', { arguments: { nested: { mode: 'other' }, items: [1, 2] } }), invocation())).statusCode, 200);
  assert.equal(fx.counts.context, 1); noDispatchEffects(fx); await ports.close();
});

test('context binding: substituted RPC id is visible to the context gate before grant', async () => {
  const fx = fixture({ contextCheck(input) { assert.equal(input.effectiveEnvelope.id, 'generated-rpc'); } });
  const { ports, runtime } = await composition(fx);
  assert.notEqual((await runtime.handle(contextBindingEvent('legacy', { id: 'other-generated-rpc' }), invocation())).statusCode, 200);
  assert.equal(fx.counts.context, 1); noDispatchEffects(fx); await ports.close();
});

test('context binding: wire or OAuth denial never invokes the context producer', async () => {
  for (const cause of ['wire', 'oauth']) {
    const fx = fixture(); const { ports, runtime } = await composition(fx);
    const input = contextBindingEvent();
    input.headers[cause === 'wire' ? 'mcp-name' : 'authorization'] = cause === 'wire' ? 'ring.other' : 'Bearer bad.invalid.token';
    input.multiValueHeaders = Object.fromEntries(Object.entries(input.headers).map(([name, value]) => [name, [value]]));
    assert.notEqual((await runtime.handle(input, invocation())).statusCode, 200);
    assert.equal(fx.counts.context, 0); noDispatchEffects(fx); await ports.close();
  }
});

test('context binding: non-call and default-disabled routes issue no context or grants', async () => {
  const fx = fixture(); const { ports, runtime } = await composition(fx);
  assert.equal((await runtime.handle(event('tools/list'), invocation())).statusCode, 200);
  assert.equal(fx.counts.context, 0); noDispatchEffects(fx); await ports.close();
  const disabled = fixture();
  const blocked = await createProductionMcpRuntime({ environment: { RING_MCP_STATE: 'blocked' }, testDependencies: disabled.dependencies });
  assert.equal((await blocked.handle({}, invocation())).statusCode, 503);
  assert.equal(disabled.counts.reads + disabled.counts.imports + disabled.counts.context + disabled.counts.grants + disabled.http.effects.calls, 0);
});


test('native Regional admission binds exact host, stage, deployment and TLS evidence', async () => {
  const fx = fixture({ native: true });
  const { ports } = await composition(fx);
  const value = event();
  Object.assign(value.requestContext, { apiId: 'a1b2c3d4e5', deploymentId: 'abc123',
    domainName: 'a1b2c3d4e5.execute-api.us-east-1.amazonaws.com' });
  const prepared = await ports.trustedTransportEvidencePort.prepareEvent({ event: value, invocationContext: invocation() });
  const request = {};
  ports.trustedTransportEvidencePort.bindRequest({ event: prepared, request });
  const proof = await ports.trustedTransportEvidencePort.resolve({ request });
  assert.equal(proof.minimumTlsVersion, 'TLSv1.2');
  assert.equal(proof.negotiatedProtocol, null);
  assert.equal(fx.counts.source, 1);
  for (const [field, bad] of [['apiId', 'otherapi00'], ['stage', 'other'], ['deploymentId', 'other'],
    ['domainName', 'other.execute-api.us-east-1.amazonaws.com']]) {
    const changed = { ...value, requestContext: { ...value.requestContext, [field]: bad } };
    await assert.rejects(ports.trustedTransportEvidencePort.prepareEvent({ event: changed, invocationContext: invocation() }), /mcp_gateway_context_denied/);
  }
  await ports.close();
});

test('native branch denies incomplete, cross-region, nonexact path and weak or pending TLS admission', async () => {
  const mutations = [
    a => { delete a.gateway.region; },
    a => { a.gateway.region = 'us-west-2'; },
    a => { a.gateway.endpointType = 'EDGE'; },
    a => { a.gateway.securityPolicy = 'TLS_1_0'; },
    a => { a.gateway.endpointAccessMode = 'BASIC'; },
    a => { a.gateway.apiStatus = 'UPDATING'; },
    a => { a.gateway.minimumTlsVersion = 'TLSv1.3'; },
    a => { a.gateway.tlsPolicyEvidenceSha256 = ''; },
    a => { a.gateway.deploymentEvidenceSha256 = ''; },
    a => { a.gateway.deploymentId = ''; },
    a => { a.gateway.resourceUri = a.gateway.resourceUri.replace('/teststage/', '/other/'); },
    a => { a.gateway.resourceUri = a.gateway.resourceUri.replace('https:', 'http:'); },
    a => { a.gateway.domainName += '.invalid'; },
    a => { a.gateway.executeApiEndpointDisabled = true; }
  ];
  for (const admission of mutations) {
    const fx = fixture({ native: true, admission });
    await assert.rejects(composition(fx), /mcp_gateway_admission_denied|mcp_production_input_denied/);
    assert.equal(fx.counts.imports, 0);
    assert.equal(fx.counts.factories, 0);
    assert.equal(fx.http.effects.calls, 0);
  }
});
