import https from 'node:https';
import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { assertAssemblyRouteAllowed, dispatchExecutableFormalRequest } from '../../../src/formal-runtime/server-composition.mjs';
import { modernDiscoverResponse, modernDispatchEnvelope, modernListResponse, modernResultResponse,
  LEGACY_MCP_PROTOCOL_VERSION } from '../../../src/formal-runtime/stateless-wire.mjs';

export const FORMAL_MCP_LAYER_MODULE = 'file:///opt/ring-b02/formal-mcp-ports.mjs';
export const FORMAL_MCP_ADMISSION_PATH = '/opt/ring-b02/formal-mcp-admission.json';
const LAYER_PATH = '/opt/ring-b02/formal-mcp-ports.mjs';
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const HASH = /^[a-f0-9]{64}$/u;
const LABEL = /^[A-Za-z0-9._:-]{1,128}$/u;
// API Gateway extendedRequestId is base64-like and normally ends with '=' (e.g. dpa3GFPbLPEFcQw=).
const EXTENDED_REQUEST_ID = /^[A-Za-z0-9._:=+\/-]{1,128}$/u;
const FORWARDED = new Set(['forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-port', 'x-forwarded-proto']);
function deny(code) { throw new TypeError(code); }
function own(value, keys = null) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny('mcp_production_input_denied');
  const fields = Object.getOwnPropertyDescriptors(value);
  const names = Reflect.ownKeys(fields);
  if (names.some(key => typeof key !== 'string' || !Object.hasOwn(fields[key], 'value')) ||
      (keys && (names.length !== keys.length || keys.some(key => !Object.hasOwn(fields, key))))) {
    deny('mcp_production_input_denied');
  }
  return Object.fromEntries(names.map(key => [key, fields[key].value]));
}
function method(port, name) {
  if (!port || types.isProxy(port)) deny('mcp_production_port_missing');
  const field = Object.getOwnPropertyDescriptor(port, name);
  if (!field || !Object.hasOwn(field, 'value') || typeof field.value !== 'function' ||
      types.isProxy(field.value)) deny('mcp_production_port_missing');
  return field.value.bind(port);
}
function seconds(clock) {
  const value = clock();
  if (!Number.isSafeInteger(value) || value < 0) deny('mcp_clock_denied');
  return value;
}
function cognitoIssuer(issuer) {
  if (typeof issuer !== 'string' || !/^https:\/\/cognito-idp\.[a-z]{2}(?:-[a-z]+)+-[0-9]\.amazonaws\.com(?:\.cn)?\/[A-Za-z0-9_-]{1,128}$/u.test(issuer)) {
    deny('cognito_issuer_denied');
  }
  return issuer + '/.well-known/jwks.json';
}

export function createPinnedCognitoJwksLoader({ issuer, maxJwksAgeSeconds,
  clockSeconds = () => Math.floor(Date.now() / 1000), requestImpl = https.request,
  timeoutMs = 3000, maximumBytes = 65536 } = {}) {
  const jwksUri = cognitoIssuer(issuer);
  if (!Number.isSafeInteger(maxJwksAgeSeconds) || maxJwksAgeSeconds < 1 || maxJwksAgeSeconds > 86400 ||
      typeof clockSeconds !== 'function' || typeof requestImpl !== 'function' ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 3000 ||
      !Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > 65536) deny('jwks_loader_config_denied');
  let closed = false;
  let pending = null;
  let cached = null;
  let active = null;
  let version = 0;
  let lastSecond = -1;
  const now = () => {
    const value = seconds(clockSeconds);
    if (value < lastSecond) { cached = null; deny('jwks_clock_regressed'); }
    lastSecond = value;
    return value;
  };
  const fetchSnapshot = () => new Promise((resolve, reject) => {
    let finished = false;
    let request = null;
    let response = null;
    let timer = null;
    const chunks = [];
    let size = 0;
    const finish = (error, result) => {
      if (finished) return;
      finished = true;
      if (timer !== null) clearTimeout(timer);
      active = null;
      if (error) { response?.destroy(); request?.destroy(); reject(new TypeError('jwks_fetch_denied')); }
      else resolve(result);
    };
    active = () => finish(true);
    timer = setTimeout(() => finish(true), timeoutMs);
    try {
      request = requestImpl(jwksUri, { method: 'GET', headers: { accept: 'application/json' },
        agent: false, rejectUnauthorized: true, minVersion: 'TLSv1.2', maxHeaderSize: 16384 }, value => {
        response = value;
        response.on('error', () => finish(true));
        response.on('aborted', () => finish(true));
        const socket = response.socket;
        if (closed || response.statusCode !== 200 || socket?.encrypted !== true || socket?.authorized !== true ||
            typeof socket.getProtocol !== 'function' || !['TLSv1.2', 'TLSv1.3'].includes(socket.getProtocol()) ||
            typeof response.headers?.['content-type'] !== 'string' ||
            !/^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(response.headers['content-type']) ||
            (response.headers['content-encoding'] !== undefined && response.headers['content-encoding'] !== 'identity')) {
          finish(true); return;
        }
        const length = response.headers['content-length'];
        if (length !== undefined && (typeof length !== 'string' || !/^[0-9]+$/u.test(length) ||
            !Number.isSafeInteger(Number(length)) || Number(length) > maximumBytes)) { finish(true); return; }
        response.on('data', chunk => {
          if (finished) return;
          if (!Buffer.isBuffer(chunk) || (size += chunk.length) > maximumBytes) { finish(true); return; }
          chunks.push(chunk);
        });
        response.on('end', () => {
          if (finished) return;
          try {
            if (closed || size === 0 || (length !== undefined && Number(length) !== size)) deny('jwks_body_denied');
            const parsed = own(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))), ['keys']);
            if (!Array.isArray(parsed.keys) || parsed.keys.length < 1 || parsed.keys.length > 16) deny('jwks_keys_denied');
            const keys = parsed.keys.map(key => {
              const item = own(key);
              if (Object.keys(item).some(name => !['kid', 'kty', 'alg', 'use', 'n', 'e', 'key_ops'].includes(name)) ||
                  typeof item.kid !== 'string' || !/^[A-Za-z0-9._~+/=-]{1,128}$/u.test(item.kid) || item.kty !== 'RSA' ||
                  item.alg !== 'RS256' || item.use !== 'sig' || typeof item.n !== 'string' ||
                  item.n.length > 1366 || !/^[A-Za-z0-9_-]+$/u.test(item.n) || typeof item.e !== 'string' ||
                  !/^[A-Za-z0-9_-]{1,6}$/u.test(item.e) || (item.key_ops !== undefined &&
                    (!Array.isArray(item.key_ops) || item.key_ops.length !== 1 || item.key_ops[0] !== 'verify'))) deny('jwks_keys_denied');
              return Object.freeze({ ...item, ...(item.key_ops ? { key_ops: Object.freeze([...item.key_ops]) } : {}) });
            });
            if (new Set(keys.map(key => key.kid)).size !== keys.length) deny('jwks_keys_denied');
            const fetchedAtSeconds = now();
            const cacheHeader = response.headers['cache-control'];
            const match = typeof cacheHeader === 'string' ? /(?:^|,)\s*max-age=([0-9]+)(?:\s*,|\s*$)/u.exec(cacheHeader) : null;
            const ttl = Math.min(maxJwksAgeSeconds, 300, match ? Math.max(1, Number(match[1])) : 60);
            const result = Object.freeze({ jwksUri, snapshotVersion: ++version, fetchedAtSeconds,
              expiresAtSeconds: fetchedAtSeconds + ttl, keys: Object.freeze(keys) });
            if (!Number.isSafeInteger(result.snapshotVersion) || !Number.isSafeInteger(result.expiresAtSeconds)) deny('jwks_version_denied');
            cached = typeof cacheHeader === 'string' && /(?:^|,)\s*(?:no-store|no-cache)(?:\s*,|\s*$)/u.test(cacheHeader) ? null : result;
            finish(false, result);
          } catch { finish(true); }
        });
      });
      request.on('error', () => finish(true));
      if (finished) request.destroy(); else request.end();
    } catch { finish(true); }
  });
  const loadPinnedJwks = async input => {
    const supplied = own(input, ['jwksUri']);
    if (closed || supplied.jwksUri !== jwksUri) deny('jwks_uri_denied');
    const current = now();
    if (cached && current < cached.expiresAtSeconds) return cached;
    if (pending === null) {
      pending = fetchSnapshot();
      pending.finally(() => { pending = null; }).catch(() => {});
    }
    return pending;
  };
  return Object.freeze({ loadPinnedJwks, async close() {
    closed = true; cached = null; active?.();
    if (pending !== null) await pending.catch(() => {});
    return Object.freeze({ closed: true, inFlight: 0 });
  } });
}

export async function readRootLayerFile(name) {
  for (const directory of ['/opt', '/opt/ring-b02']) {
    const entry = await fs.lstat(directory);
    if (!entry.isDirectory() || entry.isSymbolicLink() || entry.uid !== 0 || (entry.mode & 0o022)) deny('mcp_layer_root_denied');
  }
  const handle = await fs.open(name, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.uid !== 0 || (before.mode & 0o022) || before.size > 1_048_576) deny('mcp_layer_file_denied');
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
        before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs || bytes.length !== after.size) deny('mcp_layer_file_drift');
    return bytes;
  } finally { await handle.close(); }
}
// Pinned approval files live next to the admission file in the root-owned layer directory.
export const LAYER_DIRECTORY = FORMAL_MCP_ADMISSION_PATH.slice(0, FORMAL_MCP_ADMISSION_PATH.lastIndexOf('/'));
export function layerFilePath(name) {
  if (typeof name !== 'string' || !/^[a-z0-9][a-z0-9.-]{0,62}\.json$/u.test(name) || name.includes('..')) deny('mcp_layer_name_denied');
  return LAYER_DIRECTORY + '/' + name;
}
export async function loadPinnedLayerJson(path, sha256, { readFile = readRootLayerFile } = {}) {
  if (typeof path !== 'string' || path !== layerFilePath(path.slice(LAYER_DIRECTORY.length + 1)) || typeof readFile !== 'function') deny('mcp_layer_name_denied');
  if (typeof sha256 !== 'string' || !HASH.test(sha256)) deny('mcp_layer_pin_missing');
  const bytes = await readFile(path);
  if (!Buffer.isBuffer(bytes) || digest(bytes) !== sha256) deny('mcp_layer_pin_denied');
  let value;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { deny('mcp_layer_json_denied'); }
  return Object.freeze({ bytes, value });
}
export function admittedGateway(record, config) {
  const input = own(record, ['schema', 'decision', 'rootDecisionSha256', 'layerModuleSha256', 'oauth', 'gateway']);
  if (input.schema !== 'ring-mcp-gateway-admission-v1' || input.decision !== 'ADMITTED_GATEWAY_DEPLOYMENT' ||
      !HASH.test(input.rootDecisionSha256) || !HASH.test(input.layerModuleSha256)) deny('mcp_gateway_admission_denied');
  const oauth = own(input.oauth, ['issuer', 'clientId', 'resource', 'requiredScopes',
    'maximumTokenLifetimeSeconds', 'maxJwksAgeSeconds']);
  if (oauth.issuer !== config.issuer || oauth.clientId !== config.clientId || oauth.resource !== config.resource ||
      !Array.isArray(oauth.requiredScopes) || oauth.requiredScopes.length !== config.requiredScopes.length ||
      oauth.requiredScopes.some((scope, index) => scope !== config.requiredScopes[index]) ||
      oauth.maximumTokenLifetimeSeconds !== config.maximumTokenLifetimeSeconds ||
      oauth.maxJwksAgeSeconds !== config.maxJwksAgeSeconds) deny('mcp_gateway_admission_denied');
  const gatewayFields = ['apiId', 'stage', 'domainName', 'deploymentId', 'resourceUri',
    'minimumTlsVersion', 'tlsPolicyEvidenceSha256', 'deploymentEvidenceSha256', 'executeApiEndpointDisabled'];
  const candidate = own(input.gateway);
  const native = candidate.executeApiEndpointDisabled === false;
  const gateway = own(candidate, native ? [...gatewayFields, 'endpointType', 'region', 'securityPolicy',
    'endpointAccessMode', 'apiStatus'] : gatewayFields);
  if (gateway.apiId !== config.expectedGatewayContext.apiId || gateway.stage !== config.expectedGatewayContext.stage ||
      gateway.resourceUri !== config.resource || new URL(config.resource).hostname !== gateway.domainName ||
      !LABEL.test(gateway.deploymentId) || !['TLSv1.2', 'TLSv1.3'].includes(gateway.minimumTlsVersion) ||
      !HASH.test(gateway.tlsPolicyEvidenceSha256) || !HASH.test(gateway.deploymentEvidenceSha256) ||
      (!native && gateway.executeApiEndpointDisabled !== true)) deny('mcp_gateway_admission_denied');
  if (native) {
    const expectedHost = `${gateway.apiId}.execute-api.${gateway.region}.amazonaws.com`;
    if (gateway.endpointType !== 'REGIONAL' || !/^[a-z0-9]{10}$/u.test(gateway.apiId) ||
        typeof gateway.region !== 'string' || !/^[a-z]{2}(?:-[a-z]+)+-[0-9]$/u.test(gateway.region) ||
        gateway.region.startsWith('cn-') || !/^[A-Za-z0-9_-]{1,32}$/u.test(gateway.stage) ||
        !/^[a-z0-9]{1,128}$/u.test(gateway.deploymentId) || gateway.domainName !== expectedHost ||
        gateway.resourceUri !== `https://${expectedHost}/${gateway.stage}/mcp` ||
        gateway.securityPolicy !== 'SecurityPolicy_TLS13_1_2_2021_06' ||
        gateway.minimumTlsVersion !== 'TLSv1.2' || gateway.endpointAccessMode !== 'STRICT' ||
        gateway.apiStatus !== 'AVAILABLE') deny('mcp_gateway_admission_denied');
  }
  return Object.freeze({ ...input, oauth: Object.freeze({ ...oauth, requiredScopes: Object.freeze([...oauth.requiredScopes]) }),
    gateway: Object.freeze(gateway) });
}
function cleanHeaders(headers) {
  return Object.fromEntries(Object.entries(own(headers)).filter(([name]) => !FORWARDED.has(name.toLowerCase())));
}
export function createGatewayTransportPort({ admission, admissionSha256, invocationSourcePort }) {
  const verifyInvocation = method(invocationSourcePort, 'verifyInvocation');
  const closeSource = method(invocationSourcePort, 'close');
  const prepared = new WeakMap();
  const requests = new WeakMap();
  let closed = false;
  return Object.freeze({ productionAdmitted: true, transportEvidenceKind: 'apigateway-rest-policy-v1',
    async prepareEvent({ event, invocationContext }) {
      if (closed) deny('mcp_gateway_closed');
      const e = own(event); const c = own(e.requestContext);
      if (!invocationContext || typeof invocationContext !== 'object' || Array.isArray(invocationContext) ||
          types.isProxy(invocationContext)) deny('mcp_gateway_invocation_denied');
      const g = admission.gateway;
      // REST API Lambda proxy events (AWS_PROXY) carry no requestContext.deploymentId (verified against a real event:
      // keys are accountId, apiId, domainName, domainPrefix, extendedRequestId, httpMethod, identity, path, protocol,
      // requestId, requestTime, requestTimeEpoch, resourceId, resourcePath, stage). A present-but-different value still denies;
      // an absent value is allowed, and deployment drift is checked by the root operator against the admission file.
      if (c.apiId !== g.apiId || c.stage !== g.stage || (c.deploymentId !== undefined && c.deploymentId !== g.deploymentId) ||
          c.domainName !== g.domainName || c.protocol !== 'HTTP/1.1' ||
          !EXTENDED_REQUEST_ID.test(c.extendedRequestId)) deny('mcp_gateway_context_denied');
      // Compensating bindings for the optional deploymentId: the event's account must equal the invoked function's account and
      // the default-endpoint domainPrefix must equal the apiId (both checked only when present; nothing is hard-coded).
      const invoked = typeof invocationContext.invokedFunctionArn === 'string' ? invocationContext.invokedFunctionArn.split(':') : null;
      const account = invoked !== null && invoked.length >= 7 ? invoked[4] : undefined;
      if ((account !== undefined && (!/^[0-9]{12}$/u.test(account) || (c.accountId !== undefined && c.accountId !== account))) ||
          (c.domainPrefix !== undefined && c.domainPrefix !== c.apiId)) deny('mcp_gateway_context_denied');
      const receipt = own(await verifyInvocation({ event, invocationContext, admissionSha256 }),
        ['source', 'event', 'invocationContext', 'admissionSha256']);
      if (receipt.source !== 'aws-apigateway-rest-lambda' || receipt.event !== event ||
          receipt.invocationContext !== invocationContext || receipt.admissionSha256 !== admissionSha256) {
        deny('mcp_gateway_source_denied');
      }
      const normalized = Object.freeze({ ...e, headers: Object.freeze(cleanHeaders(e.headers)),
        multiValueHeaders: Object.freeze(cleanHeaders(e.multiValueHeaders)) });
      prepared.set(normalized, Object.freeze({ evidenceId: 'gateway.' + digest(c.extendedRequestId).slice(0, 32),
        rootDecisionSha256: admission.rootDecisionSha256, deploymentEvidenceSha256: g.deploymentEvidenceSha256,
        minimumTlsVersion: g.minimumTlsVersion }));
      return normalized;
    },
    bindRequest({ event, request }) {
      const proof = prepared.get(event);
      if (closed || !proof || !request || prepared.delete(event) !== true) deny('mcp_gateway_request_denied');
      requests.set(request, proof);
    },
    async resolve({ request }) {
      const proof = requests.get(request);
      if (closed || !proof) deny('mcp_gateway_request_denied');
      return Object.freeze({ productionAdmitted: true, encrypted: true, kind: 'apigateway-rest-policy-v1',
        negotiatedProtocol: null, ...proof });
    },
    assertRequest(request) { if (closed || !requests.has(request)) deny('mcp_gateway_request_denied'); },
    async close() { if (!closed) { closed = true; await closeSource(); } return Object.freeze({ closed: true }); }
  });
}
function createFormalApplicationPort({ assembly, formalContextPort, transport }) {
  if (!assembly || assembly.mode !== 'FORMAL' || !assembly.profile || assembly.profile.profile !== 'FORMAL' ||
      !assembly.routeSet || assembly.routeSet.timers?.length !== 0) deny('mcp_formal_assembly_missing');
  const profile = assembly.profile;
  method(profile, 'list'); method(profile, 'call'); const closeAssembly = method(assembly, 'close');
  const resolveContext = method(formalContextPort, 'resolve'); const closeContext = method(formalContextPort, 'close');
  let closed = false;
  return Object.freeze({ productionAdmitted: true, async handle(input) {
    if (closed) deny('mcp_formal_closed');
    transport.assertRequest(input.request);
    assertAssemblyRouteAllowed(assembly, input.routeId);
    if (profile.ready !== true) deny('mcp_formal_not_ready');
    if (input.wire.era === 'MODERN_STATELESS' && input.routeId === 'server/discover') return modernDiscoverResponse(input.envelope.id);
    if (input.routeId === 'initialize') return Object.freeze({ jsonrpc: '2.0', id: input.envelope.id,
      result: { protocolVersion: LEGACY_MCP_PROTOCOL_VERSION, capabilities: { tools: {} },
        serverInfo: { name: 'ring-home-mcp-hub', version: '0.1.0' },
        instructions: 'Formal MCP admission is required for every tools/call.' } });
    if (input.routeId === 'tools/list') {
      const options = Object.hasOwn(input.envelope.params, 'cursor') ? { cursor: input.envelope.params.cursor } : {};
      const result = await profile.list(Object.freeze(options));
      return input.wire.era === 'MODERN_STATELESS' ? modernListResponse({ id: input.envelope.id, result })
        : Object.freeze({ jsonrpc: '2.0', id: input.envelope.id, result });
    }
    if (input.routeId !== 'tools/call') deny('mcp_formal_route_denied');
    const validatedWire = input.wire;
    const effectiveEnvelope = validatedWire.era === 'MODERN_STATELESS'
      ? modernDispatchEnvelope(validatedWire) : validatedWire.request;
    const contextInput = Object.freeze({ request: input.request, actor: input.actor,
      validatedWire, effectiveEnvelope });
    const context = own(await resolveContext(contextInput), ['source', 'serverContext']);
    if (context.source !== 'remote') deny('mcp_formal_context_denied');
    const result = await dispatchExecutableFormalRequest({ profile, envelope: effectiveEnvelope,
      source: context.source, serverContext: context.serverContext });
    return validatedWire.era === 'MODERN_STATELESS'
      ? modernResultResponse({ id: effectiveEnvelope.id, result: result.result }) : result;
  }, async close() { if (!closed) { closed = true; try { await closeAssembly(); } finally { await closeContext(); } } return { closed: true }; } });
}

export async function loadAdmittedMcpProductionPorts({ config, clockSeconds = () => Math.floor(Date.now() / 1000),
  testDependencies = null } = {}) {
  if (!config || config.state !== 'enabled' || typeof config.admissionSha256 !== 'string' || !HASH.test(config.admissionSha256)) {
    deny('mcp_admission_pin_missing');
  }
  if (testDependencies !== null && process.env.NODE_ENV !== 'test') deny('mcp_test_dependency_denied');
  const readFile = testDependencies?.readRootLayerFile ?? readRootLayerFile;
  const importer = testDependencies?.importer ?? (specifier => import(specifier));
  const admissionBytes = await readFile(FORMAL_MCP_ADMISSION_PATH);
  if (!Buffer.isBuffer(admissionBytes) || digest(admissionBytes) !== config.admissionSha256) deny('mcp_admission_pin_denied');
  const admission = admittedGateway(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(admissionBytes)), config);
  const moduleBytes = await readFile(LAYER_PATH);
  if (!Buffer.isBuffer(moduleBytes) || digest(moduleBytes) !== admission.layerModuleSha256) deny('mcp_layer_pin_denied');
  const module = await importer(FORMAL_MCP_LAYER_MODULE);
  const createSeam = method(module, 'createRingB02FormalMcpSeam');
  const seam = own(await createSeam(), ['assembly', 'formalContextPort', 'invocationSourcePort']);
  let transport; let application; let jwks;
  try {
    transport = createGatewayTransportPort({ admission, admissionSha256: config.admissionSha256,
      invocationSourcePort: seam.invocationSourcePort });
    application = createFormalApplicationPort({ assembly: seam.assembly, formalContextPort: seam.formalContextPort, transport });
    jwks = createPinnedCognitoJwksLoader({ issuer: config.issuer, maxJwksAgeSeconds: config.maxJwksAgeSeconds,
      clockSeconds, ...(testDependencies?.requestImpl ? { requestImpl: testDependencies.requestImpl } : {}) });
  } catch (error) {
    if (jwks) await jwks.close();
    for (const owner of [seam.assembly, seam.formalContextPort, seam.invocationSourcePort]) {
      try { await method(owner, 'close')(); } catch {}
    }
    throw error;
  }
  let closed = false;
  return Object.freeze({ loadPinnedJwks: jwks.loadPinnedJwks, clockSeconds,
    trustedTransportEvidencePort: transport, formalMcpApplicationPort: application,
    async close() {
      if (closed) return Object.freeze({ closed: true, inFlight: 0 });
      closed = true;
      try { await jwks.close(); } finally { try { await application.close(); } finally { await transport.close(); } }
      return Object.freeze({ closed: true, inFlight: 0 });
    }
  });
}
