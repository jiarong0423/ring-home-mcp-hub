import { types } from 'node:util';
import { createFormalRequestAuthorizationPolicy } from '../../../src/formal-runtime/request-authorization-policy.mjs';
import { createCognitoResourceBoundAccessTokenVerifier } from '../../../src/local_ring/components/oidc-jwt-verifier.mjs';
import { validateFormalMcpWireRequest, formalWireErrorResponse } from '../../../src/formal-runtime/stateless-wire.mjs';
import { RING_ACCESS_TOKEN_PATTERN } from './ring-token-client.mjs';
import { loadAdmittedMcpProductionPorts, layerFilePath, loadPinnedLayerJson } from './mcp-production-ports.mjs';

const ENV_KEYS = Object.freeze(['RING_MCP_STATE', 'RING_MCP_ISSUER', 'RING_MCP_PUBLIC_CLIENT_ID',
  'RING_MCP_RESOURCE_URI', 'RING_MCP_REQUIRED_SCOPES', 'RING_MCP_MAX_TOKEN_LIFETIME_SECONDS',
  'RING_MCP_MAX_JWKS_AGE_SECONDS', 'RING_MCP_EXPECTED_API_ID', 'RING_MCP_EXPECTED_STAGE', 'RING_MCP_ADMISSION_SHA256']);
const EVENT_KEYS = Object.freeze(['resource', 'path', 'httpMethod', 'headers', 'multiValueHeaders',
  'queryStringParameters', 'multiValueQueryStringParameters', 'pathParameters', 'stageVariables',
  'requestContext', 'body', 'isBase64Encoded']);
const FORWARDED = new Set(['forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-port', 'x-forwarded-proto']);
const HEADER_NAME = /^[a-z0-9!#$%&'*+.^_`|~-]+$/u;
export const MAC_ENROLLMENT_APPROVAL_FILE = 'mac-enrollment-approval-v1.json';
const utf8 = new TextDecoder('utf-8', { fatal: true });

function deny(code = 'mcp_rest_denied') { throw new TypeError(code); }
function own(value, keys = null) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Reflect.ownKeys(descriptors);
  if (names.some(name => typeof name !== 'string' || !Object.hasOwn(descriptors[name], 'value')) ||
      (keys && (names.length !== keys.length || keys.some(key => !Object.hasOwn(descriptors, key))))) deny();
  return Object.fromEntries(names.map(name => [name, descriptors[name].value]));
}
function https(value) {
  if (typeof value !== 'string' || !value.length || value.length > 1024 || /[\u0000-\u0020\u007f]/u.test(value)) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.username === '' && url.password === '' && url.hash === '' &&
      url.search === '' && url.toString() === value;
  } catch { return false; }
}
function text(value, pattern, maximum = 128) {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum && pattern.test(value);
}
function numberText(value, maximum) {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/u.test(value)) deny('mcp_config_denied');
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number > maximum) deny('mcp_config_denied');
  return number;
}
export function parseNonsecretMcpEnvironment(environment) {
  if (!environment || typeof environment !== 'object' || types.isProxy(environment)) deny('mcp_config_denied');
  const state = environment.RING_MCP_STATE;
  if (state === undefined || state === 'blocked') return Object.freeze({ state: 'blocked' });
  if (state !== 'enabled') deny('mcp_config_denied');
  const selected = Object.fromEntries(ENV_KEYS.map(key => [key, environment[key]]));
  if (!https(selected.RING_MCP_ISSUER) || !https(selected.RING_MCP_RESOURCE_URI) ||
      !selected.RING_MCP_RESOURCE_URI.endsWith('/mcp') ||
      !text(selected.RING_MCP_PUBLIC_CLIENT_ID, /^[A-Za-z0-9_-]+$/u, 256) ||
      !text(selected.RING_MCP_EXPECTED_API_ID, /^[A-Za-z0-9_-]+$/u) ||
      !text(selected.RING_MCP_EXPECTED_STAGE, /^[A-Za-z0-9_-]+$/u)) deny('mcp_config_denied');
  let scopes;
  try { scopes = JSON.parse(selected.RING_MCP_REQUIRED_SCOPES); } catch { deny('mcp_config_denied'); }
  const expected = [selected.RING_MCP_RESOURCE_URI + '/tools.list', selected.RING_MCP_RESOURCE_URI + '/tools.call'];
  if (!Array.isArray(scopes) || scopes.length !== 2 || scopes.some(scope =>
    typeof scope !== 'string' || scope.length > 128 || !expected.includes(scope)) ||
    new Set(scopes).size !== 2) deny('mcp_config_denied');
  const maximumTokenLifetimeSeconds = numberText(selected.RING_MCP_MAX_TOKEN_LIFETIME_SECONDS, 300);
  if (maximumTokenLifetimeSeconds !== 300) deny('mcp_config_denied');
  return Object.freeze({ state, issuer: selected.RING_MCP_ISSUER,
    clientId: selected.RING_MCP_PUBLIC_CLIENT_ID, resource: selected.RING_MCP_RESOURCE_URI,
    requiredScopes: Object.freeze([...scopes]), maximumTokenLifetimeSeconds,
    maxJwksAgeSeconds: numberText(selected.RING_MCP_MAX_JWKS_AGE_SECONDS, 86400),
    expectedGatewayContext: Object.freeze({ apiId: selected.RING_MCP_EXPECTED_API_ID, stage: selected.RING_MCP_EXPECTED_STAGE }),
    metadataUri: selected.RING_MCP_RESOURCE_URI.slice(0, -4) + '/.well-known/oauth-protected-resource',
    admissionSha256: selected.RING_MCP_ADMISSION_SHA256 ?? null });
}
function headerMap(value, multi) {
  const data = own(value);
  if (Object.keys(data).length > 64) deny();
  const result = Object.create(null);
  let bytes = 0;
  for (const [key, untrusted] of Object.entries(data)) {
    const name = key.toLowerCase();
    if (!HEADER_NAME.test(name) || Object.hasOwn(result, name)) deny();
    let item = untrusted;
    if (multi) {
      if (!Array.isArray(item) || types.isProxy(item) || Object.getPrototypeOf(item) !== Array.prototype) deny();
      const descriptors = Object.getOwnPropertyDescriptors(item);
      if (Reflect.ownKeys(descriptors).length !== 2 || !Object.hasOwn(descriptors, '0') ||
          !Object.hasOwn(descriptors['0'], 'value') || descriptors.length.value !== 1) deny();
      item = descriptors['0'].value;
    }
    if (typeof item !== 'string' || /[\u0000-\u001f\u007f]/u.test(item) || Buffer.byteLength(item) > 4096) deny();
    bytes += Buffer.byteLength(name) + Buffer.byteLength(item);
    if (bytes > 16384) deny();
    result[name] = item;
  }
  return result;
}
export function parseRestV1McpEvent(event, expectedGatewayContext) {
  const expected = own(expectedGatewayContext, ['apiId', 'stage']);
  const input = own(event, EVENT_KEYS);
  const context = own(input.requestContext);
  if (Object.hasOwn(context, 'http') || context.apiId !== expected.apiId || context.stage !== expected.stage ||
      context.httpMethod !== input.httpMethod || context.resourcePath !== input.path || input.resource !== input.path ||
      (Object.hasOwn(context, 'path') && context.path !== input.path &&
        context.path !== '/' + expected.stage + input.path)) deny();
  const route = input.httpMethod === 'POST' && input.path === '/mcp' ? 'mcp'
    : input.httpMethod === 'POST' && input.path === '/mac/commands/fetch' ? 'mac-fetch'
    : input.httpMethod === 'POST' && input.path === '/mac/commands/receipt' ? 'mac-receipt'
    : input.httpMethod === 'POST' && input.path === '/mac/enroll' ? 'mac-enroll'
    : input.httpMethod === 'POST' && input.path === '/owner/bootstrap' ? 'owner-bootstrap'
    : input.httpMethod === 'GET' && input.path === '/.well-known/oauth-protected-resource' ? 'metadata' : null;
  if (route === null || [input.queryStringParameters, input.multiValueQueryStringParameters,
    input.pathParameters, input.stageVariables].some(value => value !== null) ||
    typeof input.isBase64Encoded !== 'boolean') deny();
  const single = headerMap(input.headers, false);
  const multi = headerMap(input.multiValueHeaders, true);
  if (Object.keys(single).length !== Object.keys(multi).length ||
      Object.keys(single).some(name => single[name] !== multi[name])) deny();
  const request = Object.freeze({ headers: Object.freeze({ ...multi }) });
  if (route === 'metadata') {
    if (input.body !== null || input.isBase64Encoded !== false) deny();
    return Object.freeze({ route, request, envelope: null });
  }
  if (route === 'mac-enroll' && input.body === null && input.isBase64Encoded === false) {
    // Enrollment takes no request data at all: the approval comes from the pinned layer file, never from the caller.
    return Object.freeze({ route, request, envelope: Object.freeze({}) });
  }
  if (!['application/json', 'application/json; charset=utf-8'].includes(multi['content-type']?.toLowerCase()) ||
      typeof input.body !== 'string') deny();
  let raw;
  if (input.isBase64Encoded) {
    if (input.body.length > 87384 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(input.body)) deny();
    raw = Buffer.from(input.body, 'base64');
    if (raw.toString('base64') !== input.body) deny();
  } else {
    if (Buffer.byteLength(input.body) > 65536 || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(input.body)) deny();
    raw = Buffer.from(input.body, 'utf8');
  }
  if (!raw.length || raw.length > 65536) deny();
  let envelope;
  try { envelope = JSON.parse(utf8.decode(raw)); } catch { deny(); }
  if (route === 'owner-bootstrap') {
    // Exactly {"ringAccessToken": <string<=8192>}; the token is never interpreted here, only shape-checked.
    const data = own(envelope, ['ringAccessToken']);
    if (typeof data.ringAccessToken !== 'string' || !RING_ACCESS_TOKEN_PATTERN.test(data.ringAccessToken)) deny();
  }
  return Object.freeze({ route, request, envelope });
}
function response(statusCode, value, extra = {}) {
  const body = JSON.stringify(value);
  if (typeof body !== 'string' || Buffer.byteLength(body) > 65536) deny('mcp_response_denied');
  return Object.freeze({ statusCode, headers: Object.freeze({ 'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store', 'referrer-policy': 'no-referrer', 'x-content-type-options': 'nosniff', ...extra }), body });
}
function blocked() { return response(503, { status: 'not_configured' }); }
function port(value, method) {
  if (!value || typeof value !== 'object' || types.isProxy(value) || value.productionAdmitted !== true) deny('mcp_ports_missing');
  const descriptor = Object.getOwnPropertyDescriptor(value, method);
  if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function' ||
      types.isProxy(descriptor.value)) deny('mcp_ports_missing');
}
export function createMcpRestComposition({ config, loadPinnedJwks, clockSeconds,
  trustedTransportEvidencePort, formalMcpApplicationPort, macCommandService = null, macEnrollmentService = null, ownerBootstrapService = null } = {}) {
  if (!config || config.state === 'blocked') return Object.freeze({ handle: async () => blocked() });
  if (config.state !== 'enabled' || typeof loadPinnedJwks !== 'function' || typeof clockSeconds !== 'function') deny('mcp_ports_missing');
  port(trustedTransportEvidencePort, 'resolve');
  port(formalMcpApplicationPort, 'handle');
  const verifier = createCognitoResourceBoundAccessTokenVerifier({ issuer: config.issuer, clientId: config.clientId,
    resource: config.resource, requiredScopes: config.requiredScopes,
    jwksUri: config.issuer + '/.well-known/jwks.json', maxJwksAgeSeconds: config.maxJwksAgeSeconds,
    maximumTokenLifetimeSeconds: config.maximumTokenLifetimeSeconds, loadPinnedJwks, clock: clockSeconds });
  const policy = createFormalRequestAuthorizationPolicy({ accessTokenVerifier: verifier,
    trustedTransportEvidencePort, resource: config.resource, authorizationServer: config.issuer, scopes: config.requiredScopes });
  return Object.freeze({ async handle(event, invocationContext) {
    let parsed;
    let wire;
    try {
      const admittedEvent = typeof trustedTransportEvidencePort.prepareEvent === 'function'
        ? await trustedTransportEvidencePort.prepareEvent({ event, invocationContext }) : event;
      parsed = parseRestV1McpEvent(admittedEvent, config.expectedGatewayContext);
      if (typeof trustedTransportEvidencePort.bindRequest === 'function') {
        trustedTransportEvidencePort.bindRequest({ event: admittedEvent, request: parsed.request });
      }
      if (parsed.route === 'metadata') return response(200, await policy.protectedResourceMetadata({ request: parsed.request }));
      if (parsed.route === 'mac-fetch' || parsed.route === 'mac-receipt') {
        // Both outbound worker operations use the same request-bound OAuth and gateway proof.
        const authorization = await policy.authorize({ request: parsed.request });
        if (!macCommandService) return blocked();
        if (parsed.route === 'mac-fetch') {
          own(parsed.envelope, []);
          return response(200, await macCommandService.fetch({ request: parsed.request, actor: authorization.actor }));
        }
        return response(200, await macCommandService.receipt({ request: parsed.request,
          actor: authorization.actor, receipt: parsed.envelope }));
      }
      if (parsed.route === 'mac-enroll') {
        // Same bearer + gateway-evidence policy as /mac/commands/fetch; the body carries nothing.
        const authorization = await policy.authorize({ request: parsed.request });
        if (!macEnrollmentService) return blocked();
        own(parsed.envelope, []);
        return response(200, await macEnrollmentService.enroll({ request: parsed.request, actor: authorization.actor }));
      }
      if (parsed.route === 'owner-bootstrap') {
        // Same bearer + gateway-evidence policy as /mac/enroll. Every post-authorization failure (service absent aside) is the same
        // generic denial: nothing reveals whether the Ring account matched, the owner exists, a latch/marker/lockout was hit, etc.
        const authorization = await policy.authorize({ request: parsed.request });
        if (!ownerBootstrapService) return blocked();
        let result = null;
        try {
          result = await ownerBootstrapService.ensureWithRingToken({ request: parsed.request, actor: authorization.actor,
            ringAccessToken: parsed.envelope.ringAccessToken });
        } catch { result = null; }
        // The same pinned approval file decides bootstrap (no owner yet) or renewal (owner exists); see cloud-owner-bootstrap.mjs.
        if (result?.bootstrapped === true) return response(200, { status: 'owner_bootstrapped' });
        if (result?.renewed === true) return response(200, { status: 'owner_renewed' });
        deny('owner_bootstrap_denied');
      }
      try { wire = validateFormalMcpWireRequest({ headers: parsed.request.headers, envelope: parsed.envelope }); }
      catch (error) {
        const body = formalWireErrorResponse(error, parsed.envelope?.id ?? null);
        if (body !== null) return response(error.status, body);
        throw error;
      }
      const authorization = await policy.authorize({ request: parsed.request, routeId: wire.routeId });
      const result = await formalMcpApplicationPort.handle(Object.freeze({ routeId: wire.routeId,
        envelope: parsed.envelope, wire, request: parsed.request,
        actor: authorization.actor, transport: authorization.transport }));
      const data = own(result);
      if (data.jsonrpc !== '2.0' || data.id !== parsed.envelope.id ||
          !(Object.hasOwn(data, 'result') || Object.hasOwn(data, 'error'))) deny('mcp_response_denied');
      return response(200, data);
    } catch (error) {
      const status = [400, 401, 403, 406, 503].includes(error?.status) ? error.status
        : error instanceof TypeError ? 400 : 503;
      const safeCode = typeof error?.code === 'string' && /^B02_FORMAL_[A-Z_]+$/u.test(error.code)
        ? error.code : status === 400 ? 'mcp_rest_denied' : 'unavailable';
      const challenge = status === 401 ? { 'www-authenticate':
        'Bearer resource_metadata="' + config.metadataUri + '"' } : {};
      return response(status, { error: safeCode }, challenge);
    }
  } });
}
export function createDisabledProductionMcpRuntime() {
  return createMcpRestComposition({ config: parseNonsecretMcpEnvironment(process.env) });
}
export async function createProductionMcpRuntime({ environment = process.env, testDependencies = null } = {}) {
  const config = parseNonsecretMcpEnvironment(environment);
  if (config.state === 'blocked') return createMcpRestComposition({ config });
  const ports = await loadAdmittedMcpProductionPorts({ config, testDependencies });
  let commandRuntime;
  let enrollmentRuntime;
  let ownerBootstrapRuntime;
  try {
    if (!testDependencies) {
      const { createRingCloudCommandService } = await import('./b02-layer-runtime.mjs');
      commandRuntime = await createRingCloudCommandService({ environment });
      if (environment.RING_MAC_ENROLLMENT_STATE === 'enabled') {
        // Enabled only with a pinned approval hash; the installer re-checks the hash and the live owner association.
        const approvalSha256 = environment.RING_MAC_ENROLLMENT_APPROVAL_SHA256;
        if (!/^[a-f0-9]{64}$/u.test(approvalSha256 ?? '')) deny('mac_enrollment_not_configured');
        const { createRingCloudMacEnrollmentInstaller } = await import('./b02-layer-runtime.mjs');
        const approvalPath = layerFilePath(MAC_ENROLLMENT_APPROVAL_FILE);
        const installer = await createRingCloudMacEnrollmentInstaller({ environment });
        enrollmentRuntime = Object.freeze({ close: installer.close, async enroll({ request, actor }) {
          const { bytes } = await loadPinnedLayerJson(approvalPath, approvalSha256);
          return installer.install({ request, actor, approvalBytes: bytes });
        } });
      }
    }
    if (!testDependencies && environment.RING_OWNER_BOOTSTRAP_STATE === 'enabled') {
      // Enabled only with a pinned approval hash (buildOwnerBootstrap fails closed otherwise).
      const { createCloudIdentityResources } = await import('./b02-layer-runtime.mjs');
      const { buildOwnerBootstrap } = await import('./browser-session-production.mjs');
      const resources = await createCloudIdentityResources({ environment });
      try {
        const bootstrap = buildOwnerBootstrap({ environment, resources });
        ownerBootstrapRuntime = Object.freeze({ close: resources.close, ensureWithRingToken: bootstrap.ensureWithRingToken });
      } catch (error) { await resources.close(); throw error; }
    }
    const runtime = createMcpRestComposition({ config, ...ports,
      macCommandService: commandRuntime?.commands ?? null, macEnrollmentService: enrollmentRuntime ?? null,
      ownerBootstrapService: ownerBootstrapRuntime ?? null });
    const closeAll = async () => {
      try { await ownerBootstrapRuntime?.close(); } finally { try { await enrollmentRuntime?.close(); } finally {
        try { await commandRuntime?.close(); } finally { await ports.close(); } } }
    };
    return Object.freeze({ handle: runtime.handle, close: closeAll });
  } catch (error) {
    try { await ownerBootstrapRuntime?.close(); } finally { try { await enrollmentRuntime?.close(); } finally {
      try { await commandRuntime?.close(); } finally { await ports.close(); } } }
    throw error;
  }
}
