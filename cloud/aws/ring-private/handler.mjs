import { createProductionBrowserSessionRuntime } from './browser-session-production.mjs';
import { parseBrowserSessionEvent } from './browser-session-http.mjs';
import { extractCloudSessionCookies } from './cloud-browser-session.mjs';
import { types } from 'node:util';
import { parseRestV1AccountLinkEvent } from './api-gateway-account-link-event.mjs';
import { parseRestApiWebhookEvent } from './api-gateway-event.mjs';
import { createProductionRuntime } from './runtime-composition.mjs';
import { createProductionMcpRuntime, parseRestV1McpEvent } from './mcp-rest-composition.mjs';
import { createProductionFamilyRelayHttp } from './family-relay-http.mjs';

export const WEBHOOK_DEADLINE_MS = 4_000;

const ROUTES = Object.freeze(new Map([
  ['GET /auth/login', 'browser'],
  ['GET /auth/callback', 'browser'],
  ['GET /auth/logout', 'browser'],
  ['POST /auth/session', 'browser'],
  ['POST /ring/token', 'token'],
  ['GET /ring/link', 'link'],
  ['GET /ring/complete', 'complete'],
  ['POST /ring/webhook', 'webhook'],
  ['POST /mcp', 'mcp'],
  ['POST /mac/commands/fetch', 'mac-fetch'],
  ['POST /mac/commands/receipt', 'mac-receipt'],
  ['POST /mac/enroll', 'mac-enroll'],
  ['POST /owner/bootstrap', 'owner-bootstrap'],
  ['GET /.well-known/oauth-protected-resource', 'metadata'],
  // family remote-approval relay (family-relay.mjs): hub and phones sign every request themselves
  ['POST /relay/mac', 'relay-mac'],
  ['POST /relay/phone', 'relay-phone'],
  ['GET /family', 'family-page'],
  ['GET /family/app.js', 'family-js']
]));
const RELAY_ROUTES = new Set(['relay-mac', 'relay-phone', 'family-page', 'family-js']);

const SAFE_HEADERS = Object.freeze({
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'content-security-policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
});

const DEFAULT_DEADLINE_PRIMITIVES = Object.freeze({
  now: Date.now,
  setTimer: globalThis.setTimeout,
  clearTimer: globalThis.clearTimeout
});

function reply(statusCode, status) {
  return {
    statusCode,
    headers: { ...SAFE_HEADERS },
    body: JSON.stringify({ status, bindingCompleted: false, retryAllowed: false, productionAdmitted: false })
  };
}

function blockedReply() {
  return {
    statusCode: 503,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
    body: JSON.stringify({ status: 'not_configured' })
  };
}

function routeOf(event) {
  try {
    if (event === null || typeof event !== 'object' || Array.isArray(event) || types.isProxy(event)) return null;
    const method = Object.getOwnPropertyDescriptor(event, 'httpMethod');
    const path = Object.getOwnPropertyDescriptor(event, 'path');
    const resource = Object.getOwnPropertyDescriptor(event, 'resource');
    if (![method, path, resource].every(value => value && Object.hasOwn(value, 'value')) ||
        typeof method.value !== 'string' || typeof path.value !== 'string' ||
        typeof resource.value !== 'string' || path.value !== resource.value) return null;
    return ROUTES.get(`${method.value} ${path.value}`) ?? null;
  } catch {
    return null;
  }
}

function mcpRoute(route) {
  return ['mcp', 'metadata', 'mac-fetch', 'mac-receipt', 'mac-enroll', 'owner-bootstrap'].includes(route);
}

function relayEventOk(event) {
  const ctx = event.requestContext;
  if (!ctx || typeof ctx !== 'object') return false;
  if (process.env.RING_MCP_EXPECTED_API_ID && ctx.apiId !== process.env.RING_MCP_EXPECTED_API_ID) return false;
  if (process.env.RING_MCP_EXPECTED_STAGE && ctx.stage !== process.env.RING_MCP_EXPECTED_STAGE) return false;
  return event.body === null || event.body === undefined || typeof event.body === 'string';
}

function preflight(route, event) {
  if (RELAY_ROUTES.has(route)) return relayEventOk(event);
  try {
    if (route === 'browser') parseBrowserSessionEvent(event);
    else if (mcpRoute(route)) parseRestV1McpEvent(event, {
      apiId: process.env.RING_MCP_EXPECTED_API_ID, stage: process.env.RING_MCP_EXPECTED_STAGE
    });
    else if (route === 'webhook') parseRestApiWebhookEvent(event);
    else parseRestV1AccountLinkEvent(event);
    return true;
  } catch {
    return false;
  }
}

function finiteResponse(value) {
  try {
    return value !== null && typeof value === 'object' && !Array.isArray(value) && !types.isProxy(value) &&
      Number.isSafeInteger(value.statusCode) && value.statusCode >= 100 && value.statusCode <= 599 &&
      typeof value.body === 'string' && Buffer.byteLength(value.body) <= 16_384 &&
      value.headers !== null && typeof value.headers === 'object' && !Array.isArray(value.headers) &&
      !types.isProxy(value.headers);
  } catch {
    return false;
  }
}

function safeAudit(route, outcome, statusCode) {
  try {
    console.info(Object.freeze({ event: 'ring_ingress', route, outcome, statusCode }));
  } catch {
    // Logging cannot alter an authorization or availability decision.
  }
}

// The AWS SDK is loaded only when the relay is first used (same lazy pattern as runtime-composition).
let familyRelayFactory = async () => createProductionFamilyRelayHttp({
  ports: (await import('./aws-sdk-v3-ports.mjs')).createDefaultAwsSdkV3Ports({ region: process.env.AWS_REGION }) });
let familyRelayHandle = null;
export function installFamilyRelayFactoryForTest(factory) {
  if (process.env.NODE_ENV !== 'test' || typeof factory !== 'function') throw new TypeError('test_family_relay_factory_denied');
  familyRelayFactory = factory; familyRelayHandle = null;
}
let browserRuntimeFactory = createProductionBrowserSessionRuntime;
let browserRuntimePromise = null;
export function installBrowserRuntimeFactoryForTest(factory) {
  if (process.env.NODE_ENV !== 'test' || typeof factory !== 'function') throw new TypeError('test_browser_factory_denied');
  browserRuntimeFactory = factory; browserRuntimePromise = null;
}
let runtimeFactory = createProductionRuntime;
let runtimePromise = null;
let deadlinePrimitives = DEFAULT_DEADLINE_PRIMITIVES;
let mcpRuntimeFactory = createProductionMcpRuntime;
let mcpRuntimePromise = null;

async function mcpRuntime() {
  if (mcpRuntimePromise === null) mcpRuntimePromise = Promise.resolve().then(() => mcpRuntimeFactory());
  try {
    const value = await mcpRuntimePromise;
    if (!value || typeof value !== 'object' || types.isProxy(value) || typeof value.handle !== 'function') {
      throw new TypeError('mcp_runtime_unavailable');
    }
    return value;
  } catch {
    mcpRuntimePromise = null;
    throw new TypeError('mcp_runtime_unavailable');
  }
}

export function installMcpRuntimeFactoryForTest(factory) {
  if (process.env.NODE_ENV !== 'test' || typeof factory !== 'function' || types.isProxy(factory)) {
    throw new TypeError('test_mcp_runtime_factory_denied');
  }
  mcpRuntimeFactory = factory;
  mcpRuntimePromise = null;
}

async function runtime(signal) {
  if (runtimePromise === null) {
    runtimePromise = Promise.resolve().then(() => runtimeFactory({ signal }));
  }
  const pending = runtimePromise;
  const discard = () => {
    if (runtimePromise === pending) runtimePromise = null;
  };
  signal?.addEventListener('abort', discard, { once: true });
  try {
    const value = await pending;
    if (value === null || typeof value !== 'object' || types.isProxy(value) ||
        typeof value.dispatch !== 'function' || typeof value.webhookHandler !== 'function') {
      throw new TypeError('runtime_invalid');
    }
    return value;
  } catch {
    discard();
    throw new TypeError('runtime_unavailable');
  } finally {
    signal?.removeEventListener('abort', discard);
  }
}

export function installRuntimeFactoryForTest(factory) {
  if (process.env.NODE_ENV !== 'test' || typeof factory !== 'function' || types.isProxy(factory)) {
    throw new TypeError('test_runtime_factory_denied');
  }
  runtimeFactory = factory;
  runtimePromise = null;
}

export function installDeadlinePrimitivesForTest(value) {
  if (process.env.NODE_ENV !== 'test' || value === null || typeof value !== 'object' || types.isProxy(value) ||
      typeof value.now !== 'function' || typeof value.setTimer !== 'function' ||
      typeof value.clearTimer !== 'function') {
    throw new TypeError('test_deadline_primitives_denied');
  }
  deadlinePrimitives = Object.freeze({ now: value.now, setTimer: value.setTimer, clearTimer: value.clearTimer });
}

export function restoreProductionRuntimeForTest() {
  if (process.env.NODE_ENV !== 'test') throw new TypeError('test_runtime_factory_denied');
  browserRuntimeFactory = createProductionBrowserSessionRuntime; browserRuntimePromise = null;
  runtimeFactory = createProductionRuntime;
  runtimePromise = null;
  deadlinePrimitives = DEFAULT_DEADLINE_PRIMITIVES;
  mcpRuntimeFactory = createProductionMcpRuntime;
  mcpRuntimePromise = null;
}

async function dispatchWebhook(event, startedAt) {
  const controller = new AbortController();
  let elapsed;
  try {
    elapsed = deadlinePrimitives.now() - startedAt;
  } catch {
    return reply(503, 'unavailable');
  }
  if (!Number.isSafeInteger(elapsed) || elapsed < 0 || elapsed >= WEBHOOK_DEADLINE_MS) {
    controller.abort();
    return reply(503, 'deadline_exceeded');
  }

  let timer;
  const timedOut = new Promise(resolve => {
    timer = deadlinePrimitives.setTimer(() => {
      controller.abort();
      resolve(Object.freeze({ kind: 'timeout' }));
    }, WEBHOOK_DEADLINE_MS - elapsed);
  });
  const operation = (async () => {
    try {
      const active = await runtime(controller.signal);
      const response = await active.webhookHandler(event, { signal: controller.signal });
      return Object.freeze({ kind: 'response', response });
    } catch {
      return Object.freeze({ kind: 'failure' });
    }
  })();

  let outcome;
  try {
    outcome = await Promise.race([operation, timedOut]);
  } finally {
    deadlinePrimitives.clearTimer(timer);
  }
  if (outcome.kind === 'timeout') return reply(503, 'deadline_exceeded');
  if (outcome.kind !== 'response' || !finiteResponse(outcome.response)) return reply(503, 'unavailable');
  return outcome.response;
}

export async function handler(event, invocationContext) {
  if (process.env.RING_BACKEND_STATE !== 'enabled') {
    const response = blockedReply();
    safeAudit('blocked', 'not_configured', response.statusCode);
    return response;
  }

  let startedAt;
  try {
    startedAt = deadlinePrimitives.now();
  } catch {
    return reply(503, 'unavailable');
  }
  const route = routeOf(event);
  if (route === null) {
    const response = reply(404, 'not_found');
    safeAudit('unknown', 'not_found', response.statusCode);
    return response;
  }
  if ((route === 'browser' && process.env.RING_BROWSER_SESSION_STATE !== 'enabled') || (mcpRoute(route) && process.env.RING_MCP_STATE !== 'enabled')) {
    const response = blockedReply();
    safeAudit(route, 'not_configured', response.statusCode);
    return response;
  }
  if (RELAY_ROUTES.has(route) && process.env.RING_FAMILY_RELAY_STATE !== 'enabled') {
    const response = blockedReply();
    safeAudit(route, 'not_configured', response.statusCode);
    return response;
  }
  if (route === 'mac-enroll' && process.env.RING_MAC_ENROLLMENT_STATE !== 'enabled') {
    const response = blockedReply();
    safeAudit(route, 'not_configured', response.statusCode);
    return response;
  }
  if (route === 'owner-bootstrap' && process.env.RING_OWNER_BOOTSTRAP_STATE !== 'enabled') {
    const response = blockedReply();
    safeAudit(route, 'not_configured', response.statusCode);
    return response;
  }
  if (!preflight(route, event)) {
    const response = reply(400, 'denied');
    safeAudit(route, 'preflight_denied', response.statusCode);
    return response;
  }

  if (route === 'link' && process.env.RING_BROWSER_SESSION_STATE === 'enabled') {
    const parsed = parseRestV1AccountLinkEvent(event);
    try { extractCloudSessionCookies(parsed.headers); } catch {
      return { statusCode: 303, headers: { ...SAFE_HEADERS, location: `/${event.requestContext.stage}/auth/login?${parsed.rawQueryString}` }, body: '' };
    }
  }

  let response;
  if (RELAY_ROUTES.has(route)) {
    try {
      familyRelayHandle ??= Promise.resolve().then(() => familyRelayFactory());
      const candidate = await (await familyRelayHandle)(route, event);
      response = finiteResponse(candidate) || ((route === 'family-page' || route === 'family-js') && candidate?.statusCode === 200) ? candidate : reply(503, 'unavailable');
    } catch { familyRelayHandle = null; response = reply(503, 'unavailable'); }
  } else if (route === 'browser') {
    try {
      browserRuntimePromise ??= Promise.resolve().then(() => browserRuntimeFactory());
      const candidate = await (await browserRuntimePromise).handle(event, invocationContext);
      response = finiteResponse(candidate) ? candidate : reply(503, 'unavailable');
    } catch { browserRuntimePromise = null; response = reply(503, 'unavailable'); }
  } else if (mcpRoute(route)) {
    try {
      const active = await mcpRuntime();
      const candidate = await active.handle(event, invocationContext);
      response = finiteResponse(candidate) ? candidate : reply(503, 'unavailable');
    } catch {
      response = reply(503, 'unavailable');
    }
  } else if (route === 'webhook') {
    response = await dispatchWebhook(event, startedAt);
  } else {
    try {
      const active = await runtime();
      const candidate = await active.dispatch(event);
      response = finiteResponse(candidate) ? candidate : reply(503, 'unavailable');
    } catch {
      response = reply(503, 'unavailable');
    }
  }
  safeAudit(route, response.statusCode === 503 ? 'unavailable' : 'handled', response.statusCode);
  return response;
}
