import { FormalRuntimeError, deepFreeze } from './protocol.mjs';

export const LEGACY_MCP_PROTOCOL_VERSION = '2025-11-25';
export const MODERN_MCP_PROTOCOL_VERSION = '2026-07-28';

const PROTOCOL_VERSION_META = 'io.modelcontextprotocol/protocolVersion';
const CLIENT_INFO_META = 'io.modelcontextprotocol/clientInfo';
const CLIENT_CAPABILITIES_META = 'io.modelcontextprotocol/clientCapabilities';
const LOG_LEVEL_META = 'io.modelcontextprotocol/logLevel';
const SERVER_INFO_META = 'io.modelcontextprotocol/serverInfo';
const MODERN_METHODS = new Set(['server/discover', 'tools/list', 'tools/call']);
const LEGACY_METHODS = new Set(['initialize', 'tools/list', 'tools/call']);
const LOG_LEVELS = new Set(['debug', 'info', 'notice', 'warning', 'error', 'critical', 'alert', 'emergency']);
const META_KEY = /^(?:[A-Za-z][A-Za-z0-9]*(?:[.-][A-Za-z0-9]+)*\/)?[A-Za-z][A-Za-z0-9]*(?:[._-][A-Za-z0-9]+)*$/;

function denyWire(code, status = 400, { rpcCode = null, data = null } = {}) {
  const error = new FormalRuntimeError(code);
  error.status = status;
  error.rpcCode = rpcCode;
  error.rpcData = data;
  throw error;
}

function denyHeaderMismatch() {
  denyWire('B02_FORMAL_WIRE_HEADER_DENIED', 400, { rpcCode: -32020 });
}

function denyUnsupportedVersion(requested) {
  denyWire('B02_FORMAL_WIRE_VERSION_DENIED', 400, { rpcCode: -32022,
    data: { supported: [MODERN_MCP_PROTOCOL_VERSION], requested: requested ?? null } });
}

function plainRecord(value, code) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) denyWire(code);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(value).some((key) => typeof key !== 'string') ||
      Object.values(descriptors).some((descriptor) => !descriptor.enumerable || !Object.hasOwn(descriptor, 'value'))) {
    denyWire(code);
  }
  return value;
}

function requiredText(value, code) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256 || value !== value.trim()) denyWire(code);
  return value;
}

function singleHeader(headers, name, { allowComma = false } = {}) {
  if (headers === null || typeof headers !== 'object' || Array.isArray(headers)) {
    denyHeaderMismatch();
  }
  const value = headers[name];
  if (value === undefined) return null;
  if (typeof value !== 'string' || value.length === 0 || value !== value.trim() || (!allowComma && value.includes(','))) {
    denyHeaderMismatch();
  }
  return value;
}

function acceptsRequiredRepresentations(headers) {
  const raw = singleHeader(headers, 'accept', { allowComma: true });
  if (raw === null) denyWire('B02_FORMAL_WIRE_ACCEPT_DENIED', 406);
  const accepted = new Set();
  for (const entry of raw.split(',')) {
    const [mediaType, ...parameters] = entry.trim().toLowerCase().split(';').map((part) => part.trim());
    const quality = parameters.find((parameter) => parameter.startsWith('q='));
    if (quality === 'q=0' || quality === 'q=0.0' || quality === 'q=0.00' || quality === 'q=0.000') continue;
    accepted.add(mediaType);
  }
  if (!accepted.has('application/json') || !accepted.has('text/event-stream')) {
    denyWire('B02_FORMAL_WIRE_ACCEPT_DENIED', 406);
  }
}

function validateRequestId(id) {
  if ((typeof id !== 'string' && typeof id !== 'number') ||
      (typeof id === 'string' && (id.length === 0 || id.length > 256)) ||
      (typeof id === 'number' && !Number.isSafeInteger(id))) {
    denyWire('B02_FORMAL_WIRE_ENVELOPE_DENIED');
  }
}

function validateClientInfo(value) {
  const info = plainRecord(value, 'B02_FORMAL_WIRE_META_DENIED');
  const allowed = new Set(['name', 'version', 'title', 'description', 'websiteUrl', 'icons']);
  const keys = Object.keys(info);
  if (!keys.includes('name') || !keys.includes('version') || keys.some((key) => !allowed.has(key))) {
    denyWire('B02_FORMAL_WIRE_META_DENIED');
  }
  requiredText(info.name, 'B02_FORMAL_WIRE_META_DENIED');
  requiredText(info.version, 'B02_FORMAL_WIRE_META_DENIED');
  for (const key of ['title', 'description']) {
    if (Object.hasOwn(info, key) && (typeof info[key] !== 'string' || info[key].length > 2048)) {
      denyWire('B02_FORMAL_WIRE_META_DENIED');
    }
  }
  if (Object.hasOwn(info, 'websiteUrl')) {
    if (typeof info.websiteUrl !== 'string' || info.websiteUrl.length > 2048) denyWire('B02_FORMAL_WIRE_META_DENIED');
    try { new URL(info.websiteUrl); } catch { denyWire('B02_FORMAL_WIRE_META_DENIED'); }
  }
  if (Object.hasOwn(info, 'icons')) validateIcons(info.icons);
}

function validateIcons(value) {
  if (!Array.isArray(value) || value.length > 32) denyWire('B02_FORMAL_WIRE_META_DENIED');
  for (const icon of value) {
    const entry = plainRecord(icon, 'B02_FORMAL_WIRE_META_DENIED');
    const allowed = new Set(['src', 'mimeType', 'sizes', 'theme']);
    const keys = Object.keys(entry);
    if (!keys.includes('src') || keys.some((key) => !allowed.has(key)) ||
        typeof entry.src !== 'string' || entry.src.length === 0 || entry.src.length > 8192) {
      denyWire('B02_FORMAL_WIRE_META_DENIED');
    }
    try { new URL(entry.src); } catch { denyWire('B02_FORMAL_WIRE_META_DENIED'); }
    if (Object.hasOwn(entry, 'mimeType') &&
        (typeof entry.mimeType !== 'string' || entry.mimeType.length > 256)) denyWire('B02_FORMAL_WIRE_META_DENIED');
    if (Object.hasOwn(entry, 'sizes') && (!Array.isArray(entry.sizes) || entry.sizes.length > 32 ||
        entry.sizes.some((size) => typeof size !== 'string' || size.length > 64))) {
      denyWire('B02_FORMAL_WIRE_META_DENIED');
    }
    if (Object.hasOwn(entry, 'theme') && !['light', 'dark'].includes(entry.theme)) {
      denyWire('B02_FORMAL_WIRE_META_DENIED');
    }
  }
}

function validateModernMeta(value) {
  const meta = plainRecord(value, 'B02_FORMAL_WIRE_META_DENIED');
  const keys = Object.keys(meta);
  if (keys.some((key) => !META_KEY.test(key))) denyWire('B02_FORMAL_WIRE_META_DENIED');
  if (meta[PROTOCOL_VERSION_META] !== MODERN_MCP_PROTOCOL_VERSION) denyWire('B02_FORMAL_WIRE_META_DENIED');
  plainRecord(meta[CLIENT_CAPABILITIES_META], 'B02_FORMAL_WIRE_META_DENIED');
  if (Object.hasOwn(meta, CLIENT_INFO_META)) validateClientInfo(meta[CLIENT_INFO_META]);
  if (Object.hasOwn(meta, LOG_LEVEL_META) && !LOG_LEVELS.has(meta[LOG_LEVEL_META])) {
    denyWire('B02_FORMAL_WIRE_META_DENIED');
  }
  return meta;
}

function validateModernParams(method, params) {
  const fields = plainRecord(params, 'B02_FORMAL_WIRE_ENVELOPE_DENIED');
  validateModernMeta(fields._meta);
  if (method === 'tools/call') {
    const keys = Object.keys(fields).sort();
    if (keys.length !== 3 || keys[0] !== '_meta' || keys[1] !== 'arguments' || keys[2] !== 'name') {
      denyWire('B02_FORMAL_WIRE_ENVELOPE_DENIED');
    }
    requiredText(fields.name, 'B02_FORMAL_WIRE_ENVELOPE_DENIED');
    plainRecord(fields.arguments, 'B02_FORMAL_WIRE_ENVELOPE_DENIED');
    return;
  }
  if (method === 'tools/list') {
    const keys = Object.keys(fields);
    if (keys.some((key) => !['_meta', 'cursor'].includes(key)) || !Object.hasOwn(fields, '_meta') ||
        (Object.hasOwn(fields, 'cursor') &&
          (typeof fields.cursor !== 'string' || fields.cursor.length === 0 || fields.cursor.length > 4096))) {
      denyWire('B02_FORMAL_WIRE_ENVELOPE_DENIED');
    }
    return;
  }
  if (Object.keys(fields).length !== 1 || !Object.hasOwn(fields, '_meta')) {
    denyWire('B02_FORMAL_WIRE_ENVELOPE_DENIED');
  }
}

function decodeMcpName(value) {
  if (!value.startsWith('=?base64?') && !value.endsWith('?=')) return value;
  if (!value.startsWith('=?base64?') || !value.endsWith('?=')) denyHeaderMismatch();
  const encoded = value.slice(9, -2);
  if (encoded.length === 0 || encoded.length % 4 !== 0 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) {
    denyHeaderMismatch();
  }
  let bytes;
  try { bytes = Buffer.from(encoded, 'base64'); } catch { denyHeaderMismatch(); }
  if (bytes.toString('base64') !== encoded) denyHeaderMismatch();
  try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch { denyHeaderMismatch(); }
}

function validateLegacyEnvelope(envelope, versionHeader) {
  if (!LEGACY_METHODS.has(envelope.method)) denyWire('B02_FORMAL_WIRE_METHOD_DENIED');
  if (envelope.method === 'initialize') {
    const params = plainRecord(envelope.params, 'B02_FORMAL_WIRE_ENVELOPE_DENIED');
    if (params.protocolVersion !== LEGACY_MCP_PROTOCOL_VERSION) denyUnsupportedVersion(params.protocolVersion);
    if (versionHeader !== null && versionHeader !== LEGACY_MCP_PROTOCOL_VERSION) {
      denyUnsupportedVersion(versionHeader);
    }
  } else if (versionHeader !== LEGACY_MCP_PROTOCOL_VERSION) {
    denyUnsupportedVersion(versionHeader);
  }
}

export function validateFormalMcpWireRequest({ headers, envelope }) {
  acceptsRequiredRepresentations(headers);
  const request = plainRecord(envelope, 'B02_FORMAL_WIRE_ENVELOPE_DENIED');
  const keys = Object.keys(request).sort();
  if (keys.length !== 4 || keys[0] !== 'id' || keys[1] !== 'jsonrpc' || keys[2] !== 'method' || keys[3] !== 'params' ||
      request.jsonrpc !== '2.0') denyWire('B02_FORMAL_WIRE_ENVELOPE_DENIED');
  validateRequestId(request.id);
  requiredText(request.method, 'B02_FORMAL_WIRE_METHOD_DENIED');
  const versionHeader = singleHeader(headers, 'mcp-protocol-version');
  const methodHeader = singleHeader(headers, 'mcp-method');
  const nameHeader = singleHeader(headers, 'mcp-name');
  const sessionHeader = singleHeader(headers, 'mcp-session-id');
  const params = plainRecord(request.params, 'B02_FORMAL_WIRE_ENVELOPE_DENIED');
  const meta = Object.hasOwn(params, '_meta') ? plainRecord(params._meta, 'B02_FORMAL_WIRE_META_DENIED') : null;
  const metaVersion = meta?.[PROTOCOL_VERSION_META] ?? null;
  const modernClaim = versionHeader === MODERN_MCP_PROTOCOL_VERSION || metaVersion === MODERN_MCP_PROTOCOL_VERSION ||
    (typeof metaVersion === 'string' && metaVersion !== LEGACY_MCP_PROTOCOL_VERSION);

  if (modernClaim) {
    if (sessionHeader !== null) denyWire('B02_FORMAL_WIRE_SESSION_DENIED');
    if (versionHeader !== metaVersion) denyHeaderMismatch();
    if (versionHeader !== MODERN_MCP_PROTOCOL_VERSION) denyUnsupportedVersion(versionHeader);
    if (!MODERN_METHODS.has(request.method) || methodHeader !== request.method) {
      denyHeaderMismatch();
    }
    validateModernParams(request.method, request.params);
    if ((request.method === 'tools/call' && (nameHeader === null || decodeMcpName(nameHeader) !== request.params.name)) ||
        (request.method !== 'tools/call' && nameHeader !== null)) {
      denyHeaderMismatch();
    }
    return deepFreeze({ era: 'MODERN_STATELESS', protocolVersion: MODERN_MCP_PROTOCOL_VERSION,
      routeId: request.method, request });
  }

  if (methodHeader !== null || nameHeader !== null) denyHeaderMismatch();
  validateLegacyEnvelope(request, versionHeader);
  return deepFreeze({ era: 'LEGACY_HANDSHAKE', protocolVersion: LEGACY_MCP_PROTOCOL_VERSION,
    routeId: request.method, request });
}

export function modernDispatchEnvelope(validated) {
  if (!validated || validated.era !== 'MODERN_STATELESS' || validated.request?.method !== 'tools/call') {
    denyWire('B02_FORMAL_WIRE_ENVELOPE_DENIED');
  }
  const request = validated.request;
  return deepFreeze({ jsonrpc: '2.0', id: request.id, method: 'tools/call',
    params: { name: request.params.name, arguments: request.params.arguments } });
}

export function modernResultResponse({ id, result }) {
  validateRequestId(id);
  const body = plainRecord(result, 'B02_FORMAL_WIRE_RESULT_DENIED');
  if (Object.hasOwn(body, 'resultType') || Object.hasOwn(body, '_meta')) denyWire('B02_FORMAL_WIRE_RESULT_DENIED', 500);
  return deepFreeze({ jsonrpc: '2.0', id, result: {
    ...body,
    resultType: 'complete',
    _meta: { [SERVER_INFO_META]: { name: 'ring-home-mcp-hub', version: '0.1.0' } }
  } });
}

export function modernListResponse({ id, result }) {
  const body = plainRecord(result, 'B02_FORMAL_WIRE_RESULT_DENIED');
  if (Object.hasOwn(body, 'ttlMs') || Object.hasOwn(body, 'cacheScope')) {
    denyWire('B02_FORMAL_WIRE_RESULT_DENIED', 500);
  }
  return modernResultResponse({ id, result: { ...body, ttlMs: 0, cacheScope: 'private' } });
}

export function formalWireErrorResponse(error, id = null) {
  if (!(error instanceof FormalRuntimeError) || ![-32020, -32022].includes(error.rpcCode)) return null;
  const response = { jsonrpc: '2.0', id,
    error: { code: error.rpcCode, message: error.rpcCode === -32020 ? 'Header mismatch' : 'Unsupported protocol version' } };
  if (error.rpcCode === -32022) response.error.data = error.rpcData;
  return deepFreeze(response);
}

export function modernDiscoverResponse(id) {
  return modernResultResponse({ id, result: {
    supportedVersions: [MODERN_MCP_PROTOCOL_VERSION],
    capabilities: { tools: {} },
    instructions: 'Every tools/call requires server-owned formal admission context.',
    ttlMs: 0,
    cacheScope: 'private'
  } });
}
