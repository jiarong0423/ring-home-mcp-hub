import { types } from 'node:util';

const EVENT_KEYS = new Set([
  'resource',
  'path',
  'httpMethod',
  'headers',
  'multiValueHeaders',
  'queryStringParameters',
  'multiValueQueryStringParameters',
  'pathParameters',
  'stageVariables',
  'requestContext',
  'body',
  'isBase64Encoded'
]);
const REQUIRED_EVENT_KEYS = [...EVENT_KEYS];
const ROUTES = new Set([
  'POST /ring/token',
  'GET /ring/link',
  'GET /ring/complete'
]);
const MAX_HEADERS = 64;
const MAX_HEADER_BYTES = 16_384;
const MAX_HEADER_VALUE_BYTES = 4_096;
const MAX_BODY_BYTES = 4_096;
const MAX_BASE64_LENGTH = Math.ceil(MAX_BODY_BYTES / 3) * 4;
const HEADER_NAME = /^[a-z0-9!#$%&'*+.^_`|~-]+$/;
const STAGE_NAME = /^[A-Za-z0-9_-]{1,128}$/;
const CANONICAL_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const LINK_TIME = /^[1-9][0-9]{12}$/;
const LINK_NONCE = /^[A-Za-z0-9_-]{43}$/;

class RestV1EventError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function fail(code = 'invalid_event') {
  throw new RestV1EventError(code);
}

function descriptors(value, code = 'invalid_event') {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value) ||
        types.isProxy(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
      fail(code);
    }
    const found = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(found);
    if (keys.some(key => typeof key !== 'string' || !Object.hasOwn(found[key], 'value'))) fail(code);
    return { found, keys };
  } catch (error) {
    if (error instanceof RestV1EventError) throw error;
    fail(code);
  }
}

function exactEvent(event) {
  const { found, keys } = descriptors(event);
  if (REQUIRED_EVENT_KEYS.some(key => !Object.hasOwn(found, key)) ||
      keys.some(key => !EVENT_KEYS.has(key))) fail();
  return Object.fromEntries(keys.map(key => [key, found[key].value]));
}

function requestContext(value) {
  const { found } = descriptors(value);
  for (const key of ['httpMethod', 'resourcePath', 'stage']) {
    if (!Object.hasOwn(found, key)) fail();
  }
  if (Object.hasOwn(found, 'http')) fail('unsupported_gateway_event');
  return Object.fromEntries(Object.entries(found).map(([key, descriptor]) => [key, descriptor.value]));
}

function oneElementArray(value, code) {
  try {
    if (!Array.isArray(value) || types.isProxy(value) || Object.getPrototypeOf(value) !== Array.prototype) fail(code);
    const found = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(found);
    if (keys.length !== 2 || !Object.hasOwn(found, '0') || !Object.hasOwn(found, 'length') ||
        !Object.hasOwn(found['0'], 'value') || found.length.value !== 1 ||
        typeof found['0'].value !== 'string') fail(code);
    return found['0'].value;
  } catch (error) {
    if (error instanceof RestV1EventError) throw error;
    fail(code);
  }
}

function headerMap(value, multi) {
  const { found, keys } = descriptors(value, 'invalid_headers');
  if (keys.length > MAX_HEADERS) fail('invalid_headers');
  const output = Object.create(null);
  let totalBytes = 0;
  for (const key of keys) {
    const name = key.toLowerCase();
    if (!HEADER_NAME.test(name) || Object.hasOwn(output, name)) fail('invalid_headers');
    const item = multi ? oneElementArray(found[key].value, 'invalid_headers') : found[key].value;
    if (typeof item !== 'string' || /[\x00-\x1f\x7f]/.test(item) ||
        Buffer.byteLength(item) > MAX_HEADER_VALUE_BYTES) fail('invalid_headers');
    totalBytes += Buffer.byteLength(name) + Buffer.byteLength(item);
    if (totalBytes > MAX_HEADER_BYTES) fail('invalid_headers');
    output[name] = item;
  }
  return output;
}

function normalizedHeaders(singleValue, multiValue) {
  const single = headerMap(singleValue, false);
  const multi = headerMap(multiValue, true);
  const singleKeys = Object.keys(single);
  const multiKeys = Object.keys(multi);
  if (singleKeys.length !== multiKeys.length ||
      singleKeys.some(key => !Object.hasOwn(multi, key) || multi[key] !== single[key])) {
    fail('header_conflict');
  }
  return Object.freeze(multi);
}

function queryMap(value, multi) {
  const { found, keys } = descriptors(value, 'invalid_query');
  if (keys.length > 8) fail('invalid_query');
  const output = Object.create(null);
  for (const key of keys) {
    if (key.length === 0 || key.length > 64 || /[^A-Za-z0-9_-]/.test(key) || Object.hasOwn(output, key)) {
      fail('invalid_query');
    }
    const item = multi ? oneElementArray(found[key].value, 'invalid_query') : found[key].value;
    if (typeof item !== 'string' || Buffer.byteLength(item) > 512 || /[\x00-\x20\x7f]/.test(item)) {
      fail('invalid_query');
    }
    output[key] = item;
  }
  return output;
}

function normalizeRawQueryString(path, singleValue, multiValue) {
  if (path !== '/ring/link') {
    if (singleValue !== null || multiValue !== null) fail('invalid_query');
    return '';
  }
  const single = queryMap(singleValue, false);
  const multi = queryMap(multiValue, true);
  const expected = ['time', 'nonce'];
  if (Object.keys(single).length !== expected.length || Object.keys(multi).length !== expected.length ||
      expected.some(key => !Object.hasOwn(single, key) || !Object.hasOwn(multi, key) || single[key] !== multi[key])) {
    fail('invalid_query');
  }
  if (!LINK_TIME.test(multi.time) || !LINK_NONCE.test(multi.nonce) ||
      Buffer.from(multi.nonce, 'base64url').toString('base64url') !== multi.nonce) fail('invalid_query');
  return `time=${multi.time}&nonce=${multi.nonce}`;
}

function normalizedBody(method, body, isBase64Encoded) {
  if (method === 'GET') {
    if (body !== null || isBase64Encoded !== false) fail('invalid_body');
    return Buffer.alloc(0);
  }
  if (typeof body !== 'string' || isBase64Encoded !== true || body.length === 0 ||
      body.length > MAX_BASE64_LENGTH || !CANONICAL_BASE64.test(body)) fail('invalid_body');
  const decoded = Buffer.from(body, 'base64');
  if (decoded.length === 0 || decoded.length > MAX_BODY_BYTES || decoded.toString('base64') !== body) {
    fail('invalid_body');
  }
  return decoded;
}

export function parseRestV1AccountLinkEvent(event) {
  const input = exactEvent(event);
  const context = requestContext(input.requestContext);
  if (typeof input.httpMethod !== 'string' || typeof input.path !== 'string' ||
      typeof input.resource !== 'string' || typeof context.httpMethod !== 'string' ||
      typeof context.resourcePath !== 'string' || typeof context.stage !== 'string') fail();
  if (!STAGE_NAME.test(context.stage)) fail('invalid_stage');
  if (input.httpMethod !== context.httpMethod || input.path !== input.resource ||
      input.resource !== context.resourcePath) fail('route_conflict');
  if (!ROUTES.has(`${input.httpMethod} ${input.path}`)) fail('unsupported_route');
  if (input.pathParameters !== null || input.stageVariables !== null) fail('invalid_gateway_parameters');
  if (Object.hasOwn(context, 'path') && context.path !== input.path &&
      context.path !== `/${context.stage}${input.path}`) fail('route_conflict');

  const headers = normalizedHeaders(input.headers, input.multiValueHeaders);
  const rawQueryString = normalizeRawQueryString(
    input.path,
    input.queryStringParameters,
    input.multiValueQueryStringParameters
  );
  const body = normalizedBody(input.httpMethod, input.body, input.isBase64Encoded);
  const transport = Object.freeze({
    method: input.httpMethod,
    path: input.path,
    resource: input.resource,
    stage: context.stage
  });

  return Object.freeze({
    method: input.httpMethod,
    path: input.path,
    headers,
    rawQueryString,
    body,
    transport
  });
}
