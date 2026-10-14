import { types } from 'node:util';
import { ProtocolError } from './protocol.mjs';

const MAX_BODY_BYTES = 65_536;
const MAX_BASE64_LENGTH = Math.ceil(MAX_BODY_BYTES / 3) * 4;
const MAX_HEADER_KEYS = 128;
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
const STAGE_NAME = /^[A-Za-z0-9_-]{1,128}$/;
const CANONICAL_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function fail(code) {
  throw new ProtocolError(code);
}

function descriptors(value, code) {
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
    if (error instanceof ProtocolError) throw error;
    fail(code);
  }
}

function exactEvent(event) {
  const { found, keys } = descriptors(event, 'unsupported_gateway_event');
  if (REQUIRED_EVENT_KEYS.some(key => !Object.hasOwn(found, key)) ||
      keys.some(key => !EVENT_KEYS.has(key))) fail('unsupported_gateway_event');
  return Object.fromEntries(keys.map(key => [key, found[key].value]));
}

function exactRequestContext(value) {
  const { found } = descriptors(value, 'unsupported_gateway_event');
  for (const key of ['httpMethod', 'resourcePath', 'stage']) {
    if (!Object.hasOwn(found, key)) fail('unsupported_gateway_event');
  }
  if (Object.hasOwn(found, 'http')) fail('unsupported_gateway_event');
  return Object.fromEntries(Object.entries(found).map(([key, descriptor]) => [key, descriptor.value]));
}

function oneElementArray(value, code) {
  try {
    if (!Array.isArray(value) || types.isProxy(value) || Object.getPrototypeOf(value) !== Array.prototype) {
      fail(code);
    }
    const found = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(found);
    if (keys.length !== 2 || !Object.hasOwn(found, '0') || !Object.hasOwn(found, 'length') ||
        !Object.hasOwn(found['0'], 'value') || found.length.value !== 1 ||
        typeof found['0'].value !== 'string') {
      fail(code);
    }
    return found['0'].value;
  } catch (error) {
    if (error instanceof ProtocolError) throw error;
    fail(code);
  }
}

function oneHeader(headers, target, multi) {
  const { found: descriptorsByName, keys } = descriptors(headers, 'invalid_headers');
  if (keys.length > MAX_HEADER_KEYS) fail('invalid_headers');
  let found = null;
  for (const name of keys) {
    if (name.toLowerCase() !== target) continue;
    if (found !== null) fail(`duplicate_${target.replace('-', '_')}`);
    const candidate = descriptorsByName[name].value;
    if (multi) {
      found = oneElementArray(candidate, `duplicate_${target.replace('-', '_')}`);
    } else {
      if (typeof candidate !== 'string') fail('invalid_headers');
      found = candidate;
    }
  }
  return found;
}

function requireMatchedHeader(event, target) {
  const value = oneHeader(event.multiValueHeaders, target, true);
  if (value === null || value.length === 0) throw new ProtocolError(`missing_${target.replace('-', '_')}`);
  if (event.headers !== undefined && event.headers !== null) {
    const mirrored = oneHeader(event.headers, target, false);
    if (mirrored !== null && mirrored !== value) throw new ProtocolError('header_conflict');
  }
  return value;
}

function decodeRawBody(event) {
  if (event.isBase64Encoded !== true || typeof event.body !== 'string' ||
      event.body.length === 0 || event.body.length > MAX_BASE64_LENGTH ||
      !CANONICAL_BASE64.test(event.body)) {
    throw new ProtocolError('invalid_gateway_body');
  }
  const rawBody = Buffer.from(event.body, 'base64');
  if (rawBody.length === 0 || rawBody.length > MAX_BODY_BYTES ||
      rawBody.toString('base64') !== event.body) {
    throw new ProtocolError('invalid_gateway_body');
  }
  return rawBody;
}

export function parseRestApiWebhookEvent(event) {
  const input = exactEvent(event);
  const context = exactRequestContext(input.requestContext);
  if (input.httpMethod !== 'POST' || context.httpMethod !== 'POST') fail('unsupported_gateway_event');
  if (input.path !== '/ring/webhook' || input.resource !== '/ring/webhook' ||
      context.resourcePath !== '/ring/webhook') fail('route_conflict');
  if (typeof context.stage !== 'string' || !STAGE_NAME.test(context.stage)) fail('invalid_stage');
  if (Object.hasOwn(context, 'path') && context.path !== input.path &&
      context.path !== `/${context.stage}${input.path}`) fail('route_conflict');
  if (input.queryStringParameters !== null || input.multiValueQueryStringParameters !== null ||
      input.pathParameters !== null || input.stageVariables !== null) fail('invalid_gateway_parameters');
  const contentType = requireMatchedHeader(input, 'content-type');
  if (contentType.toLowerCase() !== 'application/json') throw new ProtocolError('invalid_content_type');
  const signature = requireMatchedHeader(input, 'x-signature');
  const rawBody = decodeRawBody(input);
  return Object.freeze({ rawBody, rawHeaders: ['Content-Type', contentType, 'X-Signature', signature] });
}
