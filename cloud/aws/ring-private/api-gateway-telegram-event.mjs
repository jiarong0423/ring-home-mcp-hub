import { types } from 'node:util';

const EVENT_KEYS = Object.freeze(['resource', 'path', 'httpMethod', 'headers', 'multiValueHeaders',
  'queryStringParameters', 'multiValueQueryStringParameters', 'pathParameters', 'stageVariables',
  'requestContext', 'body', 'isBase64Encoded']);
const HEADER_NAME = /^[a-z0-9!#$%&'*+.^_`|~-]+$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export class TelegramRestV1EventError extends Error {
  constructor(code) { super(code); this.name = 'TelegramRestV1EventError'; this.code = code; }
}
function deny(code) { throw new TelegramRestV1EventError(code); }
function data(value, code) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny(code);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(descriptors).some(key => typeof key !== 'string' || !Object.hasOwn(descriptors[key], 'value'))) deny(code);
    return descriptors;
  } catch (error) { if (error instanceof TelegramRestV1EventError) throw error; deny(code); }
}
function exactEvent(value) {
  const descriptors = data(value, 'telegram_event_invalid');
  const keys = Reflect.ownKeys(descriptors);
  if (keys.length !== EVENT_KEYS.length || EVENT_KEYS.some(key => !Object.hasOwn(descriptors, key)) ||
      keys.some(key => !EVENT_KEYS.includes(key))) deny('telegram_event_invalid');
  return Object.fromEntries(EVENT_KEYS.map(key => [key, descriptors[key].value]));
}
function headers(value, multi) {
  const descriptors = data(value, 'telegram_headers_invalid');
  const keys = Reflect.ownKeys(descriptors);
  if (keys.length > 32) deny('telegram_headers_invalid');
  const output = Object.create(null);
  for (const key of keys) {
    const name = key.toLowerCase();
    if (!HEADER_NAME.test(name) || Object.hasOwn(output, name)) deny('telegram_headers_invalid');
    let current = descriptors[key].value;
    if (multi) {
      if (!Array.isArray(current) || types.isProxy(current)) deny('telegram_headers_invalid');
      const entries = Object.getOwnPropertyDescriptors(current);
      if (Reflect.ownKeys(entries).length !== 2 || entries.length?.value !== 1 ||
          !Object.hasOwn(entries['0'] ?? {}, 'value')) deny('telegram_headers_invalid');
      current = entries['0'].value;
    }
    if (typeof current !== 'string' || Buffer.byteLength(current) > 4096 || /[\x00-\x1f\x7f]/.test(current)) {
      deny('telegram_headers_invalid');
    }
    output[name] = current;
  }
  return output;
}

export function parseRestV1TelegramEvent(event) {
  const input = exactEvent(event);
  const request = data(input.requestContext, 'telegram_event_invalid');
  for (const key of ['stage', 'httpMethod', 'resourcePath']) if (!Object.hasOwn(request, key)) deny('telegram_event_invalid');
  if (Object.hasOwn(request, 'http')) deny('telegram_gateway_unsupported');
  const stage = request.stage.value;
  if (input.httpMethod !== 'POST' || input.path !== '/telegram/webhook' || input.resource !== '/telegram/webhook' ||
      request.httpMethod.value !== 'POST' || request.resourcePath.value !== '/telegram/webhook' ||
      typeof stage !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(stage)) deny('telegram_route_unsupported');
  if (Object.hasOwn(request, 'path') && ![input.path, `/${stage}${input.path}`].includes(request.path.value)) deny('telegram_event_invalid');
  if (input.pathParameters !== null || input.stageVariables !== null || input.queryStringParameters !== null ||
      input.multiValueQueryStringParameters !== null) deny('telegram_event_invalid');
  const single = headers(input.headers, false);
  const multiple = headers(input.multiValueHeaders, true);
  if (Object.keys(single).length !== Object.keys(multiple).length ||
      Object.keys(single).some(key => single[key] !== multiple[key])) deny('telegram_headers_invalid');
  if (single['content-type'] !== 'application/json' ||
      typeof single['x-telegram-bot-api-secret-token'] !== 'string' ||
      !/^[A-Za-z0-9_-]{32,256}$/.test(single['x-telegram-bot-api-secret-token'])) deny('telegram_headers_invalid');
  if (typeof input.body !== 'string' || input.isBase64Encoded !== true || input.body.length < 1 ||
      input.body.length > 21_848 || !BASE64.test(input.body)) deny('telegram_body_invalid');
  const body = Buffer.from(input.body, 'base64');
  if (body.length < 1 || body.length > 16_384 || body.toString('base64') !== input.body) deny('telegram_body_invalid');
  return Object.freeze({
    secretToken: single['x-telegram-bot-api-secret-token'],
    body,
    transport: Object.freeze({ method: 'POST', path: input.path, resource: input.resource, stage })
  });
}
