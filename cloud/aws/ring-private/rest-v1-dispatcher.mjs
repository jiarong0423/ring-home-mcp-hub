import { types } from 'node:util';
import { parseRestV1AccountLinkEvent } from './api-gateway-account-link-event.mjs';
import { parseRestV1TelegramEvent } from './api-gateway-telegram-event.mjs';

const SAFE_HEADERS = Object.freeze({
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'content-security-policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
});

function reply(statusCode, status) {
  return Object.freeze({
    statusCode,
    headers: SAFE_HEADERS,
    body: JSON.stringify({ status, bindingCompleted: false, retryAllowed: false, productionAdmitted: false })
  });
}

function ownData(value, required, code, optional = []) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value) ||
        types.isProxy(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
      throw new TypeError(code);
    }
    const found = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(found);
    const allowed = [...required, ...optional];
    if (required.some(key => !Object.hasOwn(found, key)) ||
        keys.some(key => typeof key !== 'string' || !allowed.includes(key) || !Object.hasOwn(found[key], 'value'))) {
      throw new TypeError(code);
    }
    return Object.fromEntries(keys.map(key => [key, found[key].value]));
  } catch (error) {
    if (error instanceof TypeError && error.message === code) throw error;
    throw new TypeError(code);
  }
}

function ownMethod(port, name) {
  if (port === null || typeof port !== 'object' || types.isProxy(port)) throw new TypeError('dispatcher_config');
  let descriptor;
  try { descriptor = Object.getOwnPropertyDescriptor(port, name); } catch { throw new TypeError('dispatcher_config'); }
  if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function' ||
      types.isProxy(descriptor.value)) throw new TypeError('dispatcher_config');
  return descriptor.value.bind(port);
}

function opaqueCopy(value, depth = 0, budget = { count: 0 }, seen = new Set()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (value === undefined) return undefined;
  if (depth > 4 || value === null || typeof value !== 'object' || Array.isArray(value) ||
      types.isProxy(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value)) || seen.has(value)) {
    throw new TypeError('source_context_invalid');
  }
  let found;
  let keys;
  try {
    found = Object.getOwnPropertyDescriptors(value);
    keys = Reflect.ownKeys(found);
  } catch { throw new TypeError('source_context_invalid'); }
  if (keys.length > 32 || keys.some(key => typeof key !== 'string' || !Object.hasOwn(found[key], 'value'))) {
    throw new TypeError('source_context_invalid');
  }
  seen.add(value);
  const output = Object.create(null);
  for (const key of keys) {
    budget.count += 1;
    if (budget.count > 64 || key.length > 128) throw new TypeError('source_context_invalid');
    output[key] = opaqueCopy(found[key].value, depth + 1, budget, seen);
  }
  seen.delete(value);
  return Object.freeze(output);
}

function cookieOnlyHeaders(headers) {
  const output = Object.create(null);
  if (!Object.hasOwn(headers, 'cookie')) return Object.freeze(output);
  const header = headers.cookie;
  if (typeof header !== 'string' || header.length < 1) throw new TypeError('cookie_invalid');
  const parts = header.split(';');
  if (parts.length > 64) throw new TypeError('cookie_invalid');
  const names = new Set();
  for (const part of parts) {
    const item = part.trim();
    const separator = item.indexOf('=');
    if (separator < 1) throw new TypeError('cookie_invalid');
    const name = item.slice(0, separator);
    const value = item.slice(separator + 1);
    if (!/^[A-Za-z0-9_!#$%&'*+.^|~-]+$/.test(name) || names.has(name) ||
        !/^[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*$/.test(value)) {
      throw new TypeError('cookie_invalid');
    }
    names.add(name);
  }
  output.cookie = header;
  return Object.freeze(output);
}

function finiteRouterResponse(value) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return false;
    const responseDescriptors = Object.getOwnPropertyDescriptors(value);
    const responseKeys = Reflect.ownKeys(responseDescriptors);
    if (responseKeys.length !== 3 || responseKeys.some(key => typeof key !== 'string' ||
        !['statusCode', 'headers', 'body'].includes(key) || !Object.hasOwn(responseDescriptors[key], 'value'))) return false;
    const status = responseDescriptors.statusCode.value;
    const headers = responseDescriptors.headers.value;
    const body = responseDescriptors.body.value;
    if (!Number.isSafeInteger(status) || status < 100 || status > 599 ||
        typeof body !== 'string' || Buffer.byteLength(body) > 16_384 ||
        headers === null || typeof headers !== 'object' || Array.isArray(headers) || types.isProxy(headers) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(headers))) return false;
    const headerDescriptors = Object.getOwnPropertyDescriptors(headers);
    const headerKeys = Reflect.ownKeys(headerDescriptors);
    if (headerKeys.length > 16 || headerKeys.some(key => typeof key !== 'string' ||
        !/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(key) || !Object.hasOwn(headerDescriptors[key], 'value') ||
        typeof headerDescriptors[key].value !== 'string' || /[\x00-\x1f\x7f]/.test(headerDescriptors[key].value) ||
        Buffer.byteLength(headerDescriptors[key].value) > 4_096)) return false;
    return true;
  } catch {
    return false;
  }
}

export function createRestV1Dispatcher(options) {
  const config = ownData(options, [
    'accountLinkHttp',
    'tokenTransportResolver',
    'linkSessionResolver'
  ], 'dispatcher_config', ['telegramWebhookHandler']);
  const handle = ownMethod(config.accountLinkHttp, 'handle');
  const handleTelegram = config.telegramWebhookHandler === undefined
    ? null
    : ownMethod(config.telegramWebhookHandler, 'handle');
  if (typeof config.tokenTransportResolver !== 'function' || types.isProxy(config.tokenTransportResolver) ||
      typeof config.linkSessionResolver !== 'function' || types.isProxy(config.linkSessionResolver)) {
    throw new TypeError('dispatcher_config');
  }
  const resolveTokenTransport = config.tokenTransportResolver;
  const resolveLinkSession = config.linkSessionResolver;

  return async function dispatch(event) {
    if (handleTelegram) {
      try {
        const telegram = parseRestV1TelegramEvent(event);
        const telegramResponse = await handleTelegram(telegram);
        return finiteRouterResponse(telegramResponse) ? telegramResponse : reply(503, 'unavailable');
      } catch (error) {
        const code = error instanceof Error && Object.getOwnPropertyDescriptor(error, 'code')?.value;
        if (code !== 'telegram_route_unsupported') return reply(400, 'denied');
      }
    }
    let normalized;
    try {
      normalized = parseRestV1AccountLinkEvent(event);
    } catch (error) {
      const code = error instanceof Error && Object.getOwnPropertyDescriptor(error, 'code')?.value;
      return code === 'unsupported_route' ? reply(404, 'not_found') : reply(400, 'denied');
    }

    let resolverHeaders;
    try {
      resolverHeaders = cookieOnlyHeaders(normalized.headers);
    } catch {
      return reply(400, 'denied');
    }

    const request = {
      method: normalized.method,
      path: normalized.path,
      headers: normalized.headers,
      rawQueryString: normalized.rawQueryString,
      body: Buffer.from(normalized.body)
    };
    try {
      if (normalized.path === '/ring/token') {
        request.tokenTransportContext = opaqueCopy(await resolveTokenTransport(normalized.transport));
      } else if (normalized.path === '/ring/link') {
        request.linkSessionContext = opaqueCopy(await resolveLinkSession(Object.freeze({
          transport: normalized.transport,
          headers: resolverHeaders
        })));
      }
    } catch {
      return reply(503, 'unavailable');
    }

    try {
      const response = await handle(Object.freeze(request));
      return finiteRouterResponse(response) ? response : reply(503, 'unavailable');
    } catch {
      return reply(503, 'unavailable');
    }
  };
}
