import { createHash } from 'node:crypto';
import { types } from 'node:util';

const COOKIE = '__Host-ring_link';
const COOKIE_ATTRIBUTES = '; Secure; HttpOnly; SameSite=Lax; Path=/';
const REQUEST_KEYS = ['method', 'path', 'headers', 'rawQueryString', 'body'];
const REQUEST_CONTEXT_KEYS = ['tokenTransportContext', 'linkSessionContext'];
const RESULT_KEYS = ['status', 'duplicate', 'bindingCompleted', 'retryAllowed', 'productionAdmitted'];
const TICKET_KEYS = ['version', 'state', 'expiresAt', 'nonce'];
const STATES = new Set(['completed', 'denied', 'expired', 'unknown']);
const EXPIRED = new Set(['code_expired', 'link_expired', 'expired_link', 'identity_expired']);
const DENIED = new Set([
  'invalid_field', 'invalid_time', 'invalid_nonce', 'source_not_authorized', 'identity_not_authorized',
  'identity_changed', 'link_not_found', 'ambiguous_link'
]);
const UNKNOWN = new Set([
  'provider_outcome_unknown', 'code_outcome_unknown', 'code_exchange_in_progress', 'code_conflict',
  'code_store_unavailable', 'code_record_invalid', 'code_state_invalid', 'link_conflict',
  'link_store_unavailable', 'link_record_invalid', 'link_state_invalid', 'unclaimed_limit',
  'workflow_unavailable', 'workflow_state_invalid', 'workflow_clock', 'code_deadline_invalid',
  'upstream_unavailable', 'upstream_status', 'upstream_content_type', 'upstream_oversize',
  'upstream_empty', 'upstream_json', 'profile_schema', 'token_payload_invalid',
  'token_envelope_unavailable', 'token_envelope_invalid', 'token_envelope_context',
  'secret_unavailable', 'secret_response_invalid', 'secret_schema_invalid', 'secret_superseded',
  'secret_loader_clock', 'secret_loader_clock_rollback'
]);
const SAFE_HEADERS = Object.freeze({
  'cache-control': 'no-store',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'content-security-policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
});
const BYTE_LENGTH = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'byteLength').get;
const PAGES = Object.freeze({
  completed: '<!doctype html><html lang="zh-Hant"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Ring 綁定結果</title><h1>Ring 綁定完成</h1><p>您可以關閉此頁面。</p></html>',
  denied: '<!doctype html><html lang="zh-Hant"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Ring 綁定結果</title><h1>Ring 綁定未完成</h1><p>這次請求未獲授權。</p></html>',
  expired: '<!doctype html><html lang="zh-Hant"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Ring 綁定結果</title><h1>Ring 綁定已逾時</h1><p>這次顯示狀態已失效。</p></html>',
  unknown: '<!doctype html><html lang="zh-Hant"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Ring 綁定結果</title><h1>Ring 綁定結果尚未確認</h1><p>請勿自動重試此流程。</p></html>'
});
class HttpBoundaryError extends Error {
  constructor(code) { super(code); this.code = code; }
}
function fail(code = 'invalid_request') { throw new HttpBoundaryError(code); }
function data(value, required, optional = []) {
  try {
    if (!value || typeof value !== 'object' || types.isProxy(value) || Array.isArray(value) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (required.some(key => !Object.hasOwn(descriptors, key)) ||
        keys.some(key => typeof key !== 'string' || ![...required, ...optional].includes(key)) ||
        keys.some(key => !Object.hasOwn(descriptors[key], 'value'))) fail();
    return Object.fromEntries(keys.map(key => [key, descriptors[key].value]));
  } catch { fail(); }
}
function errorCode(error) {
  try {
    if (!error || types.isProxy(error)) return undefined;
    const descriptor = Object.getOwnPropertyDescriptor(error, 'code');
    return descriptor && Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'string' ? descriptor.value : undefined;
  } catch { return undefined; }
}
function safeContext(value, depth = 0, seen = new Set()) {
  if (value === null || value === undefined || ['string', 'boolean'].includes(typeof value)) return;
  if (typeof value === 'number' && Number.isFinite(value)) return;
  if (!value || typeof value !== 'object' || types.isProxy(value) || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) || depth > 4 || seen.has(value)) fail();
  seen.add(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.length > 32 || seen.size > 64 || keys.some(key => typeof key !== 'string' || !Object.hasOwn(descriptors[key], 'value'))) fail();
  for (const key of keys) safeContext(descriptors[key].value, depth + 1, seen);
}
function normalized(value) {
  const request = data(value, REQUEST_KEYS, REQUEST_CONTEXT_KEYS);
  if (typeof request.method !== 'string' || typeof request.path !== 'string' ||
      typeof request.rawQueryString !== 'string' || request.rawQueryString.length > 512) fail();
  const headers = request.headers;
  if (!headers || typeof headers !== 'object' || types.isProxy(headers) || Array.isArray(headers) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(headers))) fail();
  const descriptors = Object.getOwnPropertyDescriptors(headers);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.length > 32) fail();
  const copiedHeaders = Object.create(null);
  let size = 0;
  for (const key of keys) {
    if (typeof key !== 'string' || !/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(key) || !Object.hasOwn(descriptors[key], 'value')) fail();
    const value = descriptors[key].value;
    if (typeof value !== 'string' || /[\x00-\x1f\x7f]/.test(value) || Buffer.byteLength(value) > 4096) fail();
    size += key.length + Buffer.byteLength(value);
    if (size > 16_384) fail();
    copiedHeaders[key] = value;
  }
  if (types.isProxy(request.body) || !Buffer.isBuffer(request.body) || Object.getPrototypeOf(request.body) !== Buffer.prototype) fail();
  const length = BYTE_LENGTH.call(request.body);
  if (length > 4096) fail();
  const bodyDescriptors = Object.getOwnPropertyDescriptors(request.body);
  if (Reflect.ownKeys(bodyDescriptors).some(key => typeof key !== 'string' || !/^(0|[1-9][0-9]*)$/.test(key) ||
      Number(key) >= length || !Object.hasOwn(bodyDescriptors[key], 'value'))) fail();
  const hasTokenTransportContext = Object.hasOwn(request, 'tokenTransportContext');
  const hasLinkSessionContext = Object.hasOwn(request, 'linkSessionContext');
  if ((request.path === '/ring/token' && (!hasTokenTransportContext || hasLinkSessionContext)) ||
      (request.path === '/ring/link' && (hasTokenTransportContext || !hasLinkSessionContext)) ||
      (request.path === '/ring/complete' && (hasTokenTransportContext || hasLinkSessionContext)) ||
      !['/ring/token', '/ring/link', '/ring/complete'].includes(request.path)) fail();
  if (hasTokenTransportContext) safeContext(request.tokenTransportContext);
  if (hasLinkSessionContext) safeContext(request.linkSessionContext);
  return Object.freeze({
    ...request, headers: Object.freeze(copiedHeaders), body: Buffer.from(request.body)
  });
}
function response(statusCode, body, headers = {}) {
  return Object.freeze({ statusCode, headers: Object.freeze({ ...SAFE_HEADERS, ...headers }), body });
}
function json(statusCode, status) {
  return response(statusCode, JSON.stringify({ status, bindingCompleted: false, retryAllowed: false, productionAdmitted: false }),
    { 'content-type': 'application/json; charset=utf-8' });
}
function result(value, statuses) {
  const current = data(value, RESULT_KEYS);
  if (!statuses.includes(current.status) || typeof current.duplicate !== 'boolean' ||
      current.bindingCompleted !== (current.status === 'completed') ||
      current.retryAllowed !== false || current.productionAdmitted !== false) fail('workflow_result_invalid');
  return current;
}
function tokenCode(body) {
  let encoded;
  try { encoded = new TextDecoder('utf-8', { fatal: true }).decode(body); } catch { fail(); }
  if (encoded.length === 0 || !/^[\x20-\x7e]+$/.test(encoded)) fail();
  const fields = encoded.split('&');
  if (fields.length !== 1) fail();
  const separator = fields[0].indexOf('=');
  if (separator < 1) fail();
  let key;
  let code;
  try {
    key = decodeURIComponent(fields[0].slice(0, separator).replace(/\+/g, ' '));
    code = decodeURIComponent(fields[0].slice(separator + 1).replace(/\+/g, ' '));
  } catch { fail(); }
  if (key !== 'code' || code.length < 1 || Buffer.byteLength(code) > 2048 ||
      /\p{Cc}/u.test(code) || Buffer.from(code).toString('utf8') !== code) fail();
  return code;
}
function linkQuery(raw, current) {
  const fields = raw.split('&');
  if (fields.length !== 2) fail();
  const values = Object.create(null);
  for (const field of fields) {
    const separator = field.indexOf('=');
    if (separator < 1) fail();
    const key = field.slice(0, separator);
    const value = field.slice(separator + 1);
    if (!['time', 'nonce'].includes(key) || Object.hasOwn(values, key)) fail();
    values[key] = value;
  }
  if (typeof values.time !== 'string' || !/^[1-9][0-9]{12}$/.test(values.time) ||
      typeof values.nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(values.nonce) ||
      Buffer.from(values.nonce, 'base64url').toString('base64url') !== values.nonce) fail();
  if (Number(values.time) > current || current - Number(values.time) > 600_000) fail('expired_link');
  return Object.freeze({ time: values.time, nonce: values.nonce });
}
function completionCookie(header) {
  if (typeof header !== 'string' || header.length < 1) fail('completion_invalid');
  const cookies = header.split(';');
  const names = new Set();
  let ticket;
  for (const part of cookies) {
    const item = part.trim();
    const separator = item.indexOf('=');
    if (separator < 1) fail('completion_invalid');
    const name = item.slice(0, separator);
    const value = item.slice(separator + 1);
    if (!/^[A-Za-z0-9_!#$%&'*+.^|~-]+$/.test(name) || names.has(name) ||
        !/^[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*$/.test(value)) fail('completion_invalid');
    names.add(name);
    if (name === COOKIE) ticket = value;
  }
  if (!ticket) fail('completion_invalid');
  return ticket;
}
function display(state) {
  const code = { completed: 200, denied: 403, expired: 410, unknown: 503 }[state];
  return response(code, PAGES[state], {
    'content-type': 'text/html; charset=utf-8',
    'set-cookie': COOKIE + '=' + COOKIE_ATTRIBUTES + '; Max-Age=0'
  });
}
function outcomeFromError(error) {
  const code = errorCode(error);
  if (EXPIRED.has(code)) return 'expired';
  if (DENIED.has(code)) return 'denied';
  if (UNKNOWN.has(code)) return 'unknown';
  return null;
}
function method(port, name) {
  if (!port || types.isProxy(port)) fail('http_config');
  const descriptor = Object.getOwnPropertyDescriptor(port, name);
  if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function' || types.isProxy(descriptor.value)) fail('http_config');
  return descriptor.value.bind(port);
}
export function createAccountLinkHttp(options) {
  let ports;
  try { ports = data(options, ['workflow', 'completionCodec', 'clock']); } catch { fail('http_config'); }
  const stage = method(ports.workflow, 'stageFromVerifiedIngress');
  const link = method(ports.workflow, 'continuePasswordlessLink');
  const issue = method(ports.completionCodec, 'issue');
  const verify = method(ports.completionCodec, 'verify');
  if (typeof ports.clock !== 'function' || types.isProxy(ports.clock)) fail('http_config');
  const clock = ports.clock;
  let lastNow = -1;
  function now() {
    let value;
    try { value = clock(); } catch { fail('http_clock'); }
    if (!Number.isSafeInteger(value) || value < 0 || value < lastNow) fail('http_clock');
    lastNow = value;
    return value;
  }
  return Object.freeze({
    async handle(input) {
      let request;
      let receivedAt;
      try { request = normalized(input); receivedAt = now(); }
      catch (error) { return json(errorCode(error) === 'http_clock' ? 503 : 400, errorCode(error) === 'http_clock' ? 'unavailable' : 'denied'); }
      if (request.path === '/ring/token') {
        if (request.method !== 'POST' || request.rawQueryString !== '' ||
            request.headers['content-type'] !== 'application/x-www-form-urlencoded') return json(400, 'denied');
        let code;
        try { code = tokenCode(request.body); } catch { return json(400, 'denied'); }
        try {
          result(await stage({
            code, receivedAt, bodyDigest: createHash('sha256').update(request.body).digest('hex')
          }), ['unclaimed']);
          return json(200, 'accepted');
        } catch (error) {
          const state = outcomeFromError(error);
          return json(state === 'expired' ? 410 : state === 'denied' ? 403 : 503, state === 'expired' ? 'expired' : state === 'denied' ? 'denied' : 'unavailable');
        }
      }
      if (request.path === '/ring/link') {
        if (request.method !== 'GET' || request.body.length !== 0) return json(400, 'denied');
        let query;
        try { query = linkQuery(request.rawQueryString, receivedAt); }
        catch (error) { return json(errorCode(error) === 'expired_link' ? 410 : 400, errorCode(error) === 'expired_link' ? 'expired' : 'denied'); }
        let state;
        try { state = result(await link({ query, context: request.linkSessionContext }), [...STATES]).status; }
        catch (error) { state = outcomeFromError(error); }
        if (!state) return json(503, 'unavailable');
        try {
          const ticket = issue(state);
          if (typeof ticket !== 'string' || ticket.length > 1024 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/.test(ticket)) fail();
          return response(303, '', {
            location: 'complete',
            'set-cookie': COOKIE + '=' + ticket + COOKIE_ATTRIBUTES + '; Max-Age=120'
          });
        } catch { return json(503, 'unavailable'); }
      }
      if (request.path === '/ring/complete') {
        if (request.method !== 'GET' || request.rawQueryString !== '' || request.body.length !== 0) {
          const denied = json(400, 'denied');
          return response(denied.statusCode, denied.body, { ...denied.headers, 'set-cookie': COOKIE + '=' + COOKIE_ATTRIBUTES + '; Max-Age=0' });
        }
        try {
          const value = data(verify(completionCookie(request.headers.cookie)), TICKET_KEYS);
          if (value.version !== 1 || !STATES.has(value.state) || !Number.isSafeInteger(value.expiresAt) ||
              value.expiresAt <= receivedAt || value.expiresAt - receivedAt > 120_000 ||
              typeof value.nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value.nonce)) fail('completion_invalid');
          return display(value.state);
        } catch (error) {
          return display(errorCode(error) === 'completion_expired' ? 'expired' : errorCode(error) === 'completion_clock' ||
            errorCode(error) === 'completion_clock_rollback' ? 'unknown' : 'denied');
        }
      }
      return json(400, 'denied');
    }
  });
}
