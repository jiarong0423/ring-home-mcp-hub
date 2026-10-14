import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { parseRestApiWebhookEvent } from '../api-gateway-event.mjs';
import { createWebhookDeliveryAdapter } from '../webhook-adapter.mjs';
import { MemoryRingStore } from '../store.mjs';

const now = Date.parse('2026-09-29T12:00:00Z');
const signingKey = 'generated-gateway-signing-key-for-offline-tests-only';
const accountId = 'ava1.ring.account.gateway-test';
const deviceId = 'ava1.ring.device.gateway-test';

function generatedEvent(rawBody = Buffer.from(JSON.stringify({
  meta: { version: '1.1', time: '2026-09-29T11:59:55Z', request_id: 'gateway-test-1', account_id: accountId },
  data: { id: 'gateway-motion-1', type: 'motion_detected', attributes: {
    source: deviceId, source_type: 'devices', timestamp: now - 5_000
  } }
}))) {
  const signature = `sha256=${createHmac('sha256', signingKey).update(rawBody).digest('hex')}`;
  return {
    resource: '/ring/webhook', path: '/ring/webhook', httpMethod: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Signature': signature },
    multiValueHeaders: { 'Content-Type': ['application/json'], 'X-Signature': [signature] },
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    pathParameters: null,
    stageVariables: null,
    requestContext: {
      stage: 'staging',
      httpMethod: 'POST',
      resourcePath: '/ring/webhook',
      path: '/staging/ring/webhook',
      apiId: 'generated-rest-api'
    },
    body: rawBody.toString('base64'), isBase64Encoded: true
  };
}

test('REST proxy v1 preserves exact signed bytes and feeds the delivery-only adapter', async () => {
  const source = generatedEvent();
  const decoded = parseRestApiWebhookEvent(source);
  assert.deepEqual(decoded.rawBody, Buffer.from(source.body, 'base64'));
  assert.deepEqual(decoded.rawHeaders, ['Content-Type', 'application/json', 'X-Signature', source.headers['X-Signature']]);
  const store = new MemoryRingStore({ clock: () => now });
  const adapter = createWebhookDeliveryAdapter({
    signingKey, authorizeDevice: async (account, device) => account === accountId && device === deviceId,
    store, clock: () => now
  });
  assert.deepEqual(await adapter.receive(decoded), { status: 'accepted_delivery_only', duplicate: false, deviceObserved: false });
  assert.equal(store.getSummary().events, 1);
});

test('multiValueHeaders exposes duplicate signatures even when headers collapses them', () => {
  const event = generatedEvent();
  event.multiValueHeaders['X-Signature'].push(event.headers['X-Signature']);
  assert.throws(() => parseRestApiWebhookEvent(event), /duplicate_x_signature/);
  const second = generatedEvent();
  second.multiValueHeaders['x-signature'] = [second.headers['X-Signature']];
  assert.throws(() => parseRestApiWebhookEvent(second), /duplicate_x_signature/);
});

test('missing multi-value signature cannot be rescued by collapsed headers', () => {
  const event = generatedEvent();
  delete event.multiValueHeaders['X-Signature'];
  assert.throws(() => parseRestApiWebhookEvent(event), /missing_x_signature/);
  const second = generatedEvent();
  delete second.headers['X-Signature'];
  delete second.multiValueHeaders['X-Signature'];
  assert.throws(() => parseRestApiWebhookEvent(second), /missing_x_signature/);
});

test('conflicting single and multi header maps fail closed', () => {
  const signature = generatedEvent();
  signature.headers['X-Signature'] = 'sha256=' + '0'.repeat(64);
  assert.throws(() => parseRestApiWebhookEvent(signature), /header_conflict/);
  const contentType = generatedEvent();
  contentType.headers['Content-Type'] = 'text/plain';
  assert.throws(() => parseRestApiWebhookEvent(contentType), /header_conflict/);
  const caseDuplicate = generatedEvent();
  caseDuplicate.headers['x-signature'] = caseDuplicate.headers['X-Signature'];
  assert.throws(() => parseRestApiWebhookEvent(caseDuplicate), /duplicate_x_signature/);
});

test('only REST proxy POST passes; HTTP API v2 shape fails', () => {
  const get = generatedEvent();
  get.httpMethod = 'GET';
  assert.throws(() => parseRestApiWebhookEvent(get), /unsupported_gateway_event/);
  const contextConflict = generatedEvent();
  contextConflict.requestContext.httpMethod = 'GET';
  assert.throws(() => parseRestApiWebhookEvent(contextConflict), /unsupported_gateway_event/);
  const v2 = generatedEvent();
  v2.version = '2.0';
  v2.rawPath = '/ring/webhook';
  v2.requestContext.http = { method: 'POST' };
  delete v2.multiValueHeaders;
  assert.throws(() => parseRestApiWebhookEvent(v2), /unsupported_gateway_event/);
  const v1HttpApi = generatedEvent();
  v1HttpApi.version = '1.0';
  assert.throws(() => parseRestApiWebhookEvent(v1HttpApi), /unsupported_gateway_event/);
});

test('exact REST proxy v1 metadata rejects smuggled parameters and route or stage conflicts', () => {
  const unexpected = generatedEvent();
  unexpected.unexpected = 'must-fail-closed';
  assert.throws(() => parseRestApiWebhookEvent(unexpected), /unsupported_gateway_event/);

  for (const key of [
    'queryStringParameters',
    'multiValueQueryStringParameters',
    'pathParameters',
    'stageVariables'
  ]) {
    const event = generatedEvent();
    event[key] = { injected: 'true' };
    assert.throws(() => parseRestApiWebhookEvent(event), /invalid_gateway_parameters/);
  }

  const resourceConflict = generatedEvent();
  resourceConflict.requestContext.resourcePath = '/ring/token';
  assert.throws(() => parseRestApiWebhookEvent(resourceConflict), /route_conflict/);
  const contextPathConflict = generatedEvent();
  contextPathConflict.requestContext.path = '/staging/ring/token';
  assert.throws(() => parseRestApiWebhookEvent(contextPathConflict), /route_conflict/);
  const invalidStage = generatedEvent();
  invalidStage.requestContext.stage = '../staging';
  assert.throws(() => parseRestApiWebhookEvent(invalidStage), /invalid_stage/);
  const absentContextPath = generatedEvent();
  delete absentContextPath.requestContext.path;
  assert.doesNotThrow(() => parseRestApiWebhookEvent(absentContextPath));
});

test('event, context, header maps and multi-value arrays reject getters and proxies without executing traps', () => {
  let traps = 0;
  const eventGetter = generatedEvent();
  Object.defineProperty(eventGetter, 'body', {
    enumerable: true,
    get() { traps += 1; throw new Error('must-not-read'); }
  });
  assert.throws(() => parseRestApiWebhookEvent(eventGetter), /unsupported_gateway_event/);

  const contextProxy = generatedEvent();
  contextProxy.requestContext = new Proxy({}, {
    ownKeys() { traps += 1; throw new Error('must-not-enumerate'); },
    get() { traps += 1; throw new Error('must-not-read'); }
  });
  assert.throws(() => parseRestApiWebhookEvent(contextProxy), /unsupported_gateway_event/);

  const headerGetter = generatedEvent();
  Object.defineProperty(headerGetter.multiValueHeaders, 'X-Signature', {
    enumerable: true,
    get() { traps += 1; throw new Error('must-not-read'); }
  });
  assert.throws(() => parseRestApiWebhookEvent(headerGetter), /invalid_headers/);

  const arrayProxy = generatedEvent();
  arrayProxy.multiValueHeaders['X-Signature'] = new Proxy([], {
    getPrototypeOf() { traps += 1; throw new Error('must-not-inspect'); },
    ownKeys() { traps += 1; throw new Error('must-not-enumerate'); }
  });
  assert.throws(() => parseRestApiWebhookEvent(arrayProxy), /duplicate_x_signature/);
  assert.equal(traps, 0);
});

test('Content-Type must be one unambiguous application/json value', () => {
  const wrong = generatedEvent();
  wrong.headers['Content-Type'] = 'text/plain';
  wrong.multiValueHeaders['Content-Type'] = ['text/plain'];
  assert.throws(() => parseRestApiWebhookEvent(wrong), /invalid_content_type/);
  const repeated = generatedEvent();
  repeated.multiValueHeaders['Content-Type'].push('application/json');
  assert.throws(() => parseRestApiWebhookEvent(repeated), /duplicate_content_type/);
  const missing = generatedEvent();
  delete missing.multiValueHeaders['Content-Type'];
  assert.throws(() => parseRestApiWebhookEvent(missing), /missing_content_type/);
});

test('body must be canonical base64 and no more than 64 KiB after decoding', () => {
  const textMode = generatedEvent();
  textMode.isBase64Encoded = false;
  assert.throws(() => parseRestApiWebhookEvent(textMode), /invalid_gateway_body/);
  const badAlphabet = generatedEvent();
  badAlphabet.body = '%%%=';
  assert.throws(() => parseRestApiWebhookEvent(badAlphabet), /invalid_gateway_body/);
  const badPadBits = generatedEvent();
  badPadBits.body = 'Zh==';
  assert.throws(() => parseRestApiWebhookEvent(badPadBits), /invalid_gateway_body/);
  const oversized = generatedEvent(Buffer.alloc(65_537, 0x41));
  assert.throws(() => parseRestApiWebhookEvent(oversized), /invalid_gateway_body/);
});

test('transport conversion does not repair altered signed bytes', async () => {
  const event = generatedEvent();
  const raw = Buffer.from(event.body, 'base64');
  event.body = Buffer.concat([raw, Buffer.from(' ')]).toString('base64');
  const converted = parseRestApiWebhookEvent(event);
  const store = new MemoryRingStore({ clock: () => now });
  const adapter = createWebhookDeliveryAdapter({
    signingKey, authorizeDevice: async (account, device) => account === accountId && device === deviceId,
    store, clock: () => now
  });
  await assert.rejects(adapter.receive(converted), /invalid_signature/);
  assert.equal(store.getSummary().events, 0);
});
