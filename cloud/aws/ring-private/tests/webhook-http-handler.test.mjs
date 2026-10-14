import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createWebhookHttpHandler } from '../webhook-http-handler.mjs';
import { createDynamoEventLedger } from '../dynamo-event-ledger.mjs';
import { createDynamoLinkedDeviceAuthorizer } from '../dynamo-linked-device-authorizer.mjs';

const now = Date.parse('2026-09-29T12:00:00Z');
const signingKey = 'generated-http-handler-signing-key';
const accountId = 'ava1.ring.account.generated-handler';
const deviceId = 'ava1.ring.device.generated-handler';
const hashKey = 'generated-32-byte-ledger-key-for-handler-tests';

function event(body = Buffer.from(JSON.stringify({
  meta: { version: '1.1', time: '2026-09-29T11:59:55Z', request_id: 'handler-request-1', account_id: accountId },
  data: { id: 'handler-motion-1', type: 'motion_detected', attributes: {
    source: deviceId, source_type: 'devices', timestamp: now - 5000
  } }
}))) {
  const signature = `sha256=${createHmac('sha256', signingKey).update(body).digest('hex')}`;
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
      path: '/staging/ring/webhook'
    },
    body: body.toString('base64'), isBase64Encoded: true
  };
}

function dependencies({ linked = true, revoked = false, expired = false, failLink = false, failPut = false } = {}) {
  const items = new Map();
  const calls = { links: 0, puts: 0, gets: 0 };
  const time = { now };
  const ledger = createDynamoEventLedger({
    tableName: 'GeneratedRingEvents', hashKey, clock: () => time.now,
    async putItem(input) {
      calls.puts += 1;
      if (failPut) throw new Error('generated-outage');
      const key = input.Item.pk.S;
      if (items.has(key)) throw Object.assign(new Error('conditional'), { name: 'ConditionalCheckFailedException' });
      items.set(key, structuredClone(input.Item));
    },
    async getItem(input) {
      calls.gets += 1;
      return { Item: items.get(input.Key.pk.S) };
    }
  });
  const linkAuthorizer = createDynamoLinkedDeviceAuthorizer({
    tableName: 'GeneratedLinkedDevices', hashKey, clock: () => time.now,
    async getItem(input) {
      calls.links += 1;
      if (failLink) throw new Error('generated-link-store-outage');
      if (!linked) return {};
      return { Item: {
        pk: { S: input.Key.pk.S }, status: { S: 'completed' },
        grant_version: { N: '1' }, revoked: { BOOL: revoked },
        expires_at: { N: String(Math.floor(now / 1000) + (expired ? 0 : 7200)) }
      } };
    }
  });
  const handler = createWebhookHttpHandler({
    signingKey, ledger, clock: () => time.now,
    isLinkedDevice: linkAuthorizer.isLinkedDevice
  });
  return { handler, calls, items, time };
}

test('signed REST v1 delivery stores once; retry has the same public response and no second item', async () => {
  const { handler, calls, items } = dependencies();
  const first = await handler(event());
  const second = await handler(event());
  assert.equal(first.statusCode, 200);
  assert.deepEqual(second, first);
  assert.deepEqual(JSON.parse(first.body), { status: 'accepted_delivery_only' });
  assert.equal(items.size, 1);
  assert.deepEqual(calls, { links: 2, puts: 2, gets: 1 });
});

test('bad signature is rejected before the account mapping or ledger is read', async () => {
  const { handler, calls, items } = dependencies();
  const changed = event();
  changed.body = Buffer.from(Buffer.from(changed.body, 'base64').toString('utf8') + ' ').toString('base64');
  const response = await handler(changed);
  assert.equal(response.statusCode, 401);
  assert.deepEqual(calls, { links: 0, puts: 0, gets: 0 });
  assert.equal(items.size, 0);
});

test('unsupported route or gateway shape cannot reach the mapping or ledger', async () => {
  const { handler, calls } = dependencies();
  const wrongPath = event();
  wrongPath.path = '/ring/token-exchange';
  assert.equal((await handler(wrongPath)).statusCode, 404);
  const v2 = event();
  v2.version = '2.0';
  assert.equal((await handler(v2)).statusCode, 400);
  assert.deepEqual(calls, { links: 0, puts: 0, gets: 0 });
});

test('unlinked device and storage outage fail closed without an accepted receipt', async () => {
  const unlinked = dependencies({ linked: false });
  assert.equal((await unlinked.handler(event())).statusCode, 403);
  assert.deepEqual(unlinked.calls, { links: 1, puts: 0, gets: 0 });
  const outage = dependencies({ failPut: true });
  assert.equal((await outage.handler(event())).statusCode, 503);
  assert.deepEqual(outage.calls, { links: 1, puts: 1, gets: 0 });
});

test('revoked, expired or unavailable link records cannot produce an accepted delivery', async () => {
  for (const option of [{ revoked: true }, { expired: true }]) {
    const denied = dependencies(option);
    assert.equal((await denied.handler(event())).statusCode, 403);
    assert.deepEqual(denied.calls, { links: 1, puts: 0, gets: 0 });
  }
  const unavailable = dependencies({ failLink: true });
  assert.equal((await unavailable.handler(event())).statusCode, 503);
  assert.deepEqual(unavailable.calls, { links: 1, puts: 0, gets: 0 });
});

test('an exact late retry is acknowledged from durable identity; a new stale event is rejected', async () => {
  const { handler, calls, items, time } = dependencies();
  assert.equal((await handler(event())).statusCode, 200);
  time.now += 3_600_000;
  assert.equal((await handler(event())).statusCode, 200);
  assert.deepEqual(calls, { links: 2, puts: 1, gets: 1 });
  const freshBody = JSON.parse(Buffer.from(event().body, 'base64').toString('utf8'));
  freshBody.meta.request_id = 'handler-new-stale-request';
  assert.equal((await handler(event(Buffer.from(JSON.stringify(freshBody))))).statusCode, 400);
  assert.deepEqual(calls, { links: 3, puts: 1, gets: 2 });
  assert.equal(items.size, 1);
});

test('missing signature is unauthorized and a weak signing key cannot configure the handler', async () => {
  const { handler, calls } = dependencies();
  const missing = event();
  delete missing.multiValueHeaders['X-Signature'];
  assert.equal((await handler(missing)).statusCode, 401);
  assert.deepEqual(calls, { links: 0, puts: 0, gets: 0 });
  assert.throws(() => createWebhookHttpHandler({
    signingKey: 'x', isLinkedDevice: async () => true, ledger: { acceptWebhook: async () => ({ duplicate: false }) }
  }), /signing_key_config/);
});

test('one request AbortSignal reaches linked-device authorization and durable ledger', async () => {
  const observed = [];
  const controller = new AbortController();
  const handler = createWebhookHttpHandler({
    signingKey,
    clock: () => now,
    async isLinkedDevice(_account, _device, options) {
      observed.push(options.signal);
      return true;
    },
    ledger: {
      async acceptWebhook(_request, _account, _body, options) {
        observed.push(options.signal);
        return { duplicate: false };
      }
    }
  });
  assert.equal((await handler(event(), { signal: controller.signal })).statusCode, 200);
  assert.deepEqual(observed, [controller.signal, controller.signal]);
});
