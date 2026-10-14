import test from 'node:test';
import assert from 'node:assert/strict';
import { createDynamoEventLedger } from '../dynamo-event-ledger.mjs';

const now = Date.parse('2026-09-29T12:00:00Z');
const hashKey = Buffer.from('generated-ledger-hash-key-for-offline-tests-only');
const requestId = 'generated-ring-request';
const accountId = 'generated-ring-account';
const rawBody = Buffer.from('{"generated":"motion","account":"generated-ring-account"}');

function conditionalFailure() {
  return Object.assign(new Error('conditional'), { name: 'ConditionalCheckFailedException' });
}

function fakeDynamo() {
  const items = new Map();
  const requests = [];
  return {
    items,
    requests,
    async putItem(input) {
      requests.push({ op: 'put', input });
      assert.equal(input.TableName, 'GeneratedRingEvents');
      assert.equal(input.ConditionExpression, 'attribute_not_exists(pk)');
      const pk = input.Item.pk.S;
      if (items.has(pk)) throw conditionalFailure();
      items.set(pk, structuredClone(input.Item));
      return {};
    },
    async getItem(input) {
      requests.push({ op: 'get', input });
      assert.equal(input.TableName, 'GeneratedRingEvents');
      assert.equal(input.ConsistentRead, true);
      return { Item: items.get(input.Key.pk.S) };
    }
  };
}

function ledger(dynamo, overrides = {}) {
  return createDynamoEventLedger({
    putItem: dynamo.putItem,
    getItem: dynamo.getItem,
    tableName: 'GeneratedRingEvents',
    hashKey,
    clock: () => now,
    ...overrides
  });
}

test('new webhook writes one conditional pseudonymous item with epoch-second TTL', async () => {
  const dynamo = fakeDynamo();
  assert.deepEqual(await ledger(dynamo).acceptWebhook(requestId, accountId, rawBody), { duplicate: false });
  assert.equal(dynamo.items.size, 1);
  assert.deepEqual(dynamo.requests.map(row => row.op), ['put']);
  const item = [...dynamo.items.values()][0];
  assert.deepEqual(Object.keys(item).sort(), ['account_digest', 'body_digest', 'expires_at', 'pk']);
  for (const field of ['pk', 'account_digest', 'body_digest']) assert.match(item[field].S, /^[0-9a-f]{64}$/);
  assert.equal(item.expires_at.N, String(Math.floor(now / 1000) + 604_800));
  const serialized = JSON.stringify(item);
  assert.equal(serialized.includes(requestId), false);
  assert.equal(serialized.includes(accountId), false);
  assert.equal(serialized.includes(rawBody.toString('utf8')), false);
});

test('exact retry uses a strongly consistent read and returns duplicate without overwrite', async () => {
  const dynamo = fakeDynamo();
  const adapter = ledger(dynamo);
  assert.equal((await adapter.acceptWebhook(requestId, accountId, rawBody)).duplicate, false);
  const first = structuredClone([...dynamo.items.values()][0]);
  assert.deepEqual(await adapter.acceptWebhook(requestId, accountId, rawBody), { duplicate: true });
  assert.deepEqual(dynamo.requests.map(row => row.op), ['put', 'put', 'get']);
  assert.deepEqual([...dynamo.items.values()][0], first);
});

test('same request ID with changed body or account fails after conditional collision', async () => {
  const dynamo = fakeDynamo();
  const adapter = ledger(dynamo);
  await adapter.acceptWebhook(requestId, accountId, rawBody);
  await assert.rejects(adapter.acceptWebhook(requestId, accountId, Buffer.from('{"generated":"other"}')), /event_conflict/);
  await assert.rejects(adapter.acceptWebhook(requestId, 'generated-other-account', rawBody), /event_conflict/);
  assert.equal(dynamo.items.size, 1);
});

test('parallel writers sharing the same table cannot both create the same request', async () => {
  const dynamo = fakeDynamo();
  const first = ledger(dynamo);
  const second = ledger(dynamo);
  const results = await Promise.all([
    first.acceptWebhook(requestId, accountId, rawBody),
    second.acceptWebhook(requestId, accountId, rawBody)
  ]);
  assert.deepEqual(results.map(row => row.duplicate).sort(), [false, true]);
  assert.equal(dynamo.items.size, 1);
  assert.equal(dynamo.requests.filter(row => row.op === 'get').length, 1);
});

test('a second ledger instance sees a prior write; TTL is retention metadata, not a local memory cache', async () => {
  const dynamo = fakeDynamo();
  await ledger(dynamo).acceptWebhook(requestId, accountId, rawBody);
  const restarted = ledger(dynamo);
  assert.deepEqual(await restarted.acceptWebhook(requestId, accountId, rawBody), { duplicate: true });
  assert.equal(dynamo.items.size, 1);
  assert.equal([...dynamo.items.values()][0].expires_at.N, String(Math.floor(now / 1000) + 604_800));
});

test('lookup reads strongly without creating a stale event and rejects a conflicting identity', async () => {
  const dynamo = fakeDynamo();
  const adapter = ledger(dynamo);
  assert.deepEqual(await adapter.lookupWebhook(requestId, accountId, rawBody), { duplicate: false });
  assert.equal(dynamo.items.size, 0);
  await adapter.acceptWebhook(requestId, accountId, rawBody);
  assert.deepEqual(await adapter.lookupWebhook(requestId, accountId, rawBody), { duplicate: true });
  await assert.rejects(adapter.lookupWebhook(requestId, accountId, Buffer.from('changed')), /event_conflict/);
  assert.deepEqual(dynamo.requests.map(row => row.op), ['get', 'put', 'get', 'get']);
});

test('failed PutItem or GetItem and disappearing collision record fail closed', async () => {
  const unavailablePut = ledger({
    async putItem() { throw new Error('network-failure'); },
    async getItem() { throw new Error('should-not-read'); }
  });
  await assert.rejects(unavailablePut.acceptWebhook(requestId, accountId, rawBody), /ledger_unavailable/);

  const unavailableGet = ledger({
    async putItem() { throw conditionalFailure(); },
    async getItem() { throw new Error('network-failure'); }
  });
  await assert.rejects(unavailableGet.acceptWebhook(requestId, accountId, rawBody), /ledger_unavailable/);

  const missingGet = ledger({
    async putItem() { throw conditionalFailure(); },
    async getItem() { return {}; }
  });
  await assert.rejects(missingGet.acceptWebhook(requestId, accountId, rawBody), /ledger_conflict/);
});

test('invalid configuration and input fail before any DynamoDB operation', async () => {
  const dynamo = fakeDynamo();
  assert.throws(() => ledger(dynamo, { hashKey: 'short' }), /ledger_config/);
  assert.throws(() => ledger(dynamo, { ttlSeconds: 30 }), /ledger_config/);
  const adapter = ledger(dynamo);
  await assert.rejects(adapter.acceptWebhook('', accountId, rawBody), /invalid_field/);
  await assert.rejects(adapter.acceptWebhook(requestId, accountId, Buffer.alloc(0)), /invalid_webhook/);
  await assert.rejects(adapter.acceptWebhook(requestId, accountId, Buffer.alloc(65_537)), /invalid_webhook/);
  assert.equal(dynamo.requests.length, 0);
});
