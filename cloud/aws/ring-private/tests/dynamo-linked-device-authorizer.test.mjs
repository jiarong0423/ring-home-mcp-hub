import test from 'node:test';
import assert from 'node:assert/strict';
import { createDynamoLinkedDeviceAuthorizer } from '../dynamo-linked-device-authorizer.mjs';

const now = Date.parse('2026-09-29T12:00:00Z');
const hashKey = Buffer.from('generated-linked-device-key-for-offline-tests-only');
const accountId = 'ava1.ring.account.generated-test';
const deviceId = 'ava1.ring.device.generated-test';

function item(pk, changes = {}) {
  return {
    pk: { S: pk },
    status: { S: 'completed' },
    grant_version: { N: '2' },
    expires_at: { N: String(Math.floor(now / 1000) + 3600) },
    revoked: { BOOL: false },
    ...changes
  };
}

function fixture({ read = input => ({ Item: item(input.Key.pk.S) }), clock = () => now } = {}) {
  const calls = [];
  const authorizer = createDynamoLinkedDeviceAuthorizer({
    getItem: async input => {
      calls.push(input);
      return read(input);
    },
    tableName: 'GeneratedLinkedDevices',
    hashKey,
    clock
  });
  return { authorizer, calls };
}

test('completed unrevoked positive-version fresh grant is read strongly and allows only its hashed composite key', async () => {
  const { authorizer, calls } = fixture();
  assert.equal(await authorizer.isLinkedDevice(accountId, deviceId), true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].TableName, 'GeneratedLinkedDevices');
  assert.equal(calls[0].ConsistentRead, true);
  assert.deepEqual(Object.keys(calls[0]), ['TableName', 'Key', 'ConsistentRead']);
  assert.match(calls[0].Key.pk.S, /^[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(calls[0]).includes(accountId), false);
  assert.equal(JSON.stringify(calls[0]).includes(deviceId), false);
  assert.equal(Object.hasOwn(authorizer, 'putItem'), false);
});

test('missing record and an unlinked account or device return false', async () => {
  const missing = fixture({ read: () => ({}) });
  assert.equal(await missing.authorizer.isLinkedDevice(accountId, deviceId), false);
  const known = fixture();
  await known.authorizer.isLinkedDevice(accountId, deviceId);
  const approvedKey = known.calls[0].Key.pk.S;
  const selected = fixture({ read: input => input.Key.pk.S === approvedKey ? { Item: item(approvedKey) } : {} });
  assert.equal(await selected.authorizer.isLinkedDevice(accountId, deviceId), true);
  assert.equal(await selected.authorizer.isLinkedDevice('ava1.ring.account.other', deviceId), false);
  assert.equal(await selected.authorizer.isLinkedDevice(accountId, 'ava1.ring.device.other'), false);
});

test('pending, revoked and expired records deny even if DynamoDB TTL has not deleted the item', async () => {
  for (const change of [
    { status: { S: 'pending' } },
    { status: { S: 'revoked' } },
    { revoked: { BOOL: true } },
    { expires_at: { N: String(Math.floor(now / 1000)) } }
  ]) {
    const { authorizer } = fixture({ read: input => ({ Item: item(input.Key.pk.S, change) }) });
    assert.equal(await authorizer.isLinkedDevice(accountId, deviceId), false);
  }
});

test('malformed grant version, expiry, identity and revocation marker fail closed', async () => {
  for (const change of [
    { grant_version: { N: '0' } },
    { grant_version: { N: '1.5' } },
    { grant_version: { N: '9007199254740992' } },
    { expires_at: { N: '-1' } },
    { expires_at: { N: 'NaN' } },
    { revoked: { S: 'false' } },
    { pk: { S: '0'.repeat(64) } }
  ]) {
    const { authorizer } = fixture({ read: input => ({ Item: item(input.Key.pk.S, change) }) });
    await assert.rejects(authorizer.isLinkedDevice(accountId, deviceId), /linked_record_invalid/);
  }
});

test('DynamoDB outage and invalid clock never authorize', async () => {
  const failed = fixture({ read: () => { throw new Error('generated-unavailable'); } });
  await assert.rejects(failed.authorizer.isLinkedDevice(accountId, deviceId), /linked_store_unavailable/);
  const brokenClock = fixture({ clock: () => Number.NaN });
  await assert.rejects(brokenClock.authorizer.isLinkedDevice(accountId, deviceId), /linked_clock_unavailable/);
});

test('bad input and authorizer configuration are rejected without a query', async () => {
  const { authorizer, calls } = fixture();
  await assert.rejects(authorizer.isLinkedDevice('', deviceId), /invalid_field/);
  await assert.rejects(authorizer.isLinkedDevice(accountId, ''), /invalid_field/);
  assert.equal(calls.length, 0);
  assert.throws(() => createDynamoLinkedDeviceAuthorizer({
    getItem: async () => ({}), tableName: 'GeneratedLinkedDevices', hashKey: 'short'
  }), /linked_authorizer_config/);
});
