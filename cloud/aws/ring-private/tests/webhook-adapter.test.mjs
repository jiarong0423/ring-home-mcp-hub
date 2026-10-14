import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createWebhookDeliveryAdapter } from '../webhook-adapter.mjs';
import { MemoryRingStore } from '../store.mjs';

const now = Date.parse('2026-09-29T12:00:00Z');
const signingKey = 'generated-webhook-key-for-offline-tests-only';
const accountId = 'ava1.ring.account.generated-test';
const deviceId = 'ava1.ring.device.generated-test';

function payload(overrides = {}) {
  return {
    meta: {
      version: '1.1',
      time: '2026-09-29T11:59:55Z',
      request_id: 'generated-request-1',
      account_id: accountId,
      ...overrides.meta
    },
    data: {
      id: 'generated-event-1',
      type: 'motion_detected',
      attributes: { source: deviceId, source_type: 'devices', timestamp: now - 5_000, ...overrides.attributes },
      ...overrides.data
    }
  };
}

function signedInput(value = payload()) {
  const rawBody = Buffer.from(JSON.stringify(value));
  const signature = `sha256=${createHmac('sha256', signingKey).update(rawBody).digest('hex')}`;
  return { rawBody, rawHeaders: ['Content-Type', 'application/json', 'X-Signature', signature] };
}

function fixture({ store = new MemoryRingStore({ clock: () => now }), linkedDevices = [{ accountId, deviceId }] } = {}) {
  const approved = new Set(linkedDevices.map(row => `${row.accountId}\0${row.deviceId}`));
  const adapter = createWebhookDeliveryAdapter({
    signingKey, authorizeDevice: async (account, device) => approved.has(`${account}\0${device}`),
    store, clock: () => now
  });
  return { adapter, store };
}

test('valid generated Ring-shaped motion records delivery only and never observes or commands a device', async () => {
  const { adapter, store } = fixture();
  const receipt = await adapter.receive(signedInput());
  assert.deepEqual(receipt, { status: 'accepted_delivery_only', duplicate: false, deviceObserved: false });
  assert.equal(store.getSummary().events, 1);
  assert.equal(Object.hasOwn(adapter, 'dispatch'), false);
  assert.equal(Object.hasOwn(adapter, 'execute'), false);
});

test('duplicate X-Signature headers and missing header fail before store access', async () => {
  let calls = 0;
  const store = { async acceptWebhook() { calls += 1; return { duplicate: false }; } };
  const { adapter } = fixture({ store });
  const input = signedInput();
  await assert.rejects(adapter.receive({ ...input, rawHeaders: [...input.rawHeaders, 'x-signature', input.rawHeaders[3]] }), /duplicate_signature/);
  await assert.rejects(adapter.receive({ ...input, rawHeaders: ['Content-Type', 'application/json'] }), /missing_signature/);
  await assert.rejects(adapter.receive({ ...input, rawHeaders: ['X-Signature', `${input.rawHeaders[3]}, ${input.rawHeaders[3]}`] }), /invalid_signature/);
  assert.equal(calls, 0);
});

test('body mutation with the original signature is rejected with zero store writes', async () => {
  const { adapter, store } = fixture();
  const input = signedInput();
  await assert.rejects(adapter.receive({ ...input, rawBody: Buffer.from(`${input.rawBody} `) }), /invalid_signature/);
  assert.equal(store.getSummary().events, 0);
});

test('signed motion from a wrong account or device is denied before replay reservation', async () => {
  const { adapter, store } = fixture();
  await assert.rejects(adapter.receive(signedInput(payload({ meta: { account_id: 'ava1.ring.account.other' } }))), /device_not_linked/);
  await assert.rejects(adapter.receive(signedInput(payload({ attributes: { source: 'ava1.ring.device.other' } }))), /device_not_linked/);
  assert.equal(store.getSummary().events, 0);
});

test('signed non-motion or wrong source type cannot enter the delivery ledger', async () => {
  const { adapter, store } = fixture();
  await assert.rejects(adapter.receive(signedInput(payload({ data: { type: 'device_removed' } }))), /event_not_allowed/);
  await assert.rejects(adapter.receive(signedInput(payload({ attributes: { source_type: 'accounts' } }))), /event_not_allowed/);
  assert.equal(store.getSummary().events, 0);
});

test('stale and future sent or event timestamps fail closed', async () => {
  const { adapter, store } = fixture();
  await assert.rejects(adapter.receive(signedInput(payload({ meta: { time: '2026-09-29T11:54:59Z' } }))), /stale_event/);
  await assert.rejects(adapter.receive(signedInput(payload({ meta: { time: '2026-09-29T12:01:01Z' } }))), /stale_event/);
  await assert.rejects(adapter.receive(signedInput(payload({ attributes: { timestamp: now - 300_001 } }))), /stale_event/);
  await assert.rejects(adapter.receive(signedInput(payload({ attributes: { timestamp: now + 60_001 } }))), /stale_event/);
  await assert.rejects(adapter.receive(signedInput(payload({ attributes: { timestamp: 'not-a-number' } }))), /invalid_event_time/);
  assert.equal(store.getSummary().events, 0);
});

test('exact retry is idempotent; signed conflicting body with the same request ID is denied', async () => {
  const { adapter, store } = fixture();
  const input = signedInput();
  assert.equal((await adapter.receive(input)).duplicate, false);
  assert.equal((await adapter.receive(input)).duplicate, true);
  await assert.rejects(adapter.receive(signedInput(payload({ data: { id: 'generated-event-2' } }))), /event_conflict/);
  assert.equal(store.getSummary().events, 1);
});

test('injected store failure and invalid store receipt fail closed', async () => {
  const failing = fixture({ store: { async acceptWebhook() { throw new Error('store_unavailable'); } } });
  await assert.rejects(failing.adapter.receive(signedInput()), /store_unavailable/);
  const malformed = fixture({ store: { async acceptWebhook() { return { duplicate: 'no' }; } } });
  await assert.rejects(malformed.adapter.receive(signedInput()), /store_receipt_invalid/);
});

test('test authorization callback is copied at construction and missing callback is rejected', async () => {
  const linkedDevices = [{ accountId, deviceId }];
  const { adapter } = fixture({ linkedDevices });
  linkedDevices[0].deviceId = 'ava1.ring.device.other';
  assert.equal((await adapter.receive(signedInput())).status, 'accepted_delivery_only');
  assert.throws(() => createWebhookDeliveryAdapter({
    signingKey, store: new MemoryRingStore()
  }), /adapter_config/);
  assert.throws(() => createWebhookDeliveryAdapter({
    signingKey: 'x', authorizeDevice: async () => true, store: new MemoryRingStore()
  }), /signing_key_config/);
});
