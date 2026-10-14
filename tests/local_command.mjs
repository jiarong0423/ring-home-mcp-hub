import test from 'node:test';
import assert from 'node:assert/strict';
import { createLocalRingRuntime } from '../src/local_ring/runtime.mjs';

const BASE = 1_800_000_000_000;

function harness(options = {}) {
  let current = BASE;
  let linked = false;
  let revoked = false;
  let loggedOut = false;
  let epoch = 1;
  let authorizationHook = async () => {};
  let deadline = BASE + 600_000;
  const ringConfig = Object.freeze({
    enabled: true, accountId: 'generated-local-account', sourceId: 'generated-local-source',
    sourceType: 'devices', homeId: 'generated-local-home', grantVersion: '1',
    expiresAtMs: BASE + 3_600_000,
  });
  function deny(code, status = 403) {
    const error = new Error(code);
    error.code = code;
    error.status = status;
    throw error;
  }
  const binding = {
    ringConfig,
    async link() { linked = true; },
    async authorize() {
      await authorizationHook();
      if (!linked) deny('LOCAL_IDENTITY_UNLINKED');
      if (revoked) deny('LOCAL_IDENTITY_REVOKED');
      if (loggedOut) deny('LOCAL_IDENTITY_LOGGED_OUT');
      if (current >= deadline) deny('LOCAL_IDENTITY_EXPIRED', 410);
      return Object.freeze({ actorId: 'owner', accountId: ringConfig.accountId,
        sourceId: ringConfig.sourceId, homeId: ringConfig.homeId, grantVersion: '1',
        accountEpoch: epoch, expiresAtMs: deadline });
    },
    async remove() { revoked = true; epoch += 1; },
    async logout() { loggedOut = true; },
    status() { return { mode: 'generated', linked, revoked, loggedOut }; },
  };
  const runtime = createLocalRingRuntime({ now: () => current, binding, ...options });
  const state = () => runtime.simulator.getState();
  const applied = () => state().audit.filter((entry) => entry.origin === 'ring' && entry.outcome === 'applied');
  return {
    runtime, state, applied,
    setTime(value) { current = value; },
    setDeadline(value) { deadline = value; },
    setEpoch(value) { epoch = value; },
    setAuthorizationHook(value) { authorizationHook = value; },
  };
}

function gate() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

test('LC-COMMAND valid queue then worker produces correlated virtual receipt', async () => {
  const h = harness();
  await h.runtime.link();
  assert.equal(h.state().devices.length, 7);
  const queued = await h.runtime.motion();
  assert.equal(queued.status, 'queued');
  assert.equal(queued.receipt, null);
  assert.equal(h.applied().length, 0);
  const result = await h.runtime.runWorker();
  const row = result.commands[0];
  assert.equal(row.status, 'executed_in_simulator');
  assert.equal(row.commandId, queued.commandId);
  assert.equal(row.receipt.commandId, queued.commandId);
  assert.equal(row.receipt.requestId, queued.requestId);
  assert.equal(row.receipt.edgeCommandId, h.applied()[0].commandId);
  assert.equal(row.receipt.auditId, h.applied()[0].id);
  assert.equal(row.receipt.deviceObserved, false);
  assert.equal(h.applied().length, 1);
  assert.equal(h.state().devices.find((device) => device.id === 'living_light').state.power, true);
});

test('LC-COMMAND concurrent duplicates reserve one row before awaited authority', async () => {
  const h = harness();
  await h.runtime.link();
  const paused = gate();
  h.setAuthorizationHook(() => paused.promise);
  const envelope = h.runtime.buildSyntheticEvent();
  const first = h.runtime.receive(envelope);
  const second = h.runtime.receive(envelope);
  assert.equal(h.runtime.status().commands.length, 1);
  assert.equal(h.runtime.status().commands[0].status, 'accepted');
  paused.resolve();
  const [a, b] = await Promise.all([first, second]);
  assert.equal(a.commandId, b.commandId);
  assert.equal(b.replayed, true);
  await h.runtime.runWorker();
  assert.equal(h.applied().length, 1);
  const replay = await h.runtime.receive(envelope);
  assert.equal(replay.receipt.auditId, h.applied()[0].id);
  await h.runtime.runWorker();
  assert.equal(h.applied().length, 1);
});

test('LC-COMMAND same request with independently signed different body is conflict', async () => {
  const h = harness();
  await h.runtime.link();
  await h.runtime.receive(h.runtime.buildSyntheticEvent({ requestId: 'same-request', eventId: 'first-event' }));
  await assert.rejects(h.runtime.receive(h.runtime.buildSyntheticEvent({ requestId: 'same-request', eventId: 'second-event' })),
    { code: 'LOCAL_REQUEST_BODY_CONFLICT' });
  assert.equal(h.runtime.status().commands.length, 1);
  assert.equal(h.applied().length, 0);
});

test('LC-COMMAND altered raw body does not reserve a command', async () => {
  const h = harness();
  await h.runtime.link();
  const event = h.runtime.buildSyntheticEvent();
  await assert.rejects(h.runtime.receive({ rawBody: Buffer.concat([event.rawBody, Buffer.from(' ')]), signature: event.signature }),
    { code: 'RING_SIGNATURE_INVALID' });
  assert.equal(h.runtime.status().commands.length, 0);
  assert.equal(h.applied().length, 0);
});

test('LC-COMMAND wrong signature denies before account authority', async () => {
  const h = harness();
  await h.runtime.link();
  let calls = 0;
  h.setAuthorizationHook(async () => { calls += 1; });
  const event = h.runtime.buildSyntheticEvent();
  await assert.rejects(h.runtime.receive({ rawBody: event.rawBody, signature: 'sha256=' + '0'.repeat(64) }),
    { code: 'RING_SIGNATURE_INVALID' });
  assert.equal(calls, 0);
  assert.equal(h.runtime.status().commands.length, 0);
});

for (const [name, override] of [
  ['account', { accountId: 'other-generated-account' }],
  ['source', { sourceId: 'other-generated-source' }],
  ['source type', { sourceType: 'users' }],
  ['event type', { eventType: 'app_integration_removed' }],
]) {
  test(`LC-COMMAND signed wrong ${name} produces zero action`, async () => {
    const h = harness();
    await h.runtime.link();
    await assert.rejects(h.runtime.receive(h.runtime.buildSyntheticEvent(override)), { code: 'LOCAL_EVENT_NOT_ALLOWED' });
    assert.equal(h.runtime.status().commands.length, 0);
    assert.equal(h.applied().length, 0);
  });
}

test('LC-COMMAND stale equality and future beyond limit are rejected', async () => {
  const h = harness();
  await h.runtime.link();
  for (const override of [{ eventAtMs: BASE - 300_000 }, { eventAtMs: BASE + 60_001 }, { sentAtMs: BASE + 60_001 }]) {
    await assert.rejects(h.runtime.receive(h.runtime.buildSyntheticEvent(override)), { code: 'LOCAL_EVENT_STALE' });
  }
  assert.equal(h.runtime.status().commands.length, 0);
});

test('LC-COMMAND event fields cannot redirect to door unlock or camera disarm', async () => {
  const h = harness();
  await h.runtime.link();
  for (const override of [{ targetDeviceId: 'front_door', action: 'unlock' }, { targetDeviceId: 'camera', action: 'disarm' }]) {
    await h.runtime.receive(h.runtime.buildSyntheticEvent(override));
  }
  await h.runtime.runWorker();
  assert.equal(h.applied().length, 2);
  assert.ok(h.applied().every((entry) => entry.deviceId === 'living_light' && entry.action === 'on'));
  assert.equal(h.state().devices.find((device) => device.id === 'front_door').state.locked, true);
  assert.equal(h.state().devices.find((device) => device.id === 'camera').state.armed, false);
});

test('LC-COMMAND worker offline retains queue and recovery executes once', async () => {
  const h = harness();
  await h.runtime.link();
  await h.runtime.motion();
  h.runtime.setWorkerOnline(false);
  const offline = await h.runtime.runWorker();
  assert.equal(offline.commands[0].status, 'queued');
  assert.equal(h.applied().length, 0);
  assert.equal(h.state().edge.pendingCount, 0);
  h.runtime.setWorkerOnline(true);
  await h.runtime.runWorker();
  await h.runtime.runWorker();
  assert.equal(h.applied().length, 1);
});

test('LC-COMMAND underlying edge offline produces no core Ring fallback queue', async () => {
  const h = harness();
  await h.runtime.link();
  await h.runtime.motion();
  h.runtime.simulator.setEdgeOnline({ actor: 'owner', online: false });
  await h.runtime.runWorker();
  assert.equal(h.runtime.status().commands[0].status, 'queued');
  assert.equal(h.state().edge.pendingCount, 0);
  h.runtime.simulator.setEdgeOnline({ actor: 'owner', online: true });
  assert.equal(h.applied().length, 0);
  await h.runtime.runWorker();
  assert.equal(h.applied().length, 1);
});

test('LC-COMMAND no-ack core fault cannot bypass authority through fallback flush', async () => {
  const h = harness();
  await h.runtime.link();
  await h.runtime.motion();
  h.runtime.simulator.setEdgeFault({ actor: 'owner', deviceId: 'living_light', mode: 'no_ack' });
  await h.runtime.runWorker();
  assert.equal(h.runtime.status().commands[0].status, 'denied');
  assert.equal(h.runtime.status().commands[0].code, 'LOCAL_EDGE_NOT_READY');
  assert.equal(h.state().edge.pendingCount, 0);
  await h.runtime.remove();
  h.runtime.simulator.setEdgeFault({ actor: 'owner', deviceId: 'living_light', mode: 'none' });
  h.runtime.simulator.heartbeat({ actor: 'owner' });
  assert.equal(h.applied().length, 0);
});

test('LC-COMMAND queued command expires at equality before reconnect', async () => {
  const h = harness();
  await h.runtime.link();
  await h.runtime.motion();
  h.runtime.setWorkerOnline(false);
  h.setTime(BASE + 120_000);
  h.runtime.setWorkerOnline(true);
  await h.runtime.runWorker();
  assert.equal(h.runtime.status().commands[0].status, 'expired');
  assert.equal(h.runtime.status().commands[0].code, 'LOCAL_COMMAND_EXPIRED');
  assert.equal(h.applied().length, 0);
});

for (const [method, code] of [['remove', 'LOCAL_IDENTITY_REVOKED'], ['logout', 'LOCAL_IDENTITY_LOGGED_OUT']]) {
  test(`LC-COMMAND queued command stops after ${method}`, async () => {
    const h = harness();
    await h.runtime.link();
    const queued = await h.runtime.motion();
    await h.runtime[method]();
    await h.runtime.runWorker();
    const row = h.runtime.status().commands[0];
    assert.equal(row.commandId, queued.commandId);
    assert.equal(row.status, 'denied');
    assert.equal(row.code, code);
    assert.equal(h.applied().length, 0);
    assert.equal(h.runtime.status().commands.length, 1);
  });
}

test('LC-COMMAND authority epoch changed during await denies final dispatch', async () => {
  let h;
  h = harness({ beforeExecute: async () => { h.setEpoch(2); } });
  await h.runtime.link();
  await h.runtime.motion();
  await h.runtime.runWorker();
  assert.equal(h.runtime.status().commands[0].code, 'LOCAL_AUTHORITY_CHANGED');
  assert.equal(h.applied().length, 0);
});

test('LC-COMMAND grant deadline equality after async hook denies apply', async () => {
  let h;
  h = harness({ beforeExecute: async () => { h.setTime(BASE + 1_000); } });
  h.setDeadline(BASE + 1_000);
  await h.runtime.link();
  await h.runtime.motion();
  await h.runtime.runWorker();
  assert.equal(h.runtime.status().commands[0].status, 'expired');
  assert.equal(h.runtime.status().commands[0].code, 'LOCAL_IDENTITY_EXPIRED');
  assert.equal(h.applied().length, 0);
});

test('LC-COMMAND revoke while applying async hook denies final dispatch', async () => {
  const paused = gate();
  const entered = gate();
  const h = harness({ beforeExecute: async () => { entered.resolve(); await paused.promise; } });
  await h.runtime.link();
  await h.runtime.motion();
  const work = h.runtime.runWorker();
  await entered.promise;
  assert.equal(h.runtime.status().commands[0].status, 'applying');
  await h.runtime.remove();
  paused.resolve();
  await work;
  assert.equal(h.runtime.status().commands[0].code, 'LOCAL_IDENTITY_REVOKED');
  assert.equal(h.applied().length, 0);
});

test('LC-COMMAND concurrent worker invocations share one applying transition', async () => {
  const paused = gate();
  const entered = gate();
  let executions = 0;
  const h = harness({ beforeExecute: async () => { executions += 1; entered.resolve(); await paused.promise; } });
  await h.runtime.link();
  await h.runtime.motion();
  const first = h.runtime.runWorker();
  await entered.promise;
  const second = h.runtime.runWorker();
  assert.equal(first, second);
  paused.resolve();
  await Promise.all([first, second]);
  assert.equal(executions, 1);
  assert.equal(h.applied().length, 1);
});

test('LC-COMMAND ACK lost after actual virtual apply remains unconfirmed and never redispatches', async () => {
  const h = harness({ loseAck: true });
  await h.runtime.link();
  const envelope = h.runtime.buildSyntheticEvent();
  await h.runtime.receive(envelope);
  await h.runtime.runWorker();
  assert.equal(h.applied().length, 1);
  const row = h.runtime.status().commands[0];
  assert.equal(row.status, 'execution_unconfirmed');
  assert.equal(row.code, 'LOCAL_ACK_MISSING');
  assert.equal(row.receipt, null);
  const replay = await h.runtime.receive(envelope);
  assert.equal(replay.status, 'execution_unconfirmed');
  await h.runtime.runWorker();
  assert.equal(h.applied().length, 1);
});

test('LC-COMMAND finite command capacity retains replay identity and fails closed', async () => {
  const h = harness({ maxCommands: 1 });
  await h.runtime.link();
  const envelope = h.runtime.buildSyntheticEvent();
  await h.runtime.receive(envelope);
  await h.runtime.runWorker();
  await assert.rejects(h.runtime.motion(), { code: 'LOCAL_COMMAND_CAPACITY' });
  const replay = await h.runtime.receive(envelope);
  assert.equal(replay.status, 'executed_in_simulator');
  assert.equal(h.runtime.status().commands.length, 1);
  assert.equal(h.applied().length, 1);
});

test('LC-COMMAND backwards clock during worker fails without action', async () => {
  let h;
  h = harness({ beforeExecute: async () => { h.setTime(BASE - 1); } });
  await h.runtime.link();
  await h.runtime.motion();
  await h.runtime.runWorker();
  assert.equal(h.runtime.status().commands[0].code, 'LOCAL_CLOCK_INVALID');
  h.setTime(BASE);
  assert.equal(h.applied().length, 0);
});

test('LC-COMMAND safe status exposes no raw account, source, secret or credential', async () => {
  const h = harness();
  await h.runtime.link();
  await h.runtime.motion();
  await h.runtime.runWorker();
  const output = JSON.stringify(h.runtime.status());
  for (const forbidden of ['generated-local-account', 'generated-local-source', 'rawBody', 'signature', 'idToken', 'csrfToken', 'cookie']) {
    assert.equal(output.includes(forbidden), false);
  }
  assert.throws(() => h.runtime.simulator.performRingMotion({}), { code: 'LOCAL_RUNTIME_INGRESS_REQUIRED' });
});

test('LC-COMMAND actual generated strict-v1 identity and lifecycle compose into one receipt', async () => {
  const runtime = createLocalRingRuntime({ now: () => BASE });
  await runtime.link();
  const queued = await runtime.motion();
  assert.equal(queued.status, 'queued');
  const result = await runtime.runWorker();
  assert.equal(result.mode, 'local_simulation');
  assert.equal(result.commands[0].status, 'executed_in_simulator');
  assert.equal(result.commands[0].receipt.commandId, queued.commandId);
  const applied = runtime.simulator.getState().audit.filter((entry) => entry.origin === 'ring' && entry.outcome === 'applied');
  assert.equal(applied.length, 1);
  assert.equal(result.commands[0].receipt.auditId, applied[0].id);
  assert.equal(runtime.simulator.getState().edge.pendingCount, 0);
});

test('LC-COMMAND actual signed removal during worker hook blocks generated authority', async () => {
  let runtime;
  runtime = createLocalRingRuntime({ now: () => BASE,
    beforeExecute: async () => { await runtime.remove(); } });
  await runtime.link();
  await runtime.motion();
  await runtime.runWorker();
  assert.equal(runtime.status().commands[0].status, 'denied');
  assert.equal(runtime.status().commands[0].code, 'LOCAL_IDENTITY_REVOKED');
  assert.equal(runtime.simulator.getState().audit.filter((entry) => entry.origin === 'ring' && entry.outcome === 'applied').length, 0);
  assert.equal(runtime.simulator.getState().edge.pendingCount, 0);
});

test('LC-COMMAND actual generated session idle equality is expired after await', async () => {
  let current = BASE;
  const runtime = createLocalRingRuntime({ now: () => current,
    beforeExecute: async () => { current = BASE + 900_000; } });
  await runtime.link();
  await runtime.motion();
  await runtime.runWorker();
  assert.equal(runtime.status().commands[0].status, 'expired');
  assert.equal(runtime.status().commands[0].code, 'LOCAL_IDENTITY_EXPIRED');
  assert.equal(runtime.simulator.getState().audit.filter((entry) => entry.origin === 'ring' && entry.outcome === 'applied').length, 0);
});
