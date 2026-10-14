import assert from 'node:assert/strict';
import test from 'node:test';
import { createSimulator } from '../src/core.mjs';

const START = 1_800_000_000_000;

function fixture() {
  let current = START;
  const simulator = createSimulator({ now: () => current });
  function pair(deviceId) {
    const claim = simulator.beginPair({ actor: 'owner', deviceId });
    simulator.completePair({ actor: 'owner', deviceId, code: claim.code });
  }
  function state(deviceId) {
    return simulator.getState().devices.find((device) => device.id === deviceId).state;
  }
  return {
    simulator,
    pair,
    state,
    advance(milliseconds) { current += milliseconds; },
  };
}

test('paired command uses a fresh virtual gateway proof and reports simulator-only receipt', () => {
  const { simulator, pair, state } = fixture();
  pair('living_light');
  const result = simulator.perform({ actor: 'owner', deviceId: 'living_light', action: 'on' });
  assert.equal(result.status, 'simulated_applied');
  assert.equal(result.delivery, 'simulated_wifi');
  assert.equal(result.receipt.commandId, result.commandId);
  assert.equal(result.receipt.gatewayAck, true);
  assert.equal(result.receipt.deviceObserved, false);
  assert.equal(result.receipt.signalSent, true);
  assert.equal(state('living_light').power, true);
  assert.equal(simulator.getState().edge.gatewayId, 'virtual_esp32c3');
});

test('offline low-risk command queues without state change and recovery applies it once', () => {
  const { simulator, pair, state } = fixture();
  pair('living_light');
  simulator.setEdgeOnline({ actor: 'owner', online: false });
  const queued = simulator.perform({ actor: 'owner', deviceId: 'living_light', action: 'on',
    commandId: 'light-cmd-0001' });
  assert.equal(queued.status, 'queued');
  assert.equal(queued.receipt, null);
  assert.equal(state('living_light').power, false);
  assert.equal(simulator.getState().edge.pendingCount, 1);
  const recovery = simulator.setEdgeOnline({ actor: 'owner', online: true });
  assert.equal(recovery.applied.length, 1);
  assert.equal(recovery.applied[0].status, 'simulated_applied');
  assert.equal(state('living_light').power, true);
  assert.equal(simulator.getState().edge.pendingCount, 0);
  const duplicate = simulator.perform({ actor: 'owner', deviceId: 'living_light', action: 'on',
    commandId: 'light-cmd-0001' });
  assert.equal(duplicate.replayed, true);
  assert.equal(duplicate.receipt.commandId, queued.commandId);
  assert.equal(simulator.getState().audit.filter((entry) => entry.commandId === queued.commandId
    && entry.outcome === 'applied').length, 1);
});

test('expired queued command never applies on recovery and is visible as expired', () => {
  const { simulator, pair, state, advance } = fixture();
  pair('air_conditioner');
  simulator.setEdgeOnline({ actor: 'owner', online: false });
  const queued = simulator.perform({ actor: 'owner', deviceId: 'air_conditioner', action: 'on',
    commandId: 'climate-cmd-01' });
  advance(120_001);
  const edge = simulator.getState().edge;
  assert.equal(edge.pendingCount, 0);
  assert.equal(edge.receipts.at(-1).status, 'expired');
  assert.equal(edge.receipts.at(-1).commandId, queued.commandId);
  assert.equal(simulator.setEdgeOnline({ actor: 'owner', online: true }).applied.length, 0);
  assert.equal(state('air_conditioner').power, false);
  const replay = simulator.perform({ actor: 'owner', deviceId: 'air_conditioner', action: 'on',
    commandId: 'climate-cmd-01' });
  assert.equal(replay.status, 'expired');
  assert.equal(replay.replayed, true);
});

test('simulated no-ack queues and heartbeat flushes after fault clears', () => {
  const { simulator, pair, state } = fixture();
  pair('dehumidifier');
  simulator.setEdgeFault({ actor: 'owner', deviceId: 'dehumidifier', mode: 'no_ack' });
  const result = simulator.perform({ actor: 'owner', deviceId: 'dehumidifier', action: 'on' });
  assert.equal(result.status, 'queued');
  assert.equal(state('dehumidifier').power, false);
  simulator.setEdgeFault({ actor: 'owner', deviceId: 'dehumidifier', mode: 'none' });
  const beat = simulator.heartbeat({ actor: 'owner' });
  assert.equal(beat.applied.length, 1);
  assert.equal(state('dehumidifier').power, true);
});

test('bad device HMAC fails closed and keeps virtual state unchanged', () => {
  const { simulator, pair, state } = fixture();
  pair('living_light');
  simulator.setEdgeFault({ actor: 'owner', deviceId: 'living_light', mode: 'bad_hmac' });
  assert.throws(() => simulator.perform({ actor: 'owner', deviceId: 'living_light', action: 'on' }),
    { code: 'EDGE_AUTH_DENIED' });
  assert.equal(state('living_light').power, false);
  assert.equal(simulator.getState().edge.pendingCount, 0);
  assert.equal(simulator.getState().edge.receipts.at(-1).status, 'denied');
});

test('door unlock and camera disarm fail closed while offline and are never queued', () => {
  const { simulator, pair, state } = fixture();
  pair('front_door');
  pair('camera');
  simulator.setEdgeOnline({ actor: 'owner', online: false });
  assert.throws(() => simulator.perform({ actor: 'owner', deviceId: 'front_door', action: 'unlock' }),
    { code: 'EDGE_OFFLINE_UNSAFE' });
  assert.throws(() => simulator.perform({ actor: 'owner', deviceId: 'camera', action: 'disarm' }),
    { code: 'EDGE_OFFLINE_UNSAFE' });
  assert.equal(state('front_door').locked, true);
  assert.equal(state('camera').armed, false);
  assert.equal(simulator.getState().edge.pendingCount, 0);
});

test('batch isolates each device result and excludes unsafe actions', () => {
  const { simulator, pair, state } = fixture();
  pair('living_light');
  pair('front_door');
  const batch = simulator.performBatch({ actor: 'owner', commands: [
    { deviceId: 'living_light', action: 'on' },
    { deviceId: 'air_conditioner', action: 'on' },
    { deviceId: 'front_door', action: 'unlock' },
  ] });
  assert.deepEqual(batch.results.map((result) => result.status),
    ['simulated_applied', 'denied', 'denied']);
  assert.equal(batch.results[1].code, 'DEVICE_NOT_PAIRED');
  assert.equal(batch.results[2].code, 'BATCH_UNSAFE');
  assert.equal(state('living_light').power, true);
  assert.equal(state('air_conditioner').power, false);
  assert.equal(state('front_door').locked, true);
  assert.throws(() => simulator.performBatch({ actor: 'owner', commands: [
    { deviceId: 'living_light', action: 'off' },
    { deviceId: 'living_light', action: 'on' },
  ] }), { code: 'INVALID_BATCH' });
});

test('tick updates online heartbeat without audit spam and stops while offline', () => {
  const { simulator, advance } = fixture();
  const first = simulator.getState().edge.lastHeartbeatAt;
  const initialAudit = simulator.getState().audit.length;
  advance(5_001);
  simulator.tick();
  const second = simulator.getState().edge.lastHeartbeatAt;
  assert.notEqual(second, first);
  assert.equal(simulator.getState().edge.heartbeatFresh, true);
  assert.equal(simulator.getState().audit.length, initialAudit);
  simulator.setEdgeOnline({ actor: 'owner', online: false });
  advance(10_000);
  simulator.tick();
  assert.equal(simulator.getState().edge.lastHeartbeatAt, second);
  assert.equal(simulator.getState().edge.heartbeatFresh, false);
});

test('stale heartbeat queues a command until periodic tick renews the virtual gateway', () => {
  const { simulator, pair, state, advance } = fixture();
  pair('living_light');
  advance(15_001);
  assert.equal(simulator.getState().edge.heartbeatFresh, false);
  const pending = simulator.perform({ actor: 'owner', deviceId: 'living_light', action: 'on' });
  assert.equal(pending.status, 'queued');
  assert.equal(state('living_light').power, false);
  simulator.tick();
  assert.equal(simulator.getState().edge.heartbeatFresh, true);
  assert.equal(simulator.getState().edge.pendingCount, 0);
  assert.equal(state('living_light').power, true);
});

test('offline due schedule reports queued rather than executed', () => {
  const { simulator, pair, state, advance } = fixture();
  pair('living_light');
  simulator.addSchedule({ actor: 'owner', deviceId: 'living_light', action: 'on',
    at: new Date(START + 5_000).toISOString() });
  simulator.setEdgeOnline({ actor: 'owner', online: false });
  advance(5_001);
  const result = simulator.tick();
  assert.equal(result.executed.length, 0);
  assert.equal(result.queued.length, 1);
  assert.equal(state('living_light').power, false);
});
