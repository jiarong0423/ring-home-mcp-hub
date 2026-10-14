import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const projectDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const serverPath = join(projectDir, 'src/server.mjs');
const ringEnvironmentNames = [
  'HOME_MCP_RING_TEST_ENABLED',
  'HOME_MCP_RING_TEST_SECRET',
  'HOME_MCP_RING_ACCOUNT_ID',
  'HOME_MCP_RING_SOURCE_ID',
  'HOME_MCP_RING_SOURCE_TYPE',
  'HOME_MCP_RING_HOME_ID',
  'HOME_MCP_RING_GRANT_VERSION',
  'HOME_MCP_RING_GRANT_EXPIRES_AT_MS',
];
const children = new Set();

function device(snapshot, id) {
  const found = snapshot.devices.find((item) => item.id === id);
  assert(found, `Missing virtual device ${id}`);
  return found.state;
}

function ringAudit(snapshot, requestId) {
  return snapshot.audit.filter((item) => item.origin === 'ring' && item.requestId === requestId);
}

function motion(context, overrides = {}) {
  const now = Date.now();
  const base = {
    meta: {
      version: '1.1',
      time: new Date(now).toISOString(),
      request_id: randomUUID(),
      account_id: context.accountId,
    },
    data: {
      id: randomUUID(),
      type: 'motion_detected',
      attributes: {
        source: context.sourceId,
        source_type: 'devices',
        timestamp: now,
      },
    },
  };
  return {
    ...base,
    ...overrides,
    meta: { ...base.meta, ...overrides.meta },
    data: {
      ...base.data,
      ...overrides.data,
      attributes: { ...base.data.attributes, ...overrides.data?.attributes },
    },
  };
}

async function request(context, path, { method = 'GET', token, body, rawBody, signature } = {}) {
  const payload = rawBody ?? (body === undefined ? undefined : JSON.stringify(body));
  const headers = {};
  if (payload !== undefined) headers['content-type'] = 'application/json';
  if (token) headers.authorization = `Bearer ${token}`;
  if (signature !== undefined) headers['x-signature'] = signature;
  const response = await fetch(new URL(path, context.base), { method, headers, body: payload });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}

async function signedMotion(context, body) {
  const rawBody = Buffer.from(JSON.stringify(body), 'utf8');
  const signature = `sha256=${createHmac('sha256', context.secret).update(rawBody).digest('hex')}`;
  return request(context, '/api/ring-test-event', { method: 'POST', rawBody, signature });
}

async function snapshot(context) {
  const response = await request(context, '/api/state', { token: context.token });
  assert.equal(response.status, 200);
  return response.body;
}

async function ownerPost(context, path, body) {
  const response = await request(context, path, { method: 'POST', token: context.token, body });
  assert.equal(response.status, 200, `${path} HTTP ${response.status}`);
  return response.body;
}

async function pairLight(context) {
  const started = await ownerPost(context, '/api/pair/start', { deviceId: 'living_light' });
  const completed = await ownerPost(context, '/api/pair/confirm', {
    deviceId: 'living_light', code: started.code,
  });
  assert.equal(completed.paired, true);
}

async function stop(context) {
  const child = context?.child;
  if (!child) return;
  if (child.exitCode === null && child.signalCode === null) {
    const exited = new Promise((resolve) => child.once('exit', resolve));
    child.kill('SIGTERM');
    await exited;
  }
  children.delete(child);
}

async function fixture({ grantLifetimeMs = 60_000 } = {}) {
  const secret = randomBytes(32).toString('base64url');
  const passcode = randomBytes(24).toString('base64url');
  const accountId = `bridge-account-${randomUUID()}`;
  const sourceId = `bridge-source-${randomUUID()}`;
  const homeId = `bridge-home-${randomUUID()}`;
  const environment = { ...process.env };
  for (const name of ringEnvironmentNames) delete environment[name];
  Object.assign(environment, {
    HOME_MCP_PORT: '0',
    HOME_MCP_DEMO_PASS: passcode,
    HOME_MCP_RING_TEST_ENABLED: '1',
    HOME_MCP_RING_TEST_SECRET: secret,
    HOME_MCP_RING_ACCOUNT_ID: accountId,
    HOME_MCP_RING_SOURCE_ID: sourceId,
    HOME_MCP_RING_SOURCE_TYPE: 'devices',
    HOME_MCP_RING_HOME_ID: homeId,
    HOME_MCP_RING_GRANT_VERSION: 'bridge-test-v1',
    HOME_MCP_RING_GRANT_EXPIRES_AT_MS: String(Date.now() + grantLifetimeMs),
  });
  const child = spawn(process.execPath, [serverPath], {
    cwd: projectDir,
    env: environment,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  children.add(child);
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
  let base;
  try {
    base = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Local bridge test server timed out')), 10_000);
      let stdout = '';
      child.stdout.on('data', (chunk) => {
        stdout += chunk.toString();
        const match = /Home MCP simulator: (http:\/\/127\.0\.0\.1:\d+)/.exec(stdout);
        if (match) {
          clearTimeout(timer);
          resolve(match[1]);
        }
      });
      child.once('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
      child.once('exit', (code) => {
        clearTimeout(timer);
        reject(new Error(`Local bridge test server exited before startup: rc=${code}; ${stderr.includes('EPERM') ? 'EPERM' : 'startup failure'}`));
      });
    });
  } catch (error) {
    child.kill('SIGTERM');
    children.delete(child);
    throw error;
  }
  const context = { child, base, secret, accountId, sourceId, homeId, grantExpiresAt: Number(environment.HOME_MCP_RING_GRANT_EXPIRES_AT_MS) };
  try {
    const login = await request(context, '/api/login', { method: 'POST', body: { passcode } });
    assert.equal(login.status, 200);
    context.token = login.body.token;
    await pairLight(context);
    return context;
  } catch (error) {
    await stop(context);
    throw error;
  }
}

function assertAppliedReceipt(response, body, context) {
  assert.equal(response.status, 200);
  assert.equal(response.body.status, 'executed_in_simulator');
  assert.equal(response.body.simulated, true);
  assert.equal(response.body.requestId, body.meta.request_id);
  assert.equal(response.body.deviceId, 'living_light');
  assert.equal(response.body.action, 'on');
  assert.equal(response.body.actor, `ring_automation:${context.homeId}`);
  assert.equal(response.body.receipt.commandId, response.body.commandId);
  assert.equal(response.body.receipt.requestId, body.meta.request_id);
  assert.equal(response.body.receipt.status, 'executed_in_simulator');
  assert.equal(response.body.receipt.gatewayAck, true);
  assert.equal(response.body.receipt.deviceObserved, false);
  assert.equal(response.body.receipt.simulated, true);
}

test('signed Ring motion applies only fixed light through virtual gateway; replay is exact', async () => {
  const context = await fixture();
  try {
    const event = motion(context);
    const before = await snapshot(context);
    const first = await signedMotion(context, event);
    assertAppliedReceipt(first, event, context);
    const after = await snapshot(context);
    assert.equal(device(after, 'living_light').power, true);
    assert.deepEqual(device(after, 'front_door'), device(before, 'front_door'));
    assert.deepEqual(device(after, 'camera'), device(before, 'camera'));
    const audit = ringAudit(after, event.meta.request_id);
    assert.equal(audit.filter((entry) => entry.outcome === 'applied').length, 1);
    assert.equal(audit.at(-1).commandId, first.body.commandId);
    assert.equal(audit.at(-1).id, first.body.receipt.auditId);
    const edgeReceipt = after.edge.receipts.find((item) => item.commandId === first.body.commandId);
    assert.equal(edgeReceipt?.gatewayAck, true);
    assert.equal(edgeReceipt?.deviceObserved, false);

    await ownerPost(context, '/api/action', { deviceId: 'living_light', action: 'off' });
    const beforeReplay = await snapshot(context);
    const replay = await signedMotion(context, event);
    const afterReplay = await snapshot(context);
    assert.deepEqual(replay, first);
    assert.equal(device(afterReplay, 'living_light').power, false);
    assert.deepEqual(afterReplay.audit, beforeReplay.audit);
  } finally {
    await stop(context);
  }
});

test('offline signed motion stays queued; replay does not duplicate and recovery applies once', async () => {
  const context = await fixture();
  try {
    await ownerPost(context, '/api/edge/online', { online: false });
    const event = motion(context);
    const before = await snapshot(context);
    const queued = await signedMotion(context, event);
    assert.equal(queued.status, 200);
    assert.equal(queued.body.status, 'queued');
    assert.equal(queued.body.requestId, event.meta.request_id);
    assert.equal(queued.body.deviceId, 'living_light');
    assert.equal(queued.body.receipt, null);
    const pending = await snapshot(context);
    assert.deepEqual(device(pending, 'living_light'), device(before, 'living_light'));
    assert.equal(pending.edge.pendingCount, 1);
    assert.equal(ringAudit(pending, event.meta.request_id).filter((entry) => entry.outcome === 'applied').length, 0);
    const samePending = await signedMotion(context, event);
    const afterPendingReplay = await snapshot(context);
    assert.deepEqual(samePending, queued);
    assert.equal(afterPendingReplay.edge.pendingCount, 1);
    assert.deepEqual(afterPendingReplay.audit, pending.audit);

    const reconnected = await ownerPost(context, '/api/edge/online', { online: true });
    assert.equal(reconnected.applied.length, 1);
    assert.equal(reconnected.applied[0].commandId, queued.body.commandId);
    const applied = await signedMotion(context, event);
    assertAppliedReceipt(applied, event, context);
    assert.equal(applied.body.commandId, queued.body.commandId);
    const recovered = await snapshot(context);
    assert.equal(device(recovered, 'living_light').power, true);
    assert.equal(recovered.edge.pendingCount, 0);
    assert.equal(ringAudit(recovered, event.meta.request_id).filter((entry) => entry.outcome === 'applied').length, 1);
    const again = await signedMotion(context, event);
    const afterAgain = await snapshot(context);
    assert.deepEqual(again, applied);
    assert.deepEqual(afterAgain.audit, recovered.audit);
  } finally {
    await stop(context);
  }
});

test('no-ack fallback flushes on heartbeat and reports a correlated simulated receipt', async () => {
  const context = await fixture();
  try {
    await ownerPost(context, '/api/edge/fault', { deviceId: 'living_light', mode: 'no_ack' });
    const event = motion(context);
    const queued = await signedMotion(context, event);
    assert.equal(queued.status, 200);
    assert.equal(queued.body.status, 'queued');
    assert.equal(queued.body.receipt, null);
    assert.equal(device(await snapshot(context), 'living_light').power, false);
    await ownerPost(context, '/api/edge/fault', { deviceId: 'living_light', mode: 'none' });
    const heartbeat = await ownerPost(context, '/api/edge/heartbeat', {});
    assert.equal(heartbeat.applied.length, 1);
    assert.equal(heartbeat.applied[0].commandId, queued.body.commandId);
    const replay = await signedMotion(context, event);
    assertAppliedReceipt(replay, event, context);
    assert.equal(replay.body.commandId, queued.body.commandId);
    assert.equal(ringAudit(await snapshot(context), event.meta.request_id).filter((entry) => entry.outcome === 'applied').length, 1);
  } finally {
    await stop(context);
  }
});

test('queued Ring command expires with its grant and cannot apply after reconnect', async () => {
  const context = await fixture({ grantLifetimeMs: 5_000 });
  try {
    await ownerPost(context, '/api/edge/online', { online: false });
    const event = motion(context);
    const queued = await signedMotion(context, event);
    assert.equal(queued.status, 200);
    assert.equal(queued.body.status, 'queued');
    const waitMs = Math.max(0, context.grantExpiresAt - Date.now() + 30);
    await new Promise((resolve) => setTimeout(resolve, waitMs));
    const expiredState = await snapshot(context);
    assert.equal(expiredState.edge.pendingCount, 0);
    assert.equal(device(expiredState, 'living_light').power, false);
    const reconnect = await ownerPost(context, '/api/edge/online', { online: true });
    assert.equal(reconnect.applied.length, 0);
    const replay = await signedMotion(context, event);
    assert.equal(replay.status, 200);
    assert.equal(replay.body.status, 'expired');
    assert.equal(replay.body.requestId, event.meta.request_id);
    assert.equal(replay.body.commandId, queued.body.commandId);
    assert.equal(replay.body.receipt, null);
    const finalState = await snapshot(context);
    assert.equal(device(finalState, 'living_light').power, false);
    assert.equal(ringAudit(finalState, event.meta.request_id).filter((entry) => entry.outcome === 'applied').length, 0);
  } finally {
    await stop(context);
  }
});

test('bad edge HMAC fails closed and exact Ring replay cannot dispatch later', async () => {
  const context = await fixture();
  try {
    await ownerPost(context, '/api/edge/fault', { deviceId: 'living_light', mode: 'bad_hmac' });
    const event = motion(context);
    const before = await snapshot(context);
    const denied = await signedMotion(context, event);
    assert(denied.status >= 400);
    const after = await snapshot(context);
    assert.deepEqual(device(after, 'living_light'), device(before, 'living_light'));
    assert.equal(after.edge.pendingCount, 0);
    assert.equal(ringAudit(after, event.meta.request_id).filter((entry) => entry.outcome === 'applied').length, 0);
    await ownerPost(context, '/api/edge/fault', { deviceId: 'living_light', mode: 'none' });
    const beforeReplay = await snapshot(context);
    const replay = await signedMotion(context, event);
    assert(replay.status >= 400);
    const afterReplay = await snapshot(context);
    assert.deepEqual(device(afterReplay, 'living_light'), device(beforeReplay, 'living_light'));
    assert.equal(afterReplay.edge.pendingCount, 0);
    assert.equal(ringAudit(afterReplay, event.meta.request_id).filter((entry) => entry.outcome === 'applied').length, 0);
  } finally {
    await stop(context);
  }
});

test('wrong Ring source and forged targets cannot select door or camera', async () => {
  const context = await fixture();
  try {
    for (const overrides of [
      { meta: { account_id: `wrong-${randomUUID()}` } },
      { data: { attributes: { source: `wrong-${randomUUID()}` } } },
      { data: { attributes: { source_type: 'locations' } } },
      { data: { type: 'button_press' } },
    ]) {
      const event = motion(context, overrides);
      const before = await snapshot(context);
      const ignored = await signedMotion(context, event);
      const after = await snapshot(context);
      assert.equal(ignored.status, 200);
      assert.equal(ignored.body.status, 'ignored');
      assert.deepEqual(after.audit, before.audit);
      assert.deepEqual(device(after, 'living_light'), device(before, 'living_light'));
      assert.deepEqual(device(after, 'front_door'), device(before, 'front_door'));
      assert.deepEqual(device(after, 'camera'), device(before, 'camera'));
    }
    for (const [deviceId, action] of [['front_door', 'unlock'], ['camera', 'disarm']]) {
      const event = motion(context, {
        actor: 'owner', deviceId, action,
        data: { attributes: { actor: 'owner', deviceId, action } },
      });
      const before = await snapshot(context);
      const response = await signedMotion(context, event);
      assertAppliedReceipt(response, event, context);
      const after = await snapshot(context);
      assert.deepEqual(device(after, 'front_door'), device(before, 'front_door'));
      assert.deepEqual(device(after, 'camera'), device(before, 'camera'));
      assert.equal(ringAudit(after, event.meta.request_id).filter((entry) => entry.outcome === 'applied').length, 1);
    }
  } finally {
    await stop(context);
  }
});

process.on('exit', () => {
  for (const child of children) child.kill('SIGTERM');
});
