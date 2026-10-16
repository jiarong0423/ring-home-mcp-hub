import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';

const projectDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const passcode = process.env.HOME_MCP_TEST_PASS || randomBytes(18).toString('base64url');
let child;
let base = process.env.HOME_MCP_TEST_URL;
if (!base) {
  child = spawn(process.execPath, [join(projectDir, 'src/server.mjs')], {
    cwd: projectDir,
    // Own empty phone store: never read the console's real paired phones.
    env: { ...process.env, HOME_MCP_PORT: '0', HOME_MCP_DEMO_PASS: passcode, HOME_MCP_RING_PROBE: 'off',
      HOME_MCP_PHONE_STORE: join(mkdtempSync(join(tmpdir(), 'smoke-phones-')), 'phones.json') },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  process.on('exit', () => child.kill());
  base = await new Promise((resolve, reject) => {
    let output = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error('Local test server did not start within 10 seconds'));
    }, 10_000);
    child.stdout.on('data', (chunk) => {
      output += chunk.toString();
      const found = output.match(/Home MCP simulator: (http:\/\/127\.0\.0\.1:\d+)/);
      if (found) {
        clearTimeout(timer);
        resolve(found[1]);
      }
    });
    child.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`Local test server exited before startup (${code})`));
    });
  });
} else if (!process.env.HOME_MCP_TEST_PASS) {
  throw new Error('HOME_MCP_TEST_PASS is required when HOME_MCP_TEST_URL is set');
}

async function request(path, { method = 'GET', token, body, headers = {} } = {}) {
  const response = await fetch(`${base}${path}`, {
    method,
    headers: {
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}

const denied = await request('/api/state');
assert.equal(denied.status, 401);

const login = await request('/api/login', { method: 'POST', body: { passcode } });
assert.equal(login.status, 200);
assert.equal(login.body.simulated, true);
const token = login.body.token;
assert.match(token, /^[A-Za-z0-9_-]{40,120}$/);

const initial = await request('/api/state', { token });
assert.equal(initial.status, 200);
assert.equal(initial.body.devices.length, 7);
assert(initial.body.devices.every((device) => !device.paired));
assert.equal(initial.body.edge.gatewayId, 'virtual_esp32c3');
assert.equal(initial.body.edge.online, true);

const unpairedAction = await request('/api/action', {
  method: 'POST', token, body: { deviceId: 'living_light', action: 'on' },
});
assert.equal(unpairedAction.status, 403);

for (const device of initial.body.devices) {
  const started = await request('/api/pair/start', {
    method: 'POST', token, body: { deviceId: device.id },
  });
  assert.equal(started.status, 200);
  assert.equal(started.body.simulated, true);
  const completed = await request('/api/pair/confirm', {
    method: 'POST', token, body: { deviceId: device.id, code: started.body.code },
  });
  assert.equal(completed.status, 200);
  assert.equal(completed.body.paired, true);
}

const wrongOrigin = await request('/api/state', {
  token, headers: { origin: 'https://untrusted.example' },
});
assert.equal(wrongOrigin.status, 403);

const mcpHeaders = {
  accept: 'application/json, text/event-stream',
  'mcp-protocol-version': '2025-11-25',
};
let rpcId = 0;
async function rpc(method, params) {
  const result = await request('/mcp', {
    method: 'POST', token, headers: mcpHeaders,
    body: { jsonrpc: '2.0', id: ++rpcId, method, params },
  });
  assert.equal(result.status, 200);
  return result.body;
}

const initialized = await rpc('initialize', {
  protocolVersion: '2025-11-25',
  capabilities: {},
  clientInfo: { name: 'local-smoke', version: '1.0.0' },
});
assert.equal(initialized.result.protocolVersion, '2025-11-25');

const tools = await rpc('tools/list', {});
assert.equal(tools.result.tools.length, 8);
assert(tools.result.tools.some((tool) => tool.name === 'device_front_door'));
assert(tools.result.tools.some((tool) => tool.name === 'device_batch'));

const light = await rpc('tools/call', {
  name: 'device_living_light', arguments: { action: 'on' },
});
assert.equal(light.result.isError, false);
assert.equal(light.result.structuredContent.state.power, true);
assert.equal(light.result.structuredContent.simulated, true);

const fault = await request('/api/edge/fault', {
  method: 'POST', token, body: { deviceId: 'air_conditioner', mode: 'no_ack' },
});
assert.equal(fault.status, 200);
const batch = await rpc('tools/call', {
  name: 'device_batch', arguments: { commands: [
    { deviceId: 'air_conditioner', action: 'on' },
    { deviceId: 'dehumidifier', action: 'on' },
    { deviceId: 'living_light', action: 'off' },
  ] },
});
assert.equal(batch.result.isError, false);
const batchResults = batch.result.structuredContent.results;
assert.equal(batchResults.length, 3);
assert.equal(batchResults.find((item) => item.deviceId === 'air_conditioner').status, 'queued');
assert.equal(batchResults.find((item) => item.deviceId === 'dehumidifier').status, 'simulated_applied');
assert.equal(batchResults.find((item) => item.deviceId === 'living_light').status, 'simulated_applied');
const pendingState = await request('/api/state', { token });
assert.equal(pendingState.body.devices.find((device) => device.id === 'air_conditioner').state.power, false);
assert.equal(pendingState.body.edge.pendingCount, 1);
await request('/api/edge/fault', {
  method: 'POST', token, body: { deviceId: 'air_conditioner', mode: 'none' },
});
const recovered = await request('/api/edge/heartbeat', { method: 'POST', token, body: {} });
assert.equal(recovered.status, 200);
assert.equal(recovered.body.pendingCount, 0);
assert.equal(recovered.body.applied.length, 1);
assert.equal(recovered.body.applied[0].commandId,
  batchResults.find((item) => item.deviceId === 'air_conditioner').commandId);

const disconnected = await request('/api/edge/online', {
  method: 'POST', token, body: { online: false },
});
assert.equal(disconnected.status, 200);
const queued = await request('/api/action', {
  method: 'POST', token, body: { deviceId: 'air_conditioner', action: 'off' },
});
assert.equal(queued.status, 200);
assert.equal(queued.body.status, 'queued');
const stillOn = await request('/api/state', { token });
assert.equal(stillOn.body.devices.find((device) => device.id === 'air_conditioner').state.power, true);
const connected = await request('/api/edge/online', {
  method: 'POST', token, body: { online: true },
});
assert.equal(connected.status, 200);
assert.equal(connected.body.applied.length, 1);
const nowOff = await request('/api/state', { token });
assert.equal(nowOff.body.devices.find((device) => device.id === 'air_conditioner').state.power, false);

// Door unlock is request-and-approve now (DOOR_APPROVAL_PLAN_zh.md): an agent may only ASK, and only the paired admin
// phone approves. With no admin phone there is nobody to approve, so the request itself is refused; the one-use phrase is
// no longer handed to a session holder; a stale-style unlock carrying confirmation fields is still only a request.
const unlockDenied = await rpc('tools/call', {
  name: 'device_front_door', arguments: { action: 'unlock' },
});
assert.equal(unlockDenied.error?.code, -32003);
assert.match(unlockDenied.error?.message ?? '', /ADMIN_PHONE_REQUIRED/u);
const confirmation = await request('/api/confirm/start', {
  method: 'POST', token, body: { deviceId: 'front_door', action: 'unlock' },
});
assert.equal(confirmation.status, 403);
assert.equal(confirmation.body.error, 'DOOR_APPROVAL_REQUIRED');
const selfConfirmed = await rpc('tools/call', {
  name: 'device_front_door', arguments: { action: 'unlock', confirmationId: '00000000-0000-4000-8000-000000000000', confirmationPhrase: '123456' },
});
assert.equal(selfConfirmed.error?.code, -32003);
const doorStill = await request('/api/state', { token });
assert.equal(doorStill.body.devices.find((device) => device.id === 'front_door').state.locked, true);

const unsafeSchedule = await request('/api/schedules', {
  method: 'POST', token,
  body: { deviceId: 'front_door', action: 'unlock', at: new Date(Date.now() + 5_000).toISOString() },
});
assert.equal(unsafeSchedule.status, 403);

const cameraDisarmSchedule = await request('/api/schedules', {
  method: 'POST', token,
  body: { deviceId: 'camera', action: 'disarm', at: new Date(Date.now() + 5_000).toISOString() },
});
assert.equal(cameraDisarmSchedule.status, 403);

const schedule = await request('/api/schedules', {
  method: 'POST', token,
  body: { deviceId: 'living_light', action: 'off', at: new Date(Date.now() + 1_500).toISOString() },
});
assert.equal(schedule.status, 201);
await new Promise((resolve) => setTimeout(resolve, 2_200));
const finalState = await request('/api/state', { token });
assert.equal(finalState.body.devices.find((device) => device.id === 'living_light').state.power, false);
assert.equal(finalState.body.schedules.length, 0);
assert(finalState.body.audit.some((entry) => entry.origin === 'schedule' && entry.outcome === 'applied'));

const logout = await request('/api/logout', { method: 'POST', token, body: {} });
assert.equal(logout.status, 200);
assert.equal(logout.body.revoked, true);
const revoked = await request('/api/state', { token });
assert.equal(revoked.status, 401);

if (child) child.kill();
console.log(`SMOKE_PASS seven_devices pairing auth origin mcp edge_batch_fallback door_confirmation replay schedule_policy logout at ${new Date().toISOString()}`);
