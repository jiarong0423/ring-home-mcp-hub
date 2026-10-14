import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const projectDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const secret = randomBytes(32).toString('base64url');
const passcode = randomBytes(18).toString('base64url');
const accountId = `account-${randomUUID()}`;
const sourceId = `source-${randomUUID()}`;
const homeId = `home-${randomUUID()}`;
const ringKeys = [
  'HOME_MCP_RING_TEST_ENABLED', 'HOME_MCP_RING_TEST_SECRET',
  'HOME_MCP_RING_ACCOUNT_ID', 'HOME_MCP_RING_SOURCE_ID',
  'HOME_MCP_RING_SOURCE_TYPE', 'HOME_MCP_RING_HOME_ID',
  'HOME_MCP_RING_GRANT_VERSION', 'HOME_MCP_RING_GRANT_EXPIRES_AT_MS',
];
const environment = { ...process.env };
for (const key of ringKeys) delete environment[key];
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
  HOME_MCP_RING_GRANT_EXPIRES_AT_MS: String(Date.now() + 3_600_000),
});

const child = spawn(process.execPath, [join(projectDir, 'src/server.mjs')], {
  cwd: projectDir,
  env: environment,
  stdio: ['ignore', 'pipe', 'pipe'],
});
let stderr = '';
child.stderr.on('data', (part) => { stderr += part.toString(); });

const base = await new Promise((resolve, reject) => {
  let stdout = '';
  const timer = setTimeout(() => {
    child.kill('SIGTERM');
    reject(new Error('Local bridge server startup timed out'));
  }, 10_000);
  child.stdout.on('data', (part) => {
    stdout += part.toString();
    const match = stdout.match(/Home MCP simulator: (http:\/\/127\.0\.0\.1:\d+)/);
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
    reject(new Error(`Local bridge server exited at startup: ${code}; ${stderr.trim()}`));
  });
});

async function request(path, { method = 'GET', token, body, rawBody, headers = {} } = {}) {
  const payload = rawBody ?? (body === undefined ? undefined : JSON.stringify(body));
  const response = await fetch(`${base}${path}`, {
    method,
    headers: {
      ...(payload === undefined ? {} : { 'content-type': 'application/json' }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    ...(payload === undefined ? {} : { body: payload }),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}

async function state(token) {
  const response = await request('/api/state', { token });
  assert.equal(response.status, 200);
  return response.body;
}

function deviceState(snapshot, id) {
  return snapshot.devices.find((device) => device.id === id)?.state;
}

function event(overrides = {}) {
  const now = Date.now();
  return {
    meta: {
      version: '1.1',
      time: new Date(now).toISOString(),
      request_id: randomUUID(),
      account_id: accountId,
      ...overrides.meta,
    },
    data: {
      id: randomUUID(),
      type: 'motion_detected',
      ...overrides.data,
      attributes: {
        source: sourceId,
        source_type: 'devices',
        timestamp: now,
        ...overrides.data?.attributes,
      },
    },
  };
}

function signature(rawBody) {
  return `sha256=${createHmac('sha256', secret).update(rawBody).digest('hex')}`;
}

async function ring(rawBody, alternateSignature) {
  return request('/api/ring-test-event', {
    method: 'POST',
    rawBody,
    headers: { 'x-signature': alternateSignature ?? signature(rawBody) },
  });
}

async function rpc(token, method, params) {
  const response = await request('/mcp', {
    method: 'POST',
    token,
    body: { jsonrpc: '2.0', id: randomUUID(), method, params },
    headers: {
      accept: 'application/json, text/event-stream',
      'mcp-protocol-version': '2025-11-25',
    },
  });
  assert.equal(response.status, 200);
  return response.body;
}

try {
const login = await request('/api/login', { method: 'POST', body: { passcode } });
assert.equal(login.status, 200);
const token = login.body.token;

for (const deviceId of ['living_light', 'front_door', 'camera']) {
  const started = await request('/api/pair/start', {
    method: 'POST', token, body: { deviceId },
  });
  assert.equal(started.status, 200);
  const completed = await request('/api/pair/confirm', {
    method: 'POST', token, body: { deviceId, code: started.body.code },
  });
  assert.equal(completed.status, 200);
}

await test('private Ring tool is absent from public MCP and cannot be called by the owner', async () => {
  const listed = await rpc(token, 'tools/list', {});
  assert.equal(listed.result.tools.length, 8);
  assert.equal(listed.result.tools.some((tool) => tool.name === 'ring_motion_to_light'), false);
  const before = await state(token);
  const called = await rpc(token, 'tools/call', {
    name: 'ring_motion_to_light',
    arguments: { event: event() },
  });
  assert.equal(called.error.code, -32602);
  const afterState = await state(token);
  assert.deepEqual(afterState.audit, before.audit);
  assert.deepEqual(deviceState(afterState, 'living_light'), deviceState(before, 'living_light'));
});

await test('bad HMAC and signed malformed schema stop before virtual execution', async () => {
  const before = await state(token);
  const raw = JSON.stringify(event());
  const bad = await ring(raw, `sha256=${'0'.repeat(64)}`);
  assert.equal(bad.status, 401);
  assert.equal(bad.body.error, 'RING_SIGNATURE_INVALID');
  const malformed = await ring(JSON.stringify({ meta: { version: '1.1' } }));
  assert.equal(malformed.status, 400);
  assert.equal(malformed.body.error, 'RING_PAYLOAD_INVALID');
  const afterState = await state(token);
  assert.deepEqual(afterState.audit, before.audit);
  assert.deepEqual(deviceState(afterState, 'living_light'), deviceState(before, 'living_light'));
});

await test('signed wrong account is ignored with zero virtual apply', async () => {
  const before = await state(token);
  const wrong = await ring(JSON.stringify(event({ meta: { account_id: `wrong-${randomUUID()}` } })));
  assert.equal(wrong.status, 200);
  assert.equal(wrong.body.status, 'ignored');
  assert.equal(wrong.body.reason, 'EVENT_NOT_ALLOWED');
  const afterState = await state(token);
  assert.deepEqual(afterState.audit, before.audit);
  assert.deepEqual(deviceState(afterState, 'living_light'), deviceState(before, 'living_light'));
});

await test('signed motion uses fixed light, keeps receipt and replay idempotence', async () => {
  const raw = JSON.stringify({
    ...event(),
    deviceId: 'front_door',
    action: 'unlock',
  });
  const before = await state(token);
  const first = await ring(raw);
  assert.equal(first.status, 200);
  assert.equal(first.body.status, 'executed_in_simulator');
  assert.equal(first.body.deviceId, 'living_light');
  assert.equal(first.body.action, 'on');
  assert.equal(first.body.simulated, true);
  assert.equal(first.body.receipt.commandId, first.body.commandId);
  assert.equal(first.body.receipt.requestId, first.body.requestId);
  assert.equal(first.body.receipt.gatewayAck, true);
  assert.equal(first.body.receipt.deviceObserved, false);
  const afterFirst = await state(token);
  assert.equal(afterFirst.audit.length, before.audit.length + 1);
  assert.equal(afterFirst.audit.at(-1).id, first.body.receipt.auditId);
  assert.equal(afterFirst.audit.at(-1).origin, 'ring');
  assert.equal(deviceState(afterFirst, 'living_light').power, true);
  assert.equal(deviceState(afterFirst, 'front_door').locked, true);

  const turnedOff = await request('/api/action', {
    method: 'POST', token, body: { deviceId: 'living_light', action: 'off' },
  });
  assert.equal(turnedOff.status, 200);
  const beforeReplay = await state(token);
  const replay = await ring(raw);
  const afterReplay = await state(token);
  assert.equal(replay.status, 200);
  assert.deepEqual(replay.body, first.body);
  assert.deepEqual(afterReplay.audit, beforeReplay.audit);
  assert.equal(deviceState(afterReplay, 'living_light').power, false);
  assert.equal(deviceState(afterReplay, 'front_door').locked, true);
});
} finally {
  if (child.exitCode === null && child.signalCode === null) {
    const exit = new Promise((resolve) => child.once('exit', resolve));
    child.kill('SIGTERM');
    await exit;
  }
}
