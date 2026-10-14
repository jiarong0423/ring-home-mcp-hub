import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import http from 'node:http';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyAndNormalizeRingEvent } from '../src/ring_event.mjs';

const projectDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const serverPath = join(projectDir, 'src', 'server.mjs');
const secret = randomBytes(32).toString('base64url');
const passcode = randomBytes(18).toString('base64url');
const accountId = `account-${randomUUID()}`;
const sourceId = `source-${randomUUID()}`;
const homeId = `home-${randomUUID()}`;
const sourceType = 'devices';
const grantVersion = 'test-v1';
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

function ringBody(overrides = {}) {
  const now = Date.now();
  const base = {
    meta: {
      version: '1.1',
      time: new Date(now).toISOString(),
      request_id: randomUUID(),
      account_id: accountId,
    },
    data: {
      id: randomUUID(),
      type: 'motion_detected',
      attributes: {
        source: sourceId,
        source_type: sourceType,
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

function encode(value) {
  return Buffer.from(JSON.stringify(value), 'utf8');
}

function sign(rawBody) {
  return `sha256=${createHmac('sha256', secret).update(rawBody).digest('hex')}`;
}

function sha256(rawBody) {
  return createHash('sha256').update(rawBody).digest('hex');
}

function cleanEnvironment() {
  const environment = { ...process.env };
  for (const name of ringEnvironmentNames) delete environment[name];
  environment.HOME_MCP_PORT = '0';
  environment.HOME_MCP_DEMO_PASS = passcode;
  return environment;
}

function enabledEnvironment() {
  return {
    ...cleanEnvironment(),
    HOME_MCP_RING_TEST_ENABLED: '1',
    HOME_MCP_RING_TEST_SECRET: secret,
    HOME_MCP_RING_ACCOUNT_ID: accountId,
    HOME_MCP_RING_SOURCE_ID: sourceId,
    HOME_MCP_RING_SOURCE_TYPE: sourceType,
    HOME_MCP_RING_HOME_ID: homeId,
    HOME_MCP_RING_GRANT_VERSION: grantVersion,
    HOME_MCP_RING_GRANT_EXPIRES_AT_MS: String(Date.now() + 60 * 60 * 1000),
  };
}

async function startServer(environment) {
  const child = spawn(process.execPath, [serverPath], {
    cwd: projectDir,
    env: environment,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  children.add(child);
  let stdout = '';
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
  try {
    const base = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Ring ingress local server startup timed out')), 10_000);
      const success = (url) => {
        clearTimeout(timer);
        resolve(url);
      };
      const failure = (error) => {
        clearTimeout(timer);
        reject(error);
      };
      child.stdout.on('data', (chunk) => {
        stdout += chunk.toString();
        const match = stdout.match(/Home MCP simulator: (http:\/\/127\.0\.0\.1:\d+)/);
        if (match) success(match[1]);
      });
      child.once('error', failure);
      child.once('exit', (code) => failure(new Error(`Ring ingress server exited before startup: rc=${code}; ${stderr.trim()}`)));
    });
    return { child, base };
  } catch (error) {
    child.kill('SIGTERM');
    children.delete(child);
    throw error;
  }
}

async function stopServer(server) {
  if (!server) return;
  const { child } = server;
  if (child.exitCode === null && child.signalCode === null) {
    const exited = new Promise((resolve) => child.once('exit', resolve));
    child.kill('SIGTERM');
    await exited;
  }
  children.delete(child);
}

function request(base, path, { method = 'GET', rawBody, headers = {} } = {}) {
  const url = new URL(path, base);
  const body = rawBody === undefined ? undefined : Buffer.from(rawBody);
  const requestHeaders = { ...headers };
  if (body !== undefined && !Object.keys(requestHeaders).some((key) => key.toLowerCase() === 'content-length')) {
    requestHeaders['content-length'] = String(body.length);
  }
  return new Promise((resolve, reject) => {
    const outgoing = http.request(url, { method, headers: requestHeaders }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let parsed = null;
        if (text) {
          try {
            parsed = JSON.parse(text);
          } catch (error) {
            reject(new Error(`Unexpected non-JSON response, HTTP ${response.statusCode}: ${error.message}`));
            return;
          }
        }
        resolve({ status: response.statusCode, body: parsed });
      });
      response.on('error', reject);
    });
    outgoing.setTimeout(5_000, () => outgoing.destroy(new Error('Local HTTP request timed out')));
    outgoing.on('error', reject);
    if (body !== undefined) outgoing.write(body);
    outgoing.end();
  });
}

function jsonRequest(base, path, { method = 'GET', token, value } = {}) {
  return request(base, path, {
    method,
    rawBody: value === undefined ? undefined : encode(value),
    headers: {
      ...(value === undefined ? {} : { 'content-type': 'application/json' }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
  });
}

function postRing(base, rawBody, { signature = sign(rawBody), headers = {} } = {}) {
  return request(base, '/api/ring-test-event', {
    method: 'POST',
    rawBody,
    headers: {
      'content-type': 'application/json',
      ...(signature === null ? {} : { 'x-signature': signature }),
      ...headers,
    },
  });
}

async function state(base, token) {
  const response = await jsonRequest(base, '/api/state', { token });
  assert.equal(response.status, 200);
  return response.body;
}

function selectedDeviceStates(snapshot) {
  const states = {};
  for (const id of ['living_light', 'front_door', 'camera']) {
    states[id] = snapshot.devices.find((device) => device.id === id)?.state;
  }
  return states;
}

function logCase(name, rawBody, response, before, after) {
  console.log(JSON.stringify({
    case: name,
    at: new Date().toISOString(),
    requestId: rawBody ? (() => { try { return JSON.parse(rawBody).meta?.request_id ?? null; } catch { return null; } })() : null,
    inputSha256: rawBody ? sha256(rawBody) : null,
    httpStatus: response.status,
    result: response.body?.status ?? response.body?.error ?? null,
    reason: response.body?.reason ?? null,
    auditDelta: after && before ? after.audit.length - before.audit.length : null,
    before: before ? selectedDeviceStates(before) : null,
    after: after ? selectedDeviceStates(after) : null,
  }));
}

async function expectNoChange(name, base, token, rawBody, expectedStatus, expectedResult, options = {}) {
  const before = await state(base, token);
  const response = await postRing(base, rawBody, options);
  const after = await state(base, token);
  logCase(name, rawBody, response, before, after);
  assert.equal(response.status, expectedStatus, `${name}: HTTP status`);
  assert.equal(response.body?.status ?? response.body?.error, expectedResult, `${name}: result`);
  assert.deepEqual(selectedDeviceStates(after), selectedDeviceStates(before), `${name}: device state changed`);
  assert.deepEqual(after.audit, before.audit, `${name}: audit changed`);
  return response;
}

async function pair(base, token, deviceId) {
  const started = await jsonRequest(base, '/api/pair/start', { method: 'POST', token, value: { deviceId } });
  assert.equal(started.status, 200);
  const completed = await jsonRequest(base, '/api/pair/confirm', {
    method: 'POST', token, value: { deviceId, code: started.body.code },
  });
  assert.equal(completed.status, 200);
  assert.equal(completed.body.paired, true);
}

function pureModuleCheck() {
  const rawBody = encode(ringBody());
  const normalized = verifyAndNormalizeRingEvent({ rawBody, signature: sign(rawBody), secret });
  assert.equal(normalized.version, '1.1');
  assert.equal(normalized.accountId, accountId);
  assert.equal(normalized.sourceId, sourceId);
  assert.equal(normalized.bodyDigest, sha256(rawBody));
  assert.throws(() => verifyAndNormalizeRingEvent({ rawBody, signature: null, secret }), {
    code: 'RING_SIGNATURE_INVALID', status: 401,
  });
  assert.throws(() => verifyAndNormalizeRingEvent({
    rawBody: Buffer.concat([rawBody, Buffer.from(' ')]), signature: sign(rawBody), secret,
  }), { code: 'RING_SIGNATURE_INVALID', status: 401 });
  console.log('HMAC_MODULE_PASS raw_body_signature_before_parse');
}

async function expectStartupFailure(environment, expectedMessage, label) {
  const child = spawn(process.execPath, [serverPath], {
    cwd: projectDir,
    env: environment,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  children.add(child);
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
  child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
  const exitCode = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      reject(new Error(`${label} did not fail at startup`));
    }, 10_000);
    child.once('error', (error) => { clearTimeout(timer); reject(error); });
    child.once('exit', (code) => { clearTimeout(timer); resolve(code); });
  });
  children.delete(child);
  assert.notEqual(exitCode, 0);
  assert.match(stderr, expectedMessage);
  assert.doesNotMatch(stdout, /Home MCP simulator:/);
  assert.doesNotMatch(stderr, new RegExp(secret));
  console.log(`${label}_PASS rc=${exitCode}`);
}

async function run() {
  pureModuleCheck();
  await expectStartupFailure({
    ...cleanEnvironment(),
    HOME_MCP_RING_TEST_ENABLED: '1',
    HOME_MCP_RING_TEST_SECRET: secret,
  }, /Ring test ingress configuration must be fully enabled or fully absent/, 'PARTIAL_CONFIG_FAIL_CLOSED');
  await expectStartupFailure({
    ...enabledEnvironment(),
    HOME_MCP_RING_SOURCE_TYPE: 'subscriptions',
  }, /HOME_MCP_RING_SOURCE_TYPE must be devices/, 'SOURCE_TYPE_FAIL_CLOSED');

  let disabledServer;
  let server;
  try {
    disabledServer = await startServer(cleanEnvironment());
    const disabled = await postRing(disabledServer.base, encode(ringBody()));
    assert.equal(disabled.status, 503);
    assert.equal(disabled.body?.error, 'RING_TEST_DISABLED');
    console.log('DISABLED_INGRESS_PASS status=503 guard=RING_TEST_DISABLED');
    await stopServer(disabledServer);
    disabledServer = null;

    server = await startServer(enabledEnvironment());
    const login = await jsonRequest(server.base, '/api/login', {
      method: 'POST', value: { passcode },
    });
    assert.equal(login.status, 200);
    const token = login.body.token;
    assert.match(token, /^[A-Za-z0-9_-]{40,120}$/);

    const unpairedBody = encode(ringBody());
    const unpaired = await expectNoChange(
      'unpaired_light', server.base, token, unpairedBody, 200, 'ignored',
    );
    assert.equal(unpaired.body.reason, 'LIGHT_NOT_PAIRED');

    await pair(server.base, token, 'living_light');
    await pair(server.base, token, 'front_door');
    await pair(server.base, token, 'camera');
    const armed = await jsonRequest(server.base, '/api/action', {
      method: 'POST', token, value: { deviceId: 'camera', action: 'arm' },
    });
    assert.equal(armed.status, 200);

    let appliedCount = 0;
    const validBody = encode(ringBody());
    const beforeValid = await state(server.base, token);
    const valid = await postRing(server.base, validBody);
    const afterValid = await state(server.base, token);
    logCase('valid_signed_motion', validBody, valid, beforeValid, afterValid);
    assert.equal(valid.status, 200);
    assert.equal(valid.body.status, 'executed_in_simulator');
    assert.equal(valid.body.simulated, true);
    assert.equal(valid.body.deviceId, 'living_light');
    assert.equal(valid.body.action, 'on');
    assert.equal(valid.body.actor, `ring_automation:${homeId}`);
    assert.equal(valid.body.receipt.commandId, valid.body.commandId);
    assert.equal(valid.body.receipt.requestId, valid.body.requestId);
    assert.equal(valid.body.receipt.status, 'executed_in_simulator');
    assert.equal(valid.body.receipt.simulated, true);
    assert.equal(valid.body.receipt.state.power, true);
    assert.equal(afterValid.audit.length, beforeValid.audit.length + 1);
    assert.equal(afterValid.audit.at(-1).id, valid.body.receipt.auditId);
    assert.equal(afterValid.audit.at(-1).commandId, valid.body.commandId);
    assert.equal(afterValid.audit.at(-1).requestId, valid.body.requestId);
    assert.equal(afterValid.audit.at(-1).origin, 'ring');
    assert.equal(afterValid.devices.find((device) => device.id === 'living_light').state.power, true);
    assert.equal(afterValid.devices.find((device) => device.id === 'front_door').state.locked, true);
    assert.equal(afterValid.devices.find((device) => device.id === 'camera').state.armed, true);
    appliedCount += 1;

    const turnedOff = await jsonRequest(server.base, '/api/action', {
      method: 'POST', token, value: { deviceId: 'living_light', action: 'off' },
    });
    assert.equal(turnedOff.status, 200);
    const beforeReplay = await state(server.base, token);
    const replay = await postRing(server.base, validBody);
    const afterReplay = await state(server.base, token);
    logCase('same_id_same_body_replay', validBody, replay, beforeReplay, afterReplay);
    assert.equal(replay.status, 200);
    assert.deepEqual(replay.body, valid.body);
    assert.deepEqual(afterReplay.audit, beforeReplay.audit);
    assert.equal(afterReplay.devices.find((device) => device.id === 'living_light').state.power, false);

    const conflict = ringBody({ meta: { request_id: valid.body.requestId } });
    const conflictBody = encode(conflict);
    const conflictResult = await expectNoChange(
      'same_id_different_body', server.base, token, conflictBody, 200, 'ignored_conflict',
    );
    assert.equal(conflictResult.body.reason, 'REQUEST_ID_BODY_CONFLICT');

    const badSigBody = encode(ringBody());
    const goodSig = sign(badSigBody);
    const badSig = `sha256=${goodSig.slice(7).replace(/^./, goodSig[7] === '0' ? '1' : '0')}`;
    await expectNoChange('bad_signature', server.base, token, badSigBody, 401, 'RING_SIGNATURE_INVALID', {
      signature: badSig,
    });
    await expectNoChange('missing_signature', server.base, token, badSigBody, 401, 'RING_SIGNATURE_INVALID', {
      signature: null,
    });
    await expectNoChange('duplicate_signature', server.base, token, badSigBody, 401, 'RING_SIGNATURE_INVALID', {
      signature: [goodSig, goodSig],
    });
    await expectNoChange('altered_raw_body', server.base, token, Buffer.concat([badSigBody, Buffer.from(' ')]), 401, 'RING_SIGNATURE_INVALID', {
      signature: goodSig,
    });
    const malformed = Buffer.from('{"meta":', 'utf8');
    await expectNoChange('signed_malformed_json', server.base, token, malformed, 400, 'RING_PAYLOAD_INVALID');
    const oversized = Buffer.alloc(16_385, 0x61);
    await expectNoChange('oversized_body', server.base, token, oversized, 413, 'RING_BODY_TOO_LARGE');
    await expectNoChange('wrong_content_type', server.base, token, encode(ringBody()), 415, 'JSON_REQUIRED', {
      headers: { 'content-type': 'text/plain' },
    });

    const deniedCases = [
      ['wrong_account', { meta: { account_id: `wrong-${randomUUID()}` } }, 'EVENT_NOT_ALLOWED'],
      ['wrong_source', { data: { attributes: { source: `wrong-${randomUUID()}` } } }, 'EVENT_NOT_ALLOWED'],
      ['wrong_source_type', { data: { attributes: { source_type: 'locations' } } }, 'EVENT_NOT_ALLOWED'],
      ['wrong_event_type', { data: { type: 'button_press' } }, 'EVENT_NOT_ALLOWED'],
      ['stale_event', { data: { attributes: { timestamp: Date.now() - 6 * 60 * 1000 } } }, 'EVENT_OUTSIDE_FRESHNESS_WINDOW'],
      ['future_event', { data: { attributes: { timestamp: Date.now() + 2 * 60 * 1000 } } }, 'EVENT_OUTSIDE_FRESHNESS_WINDOW'],
      ['future_meta', { meta: { time: new Date(Date.now() + 2 * 60 * 1000).toISOString() } }, 'EVENT_OUTSIDE_FRESHNESS_WINDOW'],
    ];
    for (const [name, overrides, reason] of deniedCases) {
      const rawBody = encode(ringBody(overrides));
      const response = await expectNoChange(name, server.base, token, rawBody, 200, 'ignored');
      assert.equal(response.body.reason, reason, `${name}: ignored reason`);
    }

    for (const [name, deviceId, action] of [
      ['event_supplied_unlock', 'front_door', 'unlock'],
      ['event_supplied_disarm', 'camera', 'disarm'],
    ]) {
      const malicious = ringBody({
        actor: 'owner',
        deviceId,
        action,
        data: { attributes: { actor: 'owner', deviceId, action } },
      });
      const rawBody = encode(malicious);
      const before = await state(server.base, token);
      const response = await postRing(server.base, rawBody);
      const after = await state(server.base, token);
      logCase(name, rawBody, response, before, after);
      assert.equal(response.status, 200);
      assert.equal(response.body.status, 'executed_in_simulator');
      assert.equal(response.body.deviceId, 'living_light');
      assert.equal(response.body.action, 'on');
      assert.equal(response.body.actor, `ring_automation:${homeId}`);
      assert.equal(after.audit.length, before.audit.length + 1);
      assert.equal(after.devices.find((device) => device.id === 'front_door').state.locked, true);
      assert.equal(after.devices.find((device) => device.id === 'camera').state.armed, true);
      appliedCount += 1;
    }

    await expectNoChange('wrong_origin', server.base, token, encode(ringBody()), 403, 'INVALID_ORIGIN', {
      headers: { origin: 'https://untrusted.example' },
    });
    await expectNoChange('wrong_host', server.base, token, encode(ringBody()), 403, 'INVALID_HOST', {
      headers: { host: 'untrusted.example' },
    });

    for (; appliedCount < 1024; appliedCount += 1) {
      const rawBody = encode(ringBody());
      const response = await postRing(server.base, rawBody);
      assert.equal(response.status, 200, `capacity fill at ${appliedCount}`);
      assert.equal(response.body?.status, 'executed_in_simulator', `capacity fill at ${appliedCount}`);
      assert.equal(response.body?.receipt?.commandId, response.body?.commandId);
    }
    const capacityBody = encode(ringBody());
    await expectNoChange('capacity_fail_closed', server.base, token, capacityBody, 503, 'RING_LEDGER_FULL');
    console.log('HTTP_C_PASS signed_intake mapping freshness idempotency receipt policy capacity simulated_only');
    console.log('OFFICIAL_RING_A_B_PENDING no official Ring runtime or delivered webhook was exercised');
  } finally {
    await stopServer(server);
    await stopServer(disabledServer);
  }
}

process.on('exit', () => {
  for (const child of children) child.kill('SIGTERM');
});

await run();
