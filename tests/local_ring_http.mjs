import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { createTranslator } from '../public/i18n-map.mjs';
import { createLocalRingRuntime } from '../src/local_ring/runtime.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
async function start(mode = '1') {
  const passcode = randomBytes(24).toString('base64url');
  const child = spawn(process.execPath, ['src/server.mjs'], {
    cwd: root, env: { PATH: '/usr/bin:/bin', LANG: 'C', TZ: 'UTC', HOME_MCP_PORT: '0',
      HOME_MCP_DEMO_PASS: passcode, HOME_MCP_LOCAL_RING_SIMULATION: mode }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  const base = await new Promise((resolve, reject) => {
    let text = '';
    const timer = setTimeout(() => { child.kill(); reject(new Error('Local startup timed out')); }, 10000);
    child.stdout.on('data', part => {
      text += part.toString();
      const match = text.match(/Home MCP simulator: (http:\/\/127\.0\.0\.1:\d+)/);
      if (match) { clearTimeout(timer); resolve(match[1]); }
    });
    child.stderr.on('data', () => {});
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', code => { clearTimeout(timer); reject(new Error(`Startup exited ${code}`)); });
  });
  let token;
  async function request(path, method = 'GET', body, headers = {}, authenticate = true) {
    const response = await fetch(base + path, { method, headers: {
      ...(authenticate && token ? { authorization: `Bearer ${token}` } : {}),
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      origin: base, 'x-local-ring-intent': 'simulation', ...headers,
    }, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: response.status, body: await response.json() };
  }
  const login = await request('/api/login', 'POST', { passcode });
  assert.equal(login.status, 200); token = login.body.token;
  return { base, request, stop: () => new Promise(resolve => {
    child.once('exit', resolve); child.kill('SIGTERM');
  }) };
}

test('H01 loopback UI → generated identity → queued motion → same-command simulated receipt → removal', async () => {
  const fx = await start();
  try {
    assert.equal((await fx.request('/api/local-ring/status', 'GET', undefined, {}, false)).status, 401);
    assert.equal((await fx.request('/api/local-ring/link', 'POST', {}, { origin: 'https://wrong.invalid' })).status, 403);
    assert.equal((await fx.request('/api/local-ring/link', 'POST', {}, { 'x-local-ring-intent': '' })).status, 403);
    assert.equal((await fx.request('/api/local-ring/link', 'POST', { accountId: 'attacker' })).status, 400);
    assert.equal((await fx.request('/api/local-ring/link', 'POST', {})).status, 200);
    assert.equal((await fx.request('/api/ring/discovery')).body.error, 'PROVIDER_DISABLED_IN_LOCAL_MODE');
    const queued = await fx.request('/api/local-ring/motion', 'POST', {});
    assert.equal(queued.status, 200);
    let state = (await fx.request('/api/state')).body;
    assert.equal(state.devices.length, 7);
    assert.equal(state.localRing.commands.length, 1);
    assert.equal(state.localRing.commands[0].status, 'queued');
    const pending = state.localRing.commands[0];
    assert.equal(state.devices.find(d => d.id === 'living_light').state.power, false);
    assert.equal((await fx.request('/api/local-ring/worker', 'POST', {})).status, 200);
    state = (await fx.request('/api/state')).body;
    const complete = state.localRing.commands[0];
    assert.equal(complete.status, 'executed_in_simulator');
    assert.equal(complete.commandId, pending.commandId);
    assert.equal(complete.requestId, pending.requestId);
    assert.equal(complete.receipt.requestId, complete.requestId);
    assert.equal(complete.receipt.deviceObserved, false);
    assert.ok(complete.receipt.auditId);
    assert.equal(state.devices.find(d => d.id === 'living_light').state.power, true);
    const applied = state.audit.length;
    await fx.request('/api/local-ring/worker', 'POST', {});
    assert.equal((await fx.request('/api/state')).body.audit.length, applied);
    await fx.request('/api/local-ring/motion', 'POST', {});
    assert.equal((await fx.request('/api/local-ring/remove', 'POST', {})).status, 200);
    await fx.request('/api/local-ring/worker', 'POST', {});
    state = (await fx.request('/api/state')).body;
    assert.equal(state.localRing.commands[1].status, 'denied');
    assert.equal(state.localRing.binding.identity, 'revoked');
    assert.equal(state.audit.length, applied);
    assert.equal((await fx.request('/api/local-ring/link', 'POST', {})).status, 409);
    assert.doesNotMatch(JSON.stringify(state.localRing), /idToken|privateKey|csrfToken|__Host-ring_session|local-generated-account/);
  } finally { await fx.stop(); }
});

test('H02 disabled default composition remains inaccessible', async () => {
  const fx = await start('0');
  try {
    assert.equal((await fx.request('/api/local-ring/link', 'POST', {})).status, 404);
    assert.equal((await fx.request('/api/state')).body.localRing.mode, 'disabled');
  } finally { await fx.stop(); }
});

test('H04 owner logout before simulated linking revokes the bearer', async () => {
  const fx = await start();
  try {
    assert.equal((await fx.request('/api/logout', 'POST', {})).status, 200);
    assert.equal((await fx.request('/api/state')).status, 401);
  } finally { await fx.stop(); }
});

test('H03 actual UI script distinguishes queued/missing ACK/matching simulated execution and sends fixed intent', async () => {
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  const nodes = new Map();
  const node = id => {
    if (!nodes.has(id)) nodes.set(id, { id, textContent: '', children: [], hidden: false, value: '',
      addEventListener() {}, replaceChildren() { this.children = []; }, append(...children) { this.children.push(...children); },
      setAttribute() {}, focus() {}, reset() {} });
    return nodes.get(id);
  };
  const context = vm.createContext({ document: { getElementById: node, createElement: tag => ({
    tag, textContent: '', append() {}, addEventListener() {}, setAttribute() {} }), querySelectorAll: () => [] },
    HomeMcpI18n: createTranslator('en'),
    location: { origin: 'http://127.0.0.1:8765' }, navigator: {}, setInterval: () => 0, clearInterval() {},
    setTimeout: () => 0, Intl, Date, console, URL, fetch: async () => { throw new Error('Unexpected fetch'); } });
  vm.runInContext(script, context);
  const matchingReceipt = { commandId: 'same-command', requestId: 'same-request', status: 'executed_in_simulator', gatewayAck: true, simulated: true, deviceObserved: false, auditId: 'same-audit' };
  for (const [status, receipt, expected] of [
    ['queued', undefined, 'not executed yet'],
    ['execution_unconfirmed', undefined, 'unconfirmed'],
    ['executed_in_simulator', undefined, 'unconfirmed'],
    ['executed_in_simulator', { deviceObserved: false, auditId: 'same-audit' }, 'unconfirmed'],
    ['executed_in_simulator', { ...matchingReceipt, commandId: 'other-command' }, 'unconfirmed'],
    ['executed_in_simulator', { ...matchingReceipt, requestId: 'other-request' }, 'unconfirmed'],
    ['executed_in_simulator', { ...matchingReceipt, gatewayAck: false }, 'unconfirmed'],
    ['executed_in_simulator', { ...matchingReceipt, simulated: false }, 'unconfirmed'],
    ['executed_in_simulator', { ...matchingReceipt, status: 'accepted' }, 'unconfirmed'],
    ['executed_in_simulator', matchingReceipt, 'Simulated execution done'],
  ]) {
    context.snapshot = { mode: 'local_simulation', workerOnline: true, binding: { identity: 'authenticated', authorized: true },
      commands: [{ status, receipt, commandId: 'same-command', requestId: 'same-request' }] };
    vm.runInContext('state = { localRing: snapshot }; renderLocalRing();', context);
    assert.match(node('local-ring-receipts').children[0].textContent, new RegExp(expected));
  }
  let now = Date.parse('2026-10-02T00:00:00Z');
  const actual = createLocalRingRuntime({ now: () => now });
  await actual.link();
  now += 900_000;
  context.snapshot = actual.status();
  assert.equal(context.snapshot.binding.authorized, false);
  vm.runInContext('state = { localRing: snapshot }; renderLocalRing();', context);
  assert.match(node('local-ring-status').textContent, /authorization expired or unavailable/);
  const calls = [];
  context.capture = (...args) => calls.push(args);
  vm.runInContext('request = async (...args) => capture(...args); refresh = async () => {};', context);
  await vm.runInContext('localRingOperation("motion")', context);
  assert.equal(calls[0][0], '/api/local-ring/motion');
  assert.equal(calls[0][3]['X-Local-Ring-Intent'], 'simulation');
});
