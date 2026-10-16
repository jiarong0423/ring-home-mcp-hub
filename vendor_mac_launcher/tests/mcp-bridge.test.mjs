import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { resolveConfig } from '../src/config.mjs';
import { keygen, loginUrl, openBridgeSession, listenDevice } from '../src/launcher.mjs';
import { createBridge, serveStdio, BRIDGE_TOOLS } from '../src/mcp-bridge.mjs';
import { startFakeCloud, HOST, COGNITO_HOST } from './helpers/fake-cloud.mjs';

const cfg = resolveConfig({ apiBase: `https://${HOST}/staging`, cognitoDomain: `https://${COGNITO_HOST}`, clientId: 'abcdefghijklmnopqrstuvwxyz' });
const PASS = () => Buffer.from('correct horse battery staple');
const OWNER = 'owner/fixture';
async function setup() {
  const stateDir = join(mkdtempSync(join(tmpdir(), 'ring-mac-bridge-')), 'state');
  const k = await keygen({ stateDir, cfg, passphrase: PASS(), ownerRef: OWNER, associationRevision: 1 });
  const cloud = await startFakeCloud({ enrollment: { publicKeySpki: k.publicKeySpki, ownerRef: OWNER, associationRevision: 1 }, audience: cfg.audience });
  const login = async () => cloud.authorize((await loginUrl({ stateDir, cfg })).url);
  const logs = [];
  const open = async (extra = {}) => {
    const session = await openBridgeSession({ stateDir, cfg, callbackUrl: await login(), tokenRequest: cloud.reroute, ...extra });
    return createBridge({ cfg, getAccessToken: session.getAccessToken, requestImpl: cloud.reroute, log: l => logs.push(l) });
  };
  const applied = [];
  const apply = async input => { applied.push(input); return { status: 'simulated_applied' }; };
  const listen = async (extra = {}) => listenDevice({ stateDir, cfg, passphrase: PASS(), applyHomeDevice: apply, polls: 2, intervalMs: 10,
    callbackUrl: await login(), tokenRequest: cloud.reroute, httpsRequest: cloud.reroute, log: () => {}, ...extra });
  return { cloud, open, listen, applied, logs, stateDir };
}
const rpc = (id, method, params) => ({ jsonrpc: '2.0', id, method, ...(params === undefined ? {} : { params }) });
const mcpSeen = s => s.cloud.state.seen.filter(x => x.url === '/staging/mcp');

test('bridge happy path: tools/list shows only the two home_device tools; agent command -> Mac listen applies once -> result executed:true', async () => {
  const s = await setup();
  try {
    const bridge = await s.open();
    const init = await bridge.handle(rpc(1, 'initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'inspector', version: '1' } }));
    assert.equal(init.result.protocolVersion, '2025-11-25'); assert.deepEqual(init.result.capabilities, { tools: {} });
    assert.equal(await bridge.handle({ jsonrpc: '2.0', method: 'notifications/initialized' }), null);
    const list = await bridge.handle(rpc(2, 'tools/list', {}));
    assert.deepEqual(list.result.tools.map(x => x.name), [...BRIDGE_TOOLS]);
    const set = await bridge.handle(rpc(3, 'tools/call', { name: 'home_device.command', arguments: { deviceId: 'living_light', action: 'on' } }));
    assert.equal(set.result.isError, false); assert.equal(set.result.structuredContent.status, 'PENDING');
    const commandId = set.result.structuredContent.commandId; assert.match(commandId, /^cmd_[a-f0-9]{64}$/u);
    const w = await s.listen();
    assert.equal(w.ok, true); assert.deepEqual(w.worker, { status: 'SUCCEEDED', executed: true, commandId });
    assert.deepEqual(s.applied, [{ deviceId: 'living_light', action: 'on', commandId }]);
    const r = await bridge.handle(rpc(4, 'tools/call', { name: 'home_device.result', arguments: { commandId } }));
    assert.equal(r.result.isError, false);
    assert.deepEqual({ status: r.result.structuredContent.status, executed: r.result.structuredContent.executed }, { status: 'SUCCEEDED', executed: true });
    assert.equal(JSON.parse(r.result.content[0].text).executed, true);
    const calls = mcpSeen(s);
    assert.deepEqual(calls.map(c => c.headers['mcp-method']), ['tools/list', 'tools/call', 'tools/call']);
    assert.equal(calls[0].headers['mcp-name'], undefined);
    assert.ok(s.logs.includes('tools/call home_device.result -> SUCCEEDED executed=true'));
    assert.ok(s.logs.every(l => !l.includes(s.cloud.state.token)));
  } finally { await s.cloud.close(); }
});

test('forbidden action is sent to the cloud and refused there (bridge keeps no allowlist); nothing is queued', async () => {
  const s = await setup();
  try {
    const bridge = await s.open();
    for (const [deviceId, action] of [['front_door', 'unlock'], ['camera', 'disarm']]) {
      const r = await bridge.handle(rpc(5, 'tools/call', { name: 'home_device.command', arguments: { deviceId, action } }));
      assert.equal(r.result.isError, true); assert.match(r.result.content[0].text, /^Refused by cloud MCP: MCP_HTTP_400_mcp_rest_denied$/u);
    }
    assert.equal(s.cloud.state.queue.length, 0); assert.equal(mcpSeen(s).length, 2);
  } finally { await s.cloud.close(); }
});

test('only the two home_device tools are forwarded; other methods and bad shapes are refused without any cloud call', async () => {
  const s = await setup();
  try {
    const bridge = await s.open();
    for (const name of ['software_test_switch.set', 'home_device.other', undefined]) {
      const r = await bridge.handle(rpc(6, 'tools/call', { name, arguments: {} }));
      assert.deepEqual(r.result, { content: [{ type: 'text', text: 'Refused by bridge: TOOL_NOT_FORWARDED' }], isError: true });
    }
    const badArgs = await bridge.handle(rpc(7, 'tools/call', { name: 'home_device.command', arguments: ['living_light', 'on'] }));
    assert.equal(badArgs.result.content[0].text, 'Refused by bridge: ARGUMENTS_INVALID');
    assert.equal((await bridge.handle(rpc(8, 'resources/list', {}))).error.code, -32601);
    assert.equal((await bridge.handle({ id: 9, method: 'tools/list' })).error.code, -32600);
    assert.deepEqual((await bridge.handle(rpc(10, 'ping'))).result, {});
    assert.equal((await bridge.handle(rpc(11, 'initialize', { protocolVersion: '1999-01-01' }))).result.protocolVersion, '2025-11-25');
    assert.equal(mcpSeen(s).length, 0);
  } finally { await s.cloud.close(); }
});

test('expired login: the bridge refuses every forwarded call with OAUTH_TOKEN_EXPIRED; callback is single use', async () => {
  const s = await setup();
  try {
    let now = Date.now();
    const bridge = await s.open({ clock: () => now });
    now += 300_000;
    const r = await bridge.handle(rpc(12, 'tools/call', { name: 'home_device.command', arguments: { deviceId: 'living_light', action: 'on' } }));
    assert.equal(r.result.content[0].text, 'Refused by cloud MCP: OAUTH_TOKEN_EXPIRED');
    assert.equal((await bridge.handle(rpc(13, 'tools/list', {}))).error.message, 'Cloud MCP tools/list failed: OAUTH_TOKEN_EXPIRED');
    const callbackUrl = s.cloud.authorize((await loginUrl({ stateDir: s.stateDir, cfg })).url);
    await openBridgeSession({ stateDir: s.stateDir, cfg, callbackUrl, tokenRequest: s.cloud.reroute });
    await assert.rejects(openBridgeSession({ stateDir: s.stateDir, cfg, callbackUrl, tokenRequest: s.cloud.reroute }), /PKCE_NOT_PENDING/u);
    assert.equal(mcpSeen(s).length, 0);
  } finally { await s.cloud.close(); }
});

test('listen-device: nothing queued -> EMPTY after the poll window, not ok; missing apply refused before any network call', async () => {
  const s = await setup();
  try {
    const w = await s.listen({ polls: 3 });
    assert.equal(w.ok, false); assert.deepEqual(w.worker, { status: 'EMPTY', executed: false, commandId: null });
    const before = s.cloud.state.tokenCalls;
    await assert.rejects(s.listen({ applyHomeDevice: undefined }), /HOME_DEVICE_UNAVAILABLE/u);
    assert.equal(s.cloud.state.tokenCalls, before);
  } finally { await s.cloud.close(); }
});

test('stdio: newline JSON-RPC in, responses in order on stdout, parse errors answered, notifications silent, no token anywhere', async () => {
  const s = await setup();
  try {
    const bridge = await s.open();
    const input = new PassThrough(); const output = new PassThrough(); let out = '';
    output.on('data', c => { out += c; });
    const done = serveStdio({ bridge, input, output });
    input.write(JSON.stringify(rpc(1, 'initialize', { protocolVersion: '2025-06-18' })) + '\n');
    input.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
    input.write('{not json\n');
    input.write(JSON.stringify(rpc(2, 'tools/list', {})) + '\n');
    input.end();
    await done;
    const lines = out.trim().split('\n').map(l => JSON.parse(l));
    assert.deepEqual(lines.map(l => l.id), [1, null, 2]);
    assert.equal(lines[0].result.protocolVersion, '2025-06-18'); assert.equal(lines[1].error.code, -32700);
    assert.equal(lines[2].result.tools.length, 2);
    assert.ok(!out.includes(s.cloud.state.token));
  } finally { await s.cloud.close(); }
});

test('CLI: without RING_MAC_CALLBACK_URL the bridge exits 2 with a usage ERROR and writes nothing to stdout', () => {
  const cli = join(dirname(fileURLToPath(import.meta.url)), '..', 'mcp-bridge.mjs');
  const env = { ...process.env }; delete env.RING_MAC_CALLBACK_URL;
  const r = spawnSync(process.execPath, [cli], { env, input: '', encoding: 'utf8' });
  assert.equal(r.status, 2); assert.equal(r.stdout, ''); assert.match(r.stderr, /^ERROR USAGE/u);
});
