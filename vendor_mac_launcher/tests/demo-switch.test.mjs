import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { resolveConfig } from '../src/config.mjs';
import { keygen, loginUrl, demoSwitch } from '../src/launcher.mjs';
import { callMcpTool } from '../src/mcp-client.mjs';
import { startFakeCloud, HOST, COGNITO_HOST } from './helpers/fake-cloud.mjs';

const cfg = resolveConfig({ apiBase: `https://${HOST}/staging`, cognitoDomain: `https://${COGNITO_HOST}`, clientId: 'abcdefghijklmnopqrstuvwxyz' });
const PASS = () => Buffer.from('correct horse battery staple');
const OWNER = 'owner/fixture';
async function setup() {
  const stateDir = join(mkdtempSync(join(tmpdir(), 'ring-mac-demo-')), 'state');
  const k = await keygen({ stateDir, cfg, passphrase: PASS(), ownerRef: OWNER, associationRevision: 1 });
  const cloud = await startFakeCloud({ enrollment: { publicKeySpki: k.publicKeySpki, ownerRef: OWNER, associationRevision: 1 }, audience: cfg.audience });
  const logs = [];
  const go = async (extra = {}) => demoSwitch({ stateDir, cfg, passphrase: PASS(), enabled: true, polls: 2, intervalMs: 10,
    callbackUrl: cloud.authorize((await loginUrl({ stateDir, cfg })).url), tokenRequest: cloud.reroute, httpsRequest: cloud.reroute,
    log: l => logs.push(l), ...extra });
  const noSecrets = text => {
    const files = existsSync(stateDir) ? readdirSync(stateDir, { recursive: true }).map(f => { try { return readFileSync(join(stateDir, f), 'utf8'); } catch { return ''; } }) : [];
    const dump = [text, ...logs, ...files].join('\n');
    for (const secret of [cloud.state.token, 'unused-refresh-token', 'unused.id.token']) assert.equal(dump.includes(secret), false);
  };
  return { stateDir, cloud, logs, go, noSecrets };
}
const mcpSeen = s => s.cloud.state.seen.filter(x => x.url === '/staging/mcp');

test('demo-switch happy path: one token exchange, MCP set -> worker -> MCP result executed:true, exact wire', async () => {
  const s = await setup();
  try {
    const r = await s.go();
    assert.equal(r.ok, true); assert.equal(r.mode, 'software-direct');
    assert.equal(r.set.status, 'PENDING'); assert.match(r.set.commandId, /^cmd_[a-f0-9]{64}$/u);
    assert.deepEqual(r.worker, { status: 'SUCCEEDED', executed: true });
    assert.deepEqual(r.result, { status: 'SUCCEEDED', executed: true, enabled: true, revision: 1 });
    assert.deepEqual(Object.keys(r), ['mode', 'set', 'worker', 'result', 'ok']);
    assert.equal(s.cloud.state.tokenCalls, 1, 'exactly one Cognito exchange');
    const calls = mcpSeen(s); assert.equal(calls.length, 2);
    for (const [c, name] of [[calls[0], 'software_test_switch.set'], [calls[1], 'software_test_switch.result']]) {
      assert.equal(c.headers.authorization, 'Bearer ' + s.cloud.state.token);
      assert.equal(c.headers.accept, 'application/json, text/event-stream');
      assert.equal(c.headers['content-type'], 'application/json');
      assert.equal(c.headers['mcp-protocol-version'], '2026-07-28');
      assert.equal(c.headers['mcp-method'], 'tools/call'); assert.equal(c.headers['mcp-name'], name);
      assert.equal(c.headers['mcp-session-id'], undefined);
      const b = JSON.parse(c.body);
      assert.deepEqual(Object.keys(b).sort(), ['id', 'jsonrpc', 'method', 'params']);
      assert.equal(b.method, 'tools/call'); assert.equal(b.params.name, name);
      assert.equal(b.params._meta['io.modelcontextprotocol/protocolVersion'], '2026-07-28');
    }
    assert.deepEqual(JSON.parse(calls[0].body).params.arguments, { enabled: true });
    assert.deepEqual(JSON.parse(calls[1].body).params.arguments, { commandId: r.set.commandId });
    assert.ok(s.logs.some(l => /mcp software_test_switch.set -> PENDING/u.test(l)) && s.logs.some(l => /executed=true/u.test(l)));
    s.noSecrets(JSON.stringify(r));
  } finally { await s.cloud.close(); }
});

test('demo-switch parses an SSE (text/event-stream) MCP response and enabled:false', async () => {
  const s = await setup();
  try {
    s.cloud.state.mcpSse = true;
    const r = await s.go({ enabled: false });
    assert.equal(r.ok, true); assert.equal(r.result.enabled, false);
  } finally { await s.cloud.close(); }
});

test('wrong Accept is rejected by the real wire validator (406); demo-switch fails closed before any command exists', async () => {
  const s = await setup();
  try {
    const narrowAccept = (url, o, cb) => s.cloud.reroute(url, { ...o, headers: { ...o.headers, accept: 'application/json' } }, cb);
    await assert.rejects(callMcpTool(cfg, { token: s.cloud.state.token, name: 'software_test_switch.set', arguments: { enabled: true }, id: 'x1', requestImpl: narrowAccept }),
      /MCP_HTTP_406_B02_FORMAL_WIRE_ACCEPT_DENIED/u);
    const mcpOnlyNarrow = (url, o, cb) => (url.pathname.endsWith('/mcp') ? narrowAccept : s.cloud.reroute)(url, o, cb);
    await assert.rejects(s.go({ httpsRequest: mcpOnlyNarrow }), /MCP_HTTP_406_B02_FORMAL_WIRE_ACCEPT_DENIED/u);
    assert.equal(s.cloud.state.commands.size, 0);
    // header/version mismatches map to JSON-RPC wire errors
    const badName = (url, o, cb) => s.cloud.reroute(url, { ...o, headers: { ...o.headers, 'mcp-name': 'other.tool' } }, cb);
    await assert.rejects(callMcpTool(cfg, { token: s.cloud.state.token, name: 'software_test_switch.set', arguments: { enabled: true }, id: 'x2', requestImpl: badName }), /MCP_HTTP_400_RPC-32020/u);
    const badVersion = (url, o, cb) => s.cloud.reroute(url, { ...o, headers: { ...o.headers, 'mcp-protocol-version': '2025-06-18' } }, cb);
    await assert.rejects(callMcpTool(cfg, { token: s.cloud.state.token, name: 'software_test_switch.set', arguments: { enabled: true }, id: 'x3', requestImpl: badVersion }), /MCP_HTTP_400_RPC-32020/u);
    await assert.rejects(callMcpTool(cfg, { token: 'wrong-token-value-123', name: 'software_test_switch.set', arguments: { enabled: true }, id: 'x4', requestImpl: s.cloud.reroute }), /MCP_HTTP_401_B02_FORMAL_ACCESS_TOKEN_REQUIRED/u);
  } finally { await s.cloud.close(); }
});

test('expired access token: no /mcp call, no command enqueued', async () => {
  const s = await setup();
  try {
    s.cloud.state.tokenLifetimeSeconds = 1;
    await assert.rejects(s.go(), /OAUTH_TOKEN_EXPIRED/u);
    assert.equal(mcpSeen(s).length, 0); assert.equal(s.cloud.state.commands.size, 0);
  } finally { await s.cloud.close(); }
});

test('worker fetching a different (older) queued command fails closed with WORKER_COMMAND_MISMATCH; wrong passphrase spends nothing', async () => {
  const s = await setup();
  try {
    await assert.rejects(s.go({ passphrase: Buffer.from('definitely the wrong one') }), /MAC_KEY_UNAVAILABLE/u);
    assert.equal(s.cloud.state.tokenCalls ?? 0, 0); assert.equal(mcpSeen(s).length, 0);
    s.cloud.submit(false);
    await assert.rejects(s.go(), /WORKER_COMMAND_MISMATCH/u);
  } finally { await s.cloud.close(); }
});

test('CLI demo-switch requires --callback-url and --enabled true|false', () => {
  const CLI = join(dirname(dirname(fileURLToPath(import.meta.url))), 'mac-worker.mjs');
  const env = { PATH: process.env.PATH, HOME: process.env.HOME, RING_MAC_STATE_DIR: join(mkdtempSync(join(tmpdir(), 'ring-mac-dcli-')), 's') };
  for (const args of [['demo-switch', '--enabled', 'true'], ['demo-switch', '--callback-url', 'https://x.invalid/', '--enabled', 'yes']]) {
    const r = spawnSync(process.execPath, [CLI, ...args], { env, input: '', encoding: 'utf8' });
    assert.equal(r.status, 2); assert.match(r.stderr, /^ERROR USAGE/mu);
  }
});
