import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolveConfig } from '../src/config.mjs';
import { keygen, loginUrl, demoDevice } from '../src/launcher.mjs';
import { envelope, receipt, HOME_DEVICE_ACTIONS } from '../vendor/mac-command-contract.mjs';
import { startFakeCloud, HOST, COGNITO_HOST } from './helpers/fake-cloud.mjs';

const cfg = resolveConfig({ apiBase: `https://${HOST}/staging`, cognitoDomain: `https://${COGNITO_HOST}`, clientId: 'abcdefghijklmnopqrstuvwxyz' });
const PASS = () => Buffer.from('correct horse battery staple');
const OWNER = 'owner/fixture';
async function setup() {
  const stateDir = join(mkdtempSync(join(tmpdir(), 'ring-mac-device-')), 'state');
  const k = await keygen({ stateDir, cfg, passphrase: PASS(), ownerRef: OWNER, associationRevision: 1 });
  const cloud = await startFakeCloud({ enrollment: { publicKeySpki: k.publicKeySpki, ownerRef: OWNER, associationRevision: 1 }, audience: cfg.audience });
  const applied = []; const logs = [];
  const apply = async input => { applied.push(input); return { status: 'simulated_applied' }; };
  const go = async (extra = {}) => demoDevice({ stateDir, cfg, passphrase: PASS(), deviceId: 'living_light', action: 'on', applyHomeDevice: apply,
    polls: 2, intervalMs: 10, callbackUrl: cloud.authorize((await loginUrl({ stateDir, cfg })).url), tokenRequest: cloud.reroute,
    httpsRequest: cloud.reroute, log: l => logs.push(l), ...extra });
  return { cloud, applied, logs, go };
}
const mcpSeen = s => s.cloud.state.seen.filter(x => x.url === '/staging/mcp');

test('demo-device happy path: home_device.command -> worker applies once via injected apply -> home_device.result executed:true', async () => {
  const s = await setup();
  try {
    const r = await s.go();
    assert.equal(r.ok, true);
    assert.deepEqual(r.worker, { status: 'SUCCEEDED', executed: true });
    assert.deepEqual(r.result, { status: 'SUCCEEDED', executed: true, deviceId: 'living_light', action: 'on', deviceStatus: 'simulated_applied', revision: 1 });
    assert.equal(s.applied.length, 1);
    assert.deepEqual(s.applied[0], { deviceId: 'living_light', action: 'on', commandId: r.set.commandId });
    const calls = mcpSeen(s); assert.equal(calls.length, 2);
    assert.equal(calls[0].headers['mcp-name'], 'home_device.command'); assert.equal(calls[1].headers['mcp-name'], 'home_device.result');
    assert.deepEqual(JSON.parse(calls[0].body).params.arguments, { deviceId: 'living_light', action: 'on' });
    assert.ok(s.logs.some(l => /^demo-device start mode=software-direct device=living_light action=on$/u.test(l)));
    assert.ok(s.logs.some(l => /^mcp home_device\.command -> PENDING cmd_[a-f0-9]{64}$/u.test(l)));
  } finally { await s.cloud.close(); }
});

test('local refusal (apply throws or does not apply): no receipt, not executed, cloud never sees SUCCEEDED', async () => {
  for (const apply of [async () => { throw Object.assign(new Error('x'), { code: 'NOT_PAIRED' }); }, async () => ({ status: 'queued' })]) {
    const s = await setup();
    try {
      const r = await s.go({ applyHomeDevice: apply });
      assert.equal(r.ok, false); assert.equal(r.worker.executed, false); assert.equal(r.result.executed, false);
      assert.equal(s.cloud.state.receipts.length, 0);
    } finally { await s.cloud.close(); }
  }
});

test('disallowed device/action is refused before any network call; missing apply refused', async () => {
  const s = await setup();
  try {
    for (const [deviceId, action] of [['front_door', 'unlock'], ['camera', 'disarm'], ['air_conditioner', 'set_temperature'], ['toaster', 'on'], ['living_light', 'ON']]) {
      await assert.rejects(s.go({ deviceId, action }), /HOME_DEVICE_ACTION_NOT_ALLOWED/u);
    }
    await assert.rejects(s.go({ applyHomeDevice: undefined }), /HOME_DEVICE_UNAVAILABLE/u);
    assert.equal(mcpSeen(s).length, 0); assert.equal(s.cloud.state.tokenCalls ?? 0, 0);
  } finally { await s.cloud.close(); }
});

test('contract: home_device envelope is exact and allowlisted; receipt result must be a valid home-device result', () => {
  const ok = { jsonrpc: '2.0', id: 'a1', method: 'tools/call', params: { name: 'home_device.command', arguments: { deviceId: 'robot_vacuum', action: 'dock' } } };
  assert.deepEqual(envelope(ok).params.arguments, { deviceId: 'robot_vacuum', action: 'dock' });
  const bad = args => ({ ...ok, params: { ...ok.params, arguments: args } });
  for (const a of [{ deviceId: 'robot_vacuum' }, { deviceId: 'robot_vacuum', action: 'dock', extra: 1 }, { deviceId: 'front_door', action: 'unlock' },
    { deviceId: 'constructor', action: 'on' }, { deviceId: '__proto__', action: 'on' }]) assert.throws(() => envelope(bad(a)));
  assert.throws(() => envelope({ ...ok, params: { name: 'home_device.other', arguments: { deviceId: 'camera', action: 'arm' } } }), /MAC_COMMAND_CAPABILITY/u);
  assert.equal(Object.isFrozen(HOME_DEVICE_ACTIONS) && Object.isFrozen(HOME_DEVICE_ACTIONS.camera), true);
  const base = { schema: 'ring-mac-receipt-v1', commandId: 'cmd_' + 'a'.repeat(64), envelopeSha256: 'b'.repeat(64),
    claimToken: Buffer.alloc(32, 7).toString('base64url'), status: 'SUCCEEDED' };
  const res = { kind: 'home-device', deviceId: 'camera', action: 'arm', status: 'simulated_applied', revision: 1, observedAt: 5 };
  assert.deepEqual(receipt({ ...base, result: res }).result, res);
  for (const r of [{ ...res, status: 'queued' }, { ...res, action: 'disarm' }, { ...res, extra: 1 }, { ...res, kind: 'software-test-switch' }]) {
    assert.throws(() => receipt({ ...base, result: r }));
  }
});

test('one login reused: onToken hands back the first exchange; later runs pass it as token, skip Cognito, and log "reused"', async () => {
  const s = await setup();
  try {
    let held = null;
    const first = await s.go({ onToken: t => { held = t; } });
    assert.equal(first.ok, true); assert.equal(typeof held?.accessToken, 'string'); assert.equal(s.cloud.state.tokenCalls, 1);
    s.logs.length = 0;
    const second = await s.go({ token: held, action: 'off', callbackUrl: undefined });
    assert.equal(second.ok, true); assert.equal(s.cloud.state.tokenCalls, 1, 'no second Cognito exchange');
    assert.ok(s.logs.includes('cognito session reused (not shown)'));
    assert.equal(s.applied.length, 2);
    await assert.rejects(s.go({ token: { ...held, expiresAtMs: Date.now() + 1000 }, callbackUrl: undefined }), /OAUTH_TOKEN_EXPIRED/u);
    await assert.rejects(s.go({ token: { expiresAtMs: Date.now() + 60_000 }, callbackUrl: undefined }), /OAUTH_TOKEN_EXPIRED/u);
    assert.equal(s.applied.length, 2); assert.equal(s.cloud.state.tokenCalls, 1);
  } finally { await s.cloud.close(); }
});
