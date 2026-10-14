import { fixture } from './mac-command-proof-fixture.mjs';
import { createMacCommandProofSigner, verifyMacProof } from '../../../../src/formal-runtime/mac-command-proof.mjs';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, chmod, readdir, lstat } from 'node:fs/promises';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { createDynamoMacCommandStore } from '../mac-command-store.mjs';
import { createMacCommandService } from '../mac-command-service.mjs';
import { createMacCommandJournal } from '../../../../src/formal-runtime/mac-command-journal.mjs';
import { createMacCommandWorker } from '../../../../src/formal-runtime/mac-command-worker.mjs';
import { createSoftwareTestSwitchPort } from '../../../../src/formal-runtime/software-test-switch-port.mjs';
import { createMacCommandHttpsClient } from '../../../../src/formal-runtime/mac-command-https-client.mjs';
import { commandId, command, hash, envelope } from '../../../../src/formal-runtime/mac-command-contract.mjs';

const TEST_ROOT = process.env.RING_TRANSPORT_TEST_ROOT;
if (!TEST_ROOT?.startsWith('/private/tmp/')) throw new Error('Explicit isolated RING_TRANSPORT_TEST_ROOT required');
const rpc = (id = 'test-command', enabled = true) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'software_test_switch.set', arguments: { enabled } } });
async function journal() { const directory = await mkdtemp(TEST_ROOT + '/journal-'); await chmod(directory, 0o700); return { directory, port: await createMacCommandJournal({ directory }) }; }
function formalDispatcher(f, calls) {
  const proofs = new WeakMap();
  const adapter = createSoftwareTestSwitchPort({ clock: f.clock, verifyAdmission: ({ admission, envelope: e }) => proofs.get(admission) === e });
  return async ({ command: c, envelope: e }) => {
    assert.equal(e, c.envelope); calls.push(c.commandId);
    // Synthetic issuance/consumption fixture: real dispatcher remains an integration dependency.
    const admission = Object.freeze({ accepted: true }); proofs.set(admission, e);
    return { jsonrpc: '2.0', id: e.id, result: adapter.execute({ capability: e.params.name, arguments: e.params.arguments, admission, envelope: e }) };
  };
}
function worker(f, j, dispatchFormal, wire = { fetch: f.fetch, receipt: f.accept }) {
  return createMacCommandWorker({ transport: wire, journal: j, clock: f.clock, dispatchFormal,
    authorizeCommand: async () => ({ ownerRef: 'owner-a', associationRevision: 1, assertCurrent: () => true }) });
}

test('same owner request queues, Mac claims, original command receives result; replay does not execute', async () => {
  const f = fixture(); const pending = await f.submit(); assert.equal(pending.executed, false); assert.equal(pending.status, 'PENDING');
  const j = await journal(); const calls = []; const w = worker(f, j.port, formalDispatcher(f, calls));
  const completed = await w.runOnce(); assert.equal(completed.status, 'SUCCEEDED'); assert.equal(completed.commandId, pending.commandId);
  const replay = await f.submit(); assert.deepEqual(replay, completed); assert.equal(calls.length, 1); assert.equal((await w.runOnce()).status, 'EMPTY');
  assert.deepEqual(await f.service.read({ request: f.browser, actor: f.actor, commandId: pending.commandId }), replay);
  for (const name of await readdir(j.directory)) assert.equal((await lstat(j.directory + '/' + name)).mode & 0o777, 0o600);
});
test('command IDs bind owner, session and typed JSON-RPC id', () => {
  const ids = [commandId('a', 's', 1), commandId('a', 's', '1'), commandId('b', 's', 1), commandId('a', 't', 1)]; assert.equal(new Set(ids).size, 4);
});
test('same ID changed arguments denied; another command cannot overwrite busy mailbox', async () => {
  const f = fixture(); await f.submit(); await assert.rejects(f.submit(rpc('test-command', false)), /ID_CONFLICT/u);
  await assert.rejects(f.submit(rpc('second')), /MAILBOX_BUSY/u); assert.equal((await f.fetch()).command.envelope.params.arguments.enabled, true);
});
test('foreign owner cannot fetch, read or receipt another owner command', async () => {
  const f = fixture(); const original = await f.submit(); const foreign = Object.freeze({ owner: 'owner-b', session: 'b' }); f.requests.add(foreign);
  await assert.rejects(f.service.fetch({ request: foreign, actor: f.actor }), /MAC_PROOF_REQUIRED/u);
  await assert.rejects(f.service.read({ request: foreign, actor: f.actor, commandId: original.commandId }), /NOT_FOUND/u);
  const entry = await f.fetch(); await assert.rejects(f.service.receipt({ request: foreign, actor: f.actor, receipt: f.makeReceipt(entry) }), /MAC_PROOF_REQUIRED/u);
});
test('conditional concurrent claim delivers only once and receipt requires original claim', async () => {
  const f = fixture(); await f.submit(); const values = await Promise.all([f.fetch(), f.fetch()]);
  assert.equal(values.filter(v => v.status === 'CLAIMED').length, 1); const entry = values.find(v => v.status === 'CLAIMED');
  await assert.rejects(f.accept({ ...f.makeReceipt(entry), claimToken: randomBytes(32).toString('base64url') }), /RECEIPT_DENIED/u);
  await assert.rejects(f.accept({ ...f.makeReceipt(entry), envelopeSha256: '0'.repeat(64) }), /RECEIPT_DENIED/u);
  const good = await f.accept(f.makeReceipt(entry)); assert.deepEqual(await f.accept(f.makeReceipt(entry)), good);
});
test('expired queue is not executed and original ID cannot renew expiry', async () => {
  const f = fixture(); const original = await f.submit(); f.advance(30_000);
  assert.equal((await f.fetch()).status, 'EMPTY'); assert.equal((await f.submit()).status, 'EXPIRED');
  assert.equal((await f.store.read({ ownerRef: 'owner-a', commandId: original.commandId })).command.expiresAt, f.clock());
});
test('claimed command expiry returns UNKNOWN and rejects late receipt', async () => {
  const f = fixture(); const original = await f.submit(); const entry = await f.fetch(); const r = f.makeReceipt(entry); f.advance(30_000);
  await assert.rejects(f.accept(r), /EXPIRED/u); assert.equal((await f.service.read({ request: f.browser, actor: f.actor, commandId: original.commandId })).status, 'UNKNOWN');
});
test('revoked authority rejects calls and actor/request substitution', async () => {
  const f = fixture(); await assert.rejects(f.service.submit({ request: f.browser, actor: {}, envelope: rpc() }), /AUTH_DENIED/u);
  await assert.rejects(f.submit(rpc(), { ...f.browser }), /AUTH_DENIED/u); f.revoke(); await assert.rejects(f.submit(), /AUTHORITY_REVOKED/u);
});
test('authority is synchronously rechecked after awaited store operations', async () => {
  const f = fixture(); const store = { ...f.store, enqueue: async c => { const row = await f.store.enqueue(c); f.revoke(); return row; } };
  const service = createMacCommandService({ store, macProofAuthority: f.macProofAuthority, authorize: f.authorize, clock: f.clock });
  await assert.rejects(service.submit({ request: f.browser, actor: f.actor, envelope: rpc() }), /AUTHORITY_REVOKED/u);
});
test('ambiguous Dynamo enqueue recovers exact record; ambiguous claim never redelivers', async () => {
  const f = fixture(); f.db.failNext('after'); assert.equal((await f.submit()).status, 'PENDING');
  f.db.failNext('after'); await assert.rejects(f.fetch(), /CLAIM_OUTCOME_UNKNOWN/u); assert.equal((await f.fetch()).status, 'EMPTY');
});
test('Dynamo outage fails closed without claiming execution', async () => {
  const f = fixture(); f.db.failNext('before'); await assert.rejects(f.submit(), /OUTCOME_UNKNOWN/u); assert.equal([...f.db.rows.keys()].filter(k => k.startsWith('rpl018:command:')).length, 0);
});
test('journal remains one-shot across worker restart and dispatch failure', async () => {
  const f = fixture(); await f.submit(); const entry = await f.fetch(); const j = await journal(); let calls = 0;
  const wire = { fetch: async () => entry, receipt: f.accept };
  const first = worker(f, j.port, async () => { calls++; throw new Error('ambiguous dispatch'); }, wire);
  assert.equal((await first.runOnce()).status, 'UNKNOWN');
  const reopened = await createMacCommandJournal({ directory: j.directory });
  const next = worker(f, reopened, async () => { calls++; throw new Error('must not run'); }, wire);
  assert.equal((await next.runOnce()).status, 'UNKNOWN'); assert.equal(calls, 1);
});
test('lost receipt acknowledgement retries durable receipt without duplicate action', async () => {
  const f = fixture(); const pending = await f.submit(); const j = await journal(); const calls = []; let lose = true;
  const w = worker(f, j.port, formalDispatcher(f, calls), { fetch: f.fetch, receipt: async r => { const value = await f.accept(r); if (lose) { lose = false; throw new Error('lost response'); } return value; } });
  assert.equal((await w.runOnce()).status, 'RECEIPT_PENDING'); assert.equal((await w.retryReceipt(pending.commandId)).status, 'SUCCEEDED'); assert.equal(calls.length, 1);
});
test('software switch requires private proof, original envelope, and one-shot admission', () => {
  const e = rpc(); const proof = Object.freeze({}); const port = createSoftwareTestSwitchPort({ verifyAdmission: call => call.admission === proof && call.envelope === e, clock: () => 100 });
  const input = { capability: e.params.name, arguments: e.params.arguments, admission: proof, envelope: e };
  assert.throws(() => port.execute({ ...input, admission: { accepted: true } }), /ADMISSION/u);
  assert.equal(port.execute(input).enabled, true); assert.throws(() => port.execute(input), /ADMISSION/u);
  assert.throws(() => port.execute({ ...input, capability: 'door.unlock' }), /ADMISSION/u);
});
test('unknown capabilities and getter/proxy fields never enter command contract', () => {
  assert.throws(() => envelope({ ...rpc(), params: { name: 'door.unlock', arguments: { enabled: true } } }), /CAPABILITY/u);
  const e = rpc(); Object.defineProperty(e, 'id', { get() { throw new Error('getter executed'); } }); assert.throws(() => envelope(e), /MAC_COMMAND_INPUT/u);
  assert.throws(() => envelope(new Proxy(rpc(), {})), /MAC_COMMAND_INPUT/u);
});
test('outbound HTTPS pins native endpoint, fixed routes, TLS and bounded JSON; no redirects', async () => {
  const observed = [];
  function request(url, options, callback) {
    const req = new EventEmitter(); req.destroy = () => {}; req.end = body => {
      observed.push({ url: url.href, options, body: JSON.parse(body) });
      queueMicrotask(() => { const response = new PassThrough(); response.statusCode = 200; response.headers = { 'content-type': 'application/json' }; callback(response); response.end('{"status":"EMPTY"}'); });
    }; return req;
  }
  const config = { baseUrl: 'https://abcdefghij.execute-api.ap-northeast-1.amazonaws.com/live', expectedHostname: 'abcdefghij.execute-api.ap-northeast-1.amazonaws.com', getAccessToken: async () => 'synthetic-transport-proof', request };
  config.proofSigner = createMacCommandProofSigner({ privateKey: generateKeyPairSync('ed25519').privateKey, ownerRef: 'owner-a', associationRevision: 1, audience: config.baseUrl + '/mcp' });
  const client = createMacCommandHttpsClient(config); assert.deepEqual(await client.fetch(), { status: 'EMPTY' });
  assert.equal(observed[0].url, config.baseUrl + '/mac/commands/fetch'); assert.equal(observed[0].options.rejectUnauthorized, true); assert.equal(observed[0].options.minVersion, 'TLSv1.2'); assert.deepEqual(observed[0].body, {});
  assert.equal(verifyMacProof({ header: observed[0].options.headers['x-ring-mac-proof'], publicKeySpki: config.proofSigner.publicKeySpki, ownerRef: 'owner-a', associationRevision: 1, operation: 'fetch', audience: config.baseUrl + '/mcp', token: 'synthetic-transport-proof', payload: observed[0].body, now: Date.now() }).operation, 'fetch');
  assert.throws(() => createMacCommandHttpsClient({ ...config, baseUrl: 'http://abcdefghij.execute-api.ap-northeast-1.amazonaws.com/live' }), /CONFIG/u);
  assert.throws(() => createMacCommandHttpsClient({ ...config, baseUrl: config.baseUrl + '?override=x' }), /CONFIG/u);
  const redirect = createMacCommandHttpsClient({ ...config, request(url, options, callback) { const req = new EventEmitter(); req.destroy = () => {}; req.end = () => queueMicrotask(() => { const response = new PassThrough(); response.statusCode = 302; response.headers = { location: 'https://example.com' }; callback(response); response.end(); }); return req; } });
  await assert.rejects(redirect.fetch(), /MAC_HTTPS_RESPONSE/u); config.proofSigner.close();
});
test('Mac rejects mismatched owner before journal or formal dispatch', async () => {
  const f = fixture(); await f.submit(); const j = await journal(); let dispatched = false;
  const w = createMacCommandWorker({ transport: { fetch: f.fetch, receipt: f.accept }, journal: j.port, clock: f.clock,
    authorizeCommand: async () => ({ ownerRef: 'foreign-owner', associationRevision: 1, assertCurrent: () => true }),
    dispatchFormal: async () => { dispatched = true; } });
  await assert.rejects(w.runOnce(), /MAC_WORKER_AUTHORITY/u); assert.equal(dispatched, false); assert.equal((await readdir(j.directory)).length, 0);
});
test('Mac rechecks authority after durable claim before existing formal dispatcher', async () => {
  const f = fixture(); await f.submit(); const j = await journal(); let current = true; let dispatched = false;
  const changed = { ...j.port, claim: async c => { const accepted = await j.port.claim(c); current = false; return accepted; } };
  const w = createMacCommandWorker({ transport: { fetch: f.fetch, receipt: f.accept }, journal: changed, clock: f.clock,
    authorizeCommand: async () => ({ ownerRef: 'owner-a', associationRevision: 1, assertCurrent: () => current }),
    dispatchFormal: async () => { dispatched = true; } });
  await assert.rejects(w.runOnce(), /MAC_WORKER_AUTHORITY/u); assert.equal(dispatched, false);
});
test('Mac refuses expired fetched command before dispatch', async () => {
  const f = fixture(); await f.submit(); const entry = await f.fetch(); f.advance(30_000); const j = await journal(); let dispatched = false;
  const w = worker(f, j.port, async () => { dispatched = true; }, { fetch: async () => entry, receipt: f.accept });
  await assert.rejects(w.runOnce(), /MAC_COMMAND_EXPIRED/u); assert.equal(dispatched, false);
});

// home_device.command: same queue/claim/receipt chain; the result must name the exact device and action of the envelope.
const deviceRpc = (id = 'device-command', deviceId = 'living_light', action = 'on') =>
  ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'home_device.command', arguments: { deviceId, action } } });
test('home device command: queue, claim, apply once through the device port, durable result names device and action', async () => {
  const { createHomeDevicePort } = await import('../../../../src/formal-runtime/home-device-port.mjs');
  const f = fixture(); const pending = await f.submit(deviceRpc()); assert.equal(pending.status, 'PENDING'); assert.equal(pending.executed, false);
  const j = await journal(); const applied = []; const proofs = new WeakMap();
  const port = createHomeDevicePort({ clock: f.clock, verifyAdmission: ({ admission, envelope: e }) => proofs.get(admission) === e,
    apply: async input => { applied.push(input); return { status: 'simulated_applied' }; } });
  const w = worker(f, j.port, async ({ command: c, envelope: e }) => {
    const admission = Object.freeze({ accepted: true }); proofs.set(admission, e);
    return { jsonrpc: '2.0', id: e.id, result: await port.execute({ capability: e.params.name, arguments: e.params.arguments, admission, envelope: e, commandId: c.commandId }) };
  });
  const done = await w.runOnce(); assert.equal(done.status, 'SUCCEEDED');
  assert.deepEqual(applied, [{ deviceId: 'living_light', action: 'on', commandId: pending.commandId }]);
  const read = await f.service.read({ request: f.browser, actor: f.actor, commandId: pending.commandId });
  assert.equal(read.executed, true); assert.equal(read.result.kind, 'home-device');
  assert.equal(read.result.deviceId, 'living_light'); assert.equal(read.result.action, 'on'); assert.equal(read.result.status, 'simulated_applied');
});
test('home device receipt must match the envelope: wrong device, wrong action or a switch result is denied', async () => {
  for (const result of [
    { kind: 'home-device', deviceId: 'dehumidifier', action: 'on', status: 'simulated_applied', revision: 1 },
    { kind: 'home-device', deviceId: 'living_light', action: 'off', status: 'simulated_applied', revision: 1 },
    { kind: 'software-test-switch', enabled: true, revision: 1 }]) {
    const f = fixture(); await f.submit(deviceRpc()); const entry = await f.fetch();
    const r = { schema: 'ring-mac-receipt-v1', commandId: entry.command.commandId, envelopeSha256: entry.command.envelopeSha256,
      claimToken: entry.claimToken, status: 'SUCCEEDED', result: { ...result, observedAt: f.clock() } };
    await assert.rejects(f.accept(r), /EXPIRED|RECEIPT|RESULT/u);
  }
  const f = fixture(); await f.submit(rpc('switch-cmd', true)); const entry = await f.fetch();
  await assert.rejects(f.accept({ ...f.makeReceipt(entry), result: { kind: 'home-device', deviceId: 'living_light', action: 'on', status: 'simulated_applied', revision: 1, observedAt: f.clock() } }), /EXPIRED|RECEIPT|RESULT/u);
});
test('home device command outside the allowlist is denied at submit', async () => {
  const f = fixture();
  for (const [d, a] of [['front_door', 'unlock'], ['camera', 'disarm'], ['alarm_clock', 'set_alarm'], ['living_light', 'toggle']]) {
    await assert.rejects(f.submit(deviceRpc('x-' + d + a, d, a)), /MAC_COMMAND_CAPABILITY/u);
  }
});
