// Family remote-approval relay, end to end in memory: hub (src/remote_relay.mjs) <-> cloud logic (family-relay.mjs) <->
// a phone that signs exactly like the browser page (WebCrypto ECDSA P-256, raw r||s). No network, no AWS.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { webcrypto, randomBytes, generateKeyPairSync } from 'node:crypto';
import { canonical, createFamilyRelay, createMemoryRelayStore, phoneKeyId } from '../cloud/aws/ring-private/family-relay.mjs';
import { createRemoteRelay, loadOrCreateRelayKey, relayPublicKeySpki } from '../src/remote_relay.mjs';

const { subtle } = webcrypto;
async function makePhone() {
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const { kty, crv, x, y } = await subtle.exportKey('jwk', pair.publicKey);
  const jwk = { kty, crv, x, y };
  const keyId = phoneKeyId(jwk);
  const envelope = async (op, payload, { ts = Date.now(), nonce = randomBytes(18).toString('base64url') } = {}) => {
    const sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, Buffer.from(canonical({ op, payload, keyId, ts, nonce })));
    return { op, payload, keyId, ts, nonce, signature: Buffer.from(sig).toString('base64url') };
  };
  return { jwk, keyId, envelope };
}
// The relay answers first, then the fake response is built (an error must surface as an HTTP error, not be hidden).
const fakeFetch = (relay) => async (u, init) => {
  try { const body = await relay.mac(JSON.parse(init.body)); return { ok: true, status: 200, json: async () => body }; }
  catch (e) { return { ok: false, status: e.status ?? 500, json: async () => ({ error: e.code }) }; }
};
function setup() {
  const dir = mkdtempSync(join(tmpdir(), 'relay-'));
  const hubKey = loadOrCreateRelayKey(join(dir, 'k', 'relay.key'));
  const store = createMemoryRelayStore();
  const relay = createFamilyRelay({ store, macPublicKeySpki: relayPublicKeySpki(hubKey) });
  const fetchImpl = fakeFetch(relay);
  const decisions = [];
  const hub = createRemoteRelay({ base: 'https://relay.example/staging', privateKey: hubKey, storePath: join(dir, 'phones', 'relay_phones.json'), fetchImpl, onDecision: (d) => decisions.push(d) });
  return { dir, hubKey, store, relay, hub, decisions };
}
const phoneCall = async (relay, env) => { try { return await relay.phone(env); } catch (e) { return { error: e.code, status: e.status }; } };

test('enrol a phone with the one-time code, then approve a door request from anywhere; the hub re-verifies the phone signature', async () => {
  const s = setup();
  const phone = await makePhone();
  const { code, url } = await s.hub.enable({ deviceId: 'phone_admin' });
  assert.match(code, /^[A-Z2-9]{8}$/u); assert.equal(url, `https://relay.example/staging/family#code=${code}`);
  assert.deepEqual(await phoneCall(s.relay, await phone.envelope('register', { code, jwk: phone.jwk, name: 'Amy' })), { ok: true, status: 'waiting_for_home' });
  // the code works once
  assert.equal((await phoneCall(s.relay, await (await makePhone()).envelope('register', { code, jwk: (await makePhone()).jwk, name: 'X' }))).error !== undefined, true);
  await s.hub.tick();
  assert.equal(s.hub.status().phones[0].name, 'Amy');
  const st = statSync(join(s.dir, 'phones', 'relay_phones.json'));
  assert.equal(st.mode & 0o777, 0o600);
  // a door request goes up as text; the phone sees it and approves
  const requestId = randomBytes(16).toString('base64url');
  await s.hub.publishRequest({ requestId, kind: 'ring', label: 'Ring doorbell', hasSnapshot: true, expiresAtMs: Date.now() + 60_000 });
  const pending = await phoneCall(s.relay, await phone.envelope('pending', {}));
  assert.equal(pending.request.requestId, requestId); assert.equal(pending.request.label, 'Ring doorbell');
  assert.deepEqual(await phoneCall(s.relay, await phone.envelope('decide', { requestId, decision: 'approve' })), { ok: true, status: 'sent_to_home' });
  assert.equal((await phoneCall(s.relay, await phone.envelope('decide', { requestId, decision: 'deny' }))).error, 'RELAY_ALREADY_DECIDED');
  await s.hub.tick();
  assert.deepEqual(s.decisions, [{ requestId, decision: 'approve', approver: 'Amy (remote)', deviceId: 'phone_admin' }]);
  await s.hub.publishResult({ requestId, status: 'approved', receiptId: 'abc123' });
  assert.deepEqual((await phoneCall(s.relay, await phone.envelope('pending', {}))).result, { status: 'approved', receiptId: 'abc123' });
});

test('cloud cannot forge: a decision not signed by the activated phone is rejected by the hub; unknown or revoked phones are refused', async () => {
  const s = setup();
  const phone = await makePhone(); const stranger = await makePhone();
  const { code } = await s.hub.enable({ deviceId: 'phone_admin' });
  await phoneCall(s.relay, await phone.envelope('register', { code, jwk: phone.jwk, name: 'Amy' }));
  await s.hub.tick();
  const requestId = randomBytes(16).toString('base64url');
  await s.hub.publishRequest({ requestId, kind: 'mcp', label: 'AI agent (MCP)', expiresAtMs: Date.now() + 60_000 });
  // a stranger key is not active
  assert.equal((await phoneCall(s.relay, await stranger.envelope('pending', {}))).error, 'PHONE_NOT_ACTIVE');
  // a compromised cloud writes a decision signed by some other key, claiming Amy's keyId
  const forged = await stranger.envelope('decide', { requestId, decision: 'approve' });
  await s.store.put({ pk: `relay:decision:${requestId}`, envelope: { ...forged, keyId: phone.keyId }, expiresAtMs: Date.now() + 60_000 });
  const r = await s.hub.tick();
  assert.deepEqual(r, { rejected: true }); assert.deepEqual(s.decisions, []);
  // tampered payload with a genuine signature
  const requestId2 = randomBytes(16).toString('base64url');
  await s.hub.publishRequest({ requestId: requestId2, kind: 'mcp', label: 'AI agent (MCP)', expiresAtMs: Date.now() + 60_000 });
  const real = await phone.envelope('decide', { requestId: requestId2, decision: 'deny' });
  await s.store.put({ pk: `relay:decision:${requestId2}`, envelope: { ...real, payload: { requestId: requestId2, decision: 'approve' } }, expiresAtMs: Date.now() + 60_000 });
  assert.deepEqual(await s.hub.tick(), { rejected: true }); assert.deepEqual(s.decisions, []);
  // revoke: the phone can no longer read or decide
  await s.hub.revoke(phone.keyId);
  assert.equal((await phoneCall(s.relay, await phone.envelope('pending', {}))).error, 'PHONE_NOT_ACTIVE');
});

test('replays, stale envelopes, bad hub signatures and junk are refused', async () => {
  const s = setup();
  const phone = await makePhone();
  const { code } = await s.hub.enable({ deviceId: 'phone_admin' });
  const reg = await phone.envelope('register', { code, jwk: phone.jwk, name: 'Amy' });
  await phoneCall(s.relay, reg);
  assert.equal((await phoneCall(s.relay, reg)).error, 'RELAY_REPLAY');
  await s.hub.tick();
  assert.equal((await phoneCall(s.relay, await phone.envelope('pending', {}, { ts: Date.now() - 120_000 }))).error, 'PHONE_ENVELOPE_STALE');
  const env = await phone.envelope('pending', {});
  assert.equal((await phoneCall(s.relay, { ...env, signature: Buffer.alloc(64).toString('base64url') })).error, 'PHONE_SIGNATURE_INVALID');
  // a different hub key cannot talk to the relay
  const other = generateKeyPairSync('ed25519').privateKey;
  const rogue = createRemoteRelay({ base: 'https://relay.example/staging', privateKey: other, storePath: join(s.dir, 'x.json'),
    fetchImpl: fakeFetch(s.relay) });
  await assert.rejects(rogue.enable({ deviceId: 'x' }), { code: 'MAC_SIGNATURE_INVALID' });
  // request labels are plain text only; expiry is bounded
  const requestId = randomBytes(16).toString('base64url');
  await assert.rejects(s.hub.publishRequest({ requestId, kind: 'ring', label: '<img src=x onerror=alert(1)>', expiresAtMs: Date.now() + 60_000 }), { code: 'RELAY_ARGUMENT' });
  await assert.rejects(s.hub.publishRequest({ requestId, kind: 'ring', label: 'Ring doorbell', expiresAtMs: Date.now() + 3_600_000 }), { code: 'RELAY_ARGUMENT' });
  assert.equal(readFileSync(join(s.dir, 'k', 'relay.key'), 'utf8').includes('PRIVATE KEY'), true);
  assert.equal(statSync(join(s.dir, 'k', 'relay.key')).mode & 0o777, 0o600);
});

test('publishing a request is retried on 5xx / network errors (fresh signature each time); a 4xx is final', async () => {
  const s = setup();
  let fail = 2; const ops = [];
  const flaky = async (u, init) => {
    const body = JSON.parse(init.body); ops.push(body.claims.op + ':' + body.claims.nonce.slice(0, 6));
    if (body.claims.op === 'request' && fail-- > 0) return { ok: false, status: fail === 1 ? 500 : 503, json: async () => ({ error: 'INJECTED' }) };
    try { const out = await s.relay.mac(body); return { ok: true, status: 200, json: async () => out }; }
    catch (e) { return { ok: false, status: e.status ?? 500, json: async () => ({ error: e.code }) }; }
  };
  const hub = createRemoteRelay({ base: 'https://relay.example/staging', privateKey: s.hubKey, storePath: join(s.dir, 'p2.json'), fetchImpl: flaky, sleep: async () => {} });
  await hub.publishRequest({ requestId: 'r'.repeat(22), kind: 'mcp', label: 'AI agent (MCP)', hasSnapshot: false, expiresAtMs: Date.now() + 60_000 });
  const reqOps = ops.filter((o) => o.startsWith('request:'));
  assert.equal(reqOps.length, 3, 'two failures, then delivered'); assert.equal(new Set(reqOps).size, 3, 'each try has its own nonce');
  let tries = 0;
  const bad = createRemoteRelay({ base: 'https://relay.example/staging', privateKey: s.hubKey, storePath: join(s.dir, 'p3.json'), sleep: async () => {},
    fetchImpl: async () => { tries += 1; return { ok: false, status: 400, json: async () => ({ error: 'RELAY_ARGUMENT' }) }; } });
  await assert.rejects(bad.publishResult({ requestId: 'x'.repeat(22), status: 'approved', receiptId: null }), { code: 'RELAY_ARGUMENT' });
  assert.equal(tries, 1, 'a 4xx is not retried');
});

test('Ring webhooks: the first pull only notes the queue position; later events reach the hub once, in order; a restarted hub never replays old ones', async () => {
  const { createHmac } = await import('node:crypto');
  const key = 'test-ring-hmac-key-0123456789';
  const dir = mkdtempSync(join(tmpdir(), 'relay-ring-'));
  const hubKey = loadOrCreateRelayKey(join(dir, 'relay.key'));
  const relay = createFamilyRelay({ store: createMemoryRelayStore(), macPublicKeySpki: relayPublicKeySpki(hubKey), ringWebhookKey: key });
  const deliver = (type, extra = {}) => {
    const raw = JSON.stringify({ meta: { version: '1.1', time: new Date().toISOString(), request_id: randomBytes(8).toString('hex') },
      data: { id: `dev_${type}`, type, attributes: { source: 'dev', source_type: 'devices', timestamp: Date.now(), ...extra } } });
    return relay.ringWebhook({ rawBody: Buffer.from(raw), signature: `sha256=${createHmac('sha256', key).update(raw).digest('hex')}` });
  };
  const seen = [];
  const make = () => createRemoteRelay({ base: 'https://relay.example', privateKey: hubKey, storePath: join(dir, 'phones.json'), fetchImpl: fakeFetch(relay), onRingEvent: (e) => seen.push(e) });
  await deliver('button_press');                       // before the hub started: never fired
  const hub = make();
  assert.deepEqual(await hub.pullRingEvents(), { baseline: true, head: 1 });
  await deliver('motion_detected', { sub_type: 'human' }); await deliver('device_offline');
  assert.equal((await hub.pullRingEvents()).fired, 2);
  assert.deepEqual(seen.map((e) => [e.seq, e.type, e.subType]), [[2, 'motion_detected', 'human'], [3, 'device_offline', null]]);
  assert.equal((await hub.pullRingEvents()).fired, 0);  // nothing twice
  const restarted = make();                             // a new hub process starts from the current head again
  assert.deepEqual(await restarted.pullRingEvents(), { baseline: true, head: 3 });
  await deliver('device_online');
  await restarted.pullRingEvents();
  assert.deepEqual(seen.map((e) => e.type), ['motion_detected', 'device_offline', 'device_online']);
});
