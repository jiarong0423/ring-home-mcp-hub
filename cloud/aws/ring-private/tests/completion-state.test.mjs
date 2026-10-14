import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createCompletionStateCodec, CompletionStateError } from '../completion-state.mjs';

const initial = 1_790_000_000_000;
const key = Buffer.alloc(32, 7);
const nonce = Buffer.alloc(32, 9).toString('base64url');
const failure = code => error => error instanceof CompletionStateError && error.code === code && error.message === code;
function fixture(ttlSeconds = 120) {
  let now = initial;
  const codec = createCompletionStateCodec({ hmacKey: key, clock: () => now, random: size => Buffer.alloc(size, 9), ttlSeconds });
  return { codec, setNow: value => { now = value; } };
}
function signed(source) {
  const payload = Buffer.from(source).toString('base64url');
  const signature = createHmac('sha256', key).update('ring-completion-v1\0' + payload).digest('base64url');
  return payload + '.' + signature;
}
function packet(overrides = {}) {
  return { version: 1, state: 'completed', expiresAt: initial + 120_000, nonce, ...overrides };
}
for (const state of ['completed', 'denied', 'expired', 'unknown']) {
  test('canonical short-lived display ticket round trip: ' + state, () => {
    const { codec } = fixture();
    const ticket = codec.issue(state);
    assert.match(ticket, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/);
    assert.deepEqual(codec.verify(ticket), packet({ state }));
    assert(Object.isFrozen(codec.verify(ticket)));
    const payload = JSON.parse(Buffer.from(ticket.split('.')[0], 'base64url'));
    assert.deepEqual(Object.keys(payload), ['version', 'state', 'expiresAt', 'nonce']);
    for (const name of ['id', 'account', 'token', 'owner', 'household']) assert.equal(Object.keys(payload).some(key => key.includes(name)), false);
  });
}
test('ticket replay only repeats finite display data; no authority or operation is created', () => {
  const { codec } = fixture();
  const ticket = codec.issue('completed');
  assert.deepEqual(codec.verify(ticket), codec.verify(ticket));
  assert.deepEqual(Object.keys(codec), ['issue', 'verify']);
});
for (const [name, changes] of [
  ['missing key', { hmacKey: undefined }], ['short key', { hmacKey: Buffer.alloc(31) }],
  ['string key', { hmacKey: 'generated-key-at-least-thirty-two-bytes' }], ['oversized key', { hmacKey: Buffer.alloc(4097) }],
  ['missing clock', { clock: undefined }], ['missing random', { random: undefined }],
  ['zero TTL', { ttlSeconds: 0 }], ['over 120 TTL', { ttlSeconds: 121 }],
  ['fractional TTL', { ttlSeconds: 1.5 }], ['extra field', { accountId: 'generated-account' }]
]) test('constructor finite fail closed: ' + name, () => {
  assert.throws(() => createCompletionStateCodec({ hmacKey: key, clock: () => initial, random: size => Buffer.alloc(size), ...changes }), failure('completion_config'));
});
test('configuration getters, symbols, proxies never execute traps', () => {
  let calls = 0;
  const original = { hmacKey: key, clock: () => initial, random: size => Buffer.alloc(size) };
  const getter = Object.defineProperty({ ...original }, 'hmacKey', { get() { calls += 1; return key; } });
  const proxy = new Proxy(original, { ownKeys() { calls += 1; throw Error('private'); } });
  const symbol = { ...original, [Symbol('private')]: true };
  for (const value of [getter, proxy, symbol]) assert.throws(() => createCompletionStateCodec(value), failure('completion_config'));
  assert.equal(calls, 0);
});
test('key is privately copied rather than caller mutable', () => {
  const injected = Buffer.alloc(32, 7);
  const codec = createCompletionStateCodec({ hmacKey: injected, clock: () => initial, random: size => Buffer.alloc(size, 9) });
  injected.fill(0);
  assert.deepEqual(codec.verify(signed(JSON.stringify(packet()))), packet());
});
test('forged byte-view prototypes and all invalid key shapes have one finite configuration error', () => {
  let traps = 0;
  const invalid = [
    Object.create(Uint8Array.prototype), Object.create(Buffer.prototype),
    Object.create(Uint8Array.prototype, { byteLength: { value: 32 } }),
    null, undefined, true, 32, Symbol('generated'), {}, [],
    new ArrayBuffer(32), new DataView(new ArrayBuffer(32)), new Uint16Array(32),
    new Uint8ClampedArray(32), new Uint8Array(31), new Uint8Array(4097),
    new Proxy(new Uint8Array(32), { get() { traps += 1; throw Error('private'); } })
  ];
  const detached = new Uint8Array(32);
  structuredClone(detached.buffer, { transfer: [detached.buffer] });
  invalid.push(detached);
  for (const hmacKey of invalid) {
    assert.throws(() => createCompletionStateCodec({ hmacKey, clock: () => initial, random: size => Buffer.alloc(size, 9) }), failure('completion_config'));
  }
  assert.equal(traps, 0);
});
test('valid Buffer and Uint8Array keys preserve exact ticket MAC and bypass caller accessors', () => {
  let getters = 0;
  for (const hmacKey of [Buffer.alloc(32, 7), new Uint8Array(32).fill(7)]) {
    Object.defineProperty(hmacKey, 'byteLength', { get() { getters += 1; throw Error('private'); } });
    Object.defineProperty(hmacKey, 'valueOf', { value() { getters += 1; throw Error('private'); } });
    const codec = createCompletionStateCodec({ hmacKey, clock: () => initial, random: size => Buffer.alloc(size, 9) });
    assert.equal(codec.issue('completed'), signed(JSON.stringify(packet())));
    hmacKey.fill(0);
    assert.deepEqual(codec.verify(signed(JSON.stringify(packet()))), packet());
  }
  assert.equal(getters, 0);
});
for (const value of ['', 'success', true, {}, 'completed\n']) test('state allowlist rejects non-finite display value', () => {
  assert.throws(() => fixture().codec.issue(value), failure('completion_state_invalid'));
});
for (const [name, mutate] of [
  ['payload tamper', value => 'B' + value.slice(1)],
  ['MAC tamper', value => value.slice(0, -1) + (value.at(-1) === 'A' ? 'B' : 'A')],
  ['padding', value => value.split('.')[0] + '=.' + value.split('.')[1]],
  ['extra delimiter', value => value + '.extra'],
  ['bad characters', value => '%' + value],
  ['empty', () => ''],
  ['oversized', () => 'A'.repeat(1025)],
  ['object', () => ({ ticket: 'generated' })]
]) test('canonical/MAC rejection: ' + name, () => {
  const { codec } = fixture();
  assert.throws(() => codec.verify(mutate(codec.issue('completed'))), failure('completion_invalid'));
});
for (const [name, source] of [
  ['extra private key', JSON.stringify({ ...packet(), accountId: 'generated-account' })],
  ['wrong version', JSON.stringify(packet({ version: 2 }))],
  ['unknown state', JSON.stringify(packet({ state: 'LIVE' }))],
  ['boolean state', JSON.stringify(packet({ state: true }))],
  ['future beyond TTL', JSON.stringify(packet({ expiresAt: initial + 120_001 }))],
  ['unsafe expiry', JSON.stringify(packet({ expiresAt: Number.MAX_SAFE_INTEGER + 1 }))],
  ['short nonce', JSON.stringify(packet({ nonce: 'abc' }))],
  ['noncanonical nonce', JSON.stringify(packet({ nonce: 'A'.repeat(42) + 'B' }))],
  ['duplicate state', '{"version":1,"state":"denied","state":"completed","expiresAt":' + (initial + 120_000) + ',"nonce":"' + nonce + '"}'],
  ['reordered fields', JSON.stringify({ state: 'completed', version: 1, expiresAt: initial + 120_000, nonce })],
  ['whitespace', ' ' + JSON.stringify(packet())],
  ['malformed JSON', '{']
]) test('even correctly MACed malformed payload denies: ' + name, () => {
  assert.throws(() => fixture().codec.verify(signed(source)), failure('completion_invalid'));
});
test('exact expiry boundary denies and custom TTL never extends', () => {
  const f = fixture(1); const ticket = f.codec.issue('completed');
  assert.equal(f.codec.verify(ticket).expiresAt, initial + 1000);
  f.setNow(initial + 999); assert.equal(f.codec.verify(ticket).state, 'completed');
  f.setNow(initial + 1000); assert.throws(() => f.codec.verify(ticket), failure('completion_expired'));
});
test('clock rollback fails without lowering the retained clock floor', () => {
  const f = fixture(); const ticket = f.codec.issue('completed');
  f.setNow(initial - 1); assert.throws(() => f.codec.verify(ticket), failure('completion_clock_rollback'));
  assert.throws(() => f.codec.issue('completed'), failure('completion_clock_rollback'));
  f.setNow(initial); assert.equal(f.codec.verify(ticket).state, 'completed');
});
for (const current of [NaN, Infinity, -1, 1.5, Number.MAX_SAFE_INTEGER]) {
  test('invalid/overflow clock is finite', () => {
    const codec = createCompletionStateCodec({ hmacKey: key, clock: () => current, random: size => Buffer.alloc(size) });
    assert.throws(() => codec.issue('completed'), failure('completion_clock'));
  });
}
test('throwing clock and random errors never leak details', () => {
  const clock = createCompletionStateCodec({ hmacKey: key, clock: () => { throw Error('generated-secret'); }, random: size => Buffer.alloc(size) });
  assert.throws(() => clock.issue('completed'), failure('completion_clock'));
  for (const random of [() => Buffer.alloc(31), () => 'generated-secret', () => { throw Error('generated-secret'); }]) {
    const codec = createCompletionStateCodec({ hmacKey: key, clock: () => initial, random });
    assert.throws(() => codec.issue('completed'), failure('completion_random'));
  }
});
