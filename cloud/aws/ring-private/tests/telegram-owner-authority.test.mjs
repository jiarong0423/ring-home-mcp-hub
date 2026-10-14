import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createTelegramOwnerAuthority } from '../telegram-owner-authority.mjs';

const now = Date.parse('2026-10-07T00:00:00Z');
const nonce = Buffer.alloc(32, 7).toString('base64url');
const digest = async (purpose, raw) => createHash('sha256').update(`${purpose}\0${raw}`).digest('hex');
function fixture(overrides = {}) {
  const calls = [];
  let counter = 0;
  const store = { async createEnrollment(input) { calls.push(['create', input]); return {}; },
    async admitOwner(input) { calls.push(['admit', input]); return { actorRef: input.actorRef, ownerRef: input.ownerRef,
      householdRef: input.householdRef, ownerEpoch: 1 }; } };
  const authority = createTelegramOwnerAuthority({ store, digest, clock: () => now, createNonce: () => nonce,
    createRef: prefix => `${prefix}/generated-${++counter}`, ...overrides });
  return { authority, calls };
}

test('enrollment returns one opaque nonce while persisting only digests', async () => {
  const f = fixture();
  const result = await f.authority.createEnrollment({ botId: '20001', botGeneration: 4 });
  assert.deepEqual(result, { enrollmentNonce: nonce, expiresAt: Math.floor(now / 1000) + 300 });
  const stored = f.calls[0][1];
  assert.match(stored.nonceDigest, /^[0-9a-f]{64}$/);
  assert.match(stored.botDigest, /^[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(stored).includes('20001'), false);
  assert.equal(JSON.stringify(stored).includes(nonce), false);
});

test('private chat admission sends only digests and opaque references to storage', async () => {
  const f = fixture();
  const result = await f.authority.admitPrivateChat({ enrollmentNonce: nonce, updateId: '90001', botId: '20001',
    botGeneration: 4, chatType: 'private', chatId: '10001', userId: '10001' });
  assert.equal(result.ownerEpoch, 1);
  assert.deepEqual(Object.keys(result).sort(), ['actorRef', 'householdRef', 'ownerEpoch', 'ownerRef']);
  const serialized = JSON.stringify(f.calls[0][1]);
  for (const raw of ['90001', '20001', '10001', nonce]) assert.equal(serialized.includes(raw), false);
});

test('group chat and mismatched private actor are rejected before storage', async () => {
  for (const input of [
    { enrollmentNonce: nonce, updateId: '90001', botId: '20001', botGeneration: 4, chatType: 'group', chatId: '-10001', userId: '10001' },
    { enrollmentNonce: nonce, updateId: '90001', botId: '20001', botGeneration: 4, chatType: 'private', chatId: '10002', userId: '10001' }
  ]) {
    const f = fixture();
    await assert.rejects(f.authority.admitPrivateChat(input), error => error.code === 'TG_AUTHORITY_ADMISSION_DENIED');
    assert.equal(f.calls.length, 0);
  }
});

test('store errors and hostile accessors are finite and do not echo identifiers', async () => {
  const f = fixture({ store: { async createEnrollment() {}, async admitOwner() { throw Error('10001 private'); } } });
  await assert.rejects(f.authority.admitPrivateChat({ enrollmentNonce: nonce, updateId: '90001', botId: '20001',
    botGeneration: 4, chatType: 'private', chatId: '10001', userId: '10001' }),
    error => error.code === 'TG_AUTHORITY_ADMISSION_DENIED' && !error.message.includes('10001'));
  let reads = 0;
  const hostile = { botId: '20001' };
  Object.defineProperty(hostile, 'botGeneration', { enumerable: true, get() { reads += 1; return 4; } });
  await assert.rejects(f.authority.createEnrollment(hostile), error => error.code === 'TG_AUTHORITY_INPUT_DENIED');
  assert.equal(reads, 0);
});

test('enrollment store and clock failures are fixed and never echo markers', async () => {
  const storeMarker = 'private-enrollment-store-marker';
  const brokenStore = fixture({ store: {
    async createEnrollment() { throw Error(storeMarker); },
    async admitOwner() { throw Error('unused'); }
  } });
  await assert.rejects(brokenStore.authority.createEnrollment({ botId: '20001', botGeneration: 4 }), error =>
    error.code === 'TG_AUTHORITY_UNAVAILABLE' && error.message === 'TG_AUTHORITY_UNAVAILABLE' &&
    !error.message.includes(storeMarker));

  const clockMarker = 'private-clock-marker';
  const brokenClock = fixture({ clock() { throw Error(clockMarker); } });
  await assert.rejects(brokenClock.authority.createEnrollment({ botId: '20001', botGeneration: 4 }), error =>
    error.code === 'TG_AUTHORITY_UNAVAILABLE' && error.message === 'TG_AUTHORITY_UNAVAILABLE' &&
    !error.message.includes(clockMarker));
});
