import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createAccountIdentityProjection } from '../account-identity-projection.mjs';
import { createExistingSessionIdentityAuthority } from '../existing-session-identity-authority.mjs';

const now = 1_800_000_000_000;
const accountId = 'ring-account-generated';
const envelope = Object.freeze({ version: 1, purpose: 'RING_ACCOUNT_IDENTITY', keyId: 'kms/generated',
  encryptedDataKey: Buffer.from('wrapped-generated').toString('base64url'), nonce: Buffer.alloc(12, 1).toString('base64url'),
  authTag: Buffer.alloc(16, 2).toString('base64url'), ciphertext: Buffer.from('encrypted-account').toString('base64url') });
const bundle = () => ({ productionAdmitted: true, serverNow: now, ownerEpoch: 7, sessionId: 'session/generated',
  sessionGeneration: 3, grantId: 'grant/generated', grantGeneration: 5, sessionExpiresAt: now + 600_000,
  idleExpiresAt: now + 500_000, trustExpiresAt: now + 700_000, actorRef: 'actor/generated', ownerRef: 'owner/generated',
  householdRef: 'household/generated', scopeRefs: Object.freeze(['ring/read', 'ring/link']), accountGeneration: 2,
  projectionRevision: 1, accountIdentifierEnvelope: envelope, bindingExpiresAt: now + 650_000 });
const digest = async (purpose, raw) => createHash('sha256').update(`${purpose}\0${raw}`).digest('hex');

function fixture(change = {}) {
  const calls = [];
  const store = { async loadSessionAuthority(input) { calls.push(['load', input]); return { ...bundle(), ...change }; },
    async projectAccount(input) { calls.push(['project', input]); return { accountDigest: input.accountDigest,
      accountGeneration: input.accountGeneration, projectionRevision: 1, ownerEpoch: input.ownerEpoch, expiresAt: input.expiresAt }; } };
  const projection = createAccountIdentityProjection({ store, digest, async decryptAccountIdentifier() { return accountId; } });
  const adapter = createExistingSessionIdentityAuthority({ sessionAuthority: projection.sessionAuthority,
    extractSession() { return { sessionProof: 'proof/generated', csrf: 'csrf/generated' }; },
    resolveAccountBinding: projection.resolveAccountBinding });
  return { projection, adapter, calls };
}

test('account projection integrates with AUTH-C without changing its contract', async () => {
  const f = fixture();
  const lease = await f.adapter.resolveMatchedRingAccount({ accountId, context: Object.freeze({ cookie: 'opaque' }) });
  assert.equal(lease.accountIdentifier, accountId);
  assert.equal(lease.epoch, 7);
  assert.deepEqual(lease.scopeRefs, ['ring/read', 'ring/link']);
  assert.equal(f.calls.filter(call => call[0] === 'load').length, 2);
  assert.deepEqual(await f.adapter.recheck(lease.proof), lease);
  await f.adapter.close();
  await f.projection.close();
});

test('wrong account and generation drift fail closed', async () => {
  const wrong = fixture();
  await assert.rejects(wrong.adapter.resolveMatchedRingAccount({ accountId: 'other-account', context: { cookie: 'opaque' } }),
    error => error.code === 'IDENTITY_AUTHORITY_UNAVAILABLE');
  const drift = fixture({ sessionGeneration: 4 });
  const stable = fixture();
  const lease = await stable.adapter.resolveMatchedRingAccount({ accountId, context: { cookie: 'opaque' } });
  stable.calls.length = 0;
  let generation = 3;
  const dynamicStore = { async loadSessionAuthority() { return { ...bundle(), sessionGeneration: generation }; }, async projectAccount() {} };
  const projection = createAccountIdentityProjection({ store: dynamicStore, digest, async decryptAccountIdentifier() { return accountId; } });
  const adapter = createExistingSessionIdentityAuthority({ sessionAuthority: projection.sessionAuthority,
    extractSession() { return { sessionProof: 'proof/generated', csrf: 'csrf/generated' }; }, resolveAccountBinding: projection.resolveAccountBinding });
  const dynamicLease = await adapter.resolveMatchedRingAccount({ accountId, context: { cookie: 'opaque' } });
  generation = 4;
  await assert.rejects(adapter.recheck(dynamicLease.proof), error => error.code === 'IDENTITY_SESSION_CHANGED');
  await stable.adapter.close(); await drift.projection.close(); await adapter.close(); await projection.close();
});

test('first account projection persists only a digest and encrypted identifier envelope', async () => {
  const f = fixture();
  const result = await f.projection.projectFirstAccount({ sessionProof: 'proof/generated', ownerRef: 'owner/generated',
    ownerEpoch: 7, grantDigest: 'c'.repeat(64), grantGeneration: 5, accountId,
    accountGeneration: 2, accountIdentifierEnvelope: envelope, expiresAt: Math.floor(now / 1000) + 600 });
  assert.equal(result.accountGeneration, 2);
  const stored = f.calls.find(call => call[0] === 'project')[1];
  assert.match(stored.accountDigest, /^[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(stored).includes(accountId), false);
  assert.deepEqual(stored.accountIdentifierEnvelope, envelope);
});

test('decrypt failures are fixed and never echo encrypted or raw identifiers', async () => {
  const store = { async loadSessionAuthority() { return bundle(); }, async projectAccount() {} };
  const projection = createAccountIdentityProjection({ store, digest, async decryptAccountIdentifier() {
    throw Error(`${accountId}:${envelope.ciphertext}`);
  } });
  await assert.rejects(projection.sessionAuthority.withCurrentSession({ sessionProof: 'proof/generated', csrf: 'csrf/generated' }, () => {}),
    error => error.code === 'ACCOUNT_PROJECTION_UNAVAILABLE' && !error.message.includes(accountId));
});
