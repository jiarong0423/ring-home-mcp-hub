import test from 'node:test';
import assert from 'node:assert/strict';
import { createProjectingIdentityAuthority } from '../projecting-identity-authority.mjs';

test('first account is digested, context sealed and projected without raw identifier persistence', async () => {
  const calls = [];
  const store = { async loadSessionAuthority() { throw Error('unused'); }, async projectAccount(input) { calls.push(input); return { projected: true }; } };
  const envelope = Object.freeze({ version: 1, purpose: 'RING_ACCOUNT_IDENTITY', keyId: 'alias/generated',
    encryptedDataKey: 'd3JhcHBlZA', nonce: 'AQEBAQEBAQEBAQEB', authTag: 'AgICAgICAgICAgICAgICAg', ciphertext: 'ZW5jcnlwdGVk' });
  const authority = createProjectingIdentityAuthority({ store, extractSession() { return { sessionProof: 'proof/generated', csrf: 'csrf/generated' }; },
    async digest(purpose) { assert.ok(['ring-account', 'session-proof'].includes(purpose)); return 'a'.repeat(64); },
    identityEnvelope: { async seal(accountId, binding) { calls.push({ accountId, binding }); return envelope; }, async open() { return 'account-generated'; } } });
  assert.deepEqual(await authority.projectFirstAccount({ sessionProof: 'proof/generated', ownerRef: 'owner/generated', ownerEpoch: 2,
    grantDigest: 'b'.repeat(64), grantGeneration: 3, accountId: 'account-generated', accountGeneration: 1, expiresAt: 1_900_000_000 }), { projected: true });
  assert.deepEqual(calls[0].binding, { accountDigest: 'a'.repeat(64), ownerRef: 'owner/generated', ownerEpoch: 2, accountGeneration: 1 });
  assert.equal(JSON.stringify(calls[1]).includes('account-generated'), false);
  await authority.close();
  await assert.rejects(authority.projectFirstAccount({}), error => error.code === 'PROJECTING_IDENTITY_CLOSED');
});
