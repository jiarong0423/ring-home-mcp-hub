import test from 'node:test';
import assert from 'node:assert/strict';
import { createIdentityEnvelope } from '../identity-envelope.mjs';

const key = Buffer.alloc(32, 7);
const wrapped = Buffer.from('wrapped-generated-key');
const binding = Object.freeze({ accountDigest: 'a'.repeat(64), ownerRef: 'owner/generated',
  ownerEpoch: 4, accountGeneration: 2 });

function fixture() {
  const calls = [];
  const envelope = createIdentityEnvelope({ keyId: 'alias/generated', application: 'ring-private',
    tableName: 'GeneratedTable', random: size => Buffer.alloc(size, 3),
    async generateDataKey(input) { calls.push(['generate', input]); return { Plaintext: key, CiphertextBlob: wrapped }; },
    async decryptDataKey(input) { calls.push(['decrypt', input]); return { Plaintext: key }; } });
  return { envelope, calls };
}

test('account identity is sealed and opened only with its exact projection binding', async () => {
  const f = fixture();
  const sealed = await f.envelope.seal('ring-account-generated', binding);
  assert.deepEqual(Object.keys(sealed), ['version', 'purpose', 'keyId', 'encryptedDataKey', 'nonce', 'authTag', 'ciphertext']);
  assert.equal(sealed.purpose, 'RING_ACCOUNT_IDENTITY');
  assert.equal(JSON.stringify(sealed).includes('ring-account-generated'), false);
  assert.equal(await f.envelope.open(sealed, binding), 'ring-account-generated');
  assert.deepEqual(f.calls[0][1].EncryptionContext, f.calls[1][1].EncryptionContext);
  assert.equal(f.calls[0][1].EncryptionContext.account_digest, binding.accountDigest);
});

test('binding drift, tampering and KMS failures return fixed finite errors', async () => {
  const f = fixture();
  const sealed = await f.envelope.seal('ring-account-generated', binding);
  await assert.rejects(f.envelope.open(sealed, { ...binding, accountGeneration: 3 }),
    error => error.code === 'IDENTITY_ENVELOPE_CONTEXT' && !error.message.includes('ring-account-generated'));
  await assert.rejects(f.envelope.open({ ...sealed, ciphertext: Buffer.from('tampered').toString('base64url') }, binding),
    error => error.code === 'IDENTITY_ENVELOPE_CONTEXT');
  const failed = createIdentityEnvelope({ keyId: 'alias/generated', application: 'ring-private', tableName: 'GeneratedTable',
    random: size => Buffer.alloc(size), async generateDataKey() { throw Error('private-kms'); }, async decryptDataKey() { throw Error('private-kms'); } });
  await assert.rejects(failed.seal('ring-account-generated', binding),
    error => error.code === 'IDENTITY_ENVELOPE_UNAVAILABLE' && !error.message.includes('private-kms'));
});
