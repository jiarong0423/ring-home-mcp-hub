import test from 'node:test';
import assert from 'node:assert/strict';
import { createTokenEnvelope, TOKEN_ENVELOPE_PURPOSE } from '../token-envelope.mjs';

const masterKey = Buffer.alloc(32, 7);
const payload = Object.freeze({
  accountId: 'generated-ring-account-for-offline-test',
  accessToken: 'generated-access-token-for-offline-test',
  refreshToken: 'generated-refresh-token-for-offline-test',
  tokenExpiresAt: 1_800_000_000
});

function fakeKms() {
  const calls = [];
  return {
    calls,
    async generateDataKey(input) {
      calls.push({ operation: 'generate', input });
      return { Plaintext: Buffer.from(masterKey), CiphertextBlob: Buffer.from('wrapped-generated-data-key') };
    },
    async decryptDataKey(input) {
      calls.push({ operation: 'decrypt', input });
      if (!Buffer.from(input.CiphertextBlob).equals(Buffer.from('wrapped-generated-data-key'))) throw new Error('invalid ciphertext');
      return { Plaintext: Buffer.from(masterKey) };
    }
  };
}

function adapter(kms = fakeKms()) {
  return {
    kms,
    envelope: createTokenEnvelope({
      generateDataKey: kms.generateDataKey,
      decryptDataKey: kms.decryptDataKey,
      keyId: 'alias/generated-ring-state',
      tableName: 'GeneratedRingState',
      random: size => Buffer.alloc(size, 3)
    })
  };
}

test('round trip encrypts the exact account and token payload under bound KMS context', async () => {
  const { kms, envelope } = adapter();
  const sealed = await envelope.seal(payload, { linkId: 'generated-link-a', revision: 1 });
  assert.deepEqual(await envelope.open(sealed, { linkId: 'generated-link-a', revision: 1 }), payload);
  assert.deepEqual(kms.calls.map(call => call.operation), ['generate', 'decrypt']);
  assert.deepEqual(kms.calls[0].input.EncryptionContext, {
    app: 'ring-private',
    table: 'GeneratedRingState',
    schema_version: '1',
    purpose: TOKEN_ENVELOPE_PURPOSE,
    link_id: 'generated-link-a',
    revision: '1'
  });
  const serialized = JSON.stringify(sealed);
  assert.equal(serialized.includes(payload.accountId), false);
  assert.equal(serialized.includes(payload.accessToken), false);
  assert.equal(serialized.includes(payload.refreshToken), false);
});

test('lifecycle payload uses schema v2 while legacy v1 remains readable', async () => {
  const { kms, envelope } = adapter();
  const lifecycle = Object.freeze({
    ...payload,
    refreshTokenExpiresAt: payload.tokenExpiresAt + 2_592_000_000,
    rotation: 2
  });
  const sealed = await envelope.seal(lifecycle, { linkId: 'generated-link-a', revision: 2 });
  assert.equal(sealed.schemaVersion, 2);
  assert.equal(sealed.revision, 2);
  assert.deepEqual(await envelope.open(sealed, { linkId: 'generated-link-a', revision: 2 }), lifecycle);
  assert.equal(kms.calls[0].input.EncryptionContext.schema_version, '2');
  await assert.rejects(envelope.seal({ ...lifecycle, rotation: 1 }, {
    linkId: 'generated-link-a', revision: 2
  }), /token_payload_invalid/);
  await assert.rejects(envelope.seal({ ...lifecycle, refreshTokenExpiresAt: payload.tokenExpiresAt }, {
    linkId: 'generated-link-a', revision: 2
  }), /token_payload_invalid/);
});

test('wrong link context, revision, or purpose fails before KMS decrypt', async () => {
  const { kms, envelope } = adapter();
  const sealed = await envelope.seal(payload, { linkId: 'generated-link-a', revision: 1 });
  for (const args of [
    { linkId: 'generated-link-b', revision: 1 },
    { linkId: 'generated-link-a', revision: 2 },
    { linkId: 'generated-link-a', revision: 1, purpose: 'OTHER' }
  ]) await assert.rejects(envelope.open(sealed, args), /token_envelope_context/);
  assert.equal(kms.calls.filter(call => call.operation === 'decrypt').length, 0);
});

test('supported schema-version substitution still fails authenticated decryption', async () => {
  const { kms, envelope } = adapter();
  const sealed = await envelope.seal(payload, { linkId: 'generated-link-a', revision: 1 });
  await assert.rejects(envelope.open({ ...sealed, schemaVersion: 2 }, {
    linkId: 'generated-link-a', revision: 1
  }), /token_envelope_invalid/);
  assert.equal(kms.calls.filter(call => call.operation === 'decrypt').length, 1);
});

test('ciphertext and encrypted-key swaps cannot cross envelopes', async () => {
  let counter = 1;
  const kms = fakeKms();
  const envelope = createTokenEnvelope({
    generateDataKey: async input => {
      const key = Buffer.alloc(32, counter);
      const wrapped = Buffer.from(`wrapped-key-${counter}`);
      counter += 1;
      kms.calls.push({ operation: 'generate', input, key, wrapped });
      return { Plaintext: key, CiphertextBlob: wrapped };
    },
    decryptDataKey: async input => {
      kms.calls.push({ operation: 'decrypt', input });
      const call = kms.calls.find(row => row.operation === 'generate' && row.wrapped.equals(Buffer.from(input.CiphertextBlob)));
      if (!call) throw new Error('unknown key');
      return { Plaintext: Buffer.from(call.key) };
    },
    keyId: 'alias/generated-ring-state',
    tableName: 'GeneratedRingState',
    random: size => Buffer.alloc(size, counter + 10)
  });
  const first = await envelope.seal(payload, { linkId: 'generated-link-a', revision: 1 });
  const second = await envelope.seal({ ...payload, accessToken: 'different-generated-access-token' }, { linkId: 'generated-link-a', revision: 1 });
  await assert.rejects(envelope.open({ ...first, ciphertext: second.ciphertext, authTag: second.authTag, nonce: second.nonce }, { linkId: 'generated-link-a', revision: 1 }), /token_envelope_invalid/);
  await assert.rejects(envelope.open({ ...first, encryptedDataKey: second.encryptedDataKey }, { linkId: 'generated-link-a', revision: 1 }), /token_envelope_invalid/);
});

test('KMS outages and malformed data keys fail closed with finite nonsecret errors', async () => {
  const sensitive = payload.refreshToken;
  const failing = createTokenEnvelope({
    generateDataKey: async () => { throw new Error(sensitive); },
    decryptDataKey: async () => { throw new Error(sensitive); },
    keyId: 'alias/generated-ring-state',
    tableName: 'GeneratedRingState'
  });
  await assert.rejects(failing.seal(payload, { linkId: 'generated-link-a', revision: 1 }), error => {
    assert.equal(error.code, 'token_envelope_unavailable');
    assert.equal(error.message.includes(sensitive), false);
    return true;
  });
  const malformed = adapter({
    async generateDataKey() { return { Plaintext: Buffer.alloc(31), CiphertextBlob: Buffer.from('wrapped') }; },
    async decryptDataKey() { return { Plaintext: Buffer.alloc(31) }; }
  }).envelope;
  await assert.rejects(malformed.seal(payload, { linkId: 'generated-link-a', revision: 1 }), /token_envelope_unavailable/);
});

test('invalid payload and envelope blobs fail before returning sensitive values', async () => {
  const { envelope } = adapter();
  await assert.rejects(envelope.seal({ ...payload, accessToken: '' }, { linkId: 'generated-link-a', revision: 1 }), /token_payload_invalid/);
  const sealed = await envelope.seal(payload, { linkId: 'generated-link-a', revision: 1 });
  await assert.rejects(envelope.open({ ...sealed, authTag: 'bad=' }, { linkId: 'generated-link-a', revision: 1 }), /token_envelope_invalid/);
});

test('payload is exact and accessor properties are rejected without invocation', async () => {
  const { envelope } = adapter();
  await assert.rejects(envelope.seal({ ...payload, extra: 'not-allowed' }, { linkId: 'generated-link-a', revision: 1 }), /token_payload_invalid/);
  let reads = 0;
  const accessorPayload = { ...payload };
  Object.defineProperty(accessorPayload, 'accountId', { enumerable: true, get() { reads += 1; return payload.accountId; } });
  await assert.rejects(envelope.seal(accessorPayload, { linkId: 'generated-link-a', revision: 1 }), /token_payload_invalid/);
  const accessorContext = { linkId: 'generated-link-a', revision: 1 };
  Object.defineProperty(accessorContext, 'linkId', { enumerable: true, get() { reads += 1; return 'generated-link-a'; } });
  await assert.rejects(envelope.seal(payload, accessorContext), /token_envelope_context/);
  assert.equal(reads, 0);
});
