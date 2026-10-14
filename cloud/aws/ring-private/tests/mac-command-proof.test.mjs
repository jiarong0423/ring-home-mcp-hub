import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, chmod, readFile, writeFile } from 'node:fs/promises';
import { fixture, AUDIENCE, TOKEN, rpc } from './mac-command-proof-fixture.mjs';
import { createMacEnrollmentInstaller, macEnrollmentKey } from '../mac-command-proof-authority.mjs';
import { createMacCommandProofSigner, MAC_PROOF_HEADER } from '../../../../src/formal-runtime/mac-command-proof.mjs';
import { initializeMacCommandSigningKey, openMacCommandSigningKey } from '../../../../src/formal-runtime/mac-command-signing-key.mjs';
import { hash } from '../../../../src/formal-runtime/mac-command-contract.mjs';
import { createMacCommandRuntime } from '../../../../src/formal-runtime/mac-command-runtime.mjs';
import { createMacCommandJournal } from '../../../../src/formal-runtime/mac-command-journal.mjs';
import { inMemoryRuntimeInputs } from '../../../../tests/mac-command-runtime-fixture.mjs';
const ROOT = process.env.RING_TRANSPORT_TEST_ROOT;
if (!ROOT?.startsWith('/private/tmp/')) throw new Error('Explicit isolation root required');

test('ordinary owner bearer cannot claim or forge a Mac receipt; admitted key signs exact result', async () => {
  const f = fixture(); await f.submit();
  const ownerOnly = Object.freeze({ owner: 'owner-a', session: 'browser-a', headers: { authorization: 'Bearer ' + TOKEN } }); f.requests.add(ownerOnly);
  await assert.rejects(f.service.fetch({ request: ownerOnly, actor: f.actor }), /MAC_PROOF_REQUIRED/);
  const entry = await f.fetch(); const receipt = f.makeReceipt(entry);
  await assert.rejects(f.service.receipt({ request: ownerOnly, actor: f.actor, receipt }), /MAC_PROOF_REQUIRED/);
  const request = f.signedRequest('receipt', receipt);
  await assert.rejects(f.service.receipt({ request, actor: f.actor, receipt: { ...receipt, result: { ...receipt.result, revision: 2 } } }), /MAC_PROOF_DENIED/);
  const result = await f.service.receipt({ request, actor: f.actor, receipt }); assert.equal(result.executed, true);
  await assert.rejects(f.service.receipt({ request, actor: f.actor, receipt }), /MAC_PROOF_REPLAY/);
  assert.deepEqual(await f.accept(receipt), result, 'fresh signed retry reads the original result');
  f.signer.close();
});
test('absent, wrong-key, revoked and association-mismatched enrollment fail closed', async () => {
  const f = fixture(); await f.submit();
  const other = createMacCommandProofSigner({ privateKey: generateKeyPairSync('ed25519').privateKey, ownerRef: 'owner-a', associationRevision: 1, audience: AUDIENCE, clock: f.clock });
  await assert.rejects(f.service.fetch({ request: f.signedRequest('fetch', {}, other), actor: f.actor }), /MAC_PROOF_DENIED/);
  f.enrollment.revoked.BOOL = true; await assert.rejects(f.fetch(), /MAC_ENROLLMENT_REQUIRED/); f.enrollment.revoked.BOOL = false;
  f.enrollment.association_revision.N = '2'; await assert.rejects(f.fetch(), /MAC_ENROLLMENT_REQUIRED/); f.enrollment.association_revision.N = '1';
  f.db.rows.delete(macEnrollmentKey('owner-a')); await assert.rejects(f.fetch(), /MAC_ENROLLMENT_REQUIRED/);
  other.close(); f.signer.close();
});
test('fetch nonce replay, operation substitution, bearer substitution and proof expiry deny', async () => {
  const f = fixture(); await f.submit(); const request = f.signedRequest('fetch', {});
  const entry = await f.service.fetch({ request, actor: f.actor });
  await assert.rejects(f.service.fetch({ request, actor: f.actor }), /MAC_PROOF_REPLAY/);
  await assert.rejects(f.service.receipt({ request, actor: f.actor, receipt: f.makeReceipt(entry) }), /MAC_PROOF_DENIED/);
  const swapped = { ...f.signedRequest('fetch', {}), headers: { ...f.signedRequest('fetch', {}).headers, authorization: 'Bearer another-synthetic-token' } }; f.requests.add(swapped);
  await assert.rejects(f.service.fetch({ request: swapped, actor: f.actor }), /MAC_PROOF_DENIED/);
  const expired = f.signedRequest('fetch', {}); f.advance(15000); await assert.rejects(f.service.fetch({ request: expired, actor: f.actor }), /MAC_PROOF_DENIED/);
  f.signer.close();
});
test('receipt must use the enrollment revision and key that acquired the command', async () => {
  const f = fixture(); await f.submit(); const entry = await f.fetch(); f.enrollment.revision.N = '2';
  await assert.rejects(f.accept(f.makeReceipt(entry)), /MAC_COMMAND_RECEIPT_DENIED/); f.signer.close();
});
test('owner approval digest and same-request association are required to enroll, with CAS replay denial', async () => {
  const f = fixture(); f.db.rows.delete(macEnrollmentKey('owner-a'));
  const approvalBytes = Buffer.from(JSON.stringify({ schema: 'ring-mac-enrollment-approval-v1', ownerRef: 'owner-a', associationRevision: 1,
    keyId: f.signer.keyId, publicKeySpki: f.signer.publicKeySpki, expectedRevision: 0, revision: 1, expiresAt: f.clock() + 3600000 }));
  const installer = createMacEnrollmentInstaller({ ports: f.db.ports, authorize: f.authorize, approvalSha256: hash(approvalBytes), clock: f.clock });
  await assert.rejects(installer.install({ request: f.browser, actor: {}, approvalBytes }), /AUTH_DENIED/);
  await assert.rejects(installer.install({ request: f.browser, actor: f.actor, approvalBytes: Buffer.from('{}') }), /MAC_ENROLLMENT_APPROVAL/);
  assert.equal((await installer.install({ request: f.browser, actor: f.actor, approvalBytes })).installed, true);
  await assert.rejects(installer.install({ request: f.browser, actor: f.actor, approvalBytes }), /Conditional conflict/);
  await f.submit(); assert.equal((await f.fetch()).status, 'CLAIMED'); f.signer.close();
});
test('persistent signing identity is encrypted, explicit, single-link private custody; missing or unsafe file denies', async () => {
  const directory = await mkdtemp(ROOT + '/mac-key-'); await chmod(directory, 0o700);
  const config = { directory, passphrase: Buffer.from('synthetic local passphrase'), ownerRef: 'owner-a', associationRevision: 1, audience: AUDIENCE };
  await assert.rejects(openMacCommandSigningKey(config), /MAC_KEY_UNAVAILABLE/);
  const descriptor = await initializeMacCommandSigningKey(config); const signer = await openMacCommandSigningKey(config);
  assert.equal(signer.keyId, descriptor.keyId); assert.match(await readFile(directory + '/mac-command-signing-key.pem', 'utf8'), /BEGIN ENCRYPTED PRIVATE KEY/);
  await assert.rejects(initializeMacCommandSigningKey(config), /EEXIST/);
  await assert.rejects(openMacCommandSigningKey({ ...config, passphrase: Buffer.from('different synthetic passphrase') }), /MAC_KEY_UNAVAILABLE/);
  await chmod(directory + '/mac-command-signing-key.pem', 0o644); await assert.rejects(openMacCommandSigningKey(config), /MAC_KEY_UNAVAILABLE/);
  await chmod(directory + '/mac-command-signing-key.pem', 0o600);
  await writeFile(directory + '/mac-command-signing-key.pem', generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }));
  await assert.rejects(openMacCommandSigningKey(config), /MAC_KEY_UNAVAILABLE/);
  signer.close(); config.passphrase.fill(0);
});
test('signed cloud claim runs the existing real formal grant issue/consume and exact signed software receipt', async () => {
  const local = inMemoryRuntimeInputs(); const now = local.clock.wallNowMs();
  const f = fixture({ ownerRef: 'Owner.fixture', clock: () => local.clock.wallNowMs() });
  const actor = Object.freeze({ authority: 'oauth-access-token', subject: 'Fixture.owner', resource: 'https://fixture.invalid/mcp', scopes: Object.freeze(['mcp']) });
  const sessionHandle = Object.freeze({}); const csrf = 'SyntheticCsrfNotAProductionCredential'; const bound = new WeakMap(), proofs = new WeakMap();
  const association = Object.freeze({ ownerRef: 'Owner.fixture', revision: 1, actorRef: 'Actor.fixture', householdRef: local.ringReference.householdId,
    ownerEpoch: 1, scopeRefs: Object.freeze(['mcp']), ownerId: local.binding.ownerId, botId: local.binding.botId, bindingGeneration: local.binding.generation });
  const services = {
    identityAuthority: {
      async resolveMatchedRingAccount(input) { local.sessionCurrent(); const proof = Object.freeze({}); const value = Object.freeze({ proof, actorRef: association.actorRef,
        ownerRef: association.ownerRef, householdRef: association.householdRef, scopeRefs: association.scopeRefs, accountIdentifier: input.accountId, epoch: 1, expiresAt: now + 120000 }); proofs.set(proof, value); return value; },
      async recheck(proof) { local.sessionCurrent(); const value = proofs.get(proof); if (!value) throw new Error('IDENTITY_PROOF_DENIED'); return value; }
    },
    async bindVerifiedRequest(input) {
      local.sessionCurrent(); if (input.actor !== actor || input.sessionHandle !== sessionHandle || input.csrf !== csrf) throw new Error('SESSION_DENIED');
      bound.set(input.httpRequest, Object.freeze({ httpRequest: input.httpRequest, actor, sessionHandle, association,
        identityInput: Object.freeze({ accountId: 'FixtureRingAccount', context: sessionHandle }), sessionAuthority: Object.freeze({ ownerId: local.binding.ownerId,
          botId: local.binding.botId, bindingGeneration: local.binding.generation, bootEpoch: local.bootEpoch.digest, sessionExpiresMonotonicMs: now + 120000, assertCurrentSession: local.sessionCurrent }) }));
    },
    async lookupRequest({ httpRequest, actor: supplied }) { local.sessionCurrent(); const value = bound.get(httpRequest); if (!value || supplied !== actor) throw new Error('SESSION_LOOKUP_DENIED'); return value; }
  };
  const directory = await mkdtemp(ROOT + '/signed-grant-'); await chmod(directory, 0o700);
  const journal = await createMacCommandJournal({ directory });
  const runtime = createMacCommandRuntime({ runtimeOptions: local.runtimeOptions, sessionAssociationServices: services, currentBindingPort: local.currentBindingPort,
    sessionLogin: { actor, sessionHandle, csrf }, transport: { fetch: f.fetch, receipt: f.accept }, journal });
  try {
    const submitted = await f.submit(rpc('signed-real-grant')); await runtime.start(); const result = await runtime.runOnce();
    assert.equal(result.commandId, submitted.commandId); assert.equal(result.executed, true); assert.equal(result.result.kind, 'software-test-switch');
    assert.equal(runtime.status().core.grants.issuedCount, 1); assert.equal(runtime.status().core.grants.consumedCount, 1);
    assert.equal(local.counts().transportCalls, 0); assert.equal((await runtime.runOnce()).status, 'EMPTY');
    console.log('SIGNED_REAL_GRANT ' + JSON.stringify({ grants: runtime.status().core.grants, providerCalls: local.counts().transportCalls }));
  } finally { const closed = await runtime.close(); assert.equal(closed.inFlight, 0); f.signer.close(); }
});
