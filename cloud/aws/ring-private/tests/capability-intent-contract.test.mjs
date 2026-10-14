import test from 'node:test';
import assert from 'node:assert/strict';
import { createCapabilityIntentContract } from '../capability-intent-contract.mjs';

const refs = ['ring', ...Array.from({ length: 6 }, (_, index) => Buffer.alloc(32, index + 1).toString('base64url'))];
function fixture() {
  const calls = [];
  let time = 1_800_000_000_000;
  const categories = refs.map((categoryRef, index) => ({ categoryRef, generation: index + 1,
    adapter: { projectIntent(input) { calls.push(['project', input]); return { operation: 'read', targetRef: `target/${index}` }; } } }));
  const contract = createCapabilityIntentContract({ categories, clock: () => time, random: size => Buffer.alloc(size, 9),
    localSessionPort: { async withCurrentSession(proof, callback) { calls.push(['session', proof]); return callback({ ownerRef: 'owner/generated' }); } },
    ownMcpPort: { authorizeCapability(input) { calls.push(['authorize', input]); return { authorized: true,
      authorizationRef: 'authorization/generated', expiresAt: time + 60_000 }; } },
    capabilityChannelPort: { async sealIntent(intent) { calls.push(['seal', intent]); return { sealed: true }; },
      async deliverSealedIntent(sealed) { calls.push(['deliver', sealed]); return { delivered: true }; },
      async verifyReceipt(input) { calls.push(['receipt', input]); return { intentId: input.intent.id, receivedAt: time, accepted: true }; } } });
  return { contract, calls, advance: value => { time += value; } };
}
const input = Object.freeze({ categoryRef: 'ring', generation: 1, sessionProof: 'proof/generated', csrf: 'csrf/generated', request: { view: 'summary' } });

test('exact seven-category registry authorizes local intent without execution', async () => {
  const f = fixture();
  const result = await f.contract.authorizeLocal(input);
  assert.deepEqual(result, { categoryRef: 'ring', generation: 1, authorizationRef: 'authorization/generated',
    expiresAt: 1_800_000_060_000, authorized: true, executed: false });
  assert.deepEqual(f.calls.map(call => call[0]), ['session', 'project', 'authorize']);
});

test('remote path sends only a sealed 30-second intent and verifies bounded receipt', async () => {
  const f = fixture();
  const result = await f.contract.authorizeRemote(input);
  assert.equal(result.executed, false);
  assert.equal(result.receiptVerified, true);
  assert.equal(result.expiresAt, 1_800_000_030_000);
  const intent = f.calls.find(call => call[0] === 'seal')[1];
  assert.equal(intent.expiresAt - intent.issuedAt, 30_000);
  assert.equal(f.calls.some(call => call[0] === 'execute' || call[0] === 'listen'), false);
});

test('registry and generation drift deny before all ports', async () => {
  const f = fixture();
  await assert.rejects(f.contract.authorizeLocal({ ...input, generation: 2 }), error => error.code === 'CAPABILITY_DENIED');
  assert.equal(f.calls.length, 0);
  assert.throws(() => createCapabilityIntentContract({ categories: [], localSessionPort: {}, ownMcpPort: {},
    capabilityChannelPort: {}, clock: () => 0, random: () => Buffer.alloc(16) }), /CAPABILITY_CONFIG/);
});
