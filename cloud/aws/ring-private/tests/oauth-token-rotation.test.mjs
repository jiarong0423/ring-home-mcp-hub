import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createLazyRingClient } from '../aws-composition.mjs';
import { createDynamoLinkStore } from '../dynamo-link-store.mjs';
import { computeNonce, ProtocolError } from '../protocol.mjs';
import { createRingClient } from '../ring-client.mjs';
import { createRingWorkflow } from '../workflow.mjs';

const nowMs = 1_791_000_000_000;
const nowSeconds = Math.floor(nowMs / 1000);
const accountId = 'generated-ring-account';
const accountDigest = 'a'.repeat(64);
const nonceKey = 'generated-nonce-key-at-least-thirty-two-bytes';
const recordKey = 'generated-record-key-at-least-thirty-two-bytes';
const linkId = 'generated-link';
const deadlineOptions = () => ({ deadline: nowMs + 60_000, clock: () => nowMs });
const rotatedEnvelope = Object.freeze({
  schemaVersion: 2,
  purpose: 'RING_LINK_TOKENS',
  linkId,
  revision: 2,
  encryptedDataKey: 'Z2VuZXJhdGVkLXdyYXBwZWQta2V5',
  nonce: Buffer.alloc(12, 3).toString('base64url'),
  authTag: Buffer.alloc(16, 4).toString('base64url'),
  ciphertext: 'Z2VuZXJhdGVkLXJvdGF0ZWQtY2lwaGVydGV4dA'
});

function conditionalFailure() {
  return Object.assign(new Error('conditional'), { name: 'ConditionalCheckFailedException' });
}

function envelopeAttribute(envelope) {
  return { M: {
    schema_version: { N: String(envelope.schemaVersion) },
    purpose: { S: envelope.purpose },
    link_id: { S: envelope.linkId },
    revision: { N: String(envelope.revision) },
    encrypted_data_key: { S: envelope.encryptedDataKey },
    nonce: { S: envelope.nonce },
    auth_tag: { S: envelope.authTag },
    ciphertext: { S: envelope.ciphertext }
  } };
}

function reservedItem(envelope = rotatedEnvelope) {
  return {
    PK: { S: `LINK#${linkId}` },
    SK: { S: 'STATE' },
    link_id: { S: linkId },
    status: { S: 'RESERVED' },
    revision: { N: '2' },
    identity_epoch: { N: '4' },
    expires_at: { N: String(nowSeconds + 600) },
    account_digest: { S: accountDigest },
    token_revision: { N: '2' },
    token_envelope: envelopeAttribute(envelope)
  };
}

function dynamoStore({ transactWrite, getItem = async () => ({}) } = {}) {
  return createDynamoLinkStore({
    tableName: 'GeneratedRingState',
    clock: () => nowMs,
    query: async () => ({ Items: [] }),
    getItem,
    transactWrite: transactWrite ?? (async () => ({}))
  });
}

test('refresh uses the exact client-authenticated grant and requires a newly rotated pair', async () => {
  const calls = [];
  const client = createRingClient({
    clientId: 'generated-client',
    clientSecret: 'generated-secret',
    timeoutMs: 100,
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      return Response.json({
        access_token: 'generated-access-rotated',
        refresh_token: 'generated-refresh-rotated',
        token_type: 'Bearer',
        expires_in: 14400
      });
    }
  });
  assert.deepEqual(await client.refreshTokens('generated-refresh', deadlineOptions()), {
    accessToken: 'generated-access-rotated',
    refreshToken: 'generated-refresh-rotated',
    expiresIn: 14400
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://oauth.ring.com/oauth/token');
  assert.deepEqual(Object.fromEntries(new URLSearchParams(calls[0].init.body)), {
    grant_type: 'refresh_token',
    refresh_token: 'generated-refresh',
    client_id: 'generated-client',
    client_secret: 'generated-secret'
  });
  assert.equal(calls[0].init.body.includes('client_credentials'), false);

  const unchanged = createRingClient({
    clientId: 'generated-client', clientSecret: 'generated-secret', timeoutMs: 100,
    fetchImpl: async () => Response.json({
      access_token: 'generated-access-rotated', refresh_token: 'generated-refresh',
      token_type: 'Bearer', expires_in: 14400
    })
  });
  await assert.rejects(unchanged.refreshTokens('generated-refresh', deadlineOptions()),
    error => error.code === 'provider_outcome_unknown');

  const unauthorized = createRingClient({
    clientId: 'generated-client', clientSecret: 'generated-secret', timeoutMs: 100,
    fetchImpl: async () => new Response('', { status: 401 })
  });
  await assert.rejects(unauthorized.refreshTokens('generated-refresh', deadlineOptions()),
    error => error.code === 'relink_required');
});

test('lazy composition resolves the same pinned provider secret for refresh', async () => {
  const calls = [];
  const client = createLazyRingClient({
    async loadProvider() {
      calls.push('secret');
      return { secret: { clientId: 'generated-client', clientSecret: 'generated-secret' } };
    }
  }, async (url, init) => {
    calls.push({ url, form: Object.fromEntries(new URLSearchParams(init.body)) });
    return Response.json({
      access_token: 'generated-access-rotated', refresh_token: 'generated-refresh-rotated',
      token_type: 'Bearer', expires_in: 14400
    });
  }, 100);
  await client.refreshTokens('generated-refresh', deadlineOptions());
  assert.deepEqual(calls, ['secret', {
    url: 'https://oauth.ring.com/oauth/token',
    form: {
      grant_type: 'refresh_token', refresh_token: 'generated-refresh',
      client_id: 'generated-client', client_secret: 'generated-secret'
    }
  }]);
});

test('Dynamo rotation CAS accepts one write and classifies replay, stale, and ambiguous outcomes', async () => {
  const writes = [];
  const store = dynamoStore({ transactWrite: async input => { writes.push(input); return {}; } });
  const input = {
    linkId,
    accountDigest,
    expectedLinkVersion: 2,
    expectedTokenRevision: 1,
    tokenEnvelope: rotatedEnvelope
  };
  assert.deepEqual(await store.rotateTokenEnvelope(input), {
    id: linkId, tokenRevision: 2, duplicate: false
  });
  const update = writes[0].TransactItems[0].Update;
  assert.match(update.ConditionExpression, /#status = :reserved/);
  assert.match(update.ConditionExpression, /revision = :expectedLinkVersion/);
  assert.match(update.ConditionExpression, /token_envelope\.revision = :expectedTokenRevision/);
  assert.match(update.ConditionExpression, /token_revision = :expectedTokenRevision/);
  assert.deepEqual(update.ExpressionAttributeValues[':tokenEnvelope'], envelopeAttribute(rotatedEnvelope));

  const replay = dynamoStore({
    transactWrite: async () => { throw conditionalFailure(); },
    getItem: async () => ({ Item: reservedItem() })
  });
  assert.deepEqual(await replay.rotateTokenEnvelope(input), {
    id: linkId, tokenRevision: 2, duplicate: true
  });

  const competingEnvelope = Object.freeze({
    ...rotatedEnvelope,
    ciphertext: 'Y29tcGV0aW5nLWNpcGhlcnRleHQ'
  });
  const stale = dynamoStore({
    transactWrite: async () => { throw conditionalFailure(); },
    getItem: async () => ({ Item: reservedItem(competingEnvelope) })
  });
  await assert.rejects(stale.rotateTokenEnvelope(input), error => error.code === 'token_rotation_conflict');

  let ambiguousWrites = 0;
  const ambiguous = dynamoStore({ transactWrite: async () => {
    ambiguousWrites += 1;
    throw new Error('lost-response');
  } });
  await assert.rejects(ambiguous.rotateTokenEnvelope(input),
    error => error.code === 'token_rotation_outcome_unknown');
  assert.equal(ambiguousWrites, 1);
});

function workflowFixture({ unauthorized = false } = {}) {
  const events = [];
  let state = 'UNCLAIMED';
  let refreshCalls = 0;
  let unknownReason;
  const proof = Object.freeze({});
  const identity = Object.freeze({
    proof,
    actorRef: 'generated-actor',
    ownerRef: 'generated-owner',
    householdRef: 'generated-household',
    scopeRefs: Object.freeze(['generated-read', 'generated-link']),
    accountIdentifier: 'u***r@example.test',
    epoch: 4,
    expiresAt: nowMs + 600_000
  });
  const payload = Object.freeze({
    accountId,
    accessToken: 'generated-access',
    refreshToken: 'generated-refresh',
    tokenExpiresAt: nowMs + 60_000,
    refreshTokenExpiresAt: nowMs + 2_592_000_000,
    rotation: 1
  });
  const candidateEnvelope = Object.freeze({ ...rotatedEnvelope, revision: 1 });
  const candidate = Object.freeze({
    id: linkId,
    status: 'UNCLAIMED',
    version: 1,
    identityEpoch: 0,
    expiresAt: nowSeconds + 600,
    accountDigest: createHmac('sha256', recordKey).update('ring-account\0' + accountId).digest('hex'),
    tokenEnvelope: candidateEnvelope
  });
  const store = {
    async beginCodeExchange() { throw new Error('unused'); },
    async commitUnclaimed() { throw new Error('unused'); },
    async markCodeOutcomeUnknown() { throw new Error('unused'); },
    async listUnclaimedForMatch() { return state === 'UNCLAIMED' ? [candidate] : []; },
    async reserveClaim(input) {
      if (state !== 'UNCLAIMED' || input.expectedVersion !== 1) throw new ProtocolError('link_conflict');
      state = 'RESERVED';
      events.push('reserve');
      return { id: linkId, status: 'RESERVED', version: 2, providerPhase: 'NOT_STARTED' };
    },
    async rotateTokenEnvelope(input) {
      assert.equal(state, 'RESERVED');
      assert.equal(input.expectedLinkVersion, 2);
      assert.equal(input.expectedTokenRevision, 1);
      assert.equal(input.tokenEnvelope.revision, 2);
      events.push('rotate');
      return { id: linkId, tokenRevision: 2, duplicate: false };
    },
    async beginProviderPhase(input) {
      events.push(`begin:${input.phase}`);
      return {
        id: linkId,
        status: input.phase === 'POST' ? 'RESERVED' : 'AWAITING',
        version: input.expectedVersion + 1,
        providerPhase: `${input.phase}_STARTED`
      };
    },
    async finishProviderPhase(input) {
      events.push(`finish:${input.phase}`);
      state = input.phase === 'POST' ? 'AWAITING' : 'COMPLETED';
      return {
        id: linkId,
        status: state,
        version: input.expectedVersion + 1,
        providerPhase: `${input.phase}_SUCCEEDED`
      };
    },
    async markOutcomeUnknown(input) {
      state = 'OUTCOME_UNKNOWN';
      unknownReason = input.reason;
      events.push('unknown');
      return { id: linkId, status: state, version: null, providerPhase: `${input.phase}_UNKNOWN` };
    }
  };
  const client = {
    async exchangeCode() { throw new Error('unused'); },
    async getAccountId() { throw new Error('unused'); },
    async refreshTokens() {
      refreshCalls += 1;
      events.push('refresh');
      if (unauthorized) throw new ProtocolError('relink_required');
      return {
        accessToken: 'generated-access-rotated',
        refreshToken: 'generated-refresh-rotated',
        expiresIn: 14400
      };
    },
    async confirmLink() { events.push('confirm'); },
    async completeLink() { events.push('complete'); }
  };
  const workflow = createRingWorkflow({
    client,
    store,
    clock: () => nowMs,
    secretLoader: {
      async loadProvider() { return { secret: { nonceKey } }; },
      async loadDigest() { return { secret: { recordHmacKey: recordKey } }; }
    },
    tokenEnvelope: {
      async open() { return payload; },
      async seal(value, options) {
        assert.equal(value.rotation, 2);
        assert.equal(options.revision, 2);
        return rotatedEnvelope;
      }
    },
    identityAuthority: {
      async resolveMatchedRingAccount() { return identity; },
      async recheck(candidateProof) {
        assert.equal(candidateProof, proof);
        return identity;
      }
    }
  });
  const time = String(nowMs - 1000);
  const request = Object.freeze({
    query: Object.freeze({ time, nonce: computeNonce(time, accountId, nonceKey) }),
    context: Object.freeze({})
  });
  return {
    workflow,
    request,
    events,
    state: () => state,
    refreshCalls: () => refreshCalls,
    unknownReason: () => unknownReason
  };
}

test('workflow reserves before refresh, persists rotation, then performs provider phases', async () => {
  const fixture = workflowFixture();
  assert.deepEqual(await fixture.workflow.continuePasswordlessLink(fixture.request), {
    status: 'completed', duplicate: false, bindingCompleted: true,
    retryAllowed: false, productionAdmitted: false
  });
  assert.deepEqual(fixture.events, [
    'reserve', 'refresh', 'rotate',
    'begin:POST', 'confirm', 'finish:POST',
    'begin:PATCH', 'complete', 'finish:PATCH'
  ]);
  assert.equal(fixture.state(), 'COMPLETED');
});

test('parallel near-expiry workflows have one reserve winner and one refresh call', async () => {
  const fixture = workflowFixture();
  const results = await Promise.allSettled([
    fixture.workflow.continuePasswordlessLink(fixture.request),
    fixture.workflow.continuePasswordlessLink(fixture.request)
  ]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(results.find(result => result.status === 'rejected').reason.code, 'link_conflict');
  assert.equal(fixture.refreshCalls(), 1);
});

test('refresh 401 returns relink_required and terminalizes the reserved claim', async () => {
  const fixture = workflowFixture({ unauthorized: true });
  await assert.rejects(fixture.workflow.continuePasswordlessLink(fixture.request),
    error => error.code === 'relink_required');
  assert.deepEqual(fixture.events, ['reserve', 'refresh', 'unknown']);
  assert.equal(fixture.state(), 'OUTCOME_UNKNOWN');
  assert.equal(fixture.unknownReason(), 'RELINK_REQUIRED');
});
