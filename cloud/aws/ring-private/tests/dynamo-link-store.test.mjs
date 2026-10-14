import test from 'node:test';
import assert from 'node:assert/strict';
import { createDynamoLinkStore } from '../dynamo-link-store.mjs';

const nowMs = Date.parse('2026-10-07T00:00:00Z');
const now = Math.floor(nowMs / 1000);
const codeDigest = 'b'.repeat(64);
const bodyDigest = 'c'.repeat(64);
const accountDigest = 'a'.repeat(64);
const intakeId = 'generated-intake-id';
const tokenEnvelope = Object.freeze({
  schemaVersion: 1,
  purpose: 'RING_LINK_TOKENS',
  linkId: intakeId,
  revision: 1,
  encryptedDataKey: 'Z2VuZXJhdGVkLXdyYXBwZWQta2V5',
  nonce: Buffer.alloc(12, 3).toString('base64url'),
  authTag: Buffer.alloc(16, 4).toString('base64url'),
  ciphertext: 'Z2VuZXJhdGVkLWNpcGhlcnRleHQ'
});

function conditionalFailure() {
  return Object.assign(new Error('conditional'), { name: 'ConditionalCheckFailedException' });
}

function item(id, overrides = {}) {
  return {
    link_id: { S: id },
    status: { S: 'UNCLAIMED' },
    revision: { N: '1' },
    identity_epoch: { N: '4' },
    expires_at: { N: String(now + 600) },
    ...overrides
  };
}

function envelopeAttribute(envelope = tokenEnvelope) {
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

function codeItem(status, overrides = {}) {
  return {
    intake_id: { S: intakeId },
    code_digest: { S: codeDigest },
    body_digest: { S: bodyDigest },
    status: { S: status },
    exchange_deadline: { N: String(now + 120) },
    revision: { N: '1' },
    ...(status === 'UNCLAIMED' ? { account_digest: { S: accountDigest } } : {}),
    ...overrides
  };
}

function committedLinkItem(overrides = {}) {
  return item(intakeId, {
    identity_epoch: { N: '0' },
    account_digest: { S: 'a'.repeat(64) },
    token_envelope: envelopeAttribute(),
    ...overrides
  });
}

function adapter(overrides = {}) {
  const requests = [];
  const store = createDynamoLinkStore({
    query: async input => {
      requests.push({ operation: 'query', input });
      return { Items: [] };
    },
    getItem: async input => {
      requests.push({ operation: 'get', input });
      return {};
    },
    transactWrite: async input => {
      requests.push({ operation: 'transact', input });
      return {};
    },
    tableName: 'GeneratedRingState',
    indexName: 'GSI1',
    clock: () => nowMs,
    createIntakeId: () => intakeId,
    ...overrides
  });
  return { store, requests };
}

const transition = Object.freeze({
  linkId: 'generated-link-a',
  actorRef: 'generated-actor',
  ownerRef: 'generated-owner',
  householdRef: 'generated-household',
  scopeRefs: Object.freeze(['generated-scope-read', 'generated-scope-link']),
  accountDigest: 'a'.repeat(64),
  expectedVersion: 1,
  currentEpoch: 4,
  expiresAt: now + 600
});

test('unclaimed lookup uses bounded Query pages and never exposes a Scan operation', async () => {
  const calls = [];
  const pages = [
    { Items: [item('generated-a')], LastEvaluatedKey: { PK: { S: 'cursor' } } },
    { Items: [item('generated-b')] }
  ];
  const { store } = adapter({ query: async input => { calls.push(input); return pages.shift(); } });
  const records = await store.listUnclaimed();
  assert.deepEqual(records.map(record => record.id), ['generated-a', 'generated-b']);
  assert.equal(calls.length, 2);
  assert.equal(calls.every(call => call.KeyConditionExpression === '#gsiPk = :unclaimed'), true);
  assert.equal(calls.every(call => call.ProjectionExpression === 'link_id, #status, revision, identity_epoch, expires_at'), true);
  assert.equal(calls.every(call => !call.ProjectionExpression.includes('token_envelope')), true);
  assert.equal(calls.every(call => call.Limit <= 25 && call.ConsistentRead === false), true);
  assert.equal(JSON.stringify(calls).includes('Scan'), false);
});

test('candidate and page capacity are hard bounds', async () => {
  const candidates = Array.from({ length: 2 }, (_, index) => item(`generated-${index}`));
  const { store } = adapter({
    maxCandidates: 2,
    maxQueryPages: 1,
    query: async () => ({ Items: candidates, LastEvaluatedKey: { PK: { S: 'more' } } })
  });
  await assert.rejects(store.listUnclaimed(), /unclaimed_limit/);
});

test('private match query is separately bounded and returns only encrypted custody fields', async () => {
  const calls = [];
  const privateItem = item(intakeId, {
    identity_epoch: { N: '0' },
    account_digest: { S: 'a'.repeat(64) },
    token_envelope: envelopeAttribute()
  });
  const { store } = adapter({ query: async input => { calls.push(input); return { Items: [privateItem] }; } });
  const records = await store.listUnclaimedForMatch();
  assert.deepEqual(records, [{
    id: intakeId,
    status: 'UNCLAIMED',
    version: 1,
    identityEpoch: 0,
    expiresAt: now + 600,
    accountDigest: 'a'.repeat(64),
    tokenEnvelope
  }]);
  assert.equal(calls[0].ProjectionExpression, 'link_id, #status, revision, identity_epoch, expires_at, account_digest, token_envelope');
  assert.equal(calls[0].Limit, 25);
  assert.equal(JSON.stringify(calls).includes('Scan'), false);
});

test('beginCodeExchange conditionally persists only keyed digest state and permits one provider call', async () => {
  const { store, requests } = adapter();
  const result = await store.beginCodeExchange({ codeDigest, receivedAt: now, bodyDigest, exchangeDeadline: now + 120 });
  assert.deepEqual(result, {
    intakeId,
    status: 'EXCHANGE_STARTED',
    duplicate: false,
    safeDuplicate: false,
    mayCallProvider: true
  });
  const transaction = requests[0].input;
  assert.equal(transaction.TransactItems.length, 2);
  assert.deepEqual(transaction.TransactItems[0].Put.Key, undefined);
  assert.equal(transaction.TransactItems[0].Put.Item.PK.S, `CODE#${codeDigest}`);
  assert.equal(transaction.TransactItems[1].Put.Item.PK.S, `INTAKE#${intakeId}`);
  assert.equal(transaction.TransactItems[1].Put.Item.code_digest.S, codeDigest);
  assert.equal(transaction.TransactItems[0].Put.Item.body_digest.S, bodyDigest);
  assert.equal(transaction.TransactItems[1].Put.Item.body_digest.S, bodyDigest);
  assert.equal(JSON.stringify(transaction).includes('rawCode'), false);
  assert.equal(JSON.stringify(transaction).includes('authorization_code'), false);
  let reads = 0;
  const accessor = { codeDigest, receivedAt: now, bodyDigest, exchangeDeadline: now + 120 };
  Object.defineProperty(accessor, 'codeDigest', { enumerable: true, get() { reads += 1; return codeDigest; } });
  await assert.rejects(store.beginCodeExchange(accessor), /link_state_invalid/);
  assert.equal(reads, 0);
});

test('duplicate code state distinguishes safe UNCLAIMED from non-retryable STARTED and UNKNOWN', async () => {
  const make = status => adapter({
    transactWrite: async () => { throw conditionalFailure(); },
    getItem: async input => ({ Item: input.Key.PK.S.startsWith('CODE#') ? codeItem(status) : committedLinkItem() })
  }).store;
  assert.deepEqual(await make('UNCLAIMED').beginCodeExchange({ codeDigest, receivedAt: now, bodyDigest, exchangeDeadline: now + 120 }), {
    intakeId,
    status: 'UNCLAIMED',
    duplicate: true,
    safeDuplicate: true,
    mayCallProvider: false
  });
  await assert.rejects(make('EXCHANGE_STARTED').beginCodeExchange({ codeDigest, receivedAt: now, bodyDigest, exchangeDeadline: now + 120 }), /code_exchange_in_progress/);
  await assert.rejects(make('OUTCOME_UNKNOWN').beginCodeExchange({ codeDigest, receivedAt: now, bodyDigest, exchangeDeadline: now + 120 }), /code_outcome_unknown/);
});

test('commitUnclaimed atomically advances code and intake and stores only encrypted token envelope', async () => {
  const transactions = [];
  const { store } = adapter({
    getItem: async input => {
      assert.equal(input.Key.PK.S, `INTAKE#${intakeId}`);
      return { Item: codeItem('EXCHANGE_STARTED') };
    },
    transactWrite: async input => { transactions.push(input); return {}; }
  });
  assert.deepEqual(await store.commitUnclaimed({
    intakeId,
    bodyDigest,
    accountDigest,
    exchangeDeadline: now + 120,
    tokenEnvelope,
    linkExpiresAt: now + 600
  }), { intakeId, status: 'UNCLAIMED', version: 1, duplicate: false, safeDuplicate: false });
  const transaction = transactions[0];
  assert.equal(transaction.TransactItems.length, 3);
  const link = transaction.TransactItems[2].Put.Item;
  assert.equal(link.account_digest.S, 'a'.repeat(64));
  assert.deepEqual(link.token_envelope, envelopeAttribute());
  assert.equal(link.identity_epoch.N, '0');
  assert.equal(link.GSI1PK.S, 'UNCLAIMED');
  for (const operation of transaction.TransactItems.slice(0, 2)) {
    assert.match(operation.Update.ConditionExpression, /body_digest = :bodyDigest/);
    assert.match(operation.Update.ConditionExpression, /exchange_deadline = :exchangeDeadline/);
    assert.match(operation.Update.ConditionExpression, /attribute_not_exists\(account_digest\)/);
    assert.match(operation.Update.UpdateExpression, /account_digest = :accountDigest/);
    assert.equal(operation.Update.ExpressionAttributeValues[':bodyDigest'].S, bodyDigest);
    assert.equal(operation.Update.ExpressionAttributeValues[':accountDigest'].S, accountDigest);
    assert.equal(operation.Update.ExpressionAttributeValues[':exchangeDeadline'].N, String(now + 120));
  }
  const serialized = JSON.stringify(transaction);
  for (const forbidden of ['accountId', 'accessToken', 'refreshToken', 'generated-ring-account-for-offline-test']) {
    assert.equal(serialized.includes(forbidden), false);
  }
});

test('committed intake is a safe duplicate while UNKNOWN cannot commit or resend', async () => {
  let writes = 0;
  const committed = adapter({
    getItem: async input => ({ Item: input.Key.PK.S.startsWith('INTAKE#') ? codeItem('UNCLAIMED') : committedLinkItem() }),
    transactWrite: async () => { writes += 1; return {}; }
  }).store;
  assert.deepEqual(await committed.commitUnclaimed({
    intakeId,
    bodyDigest,
    accountDigest,
    exchangeDeadline: now + 120,
    tokenEnvelope,
    linkExpiresAt: now + 600
  }), { intakeId, status: 'UNCLAIMED', version: 1, duplicate: true, safeDuplicate: true });
  assert.equal(writes, 0);
  const unknown = adapter({ getItem: async () => ({ Item: codeItem('OUTCOME_UNKNOWN') }) }).store;
  await assert.rejects(unknown.commitUnclaimed({
    intakeId,
    bodyDigest,
    accountDigest,
    exchangeDeadline: now + 120,
    tokenEnvelope,
    linkExpiresAt: now + 600
  }), /code_outcome_unknown/);
});

test('markCodeOutcomeUnknown is terminal across both keyed records and is idempotent without retry', async () => {
  const transactions = [];
  const { store } = adapter({
    getItem: async () => ({ Item: codeItem('EXCHANGE_STARTED') }),
    transactWrite: async input => { transactions.push(input); return {}; }
  });
  assert.deepEqual(await store.markCodeOutcomeUnknown({ intakeId }), {
    intakeId,
    status: 'OUTCOME_UNKNOWN',
    duplicate: false,
    safeDuplicate: false,
    retryAllowed: false
  });
  assert.equal(transactions[0].TransactItems.length, 2);
  assert.equal(transactions[0].TransactItems.every(entry => entry.Update.ExpressionAttributeValues[':unknown'].S === 'OUTCOME_UNKNOWN'), true);

  const terminal = adapter({
    getItem: async () => ({ Item: codeItem('OUTCOME_UNKNOWN') }),
    transactWrite: async () => { throw new Error('must not write'); }
  }).store;
  assert.deepEqual(await terminal.markCodeOutcomeUnknown({ intakeId }), {
    intakeId,
    status: 'OUTCOME_UNKNOWN',
    duplicate: true,
    safeDuplicate: false,
    retryAllowed: false
  });
});

test('logical expiry filters query results and blocks reserve without DynamoDB mutation', async () => {
  const { store, requests } = adapter({
    query: async input => {
      requests.push({ operation: 'query', input });
      return { Items: [item('expired', { expires_at: { N: String(now) } })] };
    }
  });
  assert.deepEqual(await store.listUnclaimed(), []);
  await assert.rejects(store.reserveClaim({ ...transition, expiresAt: now }), /link_expired/);
  assert.equal(requests.filter(request => request.operation === 'transact').length, 0);
});

test('reserve uses status, version, expiry, and current identity epoch CAS', async () => {
  const { store, requests } = adapter();
  assert.deepEqual(await store.reserveClaim(transition), {
    id: transition.linkId,
    status: 'RESERVED',
    version: 2,
    providerPhase: 'NOT_STARTED'
  });
  const input = requests[0].input.TransactItems[0].Update;
  assert.match(input.ConditionExpression, /#status = :unclaimed/);
  assert.match(input.ConditionExpression, /revision = :expectedVersion/);
  assert.match(input.ConditionExpression, /identity_epoch = :unboundEpoch/);
  assert.match(input.ConditionExpression, /account_digest = :accountDigest/);
  assert.match(input.ConditionExpression, /expires_at > :now/);
  assert.match(input.UpdateExpression, /REMOVE GSI1PK, GSI1SK/);
  assert.deepEqual(input.ExpressionAttributeValues[':scopeRefs'], { L: transition.scopeRefs.map(value => ({ S: value })) });
  assert.equal(input.ExpressionAttributeValues[':ownerRef'].S, transition.ownerRef);
  assert.equal(input.ExpressionAttributeValues[':householdRef'].S, transition.householdRef);
  const account = requests[0].input.TransactItems[1].ConditionCheck;
  assert.deepEqual(account.Key, { PK: { S: `ACCOUNT#${transition.accountDigest}` }, SK: { S: 'IDENTITY' } });
  assert.match(account.ConditionExpression, /identity_epoch = :currentEpoch/);
  assert.match(account.ConditionExpression, /revoked = :notRevoked/);
  assert.match(account.ConditionExpression, /expires_at > :now/);
});

test('formal reserve pins account generation and projection revision in both records', async () => {
  const { store, requests } = adapter();
  await store.reserveClaim({ ...transition, accountGeneration: 3, projectionRevision: 2 });
  const [link, account] = requests[0].input.TransactItems;
  assert.match(link.Update.UpdateExpression, /account_generation = :accountGeneration/);
  assert.equal(link.Update.ExpressionAttributeValues[':accountGeneration'].N, '3');
  assert.equal(link.Update.ExpressionAttributeValues[':projectionRevision'].N, '2');
  assert.match(account.ConditionCheck.ConditionExpression, /account_generation = :accountGeneration/);
  assert.match(account.ConditionCheck.ConditionExpression, /projection_revision = :projectionRevision/);
  await assert.rejects(store.reserveClaim({ ...transition, accountGeneration: 3 }), /link_state_invalid/);
});

test('CAS race fails closed and does not retry the conditional write', async () => {
  let calls = 0;
  const { store } = adapter({ transactWrite: async () => { calls += 1; throw conditionalFailure(); } });
  await assert.rejects(store.reserveClaim(transition), /link_conflict/);
  assert.equal(calls, 1);
});

test('provider POST and PATCH phases append STARTED and SUCCEEDED journal entries', async () => {
  const { store, requests } = adapter();
  assert.equal((await store.beginProviderPhase({ ...transition, phase: 'POST' })).providerPhase, 'POST_STARTED');
  assert.deepEqual(await store.finishProviderPhase({ ...transition, expectedVersion: 2, phase: 'POST' }), {
    id: transition.linkId,
    status: 'AWAITING',
    version: 3,
    providerPhase: 'POST_SUCCEEDED'
  });
  assert.equal((await store.beginProviderPhase({ ...transition, expectedVersion: 3, phase: 'PATCH' })).providerPhase, 'PATCH_STARTED');
  assert.equal((await store.finishProviderPhase({ ...transition, expectedVersion: 4, phase: 'PATCH' })).status, 'COMPLETED');
  const serialized = JSON.stringify(requests);
  assert.match(serialized, /provider_journal/);
  assert.match(serialized, /STARTED/);
  assert.match(serialized, /SUCCEEDED/);
});

test('lost return after STARTED is durably changed to OUTCOME_UNKNOWN', async () => {
  const calls = [];
  const { store } = adapter({
    transactWrite: async input => {
      calls.push(input);
      if (calls.length === 1) throw new Error('response lost after commit');
      return {};
    }
  });
  await assert.rejects(store.beginProviderPhase({ ...transition, phase: 'POST' }), /provider_outcome_unknown/);
  assert.equal(calls.length, 2);
  const unknownUpdate = calls[1].TransactItems[0].Update;
  assert.equal(unknownUpdate.ExpressionAttributeValues[':unknown'].S, 'OUTCOME_UNKNOWN');
  assert.match(unknownUpdate.UpdateExpression, /provider_journal/);
  assert.match(unknownUpdate.ConditionExpression, /revision = :expectedVersion OR revision = :startedVersion/);
  assert.equal(unknownUpdate.ExpressionAttributeValues[':journal'].L[0].M.result.S, 'OUTCOME_UNKNOWN');
});

test('OUTCOME_UNKNOWN cannot be reserved or automatically retried', async () => {
  let calls = 0;
  const { store } = adapter({ transactWrite: async input => {
    calls += 1;
    if (input.TransactItems[0].Update.ExpressionAttributeValues[':unknown']) return {};
    throw conditionalFailure();
  } });
  await store.markOutcomeUnknown({
    linkId: transition.linkId,
    accountDigest: transition.accountDigest,
    phase: 'POST',
    expectedVersion: transition.expectedVersion,
    currentEpoch: 4
  });
  await assert.rejects(store.reserveClaim(transition), /link_conflict/);
  await assert.rejects(store.beginProviderPhase({ ...transition, phase: 'POST' }), /link_conflict/);
  assert.equal(calls, 3);
});

test('DynamoDB query and update outages return finite errors without sensitive values', async () => {
  const sensitive = 'generated-sensitive-provider-value';
  const queryFailure = adapter({ query: async () => { throw new Error(sensitive); } }).store;
  await assert.rejects(queryFailure.listUnclaimed(), error => {
    assert.equal(error.code, 'link_store_unavailable');
    assert.equal(error.message.includes(sensitive), false);
    return true;
  });
  const updateFailure = adapter({ transactWrite: async () => { throw new Error(sensitive); } }).store;
  await assert.rejects(updateFailure.reserveClaim(transition), error => {
    assert.equal(error.code, 'link_store_unavailable');
    assert.equal(error.message.includes(sensitive), false);
    return true;
  });
  const codeFailure = adapter({ transactWrite: async () => { throw new Error(sensitive); } }).store;
  await assert.rejects(codeFailure.beginCodeExchange({ codeDigest, receivedAt: now, bodyDigest, exchangeDeadline: now + 120 }), error => {
    assert.equal(error.code, 'code_store_unavailable');
    assert.equal(error.message.includes(sensitive), false);
    return true;
  });
});

test('ambiguous provider write whose UNKNOWN journal also fails stays unavailable', async () => {
  let calls = 0;
  const { store } = adapter({ transactWrite: async () => { calls += 1; throw new Error('offline'); } });
  await assert.rejects(store.beginProviderPhase({ ...transition, phase: 'POST' }), /link_store_unavailable/);
  assert.equal(calls, 2);
});
