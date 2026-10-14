import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createRingClient } from '../ring-client.mjs';
import { createRingWorkflow } from '../workflow.mjs';
import { createDynamoLinkStore } from '../dynamo-link-store.mjs';
import { createTokenEnvelope } from '../token-envelope.mjs';
import { createSecretLoader } from '../secret-loader.mjs';
import { MemoryRingStore, AwsRingStoreBlocked } from '../store.mjs';
import { computeNonce, ProtocolError } from '../protocol.mjs';
import { handler } from '../handler.mjs';

const initialNow = 1_790_000_000_000;
const accountId = 'generated-ring-account';
const nonceKey = 'generated-nonce-key-at-least-thirty-two-bytes';
const recordKey = 'generated-record-key-at-least-thirty-two-bytes';
const accountDigest = createHmac('sha256', recordKey).update('ring-account\0' + accountId).digest('hex');
const safeResult = (status, duplicate = false) => ({
  status, duplicate, bindingCompleted: status === 'completed', retryAllowed: false, productionAdmitted: false
});
const rejectCode = code => error => error instanceof ProtocolError && error.code === code && error.message === code;

function fixture() {
  let now = initialNow;
  let intakeSequence = 0;
  const records = new Map();
  const calls = [];
  const events = [];
  const context = Object.freeze({});
  const identityProof = Object.freeze({});
  const control = { identityChecks: 0, identityAllowed: true };
  let identity = Object.freeze({
    proof: identityProof, actorRef: 'generated-actor', ownerRef: 'generated-owner', householdRef: 'generated-household',
    scopeRefs: Object.freeze(['generated-read', 'generated-link']), accountIdentifier: 'u***r@example.test',
    epoch: 4, expiresAt: initialNow + 300_000
  });
  const pk = key => key.PK.S + '/' + key.SK.S;
  const clone = value => structuredClone(value);
  const conditional = () => Object.assign(Error('conditional'), { name: 'ConditionalCheckFailedException' });
  records.set('ACCOUNT#' + accountDigest + '/IDENTITY', {
    identity_epoch: { N: '4' }, revoked: { BOOL: false }, expires_at: { N: String(Math.floor(now / 1000) + 600) }
  });
  function check(update) {
    const item = records.get(pk(update.Key));
    const values = update.ExpressionAttributeValues;
    if (!item) throw conditional();
    const checkEqual = (field, valueKey) => {
      if (values[valueKey] && JSON.stringify(item[field]) !== JSON.stringify(values[valueKey])) throw conditional();
    };
    if (update.ConditionExpression.includes('revision = :expectedVersion')) checkEqual('revision', ':expectedVersion');
    if (update.ConditionExpression.includes('revision = :revision')) checkEqual('revision', ':revision');
    if (update.ConditionExpression.includes('identity_epoch = :unboundEpoch')) checkEqual('identity_epoch', ':unboundEpoch');
    if (update.ConditionExpression.includes('identity_epoch = :currentEpoch')) checkEqual('identity_epoch', ':currentEpoch');
    if (update.ConditionExpression.includes('account_digest = :accountDigest')) checkEqual('account_digest', ':accountDigest');
    if (update.ConditionExpression.includes('provider_phase = :expectedProviderPhase')) checkEqual('provider_phase', ':expectedProviderPhase');
    if (update.ConditionExpression.includes('provider_phase = :started')) checkEqual('provider_phase', ':started');
    if (update.ConditionExpression.includes('#status = :expectedStatus')) checkEqual('status', ':expectedStatus');
    if (update.ConditionExpression.includes('#status = :unclaimed')) checkEqual('status', ':unclaimed');
    if (update.ConditionExpression.includes('#status = :started')) checkEqual('status', ':started');
    if (update.ConditionExpression.includes('intake_id = :intakeId')) checkEqual('intake_id', ':intakeId');
    if (update.ConditionExpression.includes('body_digest = :bodyDigest')) checkEqual('body_digest', ':bodyDigest');
    if (update.ConditionExpression.includes('exchange_deadline = :exchangeDeadline')) checkEqual('exchange_deadline', ':exchangeDeadline');
    if (update.ConditionExpression.includes('attribute_not_exists(account_digest)') && item.account_digest !== undefined) throw conditional();
    if (update.ConditionExpression.includes('expires_at > :now') && Number(item.expires_at?.N) <= Number(values[':now'].N)) throw conditional();
    if (update.ConditionExpression.includes('exchange_deadline > :now') && Number(item.exchange_deadline?.N) <= Number(values[':now'].N)) throw conditional();
    if (update.ConditionExpression.includes('revoked = :notRevoked')) checkEqual('revoked', ':notRevoked');
  }
  function apply(update) {
    const item = records.get(pk(update.Key));
    const values = update.ExpressionAttributeValues;
    if (values[':unknown']) item.status = clone(values[':unknown']);
    else if (values[':nextStatus']) item.status = clone(values[':nextStatus']);
    else if (values[':reserved'] && values[':actorRef']) item.status = clone(values[':reserved']);
    else if (values[':unclaimed'] && values[':started'] && update.UpdateExpression.includes('#status = :unclaimed')) item.status = clone(values[':unclaimed']);
    if (values[':phase']) item.provider_phase = clone(values[':phase']);
    else if (values[':succeeded']) item.provider_phase = clone(values[':succeeded']);
    else if (values[':started'] && update.UpdateExpression.includes('provider_phase = :started')) item.provider_phase = clone(values[':started']);
    else if (values[':notStarted']) item.provider_phase = clone(values[':notStarted']);
    for (const [field, input] of [
      ['actor_ref', ':actorRef'], ['owner_ref', ':ownerRef'], ['household_ref', ':householdRef'],
      ['scope_refs', ':scopeRefs'], ['identity_epoch', ':currentEpoch'], ['account_digest', ':accountDigest']
    ]) if (values[input] && update.UpdateExpression.includes(field + ' =')) item[field] = clone(values[input]);
    if (update.UpdateExpression.includes('REMOVE GSI1PK')) { delete item.GSI1PK; delete item.GSI1SK; }
    item.revision = { N: String(Number(item.revision.N) + 1) };
  }
  const store = createDynamoLinkStore({
    tableName: 'GeneratedRingWorkflow', clock: () => now, createIntakeId: () => 'generated-intake-' + (++intakeSequence),
    query: async input => {
      events.push('query');
      assert.equal(input.Limit, 25);
      if (control.query) return control.query(input, records);
      return { Items: [...records.values()].filter(item => item.GSI1PK?.S === 'UNCLAIMED').map(clone) };
    },
    getItem: async input => ({ Item: clone(records.get(pk(input.Key))) }),
    transactWrite: async input => {
      const label = input.TransactItems[0].Put ? 'begin' :
        input.TransactItems.some(item => item.Put) ? 'commit' :
        input.TransactItems[0].Update.ExpressionAttributeValues[':actorRef'] ? 'reserve' :
        input.TransactItems[0].Update.ExpressionAttributeValues[':unknown'] ? 'unknown' :
        input.TransactItems[0].Update.ExpressionAttributeValues[':nextStatus'] ? 'finish' : 'phase';
      events.push(label);
      if (control.beforeWrite) await control.beforeWrite(label, input);
      for (const operation of input.TransactItems) {
        if (operation.Put && records.has(pk(operation.Put.Item))) throw conditional();
        if (operation.Update) {
          if (label === 'unknown') {
            const item = records.get(pk(operation.Update.Key));
            if (!item) throw conditional();
          } else check(operation.Update);
        }
        if (operation.ConditionCheck) check(operation.ConditionCheck);
      }
      for (const operation of input.TransactItems) {
        if (operation.Put) records.set(pk(operation.Put.Item), clone(operation.Put.Item));
        if (operation.Update) apply(operation.Update);
      }
      if (control.afterWrite) await control.afterWrite(label, input);
      return {};
    }
  });
  const envelope = createTokenEnvelope({
    tableName: 'GeneratedRingWorkflow', keyId: 'generated-kms-key',
    generateDataKey: async () => ({ Plaintext: Buffer.alloc(32, 7), CiphertextBlob: Buffer.from('generated-wrapped-key') }),
    decryptDataKey: async () => ({ Plaintext: Buffer.alloc(32, 7) })
  });
  const secretLoader = createSecretLoader({
    providerSecretArn: 'arn:aws:secretsmanager:ap-southeast-1:111111111111:secret:generated-provider',
    digestSecretArn: 'arn:aws:secretsmanager:ap-southeast-1:111111111111:secret:generated-digest',
    clock: () => now,
    getSecretValue: async input => ({
      VersionId: 'g'.repeat(32),
      SecretString: JSON.stringify(input.SecretId.endsWith('provider') ? {
        version: 1, clientId: 'generated-client', clientSecret: 'generated-client-secret', nonceKey,
        webhookSigningKey: nonceKey
      } : { version: 1, recordHmacKey: recordKey, cookieHmacKey: 'generated-cookie-key-at-least-thirty-two-bytes' })
    })
  });
  const client = createRingClient({
    clientId: 'generated-client', clientSecret: 'generated-client-secret', timeoutMs: 100,
    fetchImpl: async (url, init) => {
      const kind = url.includes('oauth.ring.com') ? 'exchange' : url.endsWith('/users/me') ? 'profile' : init.method;
      calls.push(kind); events.push(kind);
      if (control.provider) await control.provider(kind, init);
      if (kind === 'exchange') return Response.json({ access_token: 'generated-access', refresh_token: 'generated-refresh', token_type: 'Bearer', expires_in: 14400 });
      if (kind === 'profile') return Response.json({ data: { type: control.profileType ?? 'users', id: accountId } });
      return Response.json({ data: { type: 'app-integrations', id: 'generated-integration', attributes: { status: kind === 'POST' ? 'awaiting' : 'completed' } } });
    }
  });
  const identityAuthority = {
    resolveMatchedRingAccount: async value => {
      events.push('identity-resolve'); assert.equal(value.accountId, accountId);
      if (!control.identityAllowed || value.context !== context) throw Error('private-identity-detail');
      return control.identityBoolean ? true : identity;
    },
    recheck: async candidate => {
      events.push('identity-recheck'); control.identityChecks += 1;
      if (control.identityRecheck) await control.identityRecheck(control.identityChecks);
      if (!control.identityAllowed || candidate !== identityProof) throw Error('private-identity-detail');
      return control.identityBoolean ? true : identity;
    }
  };
  const ports = { client, store, secretLoader, tokenEnvelope: envelope, identityAuthority, clock: () => now };
  const workflow = createRingWorkflow(ports);
  const ingress = () => ({ code: 'generated-code', receivedAt: initialNow, bodyDigest: 'b'.repeat(64) });
  const link = () => {
    const time = String(initialNow - 1000);
    return { query: { time, nonce: computeNonce(time, accountId, nonceKey) }, context };
  };
  return {
    workflow, ports, control, records, calls, events, ingress, link, context,
    setNow: value => { now = value; }, setIdentity: value => { identity = Object.freeze({ ...identity, ...value }); },
    state: () => [...records.values()].find(item => item.link_id)?.status.S,
    codeState: () => [...records.entries()].find(([key]) => key.startsWith('CODE#'))?.[1]?.status.S,
    addDuplicate: () => {
      const original = [...records.values()].find(item => item.link_id);
      const copy = clone(original); copy.link_id.S = 'generated-duplicate';
      copy.token_envelope.M.link_id.S = 'generated-duplicate';
      records.set('LINK#generated-duplicate/STATE', copy);
    }
  };
}

test('inert Lambda remains disabled and exchanges nothing', async () => {
  const response = await handler({ body: '{"code":"generated-code"}' });
  assert.equal(response.statusCode, 503);
  assert.deepEqual(JSON.parse(response.body), { status: 'not_configured' });
});
test('actual custody/store composition stages once and exact identity CAS completes POST then PATCH', async () => {
  const f = fixture();
  assert.deepEqual(await f.workflow.stageFromVerifiedIngress(f.ingress()), safeResult('unclaimed'));
  assert.equal(f.state(), 'UNCLAIMED');
  assert.deepEqual(await f.workflow.continuePasswordlessLink(f.link()), safeResult('completed'));
  assert.equal(f.state(), 'COMPLETED');
  assert.deepEqual(f.calls, ['exchange', 'profile', 'POST', 'PATCH']);
  const item = [...f.records.values()].find(value => value.link_id);
  assert.equal(item.actor_ref.S, 'generated-actor'); assert.equal(item.owner_ref.S, 'generated-owner');
  assert.equal(item.household_ref.S, 'generated-household');
  assert.deepEqual(item.scope_refs.L.map(value => value.S), ['generated-read', 'generated-link']);
  assert.equal(item.identity_epoch.N, '4');
  assert.equal(item.provider_phase.S, 'PATCH_SUCCEEDED');
  assert.equal(JSON.stringify(f.records.values()).includes('generated-access'), false);
  await assert.rejects(f.workflow.continuePasswordlessLink(f.link()), rejectCode('link_not_found'));
  assert.equal(f.calls.length, 4);
  assert(f.events.indexOf('begin') < f.events.indexOf('exchange'));
  assert(f.events.indexOf('exchange') < f.events.indexOf('profile'));
  assert(f.events.indexOf('profile') < f.events.indexOf('commit'));
  const codeRecord = [...f.records.entries()].find(([key]) => key.startsWith('CODE#'))[1];
  const intakeRecord = [...f.records.entries()].find(([key]) => key.startsWith('INTAKE#'))[1];
  assert.equal(codeRecord.body_digest.S, 'b'.repeat(64));
  assert.equal(intakeRecord.body_digest.S, 'b'.repeat(64));
  assert.equal(codeRecord.account_digest.S, accountDigest);
  assert.equal(intakeRecord.account_digest.S, accountDigest);
});
for (const port of ['client', 'store', 'secretLoader', 'tokenEnvelope', 'identityAuthority']) {
  test('constructor missing mandatory port: ' + port, () => {
    const f = fixture(); assert.throws(() => createRingWorkflow({ ...f.ports, [port]: undefined }), ProtocolError);
  });
}
for (const [name, change, expected] of [
  ['caller identity tuple', value => ({ ...value, ownerRef: 'forged' }), 'invalid_field'],
  ['invalid code', value => ({ ...value, code: '' }), 'invalid_field'],
  ['oversized bytes', value => ({ ...value, code: 'é'.repeat(1100) }), 'invalid_field'],
  ['invalid digest', value => ({ ...value, bodyDigest: 'raw-secret' }), 'invalid_field'],
  ['future receipt', value => ({ ...value, receivedAt: initialNow + 1 }), 'code_expired'],
  ['expired 60 seconds', value => ({ ...value, receivedAt: initialNow - 60_000 }), 'code_expired'],
  ['unsafe receipt time', value => ({ ...value, receivedAt: Number.MAX_SAFE_INTEGER }), 'code_expired'],
  ['transport context cannot cross proof boundary', value => ({ ...value, tokenTransportContext: {} }), 'invalid_field']
]) test('ingress finite pre-provider deny: ' + name, async () => {
  const f = fixture(); await assert.rejects(f.workflow.stageFromVerifiedIngress(change(f.ingress())), rejectCode(expected));
  assert.equal(f.calls.length, 0); assert.equal(f.records.size, 1);
});
test('safe duplicate performs zero additional provider work', async () => {
  const f = fixture(); await f.workflow.stageFromVerifiedIngress(f.ingress());
  assert.deepEqual(await f.workflow.stageFromVerifiedIngress(f.ingress()), safeResult('unclaimed', true));
  assert.deepEqual(f.calls, ['exchange', 'profile']);
});
test('parallel ingress conditional winner dispatches exactly once', async () => {
  const f = fixture();
  const results = await Promise.allSettled([f.workflow.stageFromVerifiedIngress(f.ingress()), f.workflow.stageFromVerifiedIngress(f.ingress())]);
  assert.equal(results.filter(value => value.status === 'fulfilled').length, 1);
  assert.equal(results.filter(value => value.status === 'rejected')[0].reason.code, 'code_exchange_in_progress');
  assert.deepEqual(f.calls, ['exchange', 'profile']);
});
for (const failAt of ['exchange', 'profile']) test('post-dispatch failure at ' + failAt + ' marks code unknown and never retries', async () => {
  const f = fixture(); f.control.provider = kind => { if (kind === failAt) throw Error('private token detail'); };
  await assert.rejects(f.workflow.stageFromVerifiedIngress(f.ingress()), rejectCode('provider_outcome_unknown'));
  assert.equal(f.codeState(), 'OUTCOME_UNKNOWN');
  const count = f.calls.length;
  await assert.rejects(f.workflow.stageFromVerifiedIngress(f.ingress()), rejectCode('code_outcome_unknown'));
  assert.equal(f.calls.length, count);
});
test('durable body proof tamper after provider returns cannot commit', async () => {
  const f = fixture(); f.control.provider = kind => {
    if (kind === 'profile') [...f.records.values()].find(item => item.code_digest).body_digest.S = 'c'.repeat(64);
  };
  await assert.rejects(f.workflow.stageFromVerifiedIngress(f.ingress()), rejectCode('provider_outcome_unknown'));
  assert.equal(f.codeState(), 'OUTCOME_UNKNOWN'); assert.equal(f.state(), undefined);
});
test('commit lost return produces unknown, persisted safe duplicate still avoids exchange', async () => {
  const f = fixture(); f.control.afterWrite = label => { if (label === 'commit') throw Error('lost return'); };
  await assert.rejects(f.workflow.stageFromVerifiedIngress(f.ingress()), rejectCode('provider_outcome_unknown'));
  assert.equal(f.codeState(), 'UNCLAIMED');
  f.control.afterWrite = undefined;
  assert.deepEqual(await f.workflow.stageFromVerifiedIngress(f.ingress()), safeResult('unclaimed', true));
  assert.equal(f.calls.length, 2);
});
for (const [name, change, expected] of [
  ['short time', value => ({ ...value, query: { ...value.query, time: '12' } }), 'invalid_time'],
  ['future time', value => ({ ...value, query: { ...value.query, time: String(initialNow + 1) } }), 'expired_link'],
  ['expired time', value => ({ ...value, query: { ...value.query, time: String(initialNow - 600_001) } }), 'expired_link'],
  ['short nonce', value => ({ ...value, query: { ...value.query, nonce: 'bad' } }), 'invalid_nonce'],
  ['noncanonical nonce', value => ({ ...value, query: { ...value.query, nonce: 'A'.repeat(42) + 'B' } }), 'invalid_nonce'],
  ['forged identity field', value => ({ ...value, actorRef: 'forged' }), 'invalid_field'],
  ['extra query', value => ({ ...value, query: { ...value.query, accountId } }), 'invalid_field'],
  ['forged context', value => ({ ...value, context: {} }), 'identity_not_authorized']
]) test('passwordless link finite deny: ' + name, async () => {
  const f = fixture(); await f.workflow.stageFromVerifiedIngress(f.ingress());
  await assert.rejects(f.workflow.continuePasswordlessLink(change(f.link())), rejectCode(expected));
  assert.deepEqual(f.calls, ['exchange', 'profile']); assert.equal(f.state(), 'UNCLAIMED');
});
test('no matching HMAC reveals no account and dispatches nothing', async () => {
  const f = fixture(); await f.workflow.stageFromVerifiedIngress(f.ingress());
  const value = f.link(); value.query.nonce = 'A'.repeat(43);
  await assert.rejects(f.workflow.continuePasswordlessLink(value), rejectCode('link_not_found'));
  assert.equal(f.calls.length, 2);
});
test('two correctly encrypted matching accounts deny ambiguous link without reserve', async () => {
  const f = fixture(); await f.workflow.stageFromVerifiedIngress(f.ingress());
  const original = [...f.records.values()].find(item => item.link_id);
  const envelope = await f.ports.tokenEnvelope.seal({ accountId, accessToken: 'generated-access', refreshToken: 'generated-refresh', tokenExpiresAt: initialNow + 600_000 }, { linkId: 'generated-second', revision: 1 });
  const copy = structuredClone(original);
  copy.link_id.S = envelope.linkId;
  for (const [field, attr] of [['schemaVersion','schema_version'],['linkId','link_id'],['encryptedDataKey','encrypted_data_key'],['nonce','nonce'],['authTag','auth_tag'],['ciphertext','ciphertext']]) {
    copy.token_envelope.M[attr] = field === 'schemaVersion' ? { N: String(envelope[field]) } : { S: envelope[field] };
  }
  f.records.set('LINK#generated-second/STATE', copy);
  await assert.rejects(f.workflow.continuePasswordlessLink(f.link()), rejectCode('ambiguous_link'));
  assert.equal(f.calls.length, 2); assert.equal(f.events.includes('reserve'), false);
});
test('boolean identity lease denied and no caller tuple substitutes authority', async () => {
  const f = fixture(); await f.workflow.stageFromVerifiedIngress(f.ingress()); f.control.identityBoolean = true;
  await assert.rejects(f.workflow.continuePasswordlessLink(f.link()), rejectCode('identity_not_authorized'));
  assert.equal(f.calls.length, 2);
});
for (const field of ['actorRef','ownerRef','householdRef','scopeRefs','epoch','expiresAt','accountIdentifier']) {
  test('identity change before reserve denies exact lease: ' + field, async () => {
    const f = fixture(); await f.workflow.stageFromVerifiedIngress(f.ingress());
    f.control.identityRecheck = count => {
      if (count === 1) f.setIdentity({ [field]: field === 'scopeRefs' ? ['generated-other'] : field === 'epoch' ? 5 : field === 'expiresAt' ? initialNow + 400_000 : 'generated-other' });
    };
    await assert.rejects(f.workflow.continuePasswordlessLink(f.link()), rejectCode('identity_changed'));
    assert.equal(f.calls.length, 2); assert.equal(f.state(), 'UNCLAIMED');
  });
}
test('current account CAS revocation blocks reserve with no provider mutation', async () => {
  const f = fixture(); await f.workflow.stageFromVerifiedIngress(f.ingress());
  f.records.get('ACCOUNT#' + accountDigest + '/IDENTITY').revoked.BOOL = true;
  await assert.rejects(f.workflow.continuePasswordlessLink(f.link()), rejectCode('link_conflict'));
  assert.equal(f.calls.length, 2); assert.equal(f.state(), 'UNCLAIMED');
});
test('identity expires before reserve', async () => {
  const f = fixture(); await f.workflow.stageFromVerifiedIngress(f.ingress()); f.setIdentity({ expiresAt: initialNow });
  await assert.rejects(f.workflow.continuePasswordlessLink(f.link()), rejectCode('identity_expired'));
  assert.equal(f.calls.length, 2);
});
for (const phase of ['POST','PATCH']) test('lost provider return in ' + phase + ' is terminal unknown and no automatic retry', async () => {
  const f = fixture(); await f.workflow.stageFromVerifiedIngress(f.ingress());
  f.control.provider = kind => { if (kind === phase) throw Error('private-provider'); };
  await assert.rejects(f.workflow.continuePasswordlessLink(f.link()), rejectCode('provider_outcome_unknown'));
  assert.equal(f.state(), 'OUTCOME_UNKNOWN');
  assert.equal(f.calls.includes('PATCH'), phase === 'PATCH');
  const count = f.calls.length;
  await assert.rejects(f.workflow.continuePasswordlessLink(f.link()), rejectCode('link_not_found'));
  assert.equal(f.calls.length, count);
});
for (const kind of ['revoke','actor','expiry']) test('identity ' + kind + ' after POST blocks PATCH and completion', async () => {
  const f = fixture(); await f.workflow.stageFromVerifiedIngress(f.ingress());
  f.control.provider = phase => {
    if (phase === 'POST') {
      if (kind === 'revoke') f.control.identityAllowed = false;
      if (kind === 'actor') f.setIdentity({ actorRef: 'generated-other' });
      if (kind === 'expiry') f.setNow(initialNow + 300_000);
    }
  };
  await assert.rejects(f.workflow.continuePasswordlessLink(f.link()), rejectCode('provider_outcome_unknown'));
  assert.deepEqual(f.calls, ['exchange', 'profile', 'POST']);
  assert.notEqual(f.state(), 'COMPLETED');
});
test('identity changes after PATCH returns cannot publish completion', async () => {
  const f = fixture(); await f.workflow.stageFromVerifiedIngress(f.ingress());
  f.control.provider = phase => { if (phase === 'PATCH') f.setIdentity({ householdRef: 'generated-other' }); };
  await assert.rejects(f.workflow.continuePasswordlessLink(f.link()), rejectCode('provider_outcome_unknown'));
  assert.equal(f.state(), 'OUTCOME_UNKNOWN');
});
for (const label of ['reserve','phase','finish']) test('storage lost return at ' + label + ' is finite unknown and no retry', async () => {
  const f = fixture(); await f.workflow.stageFromVerifiedIngress(f.ingress());
  let lost = false;
  f.control.afterWrite = current => { if (current === label && !lost) { lost = true; throw Error('storage-lost-return'); } };
  await assert.rejects(f.workflow.continuePasswordlessLink(f.link()), rejectCode('provider_outcome_unknown'));
  assert.equal(f.state(), 'OUTCOME_UNKNOWN');
  const count = f.calls.length;
  await assert.rejects(f.workflow.continuePasswordlessLink(f.link()), rejectCode('link_not_found'));
  assert.equal(f.calls.length, count);
});
test('parallel passwordless claims have one CAS winner and one POST/PATCH pair', async () => {
  const f = fixture(); await f.workflow.stageFromVerifiedIngress(f.ingress());
  const outcomes = await Promise.allSettled([f.workflow.continuePasswordlessLink(f.link()), f.workflow.continuePasswordlessLink(f.link())]);
  assert.equal(outcomes.filter(value => value.status === 'fulfilled').length, 1);
  assert.equal(outcomes.find(value => value.status === 'rejected').reason.code, 'link_conflict');
  assert.deepEqual(f.calls, ['exchange', 'profile', 'POST', 'PATCH']);
  assert.equal(f.state(), 'COMPLETED');
});
test('unknown port errors cannot leak their message or fields', async () => {
  const f = fixture();
  let getterCalls = 0;
  const broken = createRingWorkflow({ ...f.ports, secretLoader: {
    loadProvider: async () => {
      throw Object.defineProperty(Error('generated-access ' + accountId), 'code', {
        get() { getterCalls += 1; throw Error('private getter detail'); }
      });
    },
    loadDigest: f.ports.secretLoader.loadDigest
  } });
  await assert.rejects(broken.stageFromVerifiedIngress(f.ingress()), rejectCode('workflow_unavailable'));
  assert.equal(f.calls.length, 0);
  assert.equal(getterCalls, 0);
});
test('sealed persistent data excludes raw account/code/tokens and finite output excludes identity', async () => {
  const f = fixture(); const output = await f.workflow.stageFromVerifiedIngress(f.ingress());
  const serialized = JSON.stringify([...f.records.values()]);
  for (const privateValue of [accountId, 'generated-access', 'generated-refresh', 'generated-code']) assert.equal(serialized.includes(privateValue), false);
  for (const privateValue of [accountId, 'generated-owner', 'generated-intake', 'generated-access']) assert.equal(JSON.stringify(output).includes(privateValue), false);
  assert.equal(output.productionAdmitted, false);
});
test('unconfigured webhook remains unavailable on accepted G4-A store', async () => {
  const f = fixture();
  await assert.rejects(f.workflow.receiveSignedWebhook({ rawBody: Buffer.from('{}'), signature: 'unknown' }), rejectCode('webhook_not_configured'));
});
test('legacy Memory store skip/state checks remain intact and AWS legacy store stays blocked', async () => {
  const store = new MemoryRingStore({ clock: () => initialNow });
  const id = await store.putUnclaimed({ accountId, accessToken: 'generated-access', refreshToken: 'generated-refresh', expiresAt: initialNow + 60_000 });
  await store.reserveClaim(id, 'generated-owner', initialNow);
  await assert.rejects(store.advanceClaim(id, 'generated-owner', 'reserved', 'completed'), /claim_conflict/);
  await assert.rejects(store.advanceClaim(id, 'wrong-owner', 'reserved', 'awaiting'), /claim_conflict/);
  assert.deepEqual(await store.advanceClaim(id, 'generated-owner', 'reserved', 'awaiting'), { id, status: 'awaiting' });
  assert.deepEqual(await store.advanceClaim(id, 'generated-owner', 'awaiting', 'completed'), { id, status: 'completed' });
  const blocked = new AwsRingStoreBlocked();
  await assert.rejects(blocked.putUnclaimed({}), /aws_store_not_ready/);
  await assert.rejects(blocked.acceptWebhook(), /aws_store_not_ready/);
});

// ---- owner-bootstrap support: shared matchUnclaimed and the ring-account digest label ----
test('digest label regression: stored account digest uses the ring-account label shared with the identity digest', async () => {
  const f = fixture(); await f.workflow.stageFromVerifiedIngress(f.ingress());
  const stored = [...f.records.values()].find(item => item.link_id).account_digest.S;
  const labelled = label => createHmac('sha256', recordKey).update(`${label}\0${accountId}`).digest('hex');
  assert.equal(stored, labelled('ring-account'));
  assert.notEqual(stored, labelled('account'));
});
test('matchUnclaimed returns exactly the unclaimed link /ring/link would claim and writes nothing', async () => {
  const f = fixture(); await f.workflow.stageFromVerifiedIngress(f.ingress());
  const before = JSON.stringify([...f.records.entries()]);
  const calls = f.calls.length;
  const match = await f.workflow.matchUnclaimed(f.link().query);
  assert.equal(match.at, Number(f.link().query.time));
  assert.equal(match.candidate.status, 'UNCLAIMED');
  assert.equal(match.candidate.accountDigest, accountDigest);
  assert.equal(match.payload.accountId, accountId);
  assert.equal(Object.isFrozen(match), true);
  assert.equal(JSON.stringify([...f.records.entries()]), before);
  assert.equal(f.calls.length, calls);
  assert.equal(f.events.some(event => ['reserve', 'phase', 'finish', 'unknown'].includes(event)), false);
  assert.deepEqual(await f.workflow.continuePasswordlessLink(f.link()), safeResult('completed'));
});
test('matchUnclaimed and /ring/link share one decision: zero, two, expired and malformed inputs behave identically', async () => {
  const f = fixture(); await f.workflow.stageFromVerifiedIngress(f.ingress());
  const bad = { time: f.link().query.time, nonce: 'A'.repeat(43) };
  await assert.rejects(f.workflow.matchUnclaimed(bad), rejectCode('link_not_found'));
  await assert.rejects(f.workflow.continuePasswordlessLink({ query: bad, context: f.context }), rejectCode('link_not_found'));
  const old = String(initialNow - 600_001);
  await assert.rejects(f.workflow.matchUnclaimed({ time: old, nonce: computeNonce(old, accountId, nonceKey) }), rejectCode('expired_link'));
  await assert.rejects(f.workflow.matchUnclaimed({ time: 'x', nonce: bad.nonce }), rejectCode('invalid_time'));
  await assert.rejects(f.workflow.matchUnclaimed({ time: bad.time, nonce: 'short' }), rejectCode('invalid_nonce'));
  await assert.rejects(f.workflow.matchUnclaimed({ time: bad.time, nonce: bad.nonce, extra: 1 }), rejectCode('invalid_field'));
  // Two correctly encrypted matching links: ambiguous for both entry points, nothing reserved.
  const original = [...f.records.values()].find(item => item.link_id);
  const envelope = await f.ports.tokenEnvelope.seal({ accountId, accessToken: 'generated-access', refreshToken: 'generated-refresh', tokenExpiresAt: initialNow + 600_000 }, { linkId: 'generated-second', revision: 1 });
  const copy = structuredClone(original);
  copy.link_id.S = envelope.linkId;
  for (const [field, attr] of [['schemaVersion','schema_version'],['linkId','link_id'],['encryptedDataKey','encrypted_data_key'],['nonce','nonce'],['authTag','auth_tag'],['ciphertext','ciphertext']]) {
    copy.token_envelope.M[attr] = field === 'schemaVersion' ? { N: String(envelope[field]) } : { S: envelope[field] };
  }
  f.records.set('LINK#generated-second/STATE', copy);
  await assert.rejects(f.workflow.matchUnclaimed(f.link().query), rejectCode('ambiguous_link'));
  await assert.rejects(f.workflow.continuePasswordlessLink(f.link()), rejectCode('ambiguous_link'));
  assert.equal(f.events.includes('reserve'), false);
});
test('matchUnclaimed errors are finite protocol errors that never expose tokens or ids', async () => {
  const f = fixture(); await f.workflow.stageFromVerifiedIngress(f.ingress());
  const workflow = createRingWorkflow({ ...f.ports, tokenEnvelope: { seal: f.ports.tokenEnvelope.seal, open: async () => { throw Error('generated-access ' + accountId); } } });
  await assert.rejects(workflow.matchUnclaimed(f.link().query), error => error instanceof ProtocolError &&
    !JSON.stringify([error.message, error.code]).includes('generated-access') && !error.message.includes(accountId));
});
