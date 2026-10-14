import test from 'node:test';
import assert from 'node:assert/strict';
import { createIdentityEnvelope } from '../identity-envelope.mjs';
import { createDynamoIdentityAuthorityStore } from '../dynamo-identity-authority-store.mjs';

const nowMs = Date.parse('2026-10-07T00:00:00Z');
const now = Math.floor(nowMs / 1000);
const d = char => char.repeat(64);
const env = Object.freeze({ version: 1, purpose: 'RING_ACCOUNT_IDENTITY', keyId: 'kms/generated',
  encryptedDataKey: Buffer.from('wrapped-generated').toString('base64url'), nonce: Buffer.alloc(12, 1).toString('base64url'),
  authTag: Buffer.alloc(16, 2).toString('base64url'), ciphertext: Buffer.from('generated-encrypted').toString('base64url') });
const enrollment = { PK: { S: `ENROLL#${d('a')}` }, SK: { S: 'STATE' }, status: { S: 'ISSUED' },
  bot_digest: { S: d('b') }, bot_generation: { N: '2' }, expires_at: { N: String(now + 300) } };

function fixture(overrides = {}) {
  const calls = [];
  let time = nowMs;
  const items = new Map();
  const owner = { PK: { S: 'OWNER#CURRENT' }, SK: { S: 'META' }, status: { S: 'ACTIVE' },
    owner_ref: { S: 'owner/generated' }, actor_ref: { S: 'actor/generated' },
    household_ref: { S: 'household/generated' }, owner_epoch: { N: '4' } };
  const grant = { PK: { S: 'OWNER#owner/generated' }, SK: { S: `GRANT#${d('c')}` },
    grant_id: { S: 'grant/generated' }, grant_digest: { S: d('c') }, grant_generation: { N: '6' },
    owner_epoch: { N: '4' }, scope_refs: { L: [{ S: 'ring/read' }, { S: 'ring/link' }] },
    expires_at: { N: String(now + 600) }, revoked: { BOOL: false } };
  const session = { PK: { S: `SESSION#${d('d')}` }, SK: { S: 'META' }, session_id: { S: 'session/generated' },
    session_generation: { N: '5' }, csrf_digest: { S: d('e') }, owner_ref: { S: 'owner/generated' },
    owner_epoch: { N: '4' }, grant_id: { S: 'grant/generated' }, grant_digest: { S: d('c') },
    grant_generation: { N: '6' }, account_digest: { S: d('f') }, account_generation: { N: '3' },
    projection_revision: { N: '2' }, session_expires_at: { N: String(now + 500) },
    idle_expires_at: { N: String(now + 400) }, trust_expires_at: { N: String(now + 700) },
    production_admitted: { BOOL: true }, revoked: { BOOL: false } };
  const account = { PK: { S: `ACCOUNT#${d('f')}` }, SK: { S: 'IDENTITY' }, account_digest: { S: d('f') },
    owner_ref: { S: 'owner/generated' }, owner_epoch: { N: '4' }, account_generation: { N: '3' },
    projection_revision: { N: '2' }, account_identifier_envelope: { M: { version: { N: '1' },
      purpose: { S: env.purpose }, key_id: { S: env.keyId }, encrypted_data_key: { S: env.encryptedDataKey },
      nonce: { S: env.nonce }, auth_tag: { S: env.authTag }, ciphertext: { S: env.ciphertext } } },
    expires_at: { N: String(now + 550) }, revoked: { BOOL: false } };
  for (const item of [owner, grant, session, account]) items.set(`${item.PK.S}|${item.SK.S}`, item);
  const store = createDynamoIdentityAuthorityStore({
    tableName: 'GeneratedRingPrivateLinkTable',
    clock: () => time,
    getItem: async input => { calls.push({ kind: 'get', input }); return { Item: items.get(`${input.Key.PK.S}|${input.Key.SK.S}`) }; },
    transactWrite: async input => { calls.push({ kind: 'write', input }); return {}; },
    ...overrides
  });
  return { store, calls, items, setTime: value => { time = value; } };
}

test('enrollment is exact, single-table and contains no raw Telegram identifiers', async () => {
  const f = fixture();
  assert.deepEqual(await f.store.createEnrollment({ nonceDigest: d('a'), botDigest: d('b'), botGeneration: 2,
    enrollmentId: 'enroll/generated', expiresAt: now + 300 }), { enrollmentId: 'enroll/generated', expiresAt: now + 300 });
  const request = f.calls[0].input;
  assert.equal(request.TransactItems[0].Put.Item.PK.S, `ENROLL#${d('a')}`);
  assert.equal(request.TransactItems[0].Put.Item.SK.S, 'STATE');
  assert.equal(JSON.stringify(request).includes('chatId'), false);
  assert.equal(JSON.stringify(request).includes('bot-token'), false);
  assert.equal(JSON.stringify(request).includes('Scan'), false);
});

test('owner admission strongly reads enrollment and atomically consumes nonce, replay and sole owner', async () => {
  const f = fixture({ getItem: async input => { f?.calls?.push?.({ kind: 'get', input }); return { Item: enrollment }; } });
  const result = await f.store.admitOwner({ nonceDigest: d('a'), updateDigest: d('1'), botDigest: d('b'), botGeneration: 2,
    actorDigest: d('2'), chatDigest: d('3'), actorRef: 'actor/generated', ownerRef: 'owner/generated', householdRef: 'household/generated' });
  assert.deepEqual(result, { actorRef: 'actor/generated', ownerRef: 'owner/generated', householdRef: 'household/generated', ownerEpoch: 1 });
  const read = f.calls.find(call => call.kind === 'get').input;
  assert.equal(read.ConsistentRead, true);
  const tx = f.calls.find(call => call.kind === 'write').input.TransactItems;
  assert.deepEqual(tx.map(entry => (entry.Update ?? entry.Put).Key?.PK?.S ?? entry.Put.Item.PK.S),
    [`ENROLL#${d('a')}`, `TGUPDATE#${d('1')}`, 'OWNER#CURRENT']);
  assert.match(tx[0].Update.ConditionExpression, /bot_generation = :botGeneration/);
  assert.equal(JSON.stringify(tx).includes('10001'), false);
});

test('wrong bot generation and replay conflict fail closed with finite errors', async () => {
  const wrong = fixture({ getItem: async () => ({ Item: enrollment }) });
  await assert.rejects(wrong.store.admitOwner({ nonceDigest: d('a'), updateDigest: d('1'), botDigest: d('b'), botGeneration: 3,
    actorDigest: d('2'), chatDigest: d('3'), actorRef: 'actor/generated', ownerRef: 'owner/generated', householdRef: 'household/generated' }),
    error => error.code === 'AUTHORITY_ENROLLMENT_DENIED');
  const conflict = fixture({ getItem: async () => ({ Item: enrollment }), transactWrite: async () => {
    throw Object.assign(Error('raw-private'), { name: 'TransactionCanceledException' });
  } });
  await assert.rejects(conflict.store.admitOwner({ nonceDigest: d('a'), updateDigest: d('1'), botDigest: d('b'), botGeneration: 2,
    actorDigest: d('2'), chatDigest: d('3'), actorRef: 'actor/generated', ownerRef: 'owner/generated', householdRef: 'household/generated' }),
    error => error.code === 'AUTHORITY_CONFLICT' && !error.message.includes('raw-private'));
});

test('session/grant and account projection use pinned conditional transaction shapes', async () => {
  const f = fixture();
  await f.store.issueSession({ ownerRef: 'owner/generated', ownerEpoch: 4, grantId: 'grant/generated', grantDigest: d('c'),
    grantGeneration: 6, scopeRefs: ['ring/read', 'ring/link'], sessionId: 'session/generated', sessionDigest: d('d'),
    csrfDigest: d('e'), sessionGeneration: 5, sessionExpiresAt: now + 500, idleExpiresAt: now + 400, trustExpiresAt: now + 600 });
  await f.store.projectAccount({ sessionDigest: d('d'), ownerRef: 'owner/generated', ownerEpoch: 4, grantDigest: d('c'),
    grantGeneration: 6, accountDigest: d('f'), accountGeneration: 3, accountIdentifierEnvelope: env, expiresAt: now + 550 });
  const [sessionTx, projectionTx] = f.calls.filter(call => call.kind === 'write').map(call => call.input.TransactItems);
  assert.equal(sessionTx.length, 3);
  assert.equal(projectionTx.length, 4);
  assert.equal(projectionTx[3].Put.Item.PK.S, `ACCOUNT#${d('f')}`);
  assert.match(projectionTx[2].Update.ConditionExpression, /attribute_not_exists\(account_digest\)/);
  assert.equal(JSON.stringify(projectionTx).includes('ring-account-generated'), false);
});

test('authority load uses strong reads and pins every generation and expiry ceiling', async () => {
  const f = fixture();
  const result = await f.store.loadSessionAuthority({ sessionDigest: d('d'), csrfDigest: d('e') });
  assert.equal(result.productionAdmitted, true);
  assert.equal(result.ownerEpoch, 4);
  assert.equal(result.sessionGeneration, 5);
  assert.equal(result.grantGeneration, 6);
  assert.equal(result.accountGeneration, 3);
  assert.equal(result.projectionRevision, 2);
  assert.equal(result.serverNow, nowMs);
  assert.equal(result.trustExpiresAt, (now + 550) * 1000);
  assert.equal(f.calls.filter(call => call.kind === 'get').length, 4);
  assert.equal(f.calls.filter(call => call.kind === 'get').every(call => call.input.ConsistentRead === true), true);
});

test('generation drift, clock rollback and ambiguous result fail closed', async () => {
  const drift = fixture();
  drift.items.get(`ACCOUNT#${d('f')}|IDENTITY`).account_generation.N = '4';
  await assert.rejects(drift.store.loadSessionAuthority({ sessionDigest: d('d'), csrfDigest: d('e') }),
    error => error.code === 'AUTHORITY_SESSION_CHANGED');
  const rollback = fixture();
  await rollback.store.loadSessionAuthority({ sessionDigest: d('d'), csrfDigest: d('e') });
  rollback.setTime(nowMs - 1000);
  await assert.rejects(rollback.store.loadSessionAuthority({ sessionDigest: d('d'), csrfDigest: d('e') }),
    error => error.code === 'AUTHORITY_CLOCK_ROLLBACK');
  const ambiguous = fixture({ transactWrite: async () => { throw Error('secret raw'); } });
  await assert.rejects(ambiguous.store.createEnrollment({ nonceDigest: d('a'), botDigest: d('b'), botGeneration: 2,
    enrollmentId: 'enroll/generated', expiresAt: now + 300 }),
    error => error.code === 'AUTHORITY_OUTCOME_UNKNOWN' && !error.message.includes('secret raw'));
});

test('hostile proxy and accessor transaction errors stay outcome unknown without trap execution', async () => {
  let traps = 0;
  const proxyMarker = 'private-proxy-marker';
  const hostileProxy = new Proxy({}, {
    get() { traps += 1; throw Error(proxyMarker); },
    getPrototypeOf() { traps += 1; throw Error(proxyMarker); },
    ownKeys() { traps += 1; throw Error(proxyMarker); }
  });
  const proxyStore = fixture({ transactWrite: async () => { throw hostileProxy; } });
  await assert.rejects(proxyStore.store.createEnrollment({ nonceDigest: d('a'), botDigest: d('b'), botGeneration: 2,
    enrollmentId: 'enroll/generated', expiresAt: now + 300 }), error =>
    error.code === 'AUTHORITY_OUTCOME_UNKNOWN' && error.message === 'AUTHORITY_OUTCOME_UNKNOWN' &&
    !error.message.includes(proxyMarker));
  assert.equal(traps, 0);

  const accessorMarker = 'private-accessor-marker';
  const hostileAccessor = {};
  Object.defineProperty(hostileAccessor, 'name', { enumerable: true, get() { traps += 1; throw Error(accessorMarker); } });
  Object.defineProperty(hostileAccessor, 'code', { enumerable: true, get() { traps += 1; throw Error(accessorMarker); } });
  const accessorStore = fixture({ transactWrite: async () => { throw hostileAccessor; } });
  await assert.rejects(accessorStore.store.createEnrollment({ nonceDigest: d('a'), botDigest: d('b'), botGeneration: 2,
    enrollmentId: 'enroll/generated', expiresAt: now + 300 }), error =>
    error.code === 'AUTHORITY_OUTCOME_UNKNOWN' && error.message === 'AUTHORITY_OUTCOME_UNKNOWN' &&
    !error.message.includes(accessorMarker));
  assert.equal(traps, 0);
});


test('KMS ARN producer envelope survives authority read while malformed ARNs and mismatched key pins fail closed', async () => {
  const keyId = 'arn:aws:kms:ap-northeast-1:000000000000:key/12345678-1234-1234-1234-123456789abc';
  const binding = { accountDigest: d('f'), ownerRef: 'owner/generated', ownerEpoch: 4, accountGeneration: 3 };
  let decryptCalls = 0;
  const cryptoEnvelope = createIdentityEnvelope({ keyId, application: 'ring-private', tableName: 'GeneratedRingPrivateLinkTable',
    random: size => Buffer.alloc(size, 3),
    async generateDataKey(input) { assert.equal(input.KeyId, keyId); return { Plaintext: Buffer.alloc(32, 7), CiphertextBlob: Buffer.from('synthetic-wrapped-key') }; },
    async decryptDataKey(input) { decryptCalls++; assert.equal(input.KeyId, keyId); return { Plaintext: Buffer.alloc(32, 7) }; } });
  const sealed = await cryptoEnvelope.seal('synthetic-ring-account', binding);
  const f = fixture();
  const projection = { sessionDigest: d('d'), ownerRef: binding.ownerRef, ownerEpoch: binding.ownerEpoch, grantDigest: d('c'),
    grantGeneration: 6, accountDigest: binding.accountDigest, accountGeneration: binding.accountGeneration, accountIdentifierEnvelope: sealed, expiresAt: now + 550 };
  await f.store.projectAccount(projection);
  const stored = f.calls.find(call => call.kind === 'write').input.TransactItems[3].Put.Item;
  f.items.get(`ACCOUNT#${d('f')}|IDENTITY`).account_identifier_envelope = stored.account_identifier_envelope;
  const loaded = await f.store.loadSessionAuthority({ sessionDigest: d('d'), csrfDigest: d('e') });
  assert.equal(loaded.accountIdentifierEnvelope.keyId, keyId);
  assert.equal(await cryptoEnvelope.open(loaded.accountIdentifierEnvelope, binding), 'synthetic-ring-account');
  assert.equal(decryptCalls, 1);
  const otherKey = keyId.replace('123456789abc', '123456789abd');
  await assert.rejects(cryptoEnvelope.open({ ...loaded.accountIdentifierEnvelope, keyId: otherKey }, binding),
    error => error.code === 'IDENTITY_ENVELOPE_INVALID');
  assert.equal(decryptCalls, 1, 'configured key mismatch rejected before KMS decrypt');
  const malformed = [keyId + '/extra', keyId + '?override=1', keyId.replace(':kms:', ':s3:'),
    keyId.replace('000000000000', '00000000000'), keyId.replace(':key/', ':alias/'),
    keyId.replace('123456789abc', '123456789abz'), keyId.replace('arn:aws:', 'arn:aws-cn:'),
    keyId.replace('ap-northeast-1', 'cn-north-1'), keyId + '\n'];
  for (const bad of malformed) {
    const count = f.calls.filter(call => call.kind === 'write').length;
    await assert.rejects(f.store.projectAccount({ ...projection, accountIdentifierEnvelope: { ...sealed, keyId: bad } }),
      error => error.code === 'AUTHORITY_INPUT_DENIED');
    assert.equal(f.calls.filter(call => call.kind === 'write').length, count);
    f.items.get(`ACCOUNT#${d('f')}|IDENTITY`).account_identifier_envelope.M.key_id.S = bad;
    await assert.rejects(f.store.loadSessionAuthority({ sessionDigest: d('d'), csrfDigest: d('e') }),
      error => error.code === 'AUTHORITY_INPUT_DENIED');
  }
  for (const accepted of ['alias/generated', env.keyId,
    'arn:aws:kms:ap-northeast-1:000000000000:key/mrk-' + 'a'.repeat(32),
    keyId.replace('arn:aws:', 'arn:aws-cn:').replace('ap-northeast-1', 'cn-north-1'),
    keyId.replace('arn:aws:', 'arn:aws-us-gov:').replace('ap-northeast-1', 'us-gov-west-1')]) {
    await f.store.projectAccount({ ...projection, accountIdentifierEnvelope: { ...sealed, keyId: accepted } });
  }
  await assert.rejects(f.store.projectAccount({ ...projection, ownerRef: keyId }), error => error.code === 'AUTHORITY_INPUT_DENIED');
});
