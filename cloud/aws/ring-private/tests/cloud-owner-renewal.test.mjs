// Owner renewal through the same POST /owner/bootstrap service (approval schema 'ring-owner-renewal-approval-v1').
// Everything synthetic: in-memory DynamoDB, fake Ring client, no network, no AWS.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { createCloudOwnerBootstrap, ownerRenewalLatchKey, OWNER_RENEWAL_APPROVAL_SCHEMA, OWNER_BOOTSTRAP_MAX_FAILURES } from '../cloud-owner-bootstrap.mjs';
import { createCloudOwnerAssociationReader } from '../cloud-owner-association.mjs';
import { createMacCommandProofAuthority, macEnrollmentKey } from '../mac-command-proof-authority.mjs';
import { createMacCommandProofSigner, MAC_PROOF_HEADER } from '../../../../src/formal-runtime/mac-command-proof.mjs';
import { memoryDynamo, AUDIENCE } from './mac-command-proof-fixture.mjs';
import { NOW, ISS, RESOURCE, SCOPES, PROFILE, SUB, ACCOUNT_ID, ACCESS_TOKEN, sha256, digest, identityEnvelope, sealed,
  createAuth, createFakeTable, approvalFixture } from './owner-bootstrap-fixture.mjs';

const RENEW_TOKEN = 'ring-access-token-RENEW-SECRET';
const HOUR = 3600000;
const ringFake = impl => { const ring = { calls: [], async getAccountId(token) { ring.calls.push(token); return impl ? impl(token) : ACCOUNT_ID; } }; return ring; };
const service = ({ table, bytes, pinned, ring = ringFake(), clock = () => NOW }) => createCloudOwnerBootstrap({ getItem: table.getItem, transactWrite: table.transactWrite,
  tableName: 'ring-test-link', digest, identityEnvelope, profile: PROFILE, approvalSha256: pinned ?? sha256(bytes), clock, ringTokenClient: ring, loadApproval: async () => bytes });

// Live-like state: an owner created by the real bootstrap path (approval window NOW-60s..NOW+1h, association expiry NOW+2h).
async function bootstrapped() {
  const table = createFakeTable();
  const boot = approvalFixture();
  const auth = createAuth();
  const login = await auth.login();
  const out = await service({ table, bytes: boot.bytes }).ensureWithRingToken({ ...login, ringAccessToken: ACCESS_TOKEN });
  assert.equal(out.bootstrapped, true);
  const subjectDigest = await digest('oauth-subject', `${ISS}\0${SUB}`);
  const accountDigest = await digest('ring-account', ACCOUNT_ID);
  table.transactions.length = 0; table.getCalls.length = 0;
  return { table, auth, boot, subjectDigest, accountDigest,
    association: () => table.get(`OAUTH#${subjectDigest}`, 'RING_ASSOCIATION'), account: () => table.get(`ACCOUNT#${accountDigest}`, 'IDENTITY') };
}
function renewalDoc(bootSha, overrides = {}) {
  return { schema: OWNER_RENEWAL_APPROVAL_SCHEMA, mode: 'renew', issuer: ISS, resource: RESOURCE, cognitoSub: SUB, ringAccountIdSha256: sha256(ACCOUNT_ID),
    bootstrapApprovalSha256: bootSha, ownerRef: 'owner/fixture', ownerEpoch: 1, associationRevision: 1, accountGeneration: 1,
    ringScopeRefs: ['ring.read', 'ring.link'], scopes: [...SCOPES], issuedAt: NOW - 60000, notAfter: NOW + HOUR, expiresAt: NOW + 20 * HOUR, ...overrides };
}
const bytesOf = doc => Buffer.from(JSON.stringify(doc));
// Simulate that the association/account rows already passed their expiry (DynamoDB TTL has not deleted them yet).
function expire(s, at = NOW - HOUR) {
  for (const row of [s.association(), s.account()]) row.expires_at = { N: String(Math.floor(at / 1000)) };
}
const snapshot = table => JSON.stringify([...table.items.entries()].filter(([k]) => !k.startsWith('OWNER_BOOTSTRAP_ATTEMPTS#')).sort());
async function renewWith(s, { doc, bytes, pinned, ring = ringFake(), token = RENEW_TOKEN, login, clock } = {}) {
  const b = bytes ?? bytesOf(doc ?? renewalDoc(s.boot.sha));
  const svc = service({ table: s.table, bytes: b, pinned, ring, clock });
  const l = login ?? await s.auth.login();
  return { ring, sha: sha256(b), promise: svc.ensureWithRingToken({ ...l, ringAccessToken: token }) };
}
// Every denial below: nothing but (at most) the failure counter changes.
async function assertRenewDenied(s, run, code, { ringCalls = 0, counted = 0 } = {}) {
  const before = snapshot(s.table);
  const { promise, ring, sha } = await run;
  await assert.rejects(promise, error => error instanceof TypeError && error.message === code, code);
  assert.equal(snapshot(s.table), before, 'a denied renewal must not change any owner/association/account/latch/marker row');
  assert.equal(ring.calls.length, ringCalls, 'Ring calls');
  const row = s.table.get(`OWNER_BOOTSTRAP_ATTEMPTS#${sha}`, 'META');
  if (counted) assert.equal(row?.failures.N, String(counted)); else assert.equal(row, undefined, 'not counted');
  // write_denied = the conditional transaction was attempted and rejected as a whole (the snapshot above proves nothing changed)
  if (code !== 'owner_renewal_write_denied') assert.ok(s.table.transactions.every(tx => tx.every(op => op.Update?.Key.PK.S.startsWith('OWNER_BOOTSTRAP_ATTEMPTS#'))), 'only counter updates were attempted');
}
// Real DynamoDB rejects unused ExpressionAttributeValues/Names; the in-memory fixture does not, so check it here.
function assertNoUnusedPlaceholders(tx) {
  for (const op of tx) {
    const body = op.Put ?? op.Update ?? op.ConditionCheck;
    const text = `${body.ConditionExpression ?? ''} ${body.UpdateExpression ?? ''}`;
    const used = new Set(text.match(/:\w+/gu) ?? []);
    assert.deepEqual(Object.keys(body.ExpressionAttributeValues ?? {}).sort(), [...used].sort());
    assert.deepEqual(Object.keys(body.ExpressionAttributeNames ?? {}).sort(), [...new Set(text.match(/#\w+/gu) ?? [])].sort());
  }
}
const reader = table => createCloudOwnerAssociationReader({ getItem: table.getItem, transactGet: table.transactGet, tableName: 'ring-test-link', digest, profile: PROFILE, clock: () => NOW });

// ---------------- positive ----------------

test('positive after expiry: only expires_at moves; owner/subject/account/revision/epoch/generation/envelope unchanged; reader accepts again', async () => {
  const s = await bootstrapped();
  expire(s);
  await assert.rejects(reader(s.table).readForSubject(SUB), /cloud_owner_association_expired/u);
  const owner0 = structuredClone(s.table.get('OWNER#CURRENT', 'META')), assoc0 = structuredClone(s.association()), account0 = structuredClone(s.account());
  const { promise, ring, sha } = await renewWith(s);
  assert.deepEqual({ ...await promise }, { renewed: true, associationRevision: 1 });
  assert.deepEqual(ring.calls, [RENEW_TOKEN]);
  assert.equal(s.table.writeCount(), 1);
  const tx = s.table.transactions[0];
  assert.deepEqual(tx.map(op => Object.keys(op)[0]), ['ConditionCheck', 'ConditionCheck', 'Update', 'Update', 'Put', 'Put']);
  assertNoUnusedPlaceholders(tx);
  assert.match(tx[2].Update.ConditionExpression, /revision = :revision AND .*expires_at = :previous/u);
  const expires = String(Math.floor((NOW + 20 * HOUR) / 1000));
  assert.deepEqual(s.table.get('OWNER#CURRENT', 'META'), owner0, 'owner row is never written');
  assert.deepEqual(s.association(), { ...assoc0, expires_at: { N: expires }, approval_evidence_sha256: { S: sha } });
  assert.deepEqual(s.account(), { ...account0, expires_at: { N: expires } });
  const latch = s.table.get(`OWNER_RENEWAL#${sha}`, 'META');
  assert.equal(latch.expires_at, undefined, 'latch has no TTL attribute');
  assert.equal(latch.bootstrap_approval_sha256.S, s.boot.sha);
  assert.deepEqual([latch.owner_epoch.N, latch.association_revision.N, latch.account_generation.N], ['1', '1', '1']);
  assert.deepEqual(latch.ring_scope_refs, { L: [{ S: 'ring.read' }, { S: 'ring.link' }] });
  assert.deepEqual(tx[2].Update.ExpressionAttributeNames, { '#schema': 'schema', '#issuer': 'issuer', '#resource': 'resource' }); assert.equal(latch.association_action.S, 'extended'); assert.equal(latch.account_action.S, 'extended');
  assert.ok(s.table.get(`RING_TOKEN#${sha256(RENEW_TOKEN)}`, 'META'));
  assert.ok(s.table.get(`OWNER_BOOTSTRAP#${s.boot.sha}`, 'META'), 'bootstrap latch untouched');
  assert.equal(s.table.get(`OWNER_BOOTSTRAP_ATTEMPTS#${sha}`, 'META'), undefined);
  const record = await reader(s.table).readForSubject(SUB);
  assert.equal(record.revision, 1); assert.equal(record.ownerRef, 'owner/fixture'); assert.equal(record.expiresAt, Number(expires) * 1000);
  const lease = await reader(s.table).authorize(await s.auth.login());
  assert.equal(lease.associationRevision, 1);
  assert.equal(JSON.stringify([...s.table.items.values()]).includes(RENEW_TOKEN), false);
  assert.deepEqual(ownerRenewalLatchKey(sha), { PK: { S: `OWNER_RENEWAL#${sha}` }, SK: { S: 'META' } });
});

test('positive before expiry: an unexpired association is extended to the later approval expiry', async () => {
  const s = await bootstrapped();
  assert.equal(s.association().expires_at.N, String(Math.floor((NOW + 2 * HOUR) / 1000)));
  const { promise } = await renewWith(s);
  assert.equal((await promise).renewed, true);
  assert.equal(s.association().expires_at.N, String(Math.floor((NOW + 20 * HOUR) / 1000)));
  assert.equal(s.account().expires_at.N, s.association().expires_at.N);
  assert.equal((await reader(s.table).readForSubject(SUB)).revision, 1);
});

test('positive after TTL deletion: missing rows are re-created byte-identically (same revision/epoch/generation, attribute_not_exists), anchored to the bootstrap latch', async () => {
  for (const removed of [['association', 'account'], ['account'], ['association']]) {
    const s = await bootstrapped();
    expire(s);
    const assoc0 = structuredClone(s.association()), account0 = structuredClone(s.account());
    if (removed.includes('association')) s.table.items.delete(`OAUTH#${s.subjectDigest}\u0000RING_ASSOCIATION`);
    if (removed.includes('account')) s.table.items.delete(`ACCOUNT#${s.accountDigest}\u0000IDENTITY`);
    const seals = identityEnvelope.calls.length;
    const { promise, sha } = await renewWith(s);
    assert.equal((await promise).renewed, true, removed.join('+'));
    const tx = s.table.transactions[0];
    assertNoUnusedPlaceholders(tx);
    assert.equal(identityEnvelope.calls.length, seals + 1);
    assert.deepEqual(identityEnvelope.calls.at(-1).binding, { accountDigest: s.accountDigest, ownerRef: 'owner/fixture', ownerEpoch: 1, accountGeneration: 1 });
    const expires = String(Math.floor((NOW + 20 * HOUR) / 1000));
    const expectAssoc = { ...assoc0, expires_at: { N: expires }, approval_evidence_sha256: { S: sha } };
    assert.deepEqual(s.association(), expectAssoc, 'association: same fields as bootstrap wrote, new expiry/evidence');
    assert.deepEqual(s.account(), { ...account0, expires_at: { N: expires }, ...(removed.includes('account') ? { account_identifier_envelope: account0.account_identifier_envelope } : {}) });
    if (removed.includes('association')) assert.equal(tx[2].Put.ConditionExpression, 'attribute_not_exists(PK)'); else assert.ok(tx[2].Update);
    if (removed.includes('account')) assert.equal(tx[3].Put.ConditionExpression, 'attribute_not_exists(PK)'); else assert.ok(tx[3].Update);
    const latch = s.table.get(`OWNER_RENEWAL#${sha}`, 'META');
    assert.equal(latch.association_action.S, removed.includes('association') ? 'recreated' : 'extended');
    assert.equal((await reader(s.table).readForSubject(SUB)).revision, 1);
    void sealed;
  }
});

test('Mac enrollment proof still verifies after renewal (associationRevision unchanged); a bumped revision would have broken it', async () => {
  const s = await bootstrapped();
  expire(s);
  assert.equal((await (await renewWith(s)).promise).renewed, true);
  const lease = await reader(s.table).authorize(await s.auth.login());
  const db = memoryDynamo();
  const signer = createMacCommandProofSigner({ privateKey: generateKeyPairSync('ed25519').privateKey, ownerRef: 'owner/fixture', associationRevision: 1, audience: AUDIENCE, clock: () => NOW });
  // The live Mac enrollment row: revision 2 (re-keyed), bound to owner/fixture + associationRevision 1.
  db.rows.set(macEnrollmentKey('owner/fixture'), { pk: { S: macEnrollmentKey('owner/fixture') }, schema: { S: 'ring-mac-enrollment-v1' }, owner_ref: { S: 'owner/fixture' },
    association_revision: { N: '1' }, revision: { N: '2' }, key_id: { S: signer.keyId }, public_key_spki: { S: signer.publicKeySpki },
    expires_ms: { N: String(NOW + 10 * HOUR) }, approval_sha256: { S: 'a'.repeat(64) }, revoked: { BOOL: false } });
  const authority = createMacCommandProofAuthority({ ports: db.ports, audience: AUDIENCE, clock: () => NOW });
  const TOKEN = 'synthetic-mac-owner-bearer-token';
  const request = () => ({ headers: { authorization: 'Bearer ' + TOKEN, [MAC_PROOF_HEADER]: signer.signRequest({ operation: 'fetch', token: TOKEN, payload: {} }) } });
  const mac = await authority.verify({ request: request(), authority: lease, operation: 'fetch', payload: {} });
  assert.deepEqual({ ...mac }, { ownerRef: 'owner/fixture', associationRevision: 1, keyId: signer.keyId, revision: 2 });
  const bumped = { ...lease, associationRevision: 2, assertCurrent: lease.assertCurrent };
  await assert.rejects(authority.verify({ request: request(), authority: bumped, operation: 'fetch', payload: {} }), /MAC_ENROLLMENT_REQUIRED/u);
});

// ---------------- negatives (nothing written) ----------------

test('negative: different Ring account (pin mismatch, or a pin for another account than the bootstrap anchor) is a counted denial', async () => {
  const s = await bootstrapped(); expire(s);
  await assertRenewDenied(s, renewWith(s, { ring: ringFake(() => 'someone-elses-ring-account') }), 'owner_renewal_ring_denied', { ringCalls: 1, counted: 1 });
  const t = await bootstrapped(); expire(t);
  await assertRenewDenied(t, renewWith(t, { doc: renewalDoc(t.boot.sha, { ringAccountIdSha256: sha256('other-account') }), ring: ringFake(() => 'other-account') }),
    'owner_renewal_ring_denied', { ringCalls: 1, counted: 1 });
  const u = await bootstrapped(); expire(u);
  await assertRenewDenied(u, renewWith(u, { ring: ringFake(() => { throw new TypeError('ring_token_rejected'); }) }), 'owner_renewal_ring_rejected', { ringCalls: 1, counted: 1 });
  const v = await bootstrapped(); expire(v);
  await assertRenewDenied(v, renewWith(v, { ring: ringFake(() => { throw new TypeError('ring_token_denied'); }) }), 'owner_renewal_ring_denied', { ringCalls: 1 });
});

test('negative: different Cognito subject (approval names another sub; or caller and approval both name a sub that is not the anchored one)', async () => {
  const s = await bootstrapped(); expire(s);
  await assertRenewDenied(s, renewWith(s, { doc: renewalDoc(s.boot.sha, { cognitoSub: 'someone-else' }) }), 'owner_renewal_approval_denied');
  const intruder = await s.auth.login({ sub: 'intruder' });
  await assertRenewDenied(s, renewWith(s, { doc: renewalDoc(s.boot.sha, { cognitoSub: 'intruder' }), login: intruder }), 'owner_renewal_anchor_denied');
  await assertRenewDenied(s, renewWith(s, { login: intruder }), 'owner_renewal_approval_denied');
  assert.equal(s.table.get(`OAUTH#${await digest('oauth-subject', `${ISS}\0intruder`)}`, 'RING_ASSOCIATION'), undefined);
});

test('negative: no existing owner -> bootstrap path, which refuses a renewal approval; nothing written', async () => {
  const table = createFakeTable();
  const bytes = bytesOf(renewalDoc('b'.repeat(64)));
  const ring = ringFake();
  await assert.rejects(service({ table, bytes, ring }).ensureWithRingToken({ ...await createAuth().login(), ringAccessToken: RENEW_TOKEN }),
    error => error.message === 'owner_bootstrap_approval_denied');
  assert.equal(table.writeCount(), 0); assert.equal(table.items.size, 0); assert.equal(ring.calls.length, 0);
});

test('negative: bootstrap approval on the renewal path (incl. the original bootstrap bytes) and hybrid documents are refused', async () => {
  const s = await bootstrapped(); expire(s);
  await assertRenewDenied(s, renewWith(s, { bytes: s.boot.bytes }), 'owner_renewal_approval_denied');
  await assertRenewDenied(s, renewWith(s, { bytes: approvalFixture({ expiresAt: NOW + 20 * HOUR }).bytes }), 'owner_renewal_approval_denied');
  const doc = renewalDoc(s.boot.sha);
  const { mode, ...noMode } = doc;
  for (const bad of [{ ...doc, schema: 'ring-owner-bootstrap-approval-v1' }, { ...doc, mode: 'bootstrap' }, noMode, { ...doc, actorRef: 'actor/fixture' },
    { ...approvalFixture().approval, mode: 'renew' }, { ...approvalFixture().approval, schema: OWNER_RENEWAL_APPROVAL_SCHEMA }, { ...doc, extra: 1 },
    { ...doc, bootstrapApprovalSha256: 'B'.repeat(64) }, { ...doc, ownerEpoch: '1' }, { ...doc, associationRevision: 0 }, { ...doc, ringScopeRefs: [] },
    { ...doc, scopes: ['fixture.write'] }, { ...doc, issuer: 'https://cognito-idp.ap-southeast-1.amazonaws.com/other' }]) {
    await assertRenewDenied(s, renewWith(s, { doc: bad }), 'owner_renewal_approval_denied');
  }
  // wrong pin / unreadable approval
  await assertRenewDenied(s, renewWith(s, { pinned: 'e'.repeat(64) }), 'owner_renewal_approval_denied');
  void mode;
});

test('negative: mismatched ownerRef / epoch / revision / generation / scope refs / anchor / revoked or inactive rows', async () => {
  const s = await bootstrapped(); expire(s);
  const cases = [
    [{ ownerRef: 'owner/other' }, 'owner_renewal_owner_denied'],
    [{ ringScopeRefs: ['ring.read'] }, 'owner_renewal_association_denied'], [{ bootstrapApprovalSha256: 'c'.repeat(64) }, 'owner_renewal_anchor_denied']];
  for (const [overrides, code] of cases) await assertRenewDenied(s, renewWith(s, { doc: renewalDoc(s.boot.sha, overrides) }), code);
  s.association().revoked = { BOOL: true };
  await assertRenewDenied(s, renewWith(s), 'owner_renewal_association_denied');
  s.association().revoked = { BOOL: false }; s.account().revoked = { BOOL: true };
  await assertRenewDenied(s, renewWith(s), 'owner_renewal_account_denied');
  s.account().revoked = { BOOL: false };
  s.table.get('OWNER#CURRENT', 'META').status = { S: 'REVOKED' };
  await assertRenewDenied(s, renewWith(s), 'owner_renewal_owner_denied');
  s.table.get('OWNER#CURRENT', 'META').status = { S: 'ACTIVE' };
  s.table.get(`OWNER_BOOTSTRAP#${s.boot.sha}`, 'META').account_digest = { S: 'd'.repeat(64) };
  await assertRenewDenied(s, renewWith(s), 'owner_renewal_association_denied');
});

test('negative: window violations and non-extending expiry', async () => {
  const s = await bootstrapped(); expire(s);
  for (const overrides of [{ issuedAt: NOW - 2 * HOUR, notAfter: NOW - 1 }, { issuedAt: NOW + 1000, notAfter: NOW + HOUR }, { issuedAt: NOW - 60000, notAfter: NOW - 60000 + 86400001 },
    { issuedAt: NOW, notAfter: NOW }, { expiresAt: NOW + 86400001 }, { expiresAt: NOW - 1 }, { expiresAt: NOW }]) {
    await assertRenewDenied(s, renewWith(s, { doc: renewalDoc(s.boot.sha, overrides) }), 'owner_renewal_approval_denied');
  }
  const t = await bootstrapped(); // unexpired, association expiry NOW+2h: an approval that would shorten or keep it is refused
  for (const expiresAt of [NOW + HOUR, NOW + 2 * HOUR]) await assertRenewDenied(t, renewWith(t, { doc: renewalDoc(t.boot.sha, { expiresAt }) }), 'owner_renewal_association_denied');
  // Cognito token expired between approval checks and the write
  let now = NOW;
  const u = await bootstrapped(); expire(u);
  const ring = ringFake(() => { now = NOW + 300001; return ACCOUNT_ID; });
  await assertRenewDenied(u, renewWith(u, { ring, clock: () => now }), 'owner_renewal_expired', { ringCalls: 1 });
});

test('negative: latch replay (same renewal approval twice, also after TTL deletion) and Ring token replay', async () => {
  const s = await bootstrapped(); expire(s);
  const doc = renewalDoc(s.boot.sha);
  assert.equal((await (await renewWith(s, { doc })).promise).renewed, true);
  s.table.transactions.length = 0;
  // second use with a fresh token: the association already carries this expiry -> refused before Ring
  await assertRenewDenied(s, renewWith(s, { doc, token: 'ring-access-token-THIRD' }), 'owner_renewal_association_denied');
  // even if the rows were TTL-deleted, the single-use latch refuses the same approval again
  s.table.items.delete(`OAUTH#${s.subjectDigest}\u0000RING_ASSOCIATION`); s.table.items.delete(`ACCOUNT#${s.accountDigest}\u0000IDENTITY`);
  await assertRenewDenied(s, renewWith(s, { doc, token: 'ring-access-token-FOURTH' }), 'owner_renewal_write_denied', { ringCalls: 1 });
  assert.equal(s.association(), undefined);
  // Ring token replay: the bootstrap token's marker still exists (1h)
  const t = await bootstrapped(); expire(t);
  await assertRenewDenied(t, renewWith(t, { token: ACCESS_TOKEN }), 'owner_renewal_write_denied', { ringCalls: 1 });
});

test('negative: lockout after 3 counted failures (Ring not called, correct token refused); concurrent renewals produce one winner', async () => {
  assert.equal(OWNER_BOOTSTRAP_MAX_FAILURES, 3);
  const s = await bootstrapped(); expire(s);
  let id = 'wrong';
  const ring = ringFake(() => id);
  for (let i = 1; i <= 3; i += 1) await assertRenewDenied(s, renewWith(s, { ring }), 'owner_renewal_ring_denied', { ringCalls: i, counted: i });
  id = ACCOUNT_ID;
  await assertRenewDenied(s, renewWith(s, { ring }), 'owner_renewal_locked', { ringCalls: 3, counted: 3 });
  const t = await bootstrapped(); expire(t);
  const runs = await Promise.all(['ring-token-A', 'ring-token-B', 'ring-token-C'].map(token => renewWith(t, { token })));
  const results = await Promise.allSettled(runs.map(r => r.promise));
  assert.equal(results.filter(r => r.status === 'fulfilled' && r.value.renewed === true).length, 1);
  assert.ok(results.filter(r => r.status === 'rejected').every(r => ['owner_renewal_write_denied', 'owner_renewal_association_denied'].includes(r.reason.message)));
  assert.equal(t.association().expires_at.N, String(Math.floor((NOW + 20 * HOUR) / 1000)));
});

test('console spy: renewal outputs and errors carry no token, account id, approval bytes or sealed material', async () => {
  const logs = [];
  const original = { info: console.info, log: console.log, warn: console.warn, error: console.error, debug: console.debug };
  for (const name of Object.keys(original)) console[name] = (...args) => logs.push(args.map(a => typeof a === 'string' ? a : JSON.stringify(a)).join(' '));
  const outputs = [];
  try {
    const s = await bootstrapped(); expire(s);
    s.table.items.delete(`ACCOUNT#${s.accountDigest}\u0000IDENTITY`);
    outputs.push(JSON.stringify(await (await renewWith(s)).promise));
    const t = await bootstrapped(); expire(t);
    await (await renewWith(t, { ring: ringFake(() => { throw new Error(ACCOUNT_ID + RENEW_TOKEN); }) })).promise.catch(e => outputs.push(String(e.stack), e.message));
    await (await renewWith(t, { ring: ringFake(() => 'x' + ACCOUNT_ID) })).promise.catch(e => outputs.push(String(e.stack), e.message));
  } finally { Object.assign(console, original); }
  const everything = [...logs, ...outputs].join('\n');
  for (const secret of [ACCOUNT_ID, RENEW_TOKEN, ACCESS_TOKEN, 'owner/fixture', sealed.ciphertext, sha256(ACCOUNT_ID), createHash('sha256').update(RENEW_TOKEN).digest('hex')]) {
    assert.equal(everything.includes(secret), false, secret);
  }
});

test('M1: only the 1/1/1 binding bootstrap writes can be renewed; any other ownerEpoch/associationRevision/accountGeneration is an approval denial writing nothing', async () => {
  const s = await bootstrapped(); expire(s);
  for (const overrides of [{ ownerEpoch: 2 }, { associationRevision: 2 }, { accountGeneration: 2 }, { ownerEpoch: 2, associationRevision: 2, accountGeneration: 2 }, { associationRevision: 3 }]) {
    await assertRenewDenied(s, renewWith(s, { doc: renewalDoc(s.boot.sha, overrides) }), 'owner_renewal_approval_denied');
  }
  // even if the live rows really were at epoch/revision/generation 2 (installer-modified), renewal refuses
  const t = await bootstrapped(); expire(t);
  for (const row of [t.table.get('OWNER#CURRENT', 'META'), t.association(), t.account()]) row.owner_epoch = { N: '2' };
  t.association().revision = { N: '2' };
  await assertRenewDenied(t, renewWith(t, { doc: renewalDoc(t.boot.sha, { ownerEpoch: 2, associationRevision: 2 }) }), 'owner_renewal_approval_denied');
});

test('L2: association issuer/resource/schema are checked on read AND in the conditional Update (a row changed after the read fails the whole write)', async () => {
  for (const [attr, value] of [['issuer', 'https://cognito-idp.ap-southeast-1.amazonaws.com/other'], ['resource', 'https://other.example/mcp'], ['schema', 'ring-cloud-owner-association-v0']]) {
    const s = await bootstrapped(); expire(s);
    s.association()[attr] = { S: value };
    await assertRenewDenied(s, renewWith(s), 'owner_renewal_association_denied');
    const t = await bootstrapped(); expire(t);
    const before = structuredClone(t.association());
    const ring = ringFake(() => { t.association()[attr] = { S: value }; return ACCOUNT_ID; }); // changes between read and write
    const { promise, sha } = await renewWith(t, { ring });
    await assert.rejects(promise, error => error.message === 'owner_renewal_write_denied', attr);
    assert.deepEqual(t.association(), { ...before, [attr]: { S: value } }, 'expiry and evidence unchanged');
    assert.equal(t.account().expires_at.N, before.expires_at.N);
    assert.equal(t.table.get(`OWNER_RENEWAL#${sha}`, 'META'), undefined);
    assert.equal(t.table.get(`RING_TOKEN#${sha256(RENEW_TOKEN)}`, 'META'), undefined);
    assert.equal(t.table.get(`OWNER_BOOTSTRAP_ATTEMPTS#${sha}`, 'META'), undefined, 'not counted');
  }
});
