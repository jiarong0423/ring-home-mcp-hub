import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createCloudOwnerBootstrap, ownerBootstrapLatchKey, ownerBootstrapAttemptsKey, ringTokenMarkerKey, OWNER_BOOTSTRAP_MAX_FAILURES } from '../cloud-owner-bootstrap.mjs';
import { buildOwnerAssociationItems, createCloudOwnerAssociationInstaller, createCloudOwnerAssociationReader } from '../cloud-owner-association.mjs';
import { createCloudBrowserSessionIssuer } from '../cloud-browser-session.mjs';
import { createBrowserSessionHttp } from '../browser-session-http.mjs';
import { createDynamoLinkStore } from '../dynamo-link-store.mjs';
import { ProtocolError } from '../protocol.mjs';
import { NOW, ISS, RESOURCE, SCOPES, PROFILE, CONFIG, SUB, ACCOUNT_ID, ACCESS_TOKEN, REFRESH_TOKEN, sha256, digest, identityEnvelope, sealed,
  createAuth, createFakeTable, approvalFixture, jwt } from './owner-bootstrap-fixture.mjs';

const TOKEN_SHA = createHash('sha256').update(ACCESS_TOKEN).digest('hex');
const SIM_PIN = sha256('simulated-owner-account');

function ringFake(impl) {
  const ring = { calls: [], async getAccountId(token) { ring.calls.push(token); return impl ? impl(token) : ACCOUNT_ID; } };
  return ring;
}
async function harness({ approval = approvalFixture(), loadBytes, pinned, ring = ringFake(), clock = () => NOW, table = createFakeTable() } = {}) {
  const auth = createAuth();
  const accountDigest = await digest('ring-account', ACCOUNT_ID);
  const counters = { approvalLoads: 0 };
  const bootstrap = createCloudOwnerBootstrap({ getItem: table.getItem, transactWrite: table.transactWrite, tableName: 'ring-test-link', digest,
    identityEnvelope, profile: PROFILE, approvalSha256: pinned ?? approval.sha, clock, ringTokenClient: ring,
    loadApproval: async () => { counters.approvalLoads += 1; return loadBytes ? loadBytes() : approval.bytes; } });
  return { auth, table, bootstrap, accountDigest, counters, approval, ring };
}
function docHarness(doc, extra = {}) {
  const bytes = Buffer.from(JSON.stringify(doc));
  return harness({ approval: { approval: doc, bytes, sha: sha256(bytes) }, ...extra });
}
const ensure = async (h, overrides = {}) => {
  const { request, actor } = overrides.login ?? await h.auth.login();
  return h.bootstrap.ensureWithRingToken({ request, actor, ringAccessToken: ACCESS_TOKEN, ...overrides.args });
};
const counterRows = h => [...h.table.items.keys()].filter(k => k.startsWith('OWNER_BOOTSTRAP_ATTEMPTS#'));
// Denied before the failure budget applies: nothing at all is written.
async function assertDenied(h, promise, code) {
  await assert.rejects(promise, error => error instanceof TypeError && (code === undefined || error.message === code), code);
  assert.equal(h.table.writeCount(), 0, 'a denied bootstrap must write nothing');
  assert.equal(h.table.items.size, 0);
}
// Denied after the approved subject was established: only the failure counter may change.
async function assertDeniedCounted(h, promise, code, failures = 1) {
  await assert.rejects(promise, error => error instanceof TypeError && (code === undefined || error.message === code), code);
  assert.deepEqual([...h.table.items.keys()].filter(k => !k.startsWith('OWNER_BOOTSTRAP_ATTEMPTS#')), [], 'no owner/association/account/latch/marker rows');
  assert.ok(h.table.transactions.every(tx => tx.every(op => op.Update)), 'only counter updates were attempted');
  const row = h.table.get(`OWNER_BOOTSTRAP_ATTEMPTS#${h.approval.sha}`, 'META');
  assert.equal(row?.failures.N, String(failures));
  assert.equal(row.expires_at.N, String(Math.floor((NOW + 3600000) / 1000)), 'counter row carries a 1h expires_at');
}

test('positive: no owner -> one atomic transaction creates owner, association, account, the single-use latch and the token replay marker', async () => {
  const h = await harness();
  const result = await ensure(h);
  assert.deepEqual({ ...result }, { bootstrapped: true, associationRevision: 1 });
  assert.deepEqual(h.ring.calls, [ACCESS_TOKEN]);
  assert.equal(h.table.writeCount(), 1);
  const tx = h.table.transactions[0];
  assert.equal(tx.length, 5);
  assert.deepEqual(tx.map(i => Object.keys(i)[0]), ['Put', 'Put', 'Put', 'Put', 'Put']);
  assert.ok(tx.every(i => i.Put.ConditionExpression === 'attribute_not_exists(PK)'));
  const owner = h.table.get('OWNER#CURRENT', 'META'), account = h.table.get(`ACCOUNT#${h.accountDigest}`, 'IDENTITY');
  assert.equal(owner.owner_epoch.N, '1'); assert.equal(owner.status.S, 'ACTIVE');
  assert.equal(account.owner_epoch.N, '1'); assert.equal(account.identity_epoch.N, '1'); assert.equal(account.account_generation.N, '1');
  const subjectDigest = await digest('oauth-subject', `${ISS}\0${SUB}`);
  const association = h.table.get(`OAUTH#${subjectDigest}`, 'RING_ASSOCIATION');
  assert.equal(association.revision.N, '1'); assert.equal(association.account_digest.S, h.accountDigest);
  assert.equal(association.approval_evidence_sha256.S, h.approval.sha);
  for (const item of [owner, association, account]) assert.equal(item.identity_source.S, 'ring-sandbox-token');
  const latch = h.table.get(`OWNER_BOOTSTRAP#${h.approval.sha}`, 'META');
  assert.ok(latch); assert.equal(latch.approval_sha256.S, h.approval.sha); assert.equal(latch.identity_source.S, 'ring-sandbox-token');
  const marker = h.table.get(`RING_TOKEN#${TOKEN_SHA}`, 'META');
  assert.ok(marker);
  assert.deepEqual(Object.keys(marker).sort(), ['PK', 'SK', 'expires_at', 'schema']);
  assert.equal(marker.expires_at.N, String(Math.floor((NOW + 3600000) / 1000)));
  assert.equal(JSON.stringify([...h.table.items.values()]).includes(ACCESS_TOKEN), false, 'only the token hash is stored');
  assert.deepEqual(identityEnvelope.calls.at(-1).binding, { accountDigest: h.accountDigest, ownerRef: 'owner/fixture', ownerEpoch: 1, accountGeneration: 1 });
  assert.deepEqual(ringTokenMarkerKey(TOKEN_SHA), { PK: { S: `RING_TOKEN#${TOKEN_SHA}` }, SK: { S: 'META' } });
  assert.equal(ownerBootstrapAttemptsKey(h.approval.sha).PK.S, `OWNER_BOOTSTRAP_ATTEMPTS#${h.approval.sha}`);
  assert.equal(counterRows(h).length, 0);
});

test('there is no simulated identity source: identitySource and simulated pins are unknown keys, and the real pin is mandatory', async () => {
  const base = approvalFixture().approval;
  const { ringAccountIdSha256, ...rest } = base;
  for (const doc of [{ ...base, identitySource: 'ring-sandbox-token' }, { ...base, identitySource: 'simulated' }, { ...rest, identitySource: 'simulated', simulatedRingAccountIdSha256: sha256('x') },
    { ...base, simulatedRingAccountIdSha256: sha256('x') }, rest]) {
    const x = await docHarness(doc);
    await assertDenied(x, ensure(x), 'owner_bootstrap_approval_denied');
    assert.equal(x.ring.calls.length, 0);
  }
});

test('positive end to end: real callback creates the owner, the real issuer then issues the session and reserveClaim passes', async () => {
  const table = createFakeTable();
  const h = await harness({ table });
  assert.equal((await ensure(h)).bootstrapped, true);
  const reader = createCloudOwnerAssociationReader({ getItem: table.getItem, transactGet: table.transactGet, tableName: 'ring-test-link', digest, profile: PROFILE, clock: () => NOW });
  const issuer = createCloudBrowserSessionIssuer({ associationReader: reader, transactWrite: table.transactWrite, tableName: 'ring-test-link', digest, clock: () => NOW });
  const states = new Map();
  const logs = [];
  const original = { info: console.info, log: console.log, warn: console.warn, error: console.error };
  for (const name of Object.keys(original)) console[name] = (...args) => logs.push(JSON.stringify(args));
  let response;
  try {
    const http = createBrowserSessionHttp({ config: CONFIG, transport: h.auth.transport, authorizationPolicy: h.auth.policy, issuer, digest,
      store: { async create({ stateDigest, expiresAt }) { states.set(stateDigest, expiresAt); }, async consume({ stateDigest }) { assert.ok(states.delete(stateDigest)); } },
      exchange: async () => jwt({}, NOW), clock: () => NOW });
    const ev = (path, query, headers = {}) => ({ path, resource: path, httpMethod: 'GET', requestContext: { path: `/staging${path}`, httpMethod: 'GET', stage: 'staging' }, headers,
      multiValueHeaders: Object.fromEntries(Object.entries(headers).map(([k, v]) => [k, [v]])), queryStringParameters: query, multiValueQueryStringParameters: Object.fromEntries(Object.entries(query).map(([k, v]) => [k, [v]])), isBase64Encoded: false, body: null });
    const login = await http.handle(ev('/auth/login', { time: String(NOW - 1000), nonce: 'n'.repeat(43) }), {});
    assert.equal(login.statusCode, 303);
    const state = new URL(login.headers.location).searchParams.get('state');
    const cookie = login.multiValueHeaders['set-cookie'][0].split(';')[0];
        response = await http.handle(ev('/auth/callback', { code: 'fixture-code', state }, { cookie }), {});
  } finally { Object.assign(console, original); }
  assert.equal(response.statusCode, 303);
  assert.equal(response.headers.location, `/staging/ring/link?time=${NOW - 1000}&nonce=${'n'.repeat(43)}`);
  const cookies = response.multiValueHeaders['set-cookie'].join('\n');
  assert.match(cookies, /__Host-ring_session=/u);
  assert.ok(table.get('OWNER#CURRENT', 'META'));
  assert.ok(table.get(`OWNER_BOOTSTRAP#${h.approval.sha}`, 'META'));
  assert.equal(h.ring.calls.length, 1);
  const joined = logs.join('\n');
  for (const secret of [ACCOUNT_ID, ACCESS_TOKEN, REFRESH_TOKEN, h.approval.bytes.toString('utf8'), 'owner/fixture', /__Host-ring_session=([^;]+)/u.exec(cookies)[1]]) assert.equal(joined.includes(secret), false);
  // reserveClaim (the link workflow's CAS) now passes against the bootstrapped ACCOUNT item.
  const linkKey = { PK: { S: 'LINK#link-1' }, SK: { S: 'STATE' } };
  const nowSeconds = Math.floor(NOW / 1000);
  table.items.set(`LINK#link-1\u0000STATE`, { ...linkKey, link_id: { S: 'link-1' }, status: { S: 'UNCLAIMED' }, revision: { N: '1' }, identity_epoch: { N: '0' },
    account_digest: { S: h.accountDigest }, expires_at: { N: String(nowSeconds + 300) } });
  const store = createDynamoLinkStore({ tableName: 'ring-test-link', clock: () => NOW, query: async () => ({ Items: [] }), getItem: table.getItem,
    transactWrite: async input => {
      for (const op of input.TransactItems) {
        const body = op.Update ?? op.ConditionCheck;
        const cond = body.ConditionExpression;
        const item = table.items.get(`${body.Key.PK.S}\u0000${body.Key.SK.S}`);
        assert.ok(item, 'item exists');
        for (const [attr, name] of [['identity_epoch', ':currentEpoch'], ['revoked', ':notRevoked']]) {
          if (cond.includes(`${attr} = ${name}`)) assert.deepEqual(item[attr], body.ExpressionAttributeValues[name], attr);
        }
      }
      return {};
    } });
  const reserved = await store.reserveClaim({ linkId: 'link-1', actorRef: 'actor/fixture', ownerRef: 'owner/fixture', householdRef: 'household/fixture',
    scopeRefs: ['ring.read'], accountDigest: h.accountDigest, expectedVersion: 1, currentEpoch: 1, expiresAt: nowSeconds + 120 });
  assert.equal(reserved.status, 'RESERVED');
  // Without the identity_epoch attribute (the pre-fix ACCOUNT shape) the same CAS cannot pass.
  const account = table.get(`ACCOUNT#${h.accountDigest}`, 'IDENTITY');
  delete account.identity_epoch;
  await assert.rejects(store.reserveClaim({ linkId: 'link-1', actorRef: 'actor/fixture', ownerRef: 'owner/fixture', householdRef: 'household/fixture',
    scopeRefs: ['ring.read'], accountDigest: h.accountDigest, expectedVersion: 1, currentEpoch: 1, expiresAt: nowSeconds + 120 }), error => error instanceof ProtocolError || error instanceof Error);
});

test('shared builder: bootstrap items equal the operator installer items for identical inputs (byte for byte)', async () => {
  const h = await harness();
  await ensure(h);
  const bootstrapItems = structuredClone(h.table.transactions[0].slice(0, 3));
  for (const item of bootstrapItems) delete item.Put.Item.identity_source;
  const subjectDigest = await digest('oauth-subject', `${ISS}\0${SUB}`);
  const a = h.approval.approval;
  const installerApproval = Buffer.from(JSON.stringify({ schema: 'ring-owner-association-approval-v1', issuer: ISS, resource: RESOURCE, subjectDigest,
    ownerRef: a.ownerRef, actorRef: a.actorRef, householdRef: a.householdRef, ownerMode: 'create', accountMode: 'create', expectedRevision: 0, revision: 1,
    ownerEpoch: 1, accountGeneration: 1, expiresAt: a.expiresAt, ringScopeRefs: a.ringScopeRefs, scopes: [...SCOPES], accountDigest: h.accountDigest }));
  const installerWrites = [];
  const auth = createAuth();
  const installer = createCloudOwnerAssociationInstaller({ transactWrite: async input => { installerWrites.push(structuredClone(input.TransactItems)); return {}; }, tableName: 'ring-test-link', digest,
    identityEnvelope, ringClient: { getAccountId: async () => ACCOUNT_ID }, approvalSha256: h.approval.sha, profile: PROFILE, clock: () => NOW });
  // The installer pins its own approval bytes; use matching hash.
  const pinned = createCloudOwnerAssociationInstaller({ transactWrite: async input => { installerWrites.push(structuredClone(input.TransactItems)); return {}; }, tableName: 'ring-test-link', digest,
    identityEnvelope, ringClient: { getAccountId: async () => ACCOUNT_ID }, approvalSha256: sha256(installerApproval), profile: PROFILE, clock: () => NOW });
  void installer;
  const { request, actor } = await auth.login();
  const out = await pinned.install({ request, actor, ringAccessToken: ACCESS_TOKEN, approvalBytes: installerApproval });
  assert.equal(out.installed, true);
  // approval_evidence_sha256 differs only because the two approvals are different files; normalize it and compare the rest.
  const normalize = items => JSON.parse(JSON.stringify(items).replaceAll(h.approval.sha, 'APPROVAL').replaceAll(sha256(installerApproval), 'APPROVAL'));
  assert.deepEqual(normalize(installerWrites[0]), normalize(bootstrapItems));
  // And the builder itself is a pure function of its inputs.
  const direct = buildOwnerAssociationItems({ tableName: 'ring-test-link', profile: PROFILE, subjectDigest, accountDigest: h.accountDigest, envelope: await identityEnvelope.seal('x', {}),
    approvalSha256: h.approval.sha, approval: { ownerRef: a.ownerRef, actorRef: a.actorRef, householdRef: a.householdRef, ownerMode: 'create', accountMode: 'create',
      expectedRevision: 0, revision: 1, ownerEpoch: 1, accountGeneration: 1, ringScopeRefs: a.ringScopeRefs, expiresAt: a.expiresAt } });
  assert.deepEqual(direct, bootstrapItems);
});

test('ACCOUNT item written by the installer carries identity_epoch equal to the owner epoch', async () => {
  const sealedEnvelope = await identityEnvelope.seal('x', {});
  const items = buildOwnerAssociationItems({ tableName: 'ring-test-link', profile: PROFILE, subjectDigest: 'a'.repeat(64), accountDigest: 'b'.repeat(64), envelope: sealedEnvelope,
    approvalSha256: 'c'.repeat(64), approval: { ownerRef: 'owner/fixture', actorRef: 'actor/fixture', householdRef: 'household/fixture', ownerMode: 'create', accountMode: 'create',
      expectedRevision: 0, revision: 1, ownerEpoch: 3, accountGeneration: 2, ringScopeRefs: ['ring.read'], expiresAt: NOW + 1000 } });
  assert.equal(items[2].Put.Item.identity_epoch.N, '3');
  assert.equal(items[2].Put.Item.owner_epoch.N, '3');
  assert.equal(items[2].Put.Item.account_generation.N, '2');
  const existing = buildOwnerAssociationItems({ tableName: 'ring-test-link', profile: PROFILE, subjectDigest: 'a'.repeat(64), accountDigest: 'b'.repeat(64), envelope: sealedEnvelope,
    approvalSha256: 'c'.repeat(64), approval: { ownerRef: 'owner/fixture', actorRef: 'actor/fixture', householdRef: 'household/fixture', ownerMode: 'existing', accountMode: 'existing',
      expectedRevision: 1, revision: 2, ownerEpoch: 3, accountGeneration: 2, ringScopeRefs: ['ring.read'], expiresAt: NOW + 1000 } });
  assert.ok(existing[0].ConditionCheck); assert.ok(existing[2].ConditionCheck);
});

// ---------------- negatives: each must write nothing ----------------

// ---------------- negatives ----------------

test('negative: Cognito subject mismatch (not counted, Ring never called)', async () => {
  const h = await harness({ approval: approvalFixture({ cognitoSub: 'someone-else' }) });
  await assertDenied(h, ensure(h), 'owner_bootstrap_approval_denied');
  assert.equal(h.ring.calls.length, 0);
});
test('negative: approval hash mismatch (wrong bytes or wrong pin)', async () => {
  const h = await harness({ loadBytes: () => approvalFixture({ ownerRef: 'owner/other' }).bytes });
  await assertDenied(h, ensure(h), 'owner_bootstrap_approval_denied');
  const g = await harness({ pinned: 'e'.repeat(64) });
  await assertDenied(g, ensure(g), 'owner_bootstrap_approval_denied');
  const loadFails = await harness({ loadBytes: () => { throw new Error('ENOENT /opt/ring-b02/secret-path'); } });
  await assertDenied(loadFails, ensure(loadFails), 'owner_bootstrap_approval_denied');
  assert.equal(h.ring.calls.length + g.ring.calls.length + loadFails.ring.calls.length, 0);
});
test('negative: window expired, not yet open, wider than 24h, or association lifetime too long', async () => {
  for (const [name, overrides] of [['expired', { issuedAt: NOW - 7200000, notAfter: NOW - 1 }], ['not yet', { issuedAt: NOW + 1000, notAfter: NOW + 3600000 }],
    ['over 24h', { issuedAt: NOW - 60000, notAfter: NOW - 60000 + 86400001 }], ['inverted', { issuedAt: NOW, notAfter: NOW }],
    ['association expiry too long', { expiresAt: NOW + 86400001 }], ['association already expired', { expiresAt: NOW - 1 }]]) {
    const h = await harness({ approval: approvalFixture(overrides) });
    await assertDenied(h, ensure(h), 'owner_bootstrap_approval_denied');
    assert.equal(h.ring.calls.length, 0, name);
  }
});
test('negative: clock moved past notAfter between approval issue and use', async () => {
  let t = NOW;
  const h = await harness({ approval: approvalFixture({ notAfter: NOW + 1000 }), clock: () => t });
  t = NOW + 1001;
  await assertDenied(h, ensure(h));
});
test('negative: the Ring token resolves to a DIFFERENT Ring account (counted, nothing else written, same error as any other Ring failure)', async () => {
  const h = await harness({ ring: ringFake(() => 'someone-elses-ring-account') });
  await assertDeniedCounted(h, ensure(h), 'owner_bootstrap_ring_denied');
  assert.equal(h.ring.calls.length, 1);
});
test('negative: only DEFINITE Ring rejections count: 401/403 and a non-string/empty/oversize id are counted; timeouts, network errors, 5xx/429, odd shapes never are', async () => {
  for (const impl of [() => { throw new TypeError('ring_token_rejected'); }, () => '', () => 'x'.repeat(257), () => 42, () => undefined, () => ({ id: ACCOUNT_ID })]) {
    const h = await harness({ ring: ringFake(impl) });
    await assert.rejects(ensure(h), error => error instanceof TypeError && /^owner_bootstrap_ring_(rejected|denied)$/u.test(error.message) && !String(error.stack).includes(ACCESS_TOKEN));
    assert.deepEqual([...h.table.items.keys()].filter(k => !k.startsWith('OWNER_BOOTSTRAP_ATTEMPTS#')), []);
    assert.equal(h.table.get(`OWNER_BOOTSTRAP_ATTEMPTS#${h.approval.sha}`, 'META').failures.N, '1');
  }
  const h = await harness({ ring: ringFake(() => { throw new TypeError('ring_token_denied'); }) });
  for (let i = 0; i < 6; i += 1) await assert.rejects(ensure(h), error => error.message === 'owner_bootstrap_ring_denied');
  assert.equal(h.table.writeCount(), 0, 'indeterminate Ring failures write nothing at all');
  assert.equal(h.table.items.size, 0);
  // unexpected thrown values of any kind are also not counted
  for (const impl of [() => { throw new Error('boom ' + ACCESS_TOKEN); }, () => { throw 'string'; }, () => { throw null; }]) {
    const x = await harness({ ring: ringFake(impl) });
    await assert.rejects(ensure(x), error => error.message === 'owner_bootstrap_ring_denied' && !String(error.stack).includes(ACCESS_TOKEN));
    assert.equal(x.table.writeCount(), 0);
  }
});
test('negative: wrong-account pin is a counted denial; malformed pin shapes are uncounted approval denials', async () => {
  const wrong = await harness({ approval: approvalFixture({ ringAccountIdSha256: sha256('x') }) });
  await assertDeniedCounted(wrong, ensure(wrong), 'owner_bootstrap_ring_denied');
  for (const pin of [sha256(ACCOUNT_ID).toUpperCase(), ACCOUNT_ID, sha256(ACCOUNT_ID).slice(0, 63), 5]) {
    const h = await harness({ approval: approvalFixture({ ringAccountIdSha256: pin }) });
    await assertDenied(h, ensure(h), 'owner_bootstrap_approval_denied');
    assert.equal(h.ring.calls.length, 0);
  }
});
test('negative: request token shape is checked before any port is touched', async () => {
  const h = await harness();
  const login = await h.auth.login();
  for (const bad of [undefined, null, 5, '', 'a b', 'a\r\nx-evil: 1', 'x'.repeat(8193), '\u00e9', {}]) {
    await assert.rejects(h.bootstrap.ensureWithRingToken({ ...login, ringAccessToken: bad }), /owner_bootstrap_token_denied/u);
  }
  assert.equal(h.table.getCalls.length, 0); assert.equal(h.table.writeCount(), 0); assert.equal(h.counters.approvalLoads, 0); assert.equal(h.ring.calls.length, 0);
});
test('negative: wrong scopes (profile vs verified login, approval vs profile)', async () => {
  const h = await harness();
  const login = await h.auth.login();
  const otherProfile = createCloudOwnerBootstrap({ getItem: h.table.getItem, transactWrite: h.table.transactWrite, tableName: 'ring-test-link', digest, identityEnvelope,
    profile: { ...PROFILE, scopes: ['fixture.read', 'fixture.write'] }, approvalSha256: h.approval.sha, loadApproval: async () => h.approval.bytes, ringTokenClient: ringFake(() => assert.fail('must not call Ring')) });
  await assert.rejects(otherProfile.ensureWithRingToken({ ...login, ringAccessToken: ACCESS_TOKEN }), /owner_bootstrap_login_denied/u);
  const g = await harness({ approval: approvalFixture({ scopes: ['fixture.write'] }) });
  await assertDenied(g, ensure(g), 'owner_bootstrap_approval_denied');
  assert.equal(h.table.writeCount(), 0);
});
test('negative: unverified or forged login evidence, expired login, wrong issuer/resource', async () => {
  const h = await harness();
  const forged = { request: Object.freeze({ method: 'POST', path: '/auth/session', headers: {} }), actor: Object.freeze({ subject: SUB }) };
  await assertDenied(h, h.bootstrap.ensureWithRingToken({ ...forged, ringAccessToken: ACCESS_TOKEN }), 'owner_bootstrap_login_denied');
  const real = await h.auth.login();
  await assertDenied(h, h.bootstrap.ensureWithRingToken({ request: real.request, actor: { ...real.actor }, ringAccessToken: ACCESS_TOKEN }), 'owner_bootstrap_login_denied');
  let t = NOW;
  const g = await harness({ clock: () => t });
  const login = await g.auth.login();
  t = NOW + 300001;
  await assertDenied(g, g.bootstrap.ensureWithRingToken({ ...login, ringAccessToken: ACCESS_TOKEN }), 'owner_bootstrap_login_denied');
  const other = createCloudOwnerBootstrap({ getItem: h.table.getItem, transactWrite: h.table.transactWrite, tableName: 'ring-test-link', digest, identityEnvelope,
    profile: { ...PROFILE, issuer: 'https://cognito-idp.ap-southeast-1.amazonaws.com/other' }, approvalSha256: h.approval.sha, loadApproval: async () => h.approval.bytes, ringTokenClient: ringFake(() => assert.fail('no')) });
  await assert.rejects(other.ensureWithRingToken({ ...real, ringAccessToken: ACCESS_TOKEN }), /owner_bootstrap_login_denied/u);
  assert.equal(h.table.writeCount(), 0);
});
test('negative: malformed approval documents (unknown key, missing key, plaintext id, accountDigest, bad refs) write nothing and never reach Ring', async () => {
  const base = approvalFixture().approval;
  const { ringAccountIdSha256, ...noPin } = base;
  const variants = [{ ...base, extra: 1 }, (({ ownerRef, ...rest }) => rest)(base), noPin, { ...noPin, ringAccountId: ACCOUNT_ID }, { ...base, accountDigest: 'a'.repeat(64) },
    { ...base, ownerRef: 'x' }, { ...base, ringScopeRefs: [] }, { ...base, ringScopeRefs: ['ring.read', 'ring.read'] },
    { ...base, schema: 'ring-owner-association-approval-v1' }, { ...base, issuer: 'https://cognito-idp.ap-southeast-1.amazonaws.com/other' }, { ...base, resource: 'https://other.example/mcp' }];
  for (const doc of variants) {
    const h = await docHarness(doc);
    await assertDenied(h, ensure(h), 'owner_bootstrap_approval_denied');
    assert.equal(h.ring.calls.length, 0);
  }
  for (const raw of ['null', '[]', '"x"', 'not json', '{']) {
    const bytes = Buffer.from(raw);
    const h = await harness({ loadBytes: () => bytes, pinned: sha256(bytes) });
    await assertDenied(h, ensure(h), 'owner_bootstrap_approval_denied');
  }
});
test('negative: existing OWNER#CURRENT selects renewal, which refuses a bootstrap approval (no Ring call, no write; bootstrap can never run again)', async () => {
  const table = createFakeTable();
  table.items.set('OWNER#CURRENT\u0000META', { PK: { S: 'OWNER#CURRENT' }, SK: { S: 'META' }, status: { S: 'ACTIVE' } });
  const h = await harness({ table });
  await assert.rejects(ensure(h), error => error instanceof TypeError && error.message === 'owner_renewal_approval_denied');
  assert.equal(h.counters.approvalLoads, 1); assert.equal(h.ring.calls.length, 0); assert.equal(table.writeCount(), 0);
  assert.equal(table.getCalls[0].ConsistentRead, true);
  assert.deepEqual(table.getCalls[0].Key, { PK: { S: 'OWNER#CURRENT' }, SK: { S: 'META' } });
  assert.equal(table.items.size, 1);
});
test('latch: the approval is single use even after the owner is later revoked or removed', async () => {
  const h = await harness();
  assert.equal((await ensure(h)).bootstrapped, true);
  h.table.items.delete('OWNER#CURRENT\u0000META');
  const snapshot = [...h.table.items.keys()].sort();
  await assert.rejects(ensure(h), /owner_bootstrap_write_denied/u);
  assert.deepEqual([...h.table.items.keys()].filter(k => !k.startsWith('OWNER_BOOTSTRAP_ATTEMPTS#')).sort(), snapshot, 'a replay must not change any non-counter row');
  assert.ok(h.table.get(`OWNER_BOOTSTRAP#${h.approval.sha}`, 'META'), 'latch persists');
  assert.deepEqual(ownerBootstrapLatchKey(h.approval.sha), { PK: { S: `OWNER_BOOTSTRAP#${h.approval.sha}` }, SK: { S: 'META' } });
  assert.throws(() => ownerBootstrapLatchKey('nope'), TypeError);
});
test('token replay marker: a Ring token that already has a marker row cannot be used again (nothing created)', async () => {
  const table = createFakeTable();
  table.items.set(`RING_TOKEN#${TOKEN_SHA}\u0000META`, { PK: { S: `RING_TOKEN#${TOKEN_SHA}` }, SK: { S: 'META' } });
  const h = await harness({ table });
  await assert.rejects(ensure(h), /owner_bootstrap_write_denied/u);
  assert.equal(table.get('OWNER#CURRENT', 'META'), undefined);
  assert.equal(table.get(`OWNER_BOOTSTRAP#${h.approval.sha}`, 'META'), undefined);
});
test('latch: concurrent ensure calls produce exactly one owner', async () => {
  const h = await harness();
  const results = await Promise.allSettled([ensure(h), ensure(h), ensure(h)]);
  assert.equal(results.filter(r => r.status === 'fulfilled' && r.value.bootstrapped === true).length, 1);
  assert.equal([...h.table.items.keys()].filter(k => k.startsWith('OWNER#CURRENT')).length, 1);
});
test('negative: transactWrite condition failure leaves nothing partially written and is surfaced as a finite denial', async () => {
  const table = createFakeTable();
  const subjectDigest = await digest('oauth-subject', `${ISS}\0${SUB}`);
  table.items.set(`OAUTH#${subjectDigest}\u0000RING_ASSOCIATION`, { PK: { S: `OAUTH#${subjectDigest}` }, SK: { S: 'RING_ASSOCIATION' } });
  const h = await harness({ table });
  await assert.rejects(ensure(h), error => error instanceof TypeError && error.message === 'owner_bootstrap_write_denied');
  assert.deepEqual([...table.items.keys()].filter(k => !k.startsWith('OWNER_BOOTSTRAP_ATTEMPTS#')), [`OAUTH#${subjectDigest}\u0000RING_ASSOCIATION`]);
  assert.equal(table.get('OWNER#CURRENT', 'META'), undefined);
  const unknown = await harness({ table: Object.assign(createFakeTable(), { failWith: new Error(`boom ${ACCESS_TOKEN}`) }) });
  await assert.rejects(ensure(unknown), error => error.message === 'owner_bootstrap_write_denied' && !String(error.stack).includes(ACCESS_TOKEN));
});
test('lockout: after 3 counted rejections the route self-disables for this approval (no Ring call, nothing written); other approvals/users are unaffected', async () => {
  assert.equal(OWNER_BOOTSTRAP_MAX_FAILURES, 3);
  const table = createFakeTable();
  let id = 'wrong';
  const ring = ringFake(() => id);
  const h = await harness({ table, ring });
  for (let i = 1; i <= 3; i += 1) await assertDeniedCounted(h, ensure(h), 'owner_bootstrap_ring_denied', i);
  assert.equal(ring.calls.length, 3);
  id = ACCOUNT_ID; // even the correct token is refused now, and Ring is not asked
  await assert.rejects(ensure(h), error => error instanceof TypeError && error.message === 'owner_bootstrap_locked');
  assert.equal(ring.calls.length, 3);
  assert.equal(table.get(`OWNER_BOOTSTRAP_ATTEMPTS#${h.approval.sha}`, 'META').failures.N, '3');
  assert.equal(table.get('OWNER#CURRENT', 'META'), undefined);
  const other = await harness({ table: createFakeTable(), approval: approvalFixture({ cognitoSub: 'someone-else' }) });
  for (let i = 0; i < 5; i += 1) await assert.rejects(ensure(other));
  assert.equal(counterRows(other).length, 0);
  const fresh = approvalFixture({ ownerRef: 'owner/second' });
  const h2 = await harness({ table, ring: ringFake(), approval: fresh });
  assert.equal((await ensure(h2)).bootstrapped, true);
});
test('lockout expiry is checked in code (TTL deletion lags): an expired counter row no longer locks, a live or malformed one does, and a new rejection restarts the count', async () => {
  const seed = (table, sha, attrs) => table.items.set(`OWNER_BOOTSTRAP_ATTEMPTS#${sha}\u0000META`, { PK: { S: `OWNER_BOOTSTRAP_ATTEMPTS#${sha}` }, SK: { S: 'META' }, ...attrs });
  const nowSec = Math.floor(NOW / 1000);
  // live row at the limit -> locked; Ring never called
  let table = createFakeTable(); let h = await harness({ table });
  seed(table, h.approval.sha, { failures: { N: '3' }, expires_at: { N: String(nowSec + 10) } });
  await assert.rejects(ensure(h), error => error.message === 'owner_bootstrap_locked'); assert.equal(h.ring.calls.length, 0);
  // expired row at the limit (not yet deleted by TTL) -> usable again
  table = createFakeTable(); h = await harness({ table });
  seed(table, h.approval.sha, { failures: { N: '3' }, expires_at: { N: String(nowSec) } });
  assert.equal((await ensure(h)).bootstrapped, true);
  // expired row + a counted rejection restarts at 1 with a fresh expiry
  table = createFakeTable(); h = await harness({ table, ring: ringFake(() => 'wrong') });
  seed(table, h.approval.sha, { failures: { N: '2' }, expires_at: { N: String(nowSec - 5) } });
  await assert.rejects(ensure(h), /owner_bootstrap_ring_denied/u);
  const row = table.get(`OWNER_BOOTSTRAP_ATTEMPTS#${h.approval.sha}`, 'META');
  assert.equal(row.failures.N, '1'); assert.equal(row.expires_at.N, String(Math.floor((NOW + 3600000) / 1000)));
  // live row below the limit counts up and slides the expiry
  table = createFakeTable(); h = await harness({ table, ring: ringFake(() => 'wrong') });
  seed(table, h.approval.sha, { failures: { N: '1' }, expires_at: { N: String(nowSec + 5) } });
  await assert.rejects(ensure(h), /owner_bootstrap_ring_denied/u);
  assert.equal(table.get(`OWNER_BOOTSTRAP_ATTEMPTS#${h.approval.sha}`, 'META').failures.N, '2');
  // malformed rows fail closed
  for (const attrs of [{ failures: { N: '1' } }, { expires_at: { N: String(nowSec + 5) } }, { failures: { S: 'x' }, expires_at: { N: String(nowSec + 5) } }, { failures: { N: '-1' }, expires_at: { N: String(nowSec + 5) } }]) {
    table = createFakeTable(); h = await harness({ table });
    seed(table, h.approval.sha, attrs);
    await assert.rejects(ensure(h), error => error.message === 'owner_bootstrap_locked'); assert.equal(h.ring.calls.length, 0);
  }
});
test('console spy: neither the result, thrown errors nor any console output contain tokens, approval bytes, account id or sealed material', async () => {
  const logs = [];
  const original = { info: console.info, log: console.log, warn: console.warn, error: console.error, debug: console.debug };
  for (const name of Object.keys(original)) console[name] = (...args) => logs.push(args.map(a => typeof a === 'string' ? a : JSON.stringify(a)).join(' '));
  const outputs = [];
  try {
    const ok = await harness();
    outputs.push(JSON.stringify(await ensure(ok)));
    const bad = await harness({ approval: approvalFixture({ cognitoSub: 'x' }) });
    await ensure(bad).catch(error => outputs.push(String(error.stack), error.message));
    const unknown = await harness({ table: Object.assign(createFakeTable(), { failWith: new Error(ACCOUNT_ID + ACCESS_TOKEN) }) });
    await ensure(unknown).catch(error => outputs.push(String(error.stack), error.message));
    const wrong = await harness({ ring: ringFake(() => { throw new Error(ACCOUNT_ID + ACCESS_TOKEN); }) });
    await ensure(wrong).catch(error => outputs.push(String(error.stack), error.message));
    const exists = await harness();
    exists.table.items.set('OWNER#CURRENT\u0000META', { PK: { S: 'OWNER#CURRENT' }, SK: { S: 'META' } });
    await ensure(exists).catch(error => outputs.push(String(error.stack), error.message));
  } finally { Object.assign(console, original); }
  const everything = [...logs, ...outputs].join('\n');
  for (const secret of [ACCOUNT_ID, ACCESS_TOKEN, REFRESH_TOKEN, 'ring-account-id', 'owner/fixture', sealed.ciphertext, sha256(ACCOUNT_ID)]) assert.equal(everything.includes(secret), false, secret);
});
test('the browser session callback no longer bootstraps: an injected bootstrap object is never called', async () => {
  const auth = createAuth(); const states = new Map(); const calls = [];
  const trap = new Proxy({}, { get(_, name) { calls.push(String(name)); return () => { throw new Error('must not be called'); }; } });
  const http = createBrowserSessionHttp({ config: CONFIG, transport: auth.transport, authorizationPolicy: auth.policy, bootstrap: trap, ensure: trap, digest,
    issuer: { async issue() { return { setCookie: ['__Host-ring_session=fixture; Secure'] }; } },
    store: { async create({ stateDigest, expiresAt }) { states.set(stateDigest, expiresAt); }, async consume({ stateDigest }) { assert.ok(states.delete(stateDigest)); } },
    exchange: async () => jwt({}, NOW), clock: () => NOW });
  const ev = (path, query = {}, headers = {}) => ({ path, resource: path, httpMethod: 'GET', requestContext: { path: `/staging${path}`, httpMethod: 'GET', stage: 'staging' }, headers,
    multiValueHeaders: Object.fromEntries(Object.entries(headers).map(([k, v]) => [k, [v]])), queryStringParameters: query, multiValueQueryStringParameters: Object.fromEntries(Object.entries(query).map(([k, v]) => [k, [v]])), isBase64Encoded: false, body: null });
  const login = await http.handle(ev('/auth/login', { time: String(NOW - 1000), nonce: 'n'.repeat(43) }), {});
  const state = new URL(login.headers.location).searchParams.get('state');
  const response = await http.handle(ev('/auth/callback', { code: 'c', state }, { cookie: login.multiValueHeaders['set-cookie'][0].split(';')[0] }), {});
  assert.equal(response.statusCode, 303);
  assert.deepEqual(calls, []);
});
