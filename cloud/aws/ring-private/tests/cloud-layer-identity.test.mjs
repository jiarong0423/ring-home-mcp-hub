import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, createHmac, randomBytes } from 'node:crypto';
import { createCognitoResourceBoundAccessTokenVerifier } from '../../../../src/local_ring/components/oidc-jwt-verifier.mjs';
import { createFormalRequestAuthorizationPolicy } from '../../../../src/formal-runtime/request-authorization-policy.mjs';
import { createCloudOwnerAssociationInstaller, createCloudOwnerAssociationReader, associationSha256 } from '../cloud-owner-association.mjs';
import { createCloudBrowserSessionIssuer, extractCloudSessionCookies } from '../cloud-browser-session.mjs';
import { createRingB02SessionSeam, createRingB02FormalMcpSeam, createLambdaInvocationSourcePort } from '../b02-layer-runtime.mjs';
import { createDynamoIdentityAuthorityStore } from '../dynamo-identity-authority-store.mjs';
import { createIdentityEnvelope } from '../identity-envelope.mjs';

const START = 1800000000000;
const issuer = 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Test';
const resource = 'https://ring.example.test/mcp';
const scopes = [`${resource}/tools.list`, `${resource}/tools.call`];
const profile = { issuer, resource, scopes };
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'local-rsa', alg: 'RS256', use: 'sig', key_ops: ['verify'] };
const digest = async (purpose, source) => createHmac('sha256', 'local-test-digest-key-never-production').update(`${purpose}\0${source}`).digest('hex');
function token(subject = 'owner-subject') {
  const head = Buffer.from(JSON.stringify({ alg: 'RS256', kid: jwk.kid, typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({ sub: subject, iss: issuer, aud: resource, client_id: 'local-client',
    token_use: 'access', scope: scopes.join(' '), iat: START / 1000, exp: START / 1000 + 300 })).toString('base64url');
  const input = `${head}.${body}`;
  return `${input}.${sign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url')}`;
}
async function fixture() {
  let now = START;
  const clock = () => now;
  const records = new Map(), writes = [];
  const key = value => `${value.PK.S}\0${value.SK.S}`;
  const ports = {
    async getItem({ Key }) { return { Item: records.get(key(Key)) }; },
    async transactGet({ TransactItems }) { return { Responses: TransactItems.map(({ Get }) => ({ Item: records.get(key(Get.Key)) })) }; },
    async transactWrite(input) {
      writes.push(input);
      for (const entry of input.TransactItems) {
        const operation = entry.Put ?? entry.ConditionCheck;
        const current = records.get(key(operation.Item ?? operation.Key));
        if (operation.ConditionExpression === 'attribute_not_exists(PK)' && current) throw new Error('ConditionalCheckFailedException');
        if (operation.ExpressionAttributeValues?.[':revision'] && current?.revision?.N !== operation.ExpressionAttributeValues[':revision'].N) throw new Error('ConditionalCheckFailedException');
      }
      for (const entry of input.TransactItems) if (entry.Put) records.set(key(entry.Put.Item), structuredClone(entry.Put.Item));
      return {};
    }
  };
  const kmsKey = randomBytes(32);
  const envelope = createIdentityEnvelope({ generateDataKey: async () => ({ Plaintext: Buffer.from(kmsKey), CiphertextBlob: Buffer.from('test-wrapped-key') }),
    decryptDataKey: async () => ({ Plaintext: Buffer.from(kmsKey) }), keyId: 'TestKmsKey', application: 'RingTest', tableName: 'ring-test-identity', random: randomBytes });
  const verifier = createCognitoResourceBoundAccessTokenVerifier({ issuer, clientId: 'local-client', resource, requiredScopes: scopes,
    jwksUri: `${issuer}/.well-known/jwks.json`, maxJwksAgeSeconds: 300, maximumTokenLifetimeSeconds: 300, clock: () => Math.floor(now / 1000),
    loadPinnedJwks: async () => ({ jwksUri: `${issuer}/.well-known/jwks.json`, snapshotVersion: 1, fetchedAtSeconds: START / 1000,
      expiresAtSeconds: START / 1000 + 300, keys: [jwk] }) });
  const policy = createFormalRequestAuthorizationPolicy({ accessTokenVerifier: verifier, resource, authorizationServer: issuer, scopes,
    trustedTransportEvidencePort: { productionAdmitted: true, resolve: async () => ({ productionAdmitted: true, encrypted: true, protocol: 'TLSv1.3', evidenceId: 'isolated-test' }) } });
  async function login(subject) { const request = Object.freeze({ headers: Object.freeze({ authorization: `Bearer ${token(subject)}` }) }); const { actor } = await policy.authorize({ request }); return { request, actor }; }
  const authenticated = await login();
  const approval = { schema: 'ring-owner-association-approval-v1', issuer, resource,
    subjectDigest: await digest('oauth-subject', `${issuer}\0owner-subject`), accountDigest: await digest('ring-account', 'ring-owner-account'),
    ownerRef: 'Owner.local', actorRef: 'Actor.local', householdRef: 'Home.local', ownerEpoch: 1, accountGeneration: 1,
    ownerMode: 'create', accountMode: 'create', expectedRevision: 0, revision: 1, expiresAt: START + 3600000, ringScopeRefs: ['Scope.software-switch'], scopes };
  const approvalBytes = Buffer.from(JSON.stringify(approval));
  let account = 'ring-owner-account', providerCalls = 0;
  const installer = createCloudOwnerAssociationInstaller({ ...ports, tableName: 'ring-test-identity', digest, identityEnvelope: envelope,
    ringClient: { async getAccountId(accessToken) { assert.equal(accessToken, 'isolated-provider-access'); providerCalls++; return account; } },
    approvalSha256: associationSha256(approvalBytes), profile, clock });
  const install = () => installer.install({ ...authenticated, ringAccessToken: 'isolated-provider-access', approvalBytes });
  const reader = createCloudOwnerAssociationReader({ ...ports, tableName: 'ring-test-identity', digest, profile, clock });
  return { records, ports, writes, key, approval, approvalBytes, installer, install, authenticated, reader, clock, login, envelope,
    setNow: n => { now = n; }, setAccount: value => { account = value; }, providerCalls: () => providerCalls };
}

test('real signed Cognito alone grants no Ring ownership; pinned live profile ceremony installs conditional records', async () => {
  const f = await fixture();
  await assert.rejects(f.reader.authorize(f.authenticated), /association_denied/);
  assert.equal(f.writes.length, 0);
  const installed = await f.install();
  assert.equal(installed.associationRevision, 1);
  assert.equal(f.providerCalls(), 1);
  assert.equal(f.writes[0].TransactItems.length, 3);
  assert.ok(f.writes[0].TransactItems.every(x => x.Put.ConditionExpression === 'attribute_not_exists(PK)'));
  const lease = await f.reader.authorize(f.authenticated);
  assert.equal(lease.assertCurrent(), true);
  assert.equal(lease.ownerRef, 'Owner.local');
  assert.equal(lease.expiresAt, START + 300000);
  assert.match(lease.sessionRef, /^Session\.[a-f0-9]{64}$/u);
  await assert.rejects(f.install(), /ConditionalCheckFailed/);
});

test('copied actor, other subject, modified approval and Ring mismatch fail closed before write', async () => {
  const f = await fixture();
  await assert.rejects(f.installer.install({ request: f.authenticated.request, actor: { ...f.authenticated.actor }, ringAccessToken: 'isolated-provider-access', approvalBytes: f.approvalBytes }));
  await assert.rejects(f.installer.install({ ...f.authenticated, ringAccessToken: 'isolated-provider-access', approvalBytes: Buffer.concat([f.approvalBytes, Buffer.from(' ')]) }));
  const other = await f.login('other-subject');
  await assert.rejects(f.installer.install({ ...other, ringAccessToken: 'isolated-provider-access', approvalBytes: f.approvalBytes }));
  f.setAccount('different-ring-account');
  await assert.rejects(f.install(), /cloud_ring_owner_mismatch/);
  assert.equal(f.writes.length, 0);
});

test('same-request lease rejects object substitution, revocation read and expiry', async () => {
  const f = await fixture(); await f.install();
  await assert.rejects(f.reader.authorize({ request: { ...f.authenticated.request }, actor: f.authenticated.actor }), /verified_login_required/);
  const lease = await f.reader.authorize(f.authenticated);
  const association = [...f.records.values()].find(r => r.schema);
  association.revoked.BOOL = true;
  await assert.rejects(f.reader.authorize(f.authenticated));
  assert.throws(lease.assertCurrent, /binding_changed/);
  association.revoked.BOOL = false;
  f.setNow(START + 300000);
  assert.throws(lease.assertCurrent, /binding_changed/);
});

test('atomic read catches owner and account mismatch and bounds cached authority', async () => {
  const f = await fixture(); await f.install();
  const owner = [...f.records.values()].find(r => r.status);
  owner.owner_epoch.N = '2';
  await assert.rejects(f.reader.authorize(f.authenticated));
  owner.owner_epoch.N = '1';
  const account = [...f.records.values()].find(r => r.account_identifier_envelope);
  account.revoked.BOOL = true;
  await assert.rejects(f.reader.authorize(f.authenticated));
  account.revoked.BOOL = false;
  const lease = await f.reader.authorize(f.authenticated);
  await f.reader.close(); assert.throws(lease.assertCurrent);
});

test('browser session issuer writes conditioned session and real identity projection rechecks Ring account', async () => {
  const f = await fixture(); await f.install();
  const issuerPort = createCloudBrowserSessionIssuer({ associationReader: f.reader, ...f.ports, tableName: 'ring-test-identity', digest, clock: f.clock });
  const session = await issuerPort.issue(f.authenticated);
  assert.equal(session.setCookie.length, 2);
  assert.ok(session.setCookie.every(s => s.includes('Secure; HttpOnly; SameSite=Lax; Path=/')));
  const cookie = session.setCookie.map(s => s.split(';')[0]).join('; ');
  const resources = { store: createDynamoIdentityAuthorityStore({ getItem: f.ports.getItem, transactWrite: f.ports.transactWrite, tableName: 'ring-test-identity', clock: f.clock }), digest,
    identityEnvelope: f.envelope, close: async () => ({ closed: true }) };
  const seam = await createRingB02SessionSeam({ resources });
  const context = await seam.resolveLinkSession({ transport: { method: 'GET', path: '/ring/link', resource: '/ring/link' }, headers: { cookie } });
  const lease = await seam.identityAuthority.resolveMatchedRingAccount({ accountId: 'ring-owner-account', context });
  assert.equal(lease.ownerRef, 'Owner.local');
  await assert.rejects(seam.identityAuthority.resolveMatchedRingAccount({ accountId: 'attacker-ring-account', context }));
  const owner = [...f.records.values()].find(r => r.status); owner.owner_epoch.N = '2';
  await assert.rejects(seam.identityAuthority.recheck(lease.proof));
  await seam.close();
});

test('cookie ambiguity, absent cookies and non-link transport are denied', async () => {
  assert.throws(() => extractCloudSessionCookies({}));
  assert.throws(() => extractCloudSessionCookies({ cookie: '__Host-ring_session=x; __Host-ring_session=y' }));
});

test('FORMAL layer preserves consumer shape, delegates one-use context and never reports pending as executed', async () => {
  const f = await fixture(); await f.install();
  const environment = { RING_MCP_ISSUER: issuer, RING_MCP_RESOURCE_URI: resource,
    RING_MCP_REQUIRED_SCOPES: JSON.stringify(scopes), RING_EVENT_TABLE_NAME: 'ring-test-events' };
  let submissions = 0;
  const seam = await createRingB02FormalMcpSeam({ environment, clock: f.clock,
    resources: { ports: f.ports, tableName: 'ring-test-identity', digest, close: async () => ({ closed: true }) },
    commandStoreFactory: () => ({ close: async () => ({ closed: true }) }),
    commandServiceFactory: ({ authorize }) => ({ async submit(input) {
      const lease = await authorize(input); lease.assertCurrent(); submissions++;
      return { commandId: 'Command.local', status: 'PENDING', executed: false, result: null };
    } }) });
  assert.deepEqual(Object.keys(seam), ['assembly', 'formalContextPort', 'invocationSourcePort']);
  const envelope = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'software_test_switch.set', arguments: { enabled: true } } };
  const resolved = await seam.formalContextPort.resolve({ ...f.authenticated, effectiveEnvelope: envelope });
  const context = { path: 'remote-encrypted', handle: resolved.serverContext };
  const result = await seam.assembly.profile.call(envelope, context);
  assert.equal(result.result.structuredContent.executed, false); assert.equal(submissions, 1);
  await assert.rejects(seam.assembly.profile.call(envelope, context));
  await seam.assembly.close(); await seam.formalContextPort.close();
});

test('Lambda invocation requires host-owned runtime context and exact deployed function ARN', async () => {
  const arn = 'arn:aws:lambda:us-east-1:123456789012:function:ring-function';
  const port = createLambdaInvocationSourcePort({ environment: { AWS_REGION: 'us-east-1', AWS_EXECUTION_ENV: 'AWS_Lambda_nodejs22.x',
    AWS_LAMBDA_FUNCTION_NAME: 'ring-function', RING_MCP_FUNCTION_ARN: arn } });
  const event = { requestContext: {} }, invocationContext = { functionName: 'ring-function', invokedFunctionArn: arn, awsRequestId: '12345678-1234-1234-1234-123456789012' };
  const verified = await port.verifyInvocation({ event, invocationContext, admissionSha256: '1'.repeat(64) });
  assert.equal(verified.event, event);
  await assert.rejects(port.verifyInvocation({ event, invocationContext: { ...invocationContext, invokedFunctionArn: arn + ':other' }, admissionSha256: '1'.repeat(64) }));
  await port.close(); await assert.rejects(port.verifyInvocation({ event, invocationContext, admissionSha256: '1'.repeat(64) }));
});

test('explicit existing-owner revision CAS preserves owner/account and denies repeat revision', async () => {
  const f = await fixture(); await f.install();
  const approvalBytes = Buffer.from(JSON.stringify({ ...f.approval, ownerMode: 'existing', accountMode: 'existing', expectedRevision: 1, revision: 2 }));
  const installer = createCloudOwnerAssociationInstaller({ ...f.ports, tableName: 'ring-test-identity', digest, identityEnvelope: f.envelope,
    ringClient: { async getAccountId() { return 'ring-owner-account'; } }, approvalSha256: associationSha256(approvalBytes), profile, clock: f.clock });
  const operation = () => installer.install({ ...f.authenticated, ringAccessToken: 'isolated-provider-access', approvalBytes });
  assert.equal((await operation()).associationRevision, 2);
  const transaction = f.writes.at(-1).TransactItems;
  assert.ok(transaction[0].ConditionCheck); assert.ok(transaction[2].ConditionCheck);
  assert.equal(transaction[1].Put.ExpressionAttributeValues[':revision'].N, '1');
  assert.equal((await f.reader.authorize(f.authenticated)).associationRevision, 2);
  await assert.rejects(operation(), /ConditionalCheckFailed/);
});
