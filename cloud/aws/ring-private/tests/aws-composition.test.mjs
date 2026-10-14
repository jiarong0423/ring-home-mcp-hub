import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createAwsComposition,
  normalizeAwsCompositionOptions,
  parseNonsecretAwsEnvironment,
  validateAwsCompositionConfig
} from '../aws-composition.mjs';

const now = 1_791_000_000_000;
const providerArn = 'arn:aws:secretsmanager:ap-southeast-1:111111111111:secret:generated-provider';
const digestArn = 'arn:aws:secretsmanager:ap-southeast-1:111111111111:secret:generated-digest';
const telegramArn = 'arn:aws:secretsmanager:ap-southeast-1:111111111111:secret:generated-telegram';
const telegramVersion = 't'.repeat(32);
const providerVersion = 'p'.repeat(32);
const digestVersion = 'd'.repeat(32);

function config(change = {}) {
  return {
    region: 'ap-southeast-1',
    tableName: 'GeneratedRingTable',
    indexName: 'GSI1',
    kmsKeyId: 'alias/generated-ring',
    providerSecretArn: providerArn,
    providerSecretVersionId: providerVersion,
    digestSecretArn: digestArn,
    digestSecretVersionId: digestVersion,
    application: 'ring-private',
    secretCacheTtlMs: 30_000,
    providerTimeoutMs: 100,
    completionTtlSeconds: 120,
    ...change
  };
}

function awsPorts(calls) {
  return {
    async query(input) {
      calls.push(['query', input]);
      return { Items: [] };
    },
    async getItem(input) {
      calls.push(['getItem', input]);
      return {};
    },
    async transactWrite(input) {
      calls.push(['transactWrite', input]);
      return {};
    },
    async generateDataKey(input) {
      calls.push(['generateDataKey', input]);
      return { Plaintext: Buffer.alloc(32, 1), CiphertextBlob: Buffer.from('generated-wrapped-key') };
    },
    async decryptDataKey(input) {
      calls.push(['decryptDataKey', input]);
      return { Plaintext: Buffer.alloc(32, 1) };
    },
    async getSecretValue(input) {
      calls.push(['getSecretValue', input]);
      const digest = input.SecretId === digestArn;
      return {
        VersionId: digest ? digestVersion : providerVersion,
        SecretString: JSON.stringify(digest
          ? {
              version: 1,
              recordHmacKey: 'generated-record-key-at-least-thirty-two-bytes',
              cookieHmacKey: 'generated-cookie-key-at-least-thirty-two-bytes'
            }
          : {
              version: 1,
              clientId: 'generated-client',
              clientSecret: 'generated-client-secret',
              nonceKey: 'generated-nonce-key-at-least-thirty-two-bytes'
            })
      };
    }
  };
}

function options(change = {}) {
  const calls = [];
  const authorityCalls = [];
  const tokenContext = Object.freeze({ admission: 'generated-token-transport-fixture' });
  const sessionContext = Object.freeze({ admission: 'generated-link-session-fixture' });
  const value = {
    config: config(),
    awsPorts: awsPorts(calls),
    identityAuthority: {
      async resolveMatchedRingAccount() {
        throw Error('local-identity-denied');
      },
      async recheck() {
        throw Error('local-identity-denied');
      }
    },
    async tokenTransportResolver(transport) {
      authorityCalls.push(['token-resolver', transport]);
      return tokenContext;
    },
    async linkSessionResolver(input) {
      authorityCalls.push(['link-resolver', input]);
      return sessionContext;
    },
    async fetchImpl() {
      throw Error('provider-call-not-expected');
    },
    clock: () => now,
    random: size => Buffer.alloc(size, 7),
    ...change
  };
  return { value, calls, authorityCalls, tokenContext, sessionContext };
}

function formalOptions(change = {}) {
  const fixture = options({ config: config({ telegramSecretArn: telegramArn, telegramSecretVersionId: telegramVersion }),
    sessionContextExtractor() { return { sessionProof: 'proof/generated', csrf: 'csrf/generated' }; },
    localSessionPort: { async withCurrentSession(input, perform) { return perform({ ownerRef: 'owner/generated' }); } },
    ownMcpPort: { authorizeCapability() { return { authorized: true, authorizationRef: 'authorization/generated', expiresAt: now + 60_000 }; } },
    capabilityChannelPort: { async sealIntent(value) { return value; }, async deliverSealedIntent(value) { return value; },
      async verifyReceipt({ intent }) { return { intentId: intent.id, receivedAt: now, accepted: true }; } },
    capabilityAdapters: ['ring', ...Array.from({ length: 6 }, (_, index) => Buffer.alloc(32, index + 1).toString('base64url'))]
      .map((categoryRef, index) => ({ categoryRef, generation: index + 1, adapter: { projectIntent() { return { operation: 'read' }; } } })),
    ...change });
  delete fixture.value.identityAuthority;
  return fixture;
}

function event(path = '/ring/token') {
  const method = path === '/ring/token' ? 'POST' : 'GET';
  const headers = method === 'POST' ? { 'Content-Type': 'application/x-www-form-urlencoded' } : {};
  const query = path === '/ring/link' ? { time: String(now), nonce: 'A'.repeat(43) } : null;
  return {
    resource: path,
    path,
    httpMethod: method,
    headers,
    multiValueHeaders: Object.fromEntries(Object.entries(headers).map(([key, value]) => [key, [value]])),
    queryStringParameters: query,
    multiValueQueryStringParameters: query === null
      ? null
      : Object.fromEntries(Object.entries(query).map(([key, value]) => [key, [value]])),
    pathParameters: null,
    stageVariables: null,
    requestContext: { stage: 'prod', httpMethod: method, resourcePath: path, path: '/prod' + path },
    body: method === 'POST' ? Buffer.from('code=generated').toString('base64') : null,
    isBase64Encoded: method === 'POST'
  };
}

test('strict nonsecret environment accepts only the finite allowlist and converts bounded integers', () => {
  const parsed = parseNonsecretAwsEnvironment({
    AWS_REGION: 'ap-southeast-1',
    RING_LINK_TABLE_NAME: 'GeneratedRingTable',
    RING_LINK_INDEX_NAME: 'GSI1',
    RING_TOKEN_KMS_KEY_ID: 'alias/generated-ring',
    RING_PROVIDER_SECRET_ARN: providerArn,
    RING_PROVIDER_SECRET_VERSION_ID: providerVersion,
    RING_DIGEST_SECRET_ARN: digestArn,
    RING_DIGEST_SECRET_VERSION_ID: digestVersion,
    RING_APPLICATION: 'ring-private',
    RING_SECRET_CACHE_TTL_MS: '30000',
    RING_PROVIDER_TIMEOUT_MS: '100',
    RING_COMPLETION_TTL_SECONDS: '120'
  });
  assert.deepEqual(parsed, config());
  assert.equal(Object.isFrozen(parsed), true);
  assert.throws(() => parseNonsecretAwsEnvironment({
    AWS_REGION: 'ap-southeast-1',
    RING_LINK_TABLE_NAME: 'GeneratedRingTable',
    RING_TOKEN_KMS_KEY_ID: 'alias/generated-ring',
    RING_PROVIDER_SECRET_ARN: providerArn,
    RING_PROVIDER_SECRET_VERSION_ID: providerVersion,
    RING_DIGEST_SECRET_ARN: digestArn,
    RING_DIGEST_SECRET_VERSION_ID: digestVersion,
    AWS_ACCESS_KEY_ID: 'forbidden'
  }), /aws_environment_config/);
});

test('composition config rejects unknown, credential-like, cross-region and endpoint fields', () => {
  assert.throws(() => validateAwsCompositionConfig(config({ endpoint: 'https://example.test' })), /aws_composition_config/);
  assert.throws(() => validateAwsCompositionConfig(config({ credentials: { accessKeyId: 'forbidden' } })), /aws_composition_config/);
  assert.throws(() => validateAwsCompositionConfig(config({ providerSecretArn: providerArn.replace('ap-southeast-1', 'us-east-1') })), /aws_composition_config/);
  assert.throws(() => validateAwsCompositionConfig(config({ digestSecretArn: providerArn })), /aws_composition_config/);
  assert.throws(() => validateAwsCompositionConfig(config({ providerSecretVersionId: undefined })), /aws_composition_config/);
  assert.throws(() => validateAwsCompositionConfig(config({ digestSecretVersionId: 'short' })), /aws_composition_config/);
});

test('formal Telegram config is all-or-nothing, pinned, distinct and region-bound', () => {
  assert.equal(validateAwsCompositionConfig(config({ telegramSecretArn: telegramArn,
    telegramSecretVersionId: telegramVersion })).telegramSecretVersionId, telegramVersion);
  assert.throws(() => validateAwsCompositionConfig(config({ telegramSecretArn: telegramArn })), /aws_composition_config/);
  assert.throws(() => validateAwsCompositionConfig(config({ telegramSecretArn: telegramArn,
    telegramSecretVersionId: 'short' })), /aws_composition_config/);
  assert.throws(() => validateAwsCompositionConfig(config({ telegramSecretArn: providerArn,
    telegramSecretVersionId: telegramVersion })), /aws_composition_config/);
});

test('formal composition requires all authority and outbound-only capability ports', () => {
  for (const key of ['sessionContextExtractor', 'localSessionPort', 'ownMcpPort', 'capabilityChannelPort', 'capabilityAdapters']) {
    const fixture = formalOptions();
    delete fixture.value[key];
    assert.throws(() => normalizeAwsCompositionOptions(fixture.value), /aws_composition_config/);
  }
});

test('formal composition exposes projection and capability contracts while malformed webhook stops pre-secret', async () => {
  const fixture = formalOptions();
  const composition = await createAwsComposition(fixture.value);
  assert.equal(typeof composition.projectFirstAccount, 'function');
  assert.equal(typeof composition.capabilityContract.authorizeLocal, 'function');
  const input = event();
  input.resource = '/telegram/webhook'; input.path = '/telegram/webhook';
  input.requestContext.resourcePath = '/telegram/webhook'; input.requestContext.path = '/prod/telegram/webhook';
  input.headers = { 'Content-Type': 'application/json', 'X-Telegram-Bot-Api-Secret-Token': 'short' };
  input.multiValueHeaders = { 'Content-Type': ['application/json'], 'X-Telegram-Bot-Api-Secret-Token': ['short'] };
  input.body = Buffer.from('{}').toString('base64');
  assert.equal((await composition.dispatch(input)).statusCode, 400);
  assert.deepEqual(fixture.calls.map(([name, value]) => [name, value.SecretId]), [['getSecretValue', digestArn]]);
});

test('identity, route-specific resolver, fetch, clock and random dependencies are mandatory explicit injections', () => {
  for (const key of [
    'identityAuthority', 'tokenTransportResolver', 'linkSessionResolver',
    'fetchImpl', 'clock', 'random'
  ]) {
    const fixture = options();
    delete fixture.value[key];
    assert.throws(() => normalizeAwsCompositionOptions(fixture.value), /aws_composition_config/);
    assert.equal(fixture.calls.length, 0);
    assert.equal(fixture.authorityCalls.length, 0);
  }
  const fixture = options();
  delete fixture.value.tokenTransportResolver;
  delete fixture.value.linkSessionResolver;
  fixture.value.sharedResolver = async () => ({ generated: true });
  assert.throws(() => normalizeAwsCompositionOptions(fixture.value), /aws_composition_config/);
});

test('token transport gate stays pre-intake and its result never crosses into source proof', async () => {
  const fixture = options();
  const composition = await createAwsComposition(fixture.value);
  assert.deepEqual(fixture.calls.map(([name, input]) => [name, input.SecretId]), [['getSecretValue', digestArn]]);
  const response = await composition.dispatch(event());
  assert.equal(response.statusCode, 503);
  assert.deepEqual(JSON.parse(response.body), {
    status: 'unavailable',
    bindingCompleted: false,
    retryAllowed: false,
    productionAdmitted: false
  });
  assert.equal(fixture.authorityCalls.length, 1);
  assert.equal(fixture.authorityCalls[0][0], 'token-resolver');
  assert.equal(JSON.stringify(fixture.calls).includes(fixture.tokenContext.admission), false);
  assert.equal(fixture.calls.filter(([name]) => name === 'transactWrite').length, 1);
  assert.equal(fixture.calls.some(([name]) => ['query', 'generateDataKey', 'decryptDataKey'].includes(name)), false);
});

test('composition keeps link session resolution separate and forwards only frozen transport plus Cookie subset', async () => {
  const fixture = options();
  const composition = await createAwsComposition(fixture.value);
  const input = event('/ring/link');
  input.headers.Cookie = 'session=generated';
  input.multiValueHeaders.Cookie = ['session=generated'];
  input.headers.Authorization = 'must-not-cross';
  input.multiValueHeaders.Authorization = ['must-not-cross'];
  input.requestContext.authorizer = { actor: 'forged' };
  input.requestContext.identity = { sourceIp: '192.0.2.2' };
  const response = await composition.dispatch(input);
  assert.equal(response.statusCode, 303);
  assert.equal(fixture.authorityCalls.length, 1);
  assert.equal(fixture.authorityCalls[0][0], 'link-resolver');
  const resolverInput = fixture.authorityCalls[0][1];
  assert.equal(Object.isFrozen(resolverInput), true);
  assert.deepEqual(resolverInput.transport, {
    method: 'GET', path: '/ring/link', resource: '/ring/link', stage: 'prod'
  });
  assert.equal(Object.isFrozen(resolverInput.transport), true);
  assert.deepEqual({ ...resolverInput.headers }, { cookie: 'session=generated' });
  assert.equal(Object.isFrozen(resolverInput.headers), true);
  assert.equal(JSON.stringify(resolverInput).includes('must-not-cross'), false);
  assert.equal(JSON.stringify(resolverInput).includes('forged'), false);
  assert.equal(JSON.stringify(resolverInput).includes('192.0.2.2'), false);
  assert.deepEqual(fixture.calls.map(([name]) => name), ['getSecretValue', 'getSecretValue', 'query']);
});

test('completion route is display-only, skips resolver and stays finite with an invalid cookie', async () => {
  const fixture = options();
  const composition = await createAwsComposition(fixture.value);
  const input = event('/ring/complete');
  input.headers = { Cookie: '__Host-ring_link=invalid.invalid' };
  input.multiValueHeaders = { Cookie: ['__Host-ring_link=invalid.invalid'] };
  const response = await composition.dispatch(input);
  assert.equal(response.statusCode, 403);
  assert.match(response.body, /Ring 綁定未完成/);
  assert.equal(fixture.authorityCalls.length, 0);
  assert.equal(fixture.calls.length, 1);
});
