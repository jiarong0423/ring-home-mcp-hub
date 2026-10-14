import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SECRET_SCHEMA_VERSION,
  SecretLoaderError,
  createSecretLoader
} from '../secret-loader.mjs';

const providerArn = 'arn:aws:secretsmanager:ap-southeast-1:123456789012:secret:ring-home-mcp/provider-Ab12Cd';
const digestArn = 'arn:aws:secretsmanager:ap-southeast-1:123456789012:secret:ring-home-mcp/digest-Ef34Gh';
const telegramArn = 'arn:aws:secretsmanager:ap-southeast-1:123456789012:secret:ring-home-mcp/telegram-Ij56Kl';
const versionOne = 'a'.repeat(32);
const versionTwo = 'b'.repeat(32);
const versionStale = 's'.repeat(32);
const versionCurrent = 'q'.repeat(32);
const provider = Object.freeze({
  version: SECRET_SCHEMA_VERSION,
  clientId: 'generated-client-id',
  clientSecret: 'c'.repeat(32),
  nonceKey: 'n'.repeat(32),
  webhookSigningKey: 'w'.repeat(32)
});
const digest = Object.freeze({
  version: SECRET_SCHEMA_VERSION,
  recordHmacKey: 'r'.repeat(32),
  cookieHmacKey: 'k'.repeat(32)
});
function telegramSecret(botGeneration = 1) {
  const botId = '20001';
  return Object.freeze({
    version: SECRET_SCHEMA_VERSION,
    token: `${botId}:${'T'.repeat(32)}`,
    botId,
    username: 'Homemcphub_bot',
    botGeneration,
    webhookSecret: 'W'.repeat(32)
  });
}

function response(value, versionId = versionOne, binary = false) {
  const encoded = JSON.stringify(value);
  return binary
    ? { SecretBinary: Uint8Array.from(Buffer.from(encoded, 'utf8')), VersionId: versionId }
    : { SecretString: encoded, VersionId: versionId };
}

function fixture({ handler, cacheTtlMs = 100, start = 1000 } = {}) {
  const calls = [];
  let now = start;
  const getSecretValue = async input => {
    calls.push(input);
    if (handler) return handler(input, calls.length);
    if (input.SecretId === providerArn) return response(provider);
    if (input.SecretId === digestArn) return response(digest);
    return response(telegramSecret());
  };
  return {
    calls,
    advance(milliseconds) { now += milliseconds; },
    setTime(milliseconds) { now = milliseconds; },
    loader: createSecretLoader({
      getSecretValue,
      providerSecretArn: providerArn,
      digestSecretArn: digestArn,
      telegramSecretArn: telegramArn,
      cacheTtlMs,
      clock: () => now
    })
  };
}

function isCode(code) {
  return error => error instanceof SecretLoaderError && error.code === code && error.message === code;
}

test('uses exact, separate provider and digest ARNs and exposes finite metadata', async () => {
  const { loader, calls } = fixture();
  const providerResult = await loader.loadProvider();
  const digestResult = await loader.loadDigest();
  assert.deepEqual(calls, [
    { SecretId: providerArn, VersionStage: 'AWSCURRENT' },
    { SecretId: digestArn, VersionStage: 'AWSCURRENT' }
  ]);
  assert.deepEqual(providerResult.secret, provider);
  assert.deepEqual(digestResult.secret, digest);
  assert.deepEqual(Object.keys(providerResult.metadata).sort(),
    ['cacheStatus', 'expiresAt', 'kind', 'loadedAt', 'versionId']);
  assert.equal('secretArn' in providerResult.metadata, false);
  assert.equal(JSON.stringify(providerResult).includes(providerArn), false);
  assert.equal(JSON.stringify(providerResult.metadata).includes(provider.clientSecret), false);
  assert.equal(JSON.stringify(providerResult.metadata).includes(provider.nonceKey), false);
});

test('provider and digest factory pins fetch exact VersionId, propagate AbortSignal, and never request AWSCURRENT', async () => {
  const calls = [];
  const controller = new AbortController();
  const loader = createSecretLoader({
    getSecretValue: async (input, options) => {
      calls.push({ input, options });
      return input.SecretId === providerArn
        ? response(provider, versionOne)
        : response(digest, versionTwo);
    },
    providerSecretArn: providerArn,
    providerSecretVersionId: versionOne,
    digestSecretArn: digestArn,
    digestSecretVersionId: versionTwo,
    clock: () => 1000
  });
  await loader.loadProvider({ signal: controller.signal });
  await loader.loadDigest({ signal: controller.signal });
  assert.deepEqual(calls.map(call => call.input), [
    { SecretId: providerArn, VersionId: versionOne },
    { SecretId: digestArn, VersionId: versionTwo }
  ]);
  assert.equal(calls.every(call => call.options.signal === controller.signal), true);
  assert.equal(JSON.stringify(calls.map(call => call.input)).includes('AWSCURRENT'), false);
  await assert.rejects(
    loader.loadProvider({ expectedVersionId: versionTwo }),
    isCode('secret_loader_options')
  );
  assert.equal(calls.length, 2);
});

test('pinned loads without AbortSignal call the AWS port with exactly one argument', async () => {
  const calls = [];
  const loader = createSecretLoader({
    async getSecretValue(input) {
      calls.push({ input, argumentCount: arguments.length });
      return input.SecretId === providerArn
        ? response(provider, versionOne)
        : response(digest, versionTwo);
    },
    providerSecretArn: providerArn,
    providerSecretVersionId: versionOne,
    digestSecretArn: digestArn,
    digestSecretVersionId: versionTwo,
    clock: () => 1000
  });
  await loader.loadProvider();
  await loader.loadDigest();
  assert.deepEqual(calls, [
    { input: { SecretId: providerArn, VersionId: versionOne }, argumentCount: 1 },
    { input: { SecretId: digestArn, VersionId: versionTwo }, argumentCount: 1 }
  ]);
  assert.equal(JSON.stringify(calls.map(call => call.input)).includes('AWSCURRENT'), false);
});

test('rejects invalid, duplicate, or incomplete ARN configuration before retrieval', () => {
  const base = { getSecretValue: async () => response(provider), providerSecretArn: providerArn, digestSecretArn: digestArn };
  assert.throws(() => createSecretLoader({ ...base, providerSecretArn: 'ring-provider' }), isCode('secret_loader_config'));
  assert.throws(() => createSecretLoader({ ...base, digestSecretArn: providerArn }), isCode('secret_loader_config'));
  assert.throws(() => createSecretLoader({
    ...base,
    digestSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:ring-home-mcp/digest-Ef34Gh'
  }), isCode('secret_loader_config'));
  assert.throws(() => createSecretLoader({
    ...base,
    digestSecretArn: 'arn:aws-cn:secretsmanager:cn-north-1:123456789012:secret:ring-home-mcp/digest-Ef34Gh'
  }), isCode('secret_loader_config'));
  assert.throws(() => createSecretLoader({ ...base, getSecretValue: null }), isCode('secret_loader_config'));
  assert.throws(() => createSecretLoader({ ...base, cacheTtlMs: 300_001 }), isCode('secret_loader_config'));
  assert.throws(() => createSecretLoader({ ...base, providerSecretVersionId: 'short' }), isCode('secret_loader_config'));
  assert.throws(() => createSecretLoader({ ...base, digestSecretVersionId: 'short' }), isCode('secret_loader_config'));
  for (const invalidArn of [
    'arn:aws:secretsmanager:cn-north-1:123456789012:secret:ring-home-mcp/provider-Ab12Cd',
    'arn:aws-cn:secretsmanager:ap-southeast-1:123456789012:secret:ring-home-mcp/provider-Ab12Cd',
    'arn:aws-us-gov:secretsmanager:us-east-1:123456789012:secret:ring-home-mcp/provider-Ab12Cd',
    'arn:aws:secretsmanager:ap-southeast-0:123456789012:secret:ring-home-mcp/provider-Ab12Cd',
    'arn:aws:secretsmanager:ap-southeast-1:1234:secret:ring-home-mcp/provider-Ab12Cd',
    'arn:aws:s3:ap-southeast-1:123456789012:secret:ring-home-mcp/provider-Ab12Cd'
  ]) {
    assert.throws(() => createSecretLoader({ ...base, providerSecretArn: invalidArn }), isCode('secret_loader_config'));
  }
  assert.doesNotThrow(() => createSecretLoader({
    ...base,
    providerSecretArn: 'arn:aws-cn:secretsmanager:cn-north-1:123456789012:secret:ring/provider-Ab12Cd',
    digestSecretArn: 'arn:aws-cn:secretsmanager:cn-north-1:123456789012:secret:ring/digest-Ef34Gh'
  }));
  assert.doesNotThrow(() => createSecretLoader({
    ...base,
    providerSecretArn: 'arn:aws-us-gov:secretsmanager:us-gov-west-1:123456789012:secret:ring/provider-Ab12Cd',
    digestSecretArn: 'arn:aws-us-gov:secretsmanager:us-gov-west-1:123456789012:secret:ring/digest-Ef34Gh'
  }));
});

test('factory and load options are exact, descriptor-safe, and redact hostile traps', async () => {
  const base = { getSecretValue: async () => response(provider), providerSecretArn: providerArn, digestSecretArn: digestArn };
  const sensitive = 'generated-hostile-option-' + 'x'.repeat(32);
  let getterCalls = 0;
  const getterConfig = { ...base };
  Object.defineProperty(getterConfig, 'cacheTtlMs', {
    enumerable: true,
    get() { getterCalls += 1; throw new Error(sensitive); }
  });
  assert.throws(() => createSecretLoader(getterConfig), error => {
    assert.equal(isCode('secret_loader_config')(error), true);
    assert.equal(error.message.includes(sensitive), false);
    return true;
  });
  assert.equal(getterCalls, 0);
  assert.throws(() => createSecretLoader(null), isCode('secret_loader_config'));
  assert.throws(() => createSecretLoader({ ...base, unknown: true }), isCode('secret_loader_config'));
  assert.throws(() => createSecretLoader(new Proxy(base, {
    ownKeys() { throw new Error(sensitive); }
  })), isCode('secret_loader_config'));

  const { loader, calls } = fixture();
  let loadGetterCalls = 0;
  const getterOptions = {};
  Object.defineProperty(getterOptions, 'forceRefresh', {
    enumerable: true,
    get() { loadGetterCalls += 1; throw new Error(sensitive); }
  });
  for (const options of [
    null,
    { forceRefresh: true, unknown: true },
    getterOptions,
    new Proxy({}, { ownKeys() { throw new Error(sensitive); } })
  ]) {
    await assert.rejects(loader.loadProvider(options), error => {
      assert.equal(isCode('secret_loader_options')(error), true);
      assert.equal(error.message.includes(sensitive), false);
      return true;
    });
  }
  assert.equal(loadGetterCalls, 0);
  assert.equal(calls.length, 0);
});

test('enforces schema version, required fields, allowlisted fields, types, and byte lengths', async () => {
  const invalid = [
    { ...provider, version: 2 },
    { version: 1, clientId: provider.clientId, clientSecret: provider.clientSecret, nonceKey: provider.nonceKey, extra: 'denied' },
    { version: 1, clientId: provider.clientId, clientSecret: provider.clientSecret },
    { ...provider, clientId: 42 },
    { ...provider, clientSecret: 'short' },
    { ...provider, nonceKey: 'short' },
    { ...provider, webhookSigningKey: 'short' }
  ];
  for (const value of invalid) {
    const { loader } = fixture({ handler: async () => response(value) });
    await assert.rejects(loader.loadProvider(), isCode('secret_schema_invalid'));
  }
  for (const value of [
    { ...digest, version: '1' },
    { version: 1, recordHmacKey: digest.recordHmacKey },
    { ...digest, providerKey: 'x'.repeat(32) },
    { ...digest, cookieHmacKey: '' }
  ]) {
    const { loader } = fixture({ handler: async () => response(value) });
    await assert.rejects(loader.loadDigest(), isCode('secret_schema_invalid'));
  }
});

test('supports bounded UTF-8 SecretBinary and rejects ambiguous or malformed responses', async () => {
  const binary = fixture({ handler: input => response(input.SecretId === providerArn ? provider : digest, versionTwo, true) });
  assert.deepEqual((await binary.loader.loadProvider()).secret, provider);
  assert.deepEqual((await binary.loader.loadDigest()).secret, digest);

  const malformedResponses = [
    {},
    { SecretString: JSON.stringify(provider) },
    { SecretString: JSON.stringify(provider), SecretBinary: Buffer.from('{}'), VersionId: versionOne },
    { SecretBinary: Uint8Array.of(0xff, 0xfe), VersionId: versionOne },
    { SecretString: '{', VersionId: versionOne },
    { SecretString: JSON.stringify(provider), VersionId: '' }
  ];
  for (const malformed of malformedResponses) {
    const { loader } = fixture({ handler: async () => malformed });
    await assert.rejects(loader.loadProvider(), isCode('secret_response_invalid'));
  }
});

test('rejects VersionId outside 32 to 64 safe characters', async () => {
  for (const versionId of ['v'.repeat(31), 'v'.repeat(65), 'v'.repeat(31) + ':']) {
    const { loader } = fixture({ handler: async () => response(provider, versionId) });
    await assert.rejects(loader.loadProvider(), isCode('secret_response_invalid'));
  }
  for (const versionId of ['v'.repeat(32), 'v'.repeat(64)]) {
    const { loader } = fixture({ handler: async () => response(provider, versionId) });
    assert.equal((await loader.loadProvider()).metadata.versionId, versionId);
  }
});

test('rejects unpaired Unicode surrogates in SecretString and parsed fields', async () => {
  const rawUnpaired = JSON.stringify(provider).replace('generated-client-id', `generated-\ud800-client`);
  const raw = fixture({ handler: async () => ({ SecretString: rawUnpaired, VersionId: versionOne }) });
  await assert.rejects(raw.loader.loadProvider(), isCode('secret_response_invalid'));

  const escaped = JSON.stringify({ ...provider, clientId: `generated-\ud800-client` });
  const parsed = fixture({ handler: async () => ({ SecretString: escaped, VersionId: versionOne }) });
  await assert.rejects(parsed.loader.loadProvider(), isCode('secret_schema_invalid'));
});

test('returns cache hits before bounded TTL and refreshes after expiry', async () => {
  const { loader, calls, advance } = fixture({ cacheTtlMs: 100 });
  const first = await loader.loadProvider();
  advance(99);
  const cached = await loader.loadProvider();
  assert.equal(cached.metadata.cacheStatus, 'hit');
  assert.equal(cached.metadata.versionId, first.metadata.versionId);
  assert.equal(calls.length, 1);
  advance(1);
  const refreshed = await loader.loadProvider();
  assert.equal(refreshed.metadata.cacheStatus, 'miss');
  assert.equal(calls.length, 2);
});

test('refreshes a rotated VersionId after expiry or force refresh', async () => {
  const rotated = { ...provider, clientSecret: 'z'.repeat(32) };
  const { loader, advance } = fixture({
    cacheTtlMs: 50,
    handler: async (_input, count) => count === 1 ? response(provider, versionOne) : response(rotated, versionTwo)
  });
  assert.equal((await loader.loadProvider()).metadata.versionId, versionOne);
  advance(50);
  const afterExpiry = await loader.loadProvider();
  assert.equal(afterExpiry.metadata.versionId, versionTwo);
  assert.equal(afterExpiry.secret.clientSecret, rotated.clientSecret);

  const forced = await loader.loadProvider({ forceRefresh: true });
  assert.equal(forced.metadata.cacheStatus, 'miss');
});

test('invalidate can target one secret or both secrets', async () => {
  const { loader, calls } = fixture();
  await loader.loadProvider();
  await loader.loadDigest();
  loader.invalidate('provider');
  await loader.loadProvider();
  await loader.loadDigest();
  assert.deepEqual(calls.map(call => call.SecretId), [providerArn, digestArn, providerArn]);
  loader.invalidate();
  await loader.loadProvider();
  await loader.loadDigest();
  assert.equal(calls.length, 5);
  assert.throws(() => loader.invalidate('unknown'), isCode('secret_loader_kind'));
  assert.throws(() => loader.invalidate({
    [Symbol.toPrimitive]() { throw new Error('generated-sensitive-conversion'); }
  }), isCode('secret_loader_kind'));
});

test('coalesces concurrent reads while preserving provider and digest separation', async () => {
  const releases = new Map();
  const { loader, calls } = fixture({ handler: input => new Promise(resolve => releases.set(input.SecretId, resolve)) });
  const providerReads = [loader.loadProvider(), loader.loadProvider(), loader.loadProvider()];
  const digestRead = loader.loadDigest();
  assert.equal(calls.length, 2);
  releases.get(providerArn)(response(provider));
  releases.get(digestArn)(response(digest));
  const results = await Promise.all([...providerReads, digestRead]);
  assert.equal(results.filter(item => item.metadata.kind === 'provider').length, 3);
  assert.equal(results.at(-1).metadata.kind, 'digest');
});

test('coalesces concurrent force refreshes into one upstream request', async () => {
  let release;
  const { loader, calls } = fixture({
    handler: async (_input, count) => {
      if (count === 1) return response(provider, versionOne);
      return new Promise(resolve => { release = resolve; });
    }
  });
  await loader.loadProvider();
  const first = loader.loadProvider({ forceRefresh: true });
  const second = loader.loadProvider({ forceRefresh: true });
  const third = loader.loadProvider({ forceRefresh: true });
  assert.equal(calls.length, 2);
  release(response({ ...provider, clientSecret: 'f'.repeat(32) }, versionTwo));
  const results = await Promise.all([first, second, third]);
  assert.deepEqual(results.map(item => item.metadata.versionId), [versionTwo, versionTwo, versionTwo]);
  assert.equal(calls.length, 2);
});

test('invalidate prevents an older in-flight response from repopulating cache', async () => {
  const releases = [];
  const { loader, calls } = fixture({ handler: () => new Promise(resolve => releases.push(resolve)) });
  const stale = loader.loadProvider();
  loader.invalidate('provider');
  const current = loader.loadProvider();
  releases[0](response(provider, versionStale));
  releases[1](response({ ...provider, clientSecret: 'q'.repeat(32) }, versionCurrent));
  await assert.rejects(stale, isCode('secret_superseded'));
  assert.equal((await current).metadata.versionId, versionCurrent);
  assert.equal((await loader.loadProvider()).metadata.versionId, versionCurrent);
  assert.equal(calls.length, 2);
});

test('clock rollback invalidates cache, fails closed once, then refreshes', async () => {
  const { loader, calls, advance, setTime } = fixture({ cacheTtlMs: 500, start: 1000 });
  await loader.loadProvider();
  advance(100);
  assert.equal((await loader.loadProvider()).metadata.cacheStatus, 'hit');
  setTime(900);
  await assert.rejects(loader.loadProvider(), isCode('secret_loader_clock_rollback'));
  const refreshed = await loader.loadProvider();
  assert.equal(refreshed.metadata.cacheStatus, 'miss');
  assert.equal(calls.length, 2);
});

test('redacts upstream failures and never embeds sensitive content in errors', async () => {
  const sensitive = 'generated-sensitive-upstream-detail-' + 's'.repeat(32);
  const { loader } = fixture({ handler: async () => { throw new Error(sensitive); } });
  await assert.rejects(loader.loadProvider(), error => {
    assert.ok(error instanceof SecretLoaderError);
    assert.equal(error.code, 'secret_unavailable');
    assert.equal(error.message.includes(sensitive), false);
    assert.equal(JSON.stringify(error).includes(sensitive), false);
    assert.equal('cause' in error, false);
    return true;
  });

  const hostile = fixture({
    handler: async () => Object.defineProperty({}, 'SecretString', {
      get() { throw new Error(sensitive); }
    })
  });
  await assert.rejects(hostile.loader.loadProvider(), error => {
    assert.ok(error instanceof SecretLoaderError);
    assert.equal(error.code, 'secret_response_invalid');
    assert.equal(error.message.includes(sensitive), false);
    assert.equal('cause' in error, false);
    return true;
  });
});

test('loads the exact Telegram schema only through a required VersionId pin', async () => {
  const { loader, calls } = fixture();
  await assert.rejects(loader.loadTelegram(), isCode('secret_loader_options'));
  const result = await loader.loadTelegram({ expectedVersionId: versionOne });
  assert.deepEqual(result.secret, telegramSecret());
  assert.deepEqual(calls, [{ SecretId: telegramArn, VersionId: versionOne }]);
  assert.deepEqual(result.metadata, {
    kind: 'telegram',
    versionId: versionOne,
    loadedAt: 1000,
    expiresAt: 1100,
    cacheStatus: 'miss'
  });
});

test('Telegram VersionId rotation refreshes cache and wrong pins fail closed', async () => {
  const calls = [];
  const versions = [
    response(telegramSecret(1), versionOne),
    response(telegramSecret(2), versionTwo),
    response(telegramSecret(2), versionTwo)
  ];
  const loader = createSecretLoader({
    getSecretValue: async input => { calls.push(input); return versions.shift(); },
    providerSecretArn: providerArn,
    digestSecretArn: digestArn,
    telegramSecretArn: telegramArn,
    cacheTtlMs: 10_000,
    clock: () => 1000
  });
  assert.equal((await loader.loadTelegram({ expectedVersionId: versionOne })).secret.botGeneration, 1);
  assert.equal((await loader.loadTelegram({ expectedVersionId: versionTwo })).secret.botGeneration, 2);
  await assert.rejects(loader.loadTelegram({ expectedVersionId: versionOne }), isCode('secret_version_mismatch'));
  assert.equal(calls.length, 3);
});

test('rejects malformed Telegram custody material without echoing it', async () => {
  const generatedToken = `20001:${'S'.repeat(32)}`;
  const invalid = [
    { ...telegramSecret(), version: 2 },
    { ...telegramSecret(), token: generatedToken, botId: '20002' },
    { ...telegramSecret(), username: 'Other_bot' },
    { ...telegramSecret(), botGeneration: 0 },
    { ...telegramSecret(), webhookSecret: 'short' },
    { ...telegramSecret(), extra: 'denied' }
  ];
  for (const value of invalid) {
    const { loader } = fixture({ handler: async () => response(value) });
    await assert.rejects(loader.loadTelegram({ expectedVersionId: versionOne }), error => {
      assert.equal(isCode('secret_schema_invalid')(error), true);
      assert.equal(error.message.includes(generatedToken), false);
      assert.equal(JSON.stringify(error).includes(generatedToken), false);
      return true;
    });
  }
});

test('Telegram ARN is exact, isolated, and co-regional', async () => {
  const base = {
    getSecretValue: async () => response(telegramSecret()),
    providerSecretArn: providerArn,
    digestSecretArn: digestArn
  };
  assert.throws(() => createSecretLoader({ ...base, telegramSecretArn: providerArn }), isCode('secret_loader_config'));
  assert.throws(() => createSecretLoader({
    ...base,
    telegramSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:ring-home-mcp/telegram-Ij56Kl'
  }), isCode('secret_loader_config'));
  const withoutTelegram = createSecretLoader(base);
  await assert.rejects(withoutTelegram.loadTelegram({ expectedVersionId: versionOne }), isCode('secret_loader_config'));
});
