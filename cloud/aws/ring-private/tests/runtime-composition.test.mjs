import test from 'node:test';
import assert from 'node:assert/strict';
import { createProductionRuntime } from '../runtime-composition.mjs';

const providerArn = 'arn:aws:secretsmanager:ap-southeast-1:111111111111:secret:generated-provider';
const digestArn = 'arn:aws:secretsmanager:ap-southeast-1:111111111111:secret:generated-digest';
const providerVersion = 'p'.repeat(32);
const digestVersion = 'd'.repeat(32);

function environment(change = {}) {
  return {
    RING_BACKEND_STATE: 'enabled',
    AWS_REGION: 'ap-southeast-1',
    RING_LINK_TABLE_NAME: 'GeneratedRingLink',
    RING_LINK_INDEX_NAME: 'GSI1',
    RING_EVENT_TABLE_NAME: 'GeneratedRingEvent',
    RING_TOKEN_KMS_KEY_ID: 'alias/generated-ring',
    RING_PROVIDER_SECRET_ARN: providerArn,
    RING_PROVIDER_SECRET_VERSION_ID: providerVersion,
    RING_DIGEST_SECRET_ARN: digestArn,
    RING_DIGEST_SECRET_VERSION_ID: digestVersion,
    ...change
  };
}

function b02Seam() {
  return {
    async resolveLinkSession() {
      return { sessionProof: 'generated-session-proof', csrf: 'generated-csrf' };
    },
    identityAuthority: {
      async resolveMatchedRingAccount() {
        throw new Error('generated identity denied');
      },
      async recheck() {
        throw new Error('generated identity denied');
      }
    }
  };
}

function ports(calls) {
  const noOp = async () => ({});
  return {
    query: noOp,
    getItem: noOp,
    putItem: noOp,
    transactWrite: noOp,
    generateDataKey: noOp,
    decryptDataKey: noOp,
    async getSecretValue(input, options) {
      calls.push({ input, options, argumentCount: arguments.length });
      const provider = input.SecretId === providerArn;
      return {
        VersionId: provider ? providerVersion : digestVersion,
        SecretString: JSON.stringify(provider
          ? {
              version: 1,
              clientId: 'generated-client',
              clientSecret: 'generated-client-secret',
              nonceKey: 'generated-nonce-key-at-least-32-bytes',
              webhookSigningKey: 'generated-webhook-signing-key-32-bytes'
            }
          : {
              version: 1,
              recordHmacKey: 'generated-record-hmac-key-at-least-32-bytes',
              cookieHmacKey: 'generated-cookie-hmac-key-at-least-32-bytes'
            })
      };
    }
  };
}

test('production runtime requires exact provider/digest pins and propagates one AbortSignal through cold secret reads', async () => {
  const calls = [];
  const observed = {};
  const controller = new AbortController();
  const runtime = await createProductionRuntime({
    environment: environment(),
    awsPorts: ports(calls),
    b02SessionSeam: b02Seam(),
    fetchImpl: async () => {
      throw new Error('provider disabled');
    },
    clock: () => 1_791_000_000_000,
    random: size => Buffer.alloc(size, 7),
    signal: controller.signal,
    async compositionFactory(options) {
      observed.config = options.config;
      observed.signal = options.signal;
      observed.tokenContext = options.tokenTransportResolver({
        method: 'POST',
        path: '/ring/token',
        resource: '/ring/token',
        stage: 'staging'
      });
      return {
        async dispatch() {
          return { statusCode: 202, headers: {}, body: '{}' };
        }
      };
    },
    eventLedgerFactory() {
      return {
        async lookupWebhook() {
          return { duplicate: false };
        },
        async acceptWebhook() {
          return { duplicate: false };
        }
      };
    },
    linkedDeviceAuthorizerFactory() {
      return {
        async isLinkedDevice() {
          return true;
        }
      };
    },
    webhookHandlerFactory() {
      return async () => ({ statusCode: 200, headers: {}, body: '{}' });
    }
  });

  assert.equal(observed.signal, controller.signal);
  assert.equal(observed.config.providerSecretVersionId, providerVersion);
  assert.equal(observed.config.digestSecretVersionId, digestVersion);
  assert.deepEqual(observed.tokenContext, {
    protocol: 'ring-one-way-authorization-code',
    version: 1,
    authority: 'LOCAL_CONSERVATIVE'
  });
  assert.deepEqual(calls.map(call => call.input), [
    { SecretId: providerArn, VersionId: providerVersion },
    { SecretId: digestArn, VersionId: digestVersion }
  ]);
  assert.equal(calls.every(call => call.options.signal === controller.signal), true);
  assert.equal(calls.every(call => call.argumentCount === 2), true);
  assert.equal(JSON.stringify(calls.map(call => call.input)).includes('AWSCURRENT'), false);
  assert.equal(typeof runtime.dispatch, 'function');
  assert.equal(typeof runtime.webhookHandler, 'function');
});

test('production runtime without AbortSignal preserves pinned reads and omits AWS port options', async () => {
  const calls = [];
  const runtime = await createProductionRuntime({
    environment: environment(),
    awsPorts: ports(calls),
    b02SessionSeam: b02Seam(),
    fetchImpl: async () => {
      throw new Error('provider disabled');
    },
    clock: () => 1_791_000_000_000,
    random: size => Buffer.alloc(size, 7),
    async compositionFactory() {
      return {
        async dispatch() {
          return { statusCode: 202, headers: {}, body: '{}' };
        }
      };
    },
    eventLedgerFactory() {
      return {
        async lookupWebhook() {
          return { duplicate: false };
        },
        async acceptWebhook() {
          return { duplicate: false };
        }
      };
    },
    linkedDeviceAuthorizerFactory() {
      return {
        async isLinkedDevice() {
          return true;
        }
      };
    },
    webhookHandlerFactory() {
      return async () => ({ statusCode: 200, headers: {}, body: '{}' });
    }
  });

  assert.deepEqual(calls.map(call => call.input), [
    { SecretId: providerArn, VersionId: providerVersion },
    { SecretId: digestArn, VersionId: digestVersion }
  ]);
  assert.equal(calls.every(call => call.argumentCount === 1 && call.options === undefined), true);
  assert.equal(JSON.stringify(calls.map(call => call.input)).includes('AWSCURRENT'), false);
  assert.equal(typeof runtime.dispatch, 'function');
  assert.equal(typeof runtime.webhookHandler, 'function');
});

test('disabled, unpinned and already-aborted runtime states fail before AWS access', async () => {
  const calls = [];
  const common = {
    awsPorts: ports(calls),
    b02SessionSeam: b02Seam(),
    fetchImpl: async () => {},
    clock: () => 1,
    random: size => Buffer.alloc(size)
  };
  await assert.rejects(
    createProductionRuntime({ ...common, environment: environment({ RING_BACKEND_STATE: 'blocked' }) }),
    /runtime_disabled/
  );
  const missingProviderPin = environment();
  delete missingProviderPin.RING_PROVIDER_SECRET_VERSION_ID;
  await assert.rejects(
    createProductionRuntime({ ...common, environment: missingProviderPin }),
    /aws_environment_config/
  );
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    createProductionRuntime({ ...common, environment: environment(), signal: controller.signal }),
    /runtime_aborted/
  );
  assert.equal(calls.length, 0);
});
