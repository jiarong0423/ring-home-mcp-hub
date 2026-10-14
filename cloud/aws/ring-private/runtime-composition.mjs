import { randomBytes } from 'node:crypto';
import { types } from 'node:util';
import { createAwsComposition, parseNonsecretAwsEnvironment } from './aws-composition.mjs';
import { validateB02SessionSeam, loadB02SessionSeam } from './b02-session-seam.mjs';
import { createDynamoEventLedger } from './dynamo-event-ledger.mjs';
import { createDynamoLinkedDeviceAuthorizer } from './dynamo-linked-device-authorizer.mjs';
import { createSecretLoader } from './secret-loader.mjs';
import { createWebhookHttpHandler } from './webhook-http-handler.mjs';

const COMPOSITION_ENVIRONMENT_KEYS = Object.freeze([
  'AWS_REGION',
  'RING_LINK_TABLE_NAME',
  'RING_LINK_INDEX_NAME',
  'RING_TOKEN_KMS_KEY_ID',
  'RING_PROVIDER_SECRET_ARN',
  'RING_PROVIDER_SECRET_VERSION_ID',
  'RING_DIGEST_SECRET_ARN',
  'RING_DIGEST_SECRET_VERSION_ID',
  'RING_APPLICATION',
  'RING_SECRET_CACHE_TTL_MS',
  'RING_PROVIDER_TIMEOUT_MS',
  'RING_COMPLETION_TTL_SECONDS'
]);

function fail(code = 'runtime_composition_config') {
  throw new TypeError(code);
}

function environmentValue(environment, name) {
  const value = environment?.[name];
  if (typeof value !== 'string' || value.length === 0) fail('runtime_environment_config');
  return value;
}

function compositionEnvironment(environment) {
  const selected = Object.create(null);
  for (const key of COMPOSITION_ENVIRONMENT_KEYS) {
    if (environment?.[key] !== undefined) selected[key] = environment[key];
  }
  return selected;
}

function ownPort(value, methods) {
  if (value === null || typeof value !== 'object' || types.isProxy(value)) fail();
  for (const method of methods) {
    const descriptor = Object.getOwnPropertyDescriptor(value, method);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function' ||
        types.isProxy(descriptor.value)) fail();
  }
  return value;
}

function localConservativeTokenTransport(transport) {
  if (transport?.method !== 'POST' || transport?.path !== '/ring/token' ||
      transport?.resource !== '/ring/token' || typeof transport?.stage !== 'string') {
    fail('token_transport_denied');
  }
  return Object.freeze({
    protocol: 'ring-one-way-authorization-code',
    version: 1,
    authority: 'LOCAL_CONSERVATIVE'
  });
}

function requireSignal(value) {
  if (value === undefined) return undefined;
  try {
    if (typeof AbortSignal === 'undefined' || !(value instanceof AbortSignal)) fail();
    return value;
  } catch {
    fail();
  }
}

function ensureActive(signal) {
  if (signal?.aborted) fail('runtime_aborted');
}

async function defaultAwsPorts(region) {
  let module;
  try {
    module = await import('./aws-sdk-v3-ports.mjs');
  } catch {
    fail('runtime_aws_sdk_unavailable');
  }
  if (typeof module.createDefaultAwsSdkV3Ports !== 'function') fail('runtime_aws_sdk_unavailable');
  return module.createDefaultAwsSdkV3Ports({ region });
}

export async function createProductionRuntime({
  environment = process.env,
  awsPorts,
  b02SessionSeam,
  fetchImpl = globalThis.fetch,
  clock = Date.now,
  random = randomBytes,
  compositionFactory = createAwsComposition,
  secretLoaderFactory = createSecretLoader,
  eventLedgerFactory = createDynamoEventLedger,
  linkedDeviceAuthorizerFactory = createDynamoLinkedDeviceAuthorizer,
  webhookHandlerFactory = createWebhookHttpHandler,
  signal: signalValue
} = {}) {
  const signal = requireSignal(signalValue);
  ensureActive(signal);
  if (environmentValue(environment, 'RING_BACKEND_STATE') !== 'enabled') fail('runtime_disabled');
  const config = parseNonsecretAwsEnvironment(compositionEnvironment(environment));
  const eventTableName = environmentValue(environment, 'RING_EVENT_TABLE_NAME');
  const ports = awsPorts ?? await defaultAwsPorts(config.region);
  ensureActive(signal);
  ownPort(ports, ['query', 'getItem', 'putItem', 'transactWrite', 'generateDataKey', 'decryptDataKey', 'getSecretValue']);
  const b02 = b02SessionSeam === undefined
    ? await loadB02SessionSeam()
    : validateB02SessionSeam(b02SessionSeam);
  ensureActive(signal);
  if (typeof fetchImpl !== 'function' || typeof clock !== 'function' || typeof random !== 'function' ||
      typeof compositionFactory !== 'function' || typeof secretLoaderFactory !== 'function' ||
      typeof eventLedgerFactory !== 'function' || typeof linkedDeviceAuthorizerFactory !== 'function' ||
      typeof webhookHandlerFactory !== 'function') fail();

  const composition = await compositionFactory({
    config,
    awsPorts: ports,
    identityAuthority: b02.identityAuthority,
    tokenTransportResolver: localConservativeTokenTransport,
    linkSessionResolver: b02.resolveLinkSession,
    fetchImpl,
    clock,
    random,
    signal
  });
  ownPort(composition, ['dispatch']);

  const loader = secretLoaderFactory({
    getSecretValue: ports.getSecretValue,
    providerSecretArn: config.providerSecretArn,
    providerSecretVersionId: config.providerSecretVersionId,
    digestSecretArn: config.digestSecretArn,
    digestSecretVersionId: config.digestSecretVersionId,
    cacheTtlMs: config.secretCacheTtlMs,
    clock
  });
  ownPort(loader, ['loadProvider', 'loadDigest']);
  const [providerResult, digestResult] = await Promise.all([
    loader.loadProvider({ signal }),
    loader.loadDigest({ signal })
  ]);
  ensureActive(signal);
  const webhookSigningKey = providerResult?.secret?.webhookSigningKey;
  const recordHmacKey = digestResult?.secret?.recordHmacKey;
  const ledger = eventLedgerFactory({
    putItem: ports.putItem,
    getItem: ports.getItem,
    tableName: eventTableName,
    hashKey: recordHmacKey,
    clock
  });
  const linked = linkedDeviceAuthorizerFactory({
    getItem: ports.getItem,
    tableName: eventTableName,
    hashKey: recordHmacKey,
    clock
  });
  const webhookHandler = webhookHandlerFactory({
    signingKey: webhookSigningKey,
    isLinkedDevice: linked.isLinkedDevice,
    ledger,
    clock
  });
  if (typeof webhookHandler !== 'function' || types.isProxy(webhookHandler)) fail();

  return Object.freeze({
    dispatch: composition.dispatch.bind(composition),
    webhookHandler
  });
}
