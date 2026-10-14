import { types } from 'node:util';
import { createAccountLinkHttp } from './account-link-http.mjs';
import { createCompletionStateCodec } from './completion-state.mjs';
import { createDynamoLinkStore } from './dynamo-link-store.mjs';
import { createRestV1Dispatcher } from './rest-v1-dispatcher.mjs';
import { createRingClient } from './ring-client.mjs';
import { createSecretLoader } from './secret-loader.mjs';
import { createTokenEnvelope } from './token-envelope.mjs';
import { createRingWorkflow } from './workflow.mjs';
import { createDynamoIdentityAuthorityStore } from './dynamo-identity-authority-store.mjs';
import { createIdentityEnvelope } from './identity-envelope.mjs';
import { createProjectingIdentityAuthority } from './projecting-identity-authority.mjs';
import { createTelegramOwnerAuthority } from './telegram-owner-authority.mjs';
import { createTelegramBotClient } from './telegram-bot-client.mjs';
import { createTelegramWebhookHandler } from './telegram-webhook-handler.mjs';
import { createCapabilityIntentContract } from './capability-intent-contract.mjs';
import { createHmac } from 'node:crypto';

const CONFIG_KEYS = Object.freeze([
  'region',
  'tableName',
  'indexName',
  'kmsKeyId',
  'providerSecretArn',
  'providerSecretVersionId',
  'digestSecretArn',
  'digestSecretVersionId',
  'telegramSecretArn',
  'telegramSecretVersionId',
  'application',
  'secretCacheTtlMs',
  'providerTimeoutMs',
  'completionTtlSeconds'
]);
const REQUIRED_CONFIG_KEYS = Object.freeze([
  'region',
  'tableName',
  'kmsKeyId',
  'providerSecretArn',
  'providerSecretVersionId',
  'digestSecretArn',
  'digestSecretVersionId'
]);
const ENVIRONMENT_KEYS = Object.freeze([
  'AWS_REGION',
  'RING_LINK_TABLE_NAME',
  'RING_LINK_INDEX_NAME',
  'RING_TOKEN_KMS_KEY_ID',
  'RING_PROVIDER_SECRET_ARN',
  'RING_PROVIDER_SECRET_VERSION_ID',
  'RING_DIGEST_SECRET_ARN',
  'RING_DIGEST_SECRET_VERSION_ID',
  'RING_TELEGRAM_SECRET_ARN',
  'RING_TELEGRAM_SECRET_VERSION_ID',
  'RING_APPLICATION',
  'RING_SECRET_CACHE_TTL_MS',
  'RING_PROVIDER_TIMEOUT_MS',
  'RING_COMPLETION_TTL_SECONDS'
]);
const OPTION_KEYS = Object.freeze([
  'config',
  'awsPorts',
  'identityAuthority',
  'tokenTransportResolver',
  'linkSessionResolver',
  'fetchImpl',
  'clock',
  'random',
  'sessionContextExtractor',
  'localSessionPort',
  'ownMcpPort',
  'capabilityChannelPort',
  'capabilityAdapters',
  'signal'
]);
const REGION = /^(?:af|ap|ca|eu|il|me|mx|sa|us|cn)-(?:central|east|north|northeast|northwest|south|southeast|southwest|west)-[1-9][0-9]*$/;
const RESOURCE_NAME = /^[A-Za-z0-9_.-]{3,255}$/;
const APPLICATION = /^[A-Za-z0-9_.-]{3,64}$/;
const SECRET_ARN = /^arn:(aws|aws-us-gov|aws-cn):secretsmanager:([a-z0-9-]+):[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]{1,512}$/;
const KMS_KEY = /^(?:arn:(?:aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:[0-9]{12}:key\/[0-9a-fA-F-]{36}|alias\/[A-Za-z0-9/_-]{1,256})$/;
const SECRET_VERSION = /^[A-Za-z0-9_-]{32,64}$/;
const BYTE_LENGTH = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'byteLength').get;

function fail(code = 'aws_composition_config') {
  throw new TypeError(code);
}

function exactData(value, allowed, required, code = 'aws_composition_config') {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail(code);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (required.some(key => !Object.hasOwn(descriptors, key)) ||
        keys.some(key => typeof key !== 'string' || !allowed.includes(key) ||
          !Object.hasOwn(descriptors[key], 'value'))) fail(code);
    return Object.fromEntries(keys.map(key => [key, descriptors[key].value]));
  } catch {
    fail(code);
  }
}

function integer(value, fallback, minimum, maximum) {
  const current = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(current) || current < minimum || current > maximum) fail();
  return current;
}

function integerText(value, fallback, minimum, maximum) {
  if (value === undefined) return fallback;
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) fail('aws_environment_config');
  const current = Number(value);
  if (!Number.isSafeInteger(current) || current < minimum || current > maximum) fail('aws_environment_config');
  return current;
}

function secretRegion(value) {
  const match = SECRET_ARN.exec(value);
  return match?.[2];
}

export function validateAwsCompositionConfig(value) {
  const config = exactData(value, CONFIG_KEYS, REQUIRED_CONFIG_KEYS);
  const telegramEnabled = config.telegramSecretArn !== undefined || config.telegramSecretVersionId !== undefined;
  if (typeof config.region !== 'string' || !REGION.test(config.region) ||
      typeof config.tableName !== 'string' || !RESOURCE_NAME.test(config.tableName) ||
      (config.indexName !== undefined && (typeof config.indexName !== 'string' || !RESOURCE_NAME.test(config.indexName))) ||
      typeof config.kmsKeyId !== 'string' || !KMS_KEY.test(config.kmsKeyId) ||
      typeof config.providerSecretArn !== 'string' || !SECRET_ARN.test(config.providerSecretArn) ||
      typeof config.providerSecretVersionId !== 'string' || !SECRET_VERSION.test(config.providerSecretVersionId) ||
      typeof config.digestSecretArn !== 'string' || !SECRET_ARN.test(config.digestSecretArn) ||
      typeof config.digestSecretVersionId !== 'string' || !SECRET_VERSION.test(config.digestSecretVersionId) ||
      config.providerSecretArn === config.digestSecretArn ||
      (telegramEnabled && (typeof config.telegramSecretArn !== 'string' || !SECRET_ARN.test(config.telegramSecretArn) ||
        typeof config.telegramSecretVersionId !== 'string' || !SECRET_VERSION.test(config.telegramSecretVersionId) ||
        [config.providerSecretArn, config.digestSecretArn].includes(config.telegramSecretArn) ||
        secretRegion(config.telegramSecretArn) !== config.region)) ||
      secretRegion(config.providerSecretArn) !== config.region || secretRegion(config.digestSecretArn) !== config.region ||
      (config.application !== undefined && (typeof config.application !== 'string' || !APPLICATION.test(config.application)))) {
    fail();
  }
  return Object.freeze({
    region: config.region,
    tableName: config.tableName,
    indexName: config.indexName ?? 'GSI1',
    kmsKeyId: config.kmsKeyId,
    providerSecretArn: config.providerSecretArn,
    providerSecretVersionId: config.providerSecretVersionId,
    digestSecretArn: config.digestSecretArn,
    digestSecretVersionId: config.digestSecretVersionId,
    ...(telegramEnabled ? { telegramSecretArn: config.telegramSecretArn,
      telegramSecretVersionId: config.telegramSecretVersionId } : {}),
    application: config.application ?? 'ring-private',
    secretCacheTtlMs: integer(config.secretCacheTtlMs, 30_000, 1, 300_000),
    providerTimeoutMs: integer(config.providerTimeoutMs, 4_000, 100, 10_000),
    completionTtlSeconds: integer(config.completionTtlSeconds, 120, 1, 120)
  });
}

export function parseNonsecretAwsEnvironment(value) {
  const environment = exactData(value, ENVIRONMENT_KEYS, [
    'AWS_REGION',
    'RING_LINK_TABLE_NAME',
    'RING_TOKEN_KMS_KEY_ID',
    'RING_PROVIDER_SECRET_ARN',
    'RING_PROVIDER_SECRET_VERSION_ID',
    'RING_DIGEST_SECRET_ARN',
    'RING_DIGEST_SECRET_VERSION_ID'
  ], 'aws_environment_config');
  return validateAwsCompositionConfig({
    region: environment.AWS_REGION,
    tableName: environment.RING_LINK_TABLE_NAME,
    indexName: environment.RING_LINK_INDEX_NAME,
    kmsKeyId: environment.RING_TOKEN_KMS_KEY_ID,
    providerSecretArn: environment.RING_PROVIDER_SECRET_ARN,
    providerSecretVersionId: environment.RING_PROVIDER_SECRET_VERSION_ID,
    digestSecretArn: environment.RING_DIGEST_SECRET_ARN,
    digestSecretVersionId: environment.RING_DIGEST_SECRET_VERSION_ID,
    telegramSecretArn: environment.RING_TELEGRAM_SECRET_ARN,
    telegramSecretVersionId: environment.RING_TELEGRAM_SECRET_VERSION_ID,
    application: environment.RING_APPLICATION,
    secretCacheTtlMs: integerText(environment.RING_SECRET_CACHE_TTL_MS, 30_000, 1, 300_000),
    providerTimeoutMs: integerText(environment.RING_PROVIDER_TIMEOUT_MS, 4_000, 100, 10_000),
    completionTtlSeconds: integerText(environment.RING_COMPLETION_TTL_SECONDS, 120, 1, 120)
  });
}

function requireFunction(value) {
  if (typeof value !== 'function' || types.isProxy(value)) fail();
  return value;
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

function requirePort(value, methods) {
  try {
    if (value === null || typeof value !== 'object' || types.isProxy(value)) fail();
    for (const method of methods) {
      const descriptor = Object.getOwnPropertyDescriptor(value, method);
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function' ||
          types.isProxy(descriptor.value)) fail();
    }
    return value;
  } catch {
    fail();
  }
}

export function normalizeAwsCompositionOptions(value) {
  const options = exactData(value, OPTION_KEYS, [
    'config',
    'tokenTransportResolver',
    'linkSessionResolver',
    'fetchImpl',
    'clock',
    'random'
  ]);
  const config = validateAwsCompositionConfig(options.config);
  const formal = config.telegramSecretArn !== undefined;
  if (!formal && options.identityAuthority === undefined) fail();
  if (formal && ['sessionContextExtractor', 'localSessionPort', 'ownMcpPort', 'capabilityChannelPort', 'capabilityAdapters']
    .some(key => options[key] === undefined)) fail();
  if (options.awsPorts === undefined) fail();
  const awsPorts = requirePort(options.awsPorts, [
      'query',
      'getItem',
      'transactWrite',
      'generateDataKey',
      'decryptDataKey',
      'getSecretValue'
    ]);
  return Object.freeze({
    config,
    awsPorts,
    identityAuthority: options.identityAuthority === undefined ? undefined : requirePort(options.identityAuthority, ['resolveMatchedRingAccount', 'recheck']),
    tokenTransportResolver: requireFunction(options.tokenTransportResolver),
    linkSessionResolver: requireFunction(options.linkSessionResolver),
    fetchImpl: requireFunction(options.fetchImpl),
    clock: requireFunction(options.clock),
    random: requireFunction(options.random),
    sessionContextExtractor: options.sessionContextExtractor === undefined ? undefined : requireFunction(options.sessionContextExtractor),
    localSessionPort: options.localSessionPort === undefined ? undefined : requirePort(options.localSessionPort, ['withCurrentSession']),
    ownMcpPort: options.ownMcpPort === undefined ? undefined : requirePort(options.ownMcpPort, ['authorizeCapability']),
    capabilityChannelPort: options.capabilityChannelPort === undefined ? undefined : requirePort(options.capabilityChannelPort,
      ['sealIntent', 'deliverSealedIntent', 'verifyReceipt']),
    capabilityAdapters: options.capabilityAdapters,
    signal: requireSignal(options.signal)
  });
}

export function createLazyRingClient(secretLoader, fetchImpl, timeoutMs) {
  async function invoke(method, parameters) {
    const response = await secretLoader.loadProvider();
    const secret = response?.secret;
    const client = createRingClient({
      fetchImpl,
      timeoutMs,
      clientId: secret?.clientId,
      clientSecret: secret?.clientSecret
    });
    return client[method](...parameters);
  }
  return Object.freeze({
    exchangeCode: (...parameters) => invoke('exchangeCode', parameters),
    refreshTokens: (...parameters) => invoke('refreshTokens', parameters),
    getAccountId: (...parameters) => invoke('getAccountId', parameters),
    confirmLink: (...parameters) => invoke('confirmLink', parameters),
    completeLink: (...parameters) => invoke('completeLink', parameters)
  });
}

function randomHex(random, size) {
  try {
    const value = random(size);
    if (types.isProxy(value) || !types.isUint8Array(value) || BYTE_LENGTH.call(value) !== size) {
      fail('aws_composition_random');
    }
    const copy = Buffer.alloc(size);
    Uint8Array.prototype.set.call(copy, value);
    return copy.toString('hex');
  } catch {
    fail('aws_composition_random');
  }
}

export async function createAwsComposition(value) {
  const options = normalizeAwsCompositionOptions(value);
  const { config, awsPorts, clock, random } = options;
  const secretLoader = createSecretLoader({
    getSecretValue: awsPorts.getSecretValue,
    providerSecretArn: config.providerSecretArn,
    providerSecretVersionId: config.providerSecretVersionId,
    digestSecretArn: config.digestSecretArn,
    digestSecretVersionId: config.digestSecretVersionId,
    telegramSecretArn: config.telegramSecretArn,
    cacheTtlMs: config.secretCacheTtlMs,
    clock
  });
  const digest = (await secretLoader.loadDigest({ signal: options.signal }))?.secret;
  const tokenEnvelope = createTokenEnvelope({
    generateDataKey: awsPorts.generateDataKey,
    decryptDataKey: awsPorts.decryptDataKey,
    keyId: config.kmsKeyId,
    application: config.application,
    tableName: config.tableName,
    random
  });
  const store = createDynamoLinkStore({
    query: awsPorts.query,
    getItem: awsPorts.getItem,
    transactWrite: awsPorts.transactWrite,
    tableName: config.tableName,
    indexName: config.indexName,
    clock,
    createIntakeId: () => randomHex(random, 16)
  });
  let formal;
  if (config.telegramSecretArn !== undefined) {
    const keyedDigest = async (purpose, source) => {
      if (typeof source !== 'string' || source.length < 1 || source.length > 4096) fail('aws_composition_digest');
      return createHmac('sha256', digest?.recordHmacKey ?? '').update(`${purpose}\0${source}`, 'utf8').digest('hex');
    };
    const authorityStore = createDynamoIdentityAuthorityStore({ getItem: awsPorts.getItem,
      transactWrite: awsPorts.transactWrite, tableName: config.tableName, clock });
    const identityEnvelope = createIdentityEnvelope({ generateDataKey: awsPorts.generateDataKey,
      decryptDataKey: awsPorts.decryptDataKey, keyId: config.kmsKeyId, application: config.application,
      tableName: config.tableName, random });
    const projecting = createProjectingIdentityAuthority({ store: authorityStore, digest: keyedDigest,
      identityEnvelope, extractSession: options.sessionContextExtractor });
    const ownerAuthority = createTelegramOwnerAuthority({ store: authorityStore, digest: keyedDigest, clock,
      createNonce: () => Buffer.from(randomHex(random, 32), 'hex').toString('base64url'),
      createRef: prefix => `${prefix}/${randomHex(random, 16)}` });
    const telegramWebhookHandler = createTelegramWebhookHandler({ secretLoader,
      expectedVersionId: config.telegramSecretVersionId, clock, ownerAuthority,
      createClient: secret => createTelegramBotClient({ fetchImpl: options.fetchImpl,
        timeoutMs: config.providerTimeoutMs, ...secret }) });
    const capabilityContract = createCapabilityIntentContract({ categories: options.capabilityAdapters,
      localSessionPort: options.localSessionPort, ownMcpPort: options.ownMcpPort,
      capabilityChannelPort: options.capabilityChannelPort, clock, random });
    formal = Object.freeze({ authorityStore, identityEnvelope, projecting, telegramWebhookHandler, capabilityContract });
  }
  const client = createLazyRingClient(secretLoader, options.fetchImpl, config.providerTimeoutMs);
  const workflow = createRingWorkflow({
    client,
    store,
    secretLoader,
    tokenEnvelope,
    identityAuthority: formal?.projecting.identityAuthority ?? options.identityAuthority,
    clock
  });
  const completionCodec = createCompletionStateCodec({
    hmacKey: Buffer.from(digest?.cookieHmacKey ?? '', 'utf8'),
    clock,
    random,
    ttlSeconds: config.completionTtlSeconds
  });
  const accountLinkHttp = createAccountLinkHttp({ workflow, completionCodec, clock });
  const dispatch = createRestV1Dispatcher({
    accountLinkHttp,
    tokenTransportResolver: options.tokenTransportResolver,
    linkSessionResolver: options.linkSessionResolver,
    ...(formal ? { telegramWebhookHandler: formal.telegramWebhookHandler } : {})
  });
  return Object.freeze({ dispatch, accountLinkHttp, workflow,
    ...(formal ? { projectFirstAccount: formal.projecting.projectFirstAccount,
      capabilityContract: formal.capabilityContract } : {}) });
}
