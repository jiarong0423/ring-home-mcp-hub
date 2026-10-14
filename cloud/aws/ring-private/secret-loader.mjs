export const SECRET_SCHEMA_VERSION = 1;

const MAX_SECRET_BYTES = 65_536;
const MAX_CACHE_TTL_MS = 300_000;
const SECRET_ARN = /^arn:(aws|aws-us-gov|aws-cn):secretsmanager:([a-z0-9-]+):([0-9]{12}):secret:([A-Za-z0-9/_+=.@-]{1,512})$/;
const SAFE_TEXT = /^[^\x00-\x1f\x7f]+$/;
const SECRET_VERSION_ID = /^[A-Za-z0-9_-]{32,64}$/;
const TELEGRAM_BOT_ID = /^[1-9][0-9]{0,19}$/;
const TELEGRAM_TOKEN = /^([1-9][0-9]{0,19}):([A-Za-z0-9_-]{20,128})$/;
const TELEGRAM_WEBHOOK_SECRET = /^[A-Za-z0-9_-]{32,256}$/;
const REGION_BY_PARTITION = Object.freeze({
  aws: /^(?:af|ap|ca|eu|il|me|mx|sa|us)-(?:central|east|north|northeast|northwest|south|southeast|southwest|west)-[1-9][0-9]*$/,
  'aws-cn': /^cn-(?:north|northwest)-[1-9][0-9]*$/,
  'aws-us-gov': /^us-gov-(?:east|west)-[1-9][0-9]*$/
});
const FACTORY_KEYS = Object.freeze([
  'getSecretValue',
  'providerSecretArn',
  'providerSecretVersionId',
  'digestSecretArn',
  'digestSecretVersionId',
  'telegramSecretArn',
  'cacheTtlMs',
  'clock'
]);

const SCHEMAS = Object.freeze({
  provider: Object.freeze({
    required: Object.freeze(['version', 'clientId', 'clientSecret', 'nonceKey']),
    optional: Object.freeze(['webhookSigningKey']),
    limits: Object.freeze({
      clientId: Object.freeze([3, 512]),
      clientSecret: Object.freeze([16, 4096]),
      nonceKey: Object.freeze([32, 4096]),
      webhookSigningKey: Object.freeze([32, 4096])
    })
  }),
  digest: Object.freeze({
    required: Object.freeze(['version', 'recordHmacKey', 'cookieHmacKey']),
    optional: Object.freeze([]),
    limits: Object.freeze({
      recordHmacKey: Object.freeze([32, 4096]),
      cookieHmacKey: Object.freeze([32, 4096])
    })
  }),
  telegram: Object.freeze({
    required: Object.freeze([
      'version',
      'token',
      'botId',
      'username',
      'botGeneration',
      'webhookSecret'
    ]),
    optional: Object.freeze([])
  })
});

export class SecretLoaderError extends Error {
  constructor(code) {
    super(code);
    this.name = 'SecretLoaderError';
    this.code = code;
  }
}

function fail(code) {
  throw new SecretLoaderError(code);
}

function dataProperties(value, allowedKeys, code, { allowUndefined = false } = {}) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(code);
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) fail(code);
    const keys = Reflect.ownKeys(value);
    if (keys.some(key => typeof key !== 'string' || !allowedKeys.includes(key))) fail(code);
    const result = Object.create(null);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) fail(code);
      if (!allowUndefined && descriptor.value === undefined) fail(code);
      result[key] = descriptor.value;
    }
    return result;
  } catch (error) {
    if (error instanceof SecretLoaderError) throw error;
    fail(code);
  }
}

function factoryOptions(options) {
  const values = dataProperties(options, FACTORY_KEYS, 'secret_loader_config', { allowUndefined: true });
  return {
    getSecretValue: values.getSecretValue,
    providerSecretArn: values.providerSecretArn,
    providerSecretVersionId: values.providerSecretVersionId,
    digestSecretArn: values.digestSecretArn,
    digestSecretVersionId: values.digestSecretVersionId,
    telegramSecretArn: values.telegramSecretArn,
    cacheTtlMs: values.cacheTtlMs === undefined ? 30_000 : values.cacheTtlMs,
    clock: values.clock === undefined ? Date.now : values.clock
  };
}

function abortSignal(value) {
  if (value === undefined) return undefined;
  try {
    if (typeof AbortSignal === 'undefined' || !(value instanceof AbortSignal)) fail('secret_loader_options');
    return value;
  } catch (error) {
    if (error instanceof SecretLoaderError) throw error;
    fail('secret_loader_options');
  }
}

function loadOptions(options, { requirePinnedVersion = false, defaultExpectedVersionId } = {}) {
  if (options === undefined) {
    if (requirePinnedVersion && defaultExpectedVersionId === undefined) fail('secret_loader_options');
    return Object.freeze({ forceRefresh: false, expectedVersionId: defaultExpectedVersionId, signal: undefined });
  }
  const values = dataProperties(options, ['forceRefresh', 'expectedVersionId', 'signal'], 'secret_loader_options', {
    allowUndefined: true
  });
  const forceRefresh = Object.hasOwn(values, 'forceRefresh') ? values.forceRefresh : false;
  if (typeof forceRefresh !== 'boolean') fail('secret_loader_options');
  const requestedVersionId = values.expectedVersionId;
  if (defaultExpectedVersionId !== undefined && requestedVersionId !== undefined &&
      requestedVersionId !== defaultExpectedVersionId) {
    fail('secret_loader_options');
  }
  const expectedVersionId = defaultExpectedVersionId ?? requestedVersionId;
  if (expectedVersionId !== undefined &&
      (typeof expectedVersionId !== 'string' || !SECRET_VERSION_ID.test(expectedVersionId))) {
    fail('secret_loader_options');
  }
  if (requirePinnedVersion && expectedVersionId === undefined) fail('secret_loader_options');
  return Object.freeze({ forceRefresh, expectedVersionId, signal: abortSignal(values.signal) });
}

function optionalVersionId(value) {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || !SECRET_VERSION_ID.test(value)) fail('secret_loader_config');
  return value;
}

function requireArn(value) {
  if (typeof value !== 'string' || value.length > 2048) fail('secret_loader_config');
  const match = SECRET_ARN.exec(value);
  if (!match || !REGION_BY_PARTITION[match[1]].test(match[2])) fail('secret_loader_config');
  return Object.freeze({ value, partition: match[1], region: match[2] });
}

function rawClockValue(clock) {
  let value;
  try {
    value = clock();
  } catch {
    fail('secret_loader_clock');
  }
  if (!Number.isSafeInteger(value) || value < 0) fail('secret_loader_clock');
  return value;
}

function ownDataValue(value, key) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor) return Object.freeze({ present: false, value: undefined });
  if (!Object.hasOwn(descriptor, 'value')) fail('secret_response_invalid');
  return Object.freeze({ present: true, value: descriptor.value });
}

function isUnicodeScalarString(value) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function strictUtf8String(value) {
  if (!isUnicodeScalarString(value)) fail('secret_response_invalid');
  const bytes = Buffer.from(value, 'utf8');
  if (bytes.toString('utf8') !== value) fail('secret_response_invalid');
  return bytes;
}

function decodeSecret(response) {
  if (!response || typeof response !== 'object' || Array.isArray(response)) fail('secret_response_invalid');
  const stringField = ownDataValue(response, 'SecretString');
  const binaryField = ownDataValue(response, 'SecretBinary');
  const hasString = stringField.present && stringField.value !== undefined && stringField.value !== null;
  const hasBinary = binaryField.present && binaryField.value !== undefined && binaryField.value !== null;
  if (hasString === hasBinary || (hasString && typeof stringField.value !== 'string')) {
    fail('secret_response_invalid');
  }

  let encoded;
  if (hasString) {
    const bytes = strictUtf8String(stringField.value);
    if (bytes.length < 2 || bytes.length > MAX_SECRET_BYTES) fail('secret_response_invalid');
    encoded = stringField.value;
  } else {
    const binary = binaryField.value;
    if (!(Buffer.isBuffer(binary) || binary instanceof Uint8Array)) fail('secret_response_invalid');
    const bytes = Buffer.from(binary);
    if (bytes.length < 2 || bytes.length > MAX_SECRET_BYTES) fail('secret_response_invalid');
    try {
      encoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
      fail('secret_response_invalid');
    }
    strictUtf8String(encoded);
  }

  let parsed;
  try {
    parsed = JSON.parse(encoded);
  } catch {
    fail('secret_response_invalid');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) fail('secret_schema_invalid');
  return parsed;
}

function requireBoundedText(value, [minimum, maximum]) {
  if (typeof value !== 'string' || !SAFE_TEXT.test(value) || !isUnicodeScalarString(value)) {
    fail('secret_schema_invalid');
  }
  const bytes = Buffer.from(value, 'utf8');
  if (bytes.toString('utf8') !== value || bytes.length < minimum || bytes.length > maximum) {
    fail('secret_schema_invalid');
  }
  return value;
}

function validateSecret(kind, parsed) {
  const schema = SCHEMAS[kind];
  const allowed = [...schema.required, ...schema.optional];
  let values;
  try {
    values = dataProperties(parsed, allowed, 'secret_schema_invalid');
  } catch (error) {
    if (error instanceof SecretLoaderError) throw error;
    fail('secret_schema_invalid');
  }
  if (values.version !== SECRET_SCHEMA_VERSION ||
      schema.required.some(key => !Object.hasOwn(values, key))) {
    fail('secret_schema_invalid');
  }

  if (kind === 'telegram') {
    const token = requireBoundedText(values.token, [23, 149]);
    const botId = requireBoundedText(values.botId, [1, 20]);
    const username = requireBoundedText(values.username, [1, 64]);
    const webhookSecret = requireBoundedText(values.webhookSecret, [32, 256]);
    const tokenMatch = TELEGRAM_TOKEN.exec(token);
    if (!tokenMatch || tokenMatch[1] !== botId || !TELEGRAM_BOT_ID.test(botId) ||
        username !== 'Homemcphub_bot' || !TELEGRAM_WEBHOOK_SECRET.test(webhookSecret) ||
        !Number.isSafeInteger(values.botGeneration) || values.botGeneration < 1) {
      fail('secret_schema_invalid');
    }
    return Object.freeze({
      version: SECRET_SCHEMA_VERSION,
      token,
      botId,
      username,
      botGeneration: values.botGeneration,
      webhookSecret
    });
  }

  const secret = { version: SECRET_SCHEMA_VERSION };
  for (const key of allowed) {
    if (key === 'version' || !Object.hasOwn(values, key)) continue;
    secret[key] = requireBoundedText(values[key], schema.limits[key]);
  }
  return Object.freeze(secret);
}

function requireVersionId(response) {
  const field = ownDataValue(response, 'VersionId');
  const value = field.value;
  if (!field.present || typeof value !== 'string' || !SECRET_VERSION_ID.test(value)) {
    fail('secret_response_invalid');
  }
  return value;
}

export function createSecretLoader(options) {
  const {
    getSecretValue,
    providerSecretArn,
    providerSecretVersionId,
    digestSecretArn,
    digestSecretVersionId,
    telegramSecretArn,
    cacheTtlMs,
    clock
  } = factoryOptions(options);
  if (typeof getSecretValue !== 'function' || typeof clock !== 'function' ||
      !Number.isSafeInteger(cacheTtlMs) || cacheTtlMs < 1 || cacheTtlMs > MAX_CACHE_TTL_MS) {
    fail('secret_loader_config');
  }
  const parsedArns = {
    provider: requireArn(providerSecretArn),
    digest: requireArn(digestSecretArn)
  };
  if (telegramSecretArn !== undefined) parsedArns.telegram = requireArn(telegramSecretArn);
  Object.freeze(parsedArns);
  const arnValues = Object.values(parsedArns);
  if (new Set(arnValues.map(arn => arn.value)).size !== arnValues.length ||
      arnValues.some(arn => arn.partition !== parsedArns.provider.partition ||
        arn.region !== parsedArns.provider.region)) {
    fail('secret_loader_config');
  }
  const arns = Object.freeze(Object.fromEntries(
    Object.entries(parsedArns).map(([kind, arn]) => [kind, arn.value])
  ));
  const pinnedVersions = Object.freeze({
    provider: optionalVersionId(providerSecretVersionId),
    digest: optionalVersionId(digestSecretVersionId),
    telegram: undefined
  });

  const cache = new Map();
  const inFlight = new Map();
  const epochs = new Map(Object.keys(SCHEMAS).map(kind => [kind, 0]));
  let lastClock = null;

  function invalidateKinds(kinds) {
    for (const kind of kinds) {
      cache.delete(kind);
      epochs.set(kind, epochs.get(kind) + 1);
      inFlight.delete(kind);
    }
  }

  function readClock() {
    const value = rawClockValue(clock);
    if (lastClock !== null && value < lastClock) {
      lastClock = value;
      invalidateKinds(Object.keys(SCHEMAS));
      fail('secret_loader_clock_rollback');
    }
    lastClock = value;
    return value;
  }

  function result(entry, cacheStatus) {
    return Object.freeze({
      secret: entry.secret,
      metadata: Object.freeze({
        kind: entry.kind,
        versionId: entry.versionId,
        loadedAt: entry.loadedAt,
        expiresAt: entry.expiresAt,
        cacheStatus
      })
    });
  }

  async function fetchSecret(kind, epoch, expectedVersionId, signal) {
    if (signal?.aborted) fail('secret_unavailable');
    let response;
    try {
      const request = expectedVersionId === undefined
        ? { SecretId: arns[kind], VersionStage: 'AWSCURRENT' }
        : { SecretId: arns[kind], VersionId: expectedVersionId };
      response = signal === undefined
        ? await getSecretValue(request)
        : await getSecretValue(request, { signal });
    } catch {
      if (epochs.get(kind) !== epoch) fail('secret_superseded');
      fail('secret_unavailable');
    }
    if (epochs.get(kind) !== epoch) fail('secret_superseded');

    let secret;
    let versionId;
    try {
      secret = validateSecret(kind, decodeSecret(response));
      versionId = requireVersionId(response);
    } catch (error) {
      if (error instanceof SecretLoaderError) throw error;
      fail('secret_response_invalid');
    }
    if (expectedVersionId !== undefined && versionId !== expectedVersionId) {
      fail('secret_version_mismatch');
    }
    if (epochs.get(kind) !== epoch) fail('secret_superseded');
    const loadedAt = readClock();
    if (epochs.get(kind) !== epoch) fail('secret_superseded');
    const expiresAt = loadedAt + cacheTtlMs;
    if (!Number.isSafeInteger(expiresAt)) fail('secret_loader_clock');
    const entry = Object.freeze({ kind, versionId, loadedAt, expiresAt, secret });
    cache.set(kind, entry);
    return result(entry, 'miss');
  }

  async function load(kind, optionsValue) {
    if (!Object.hasOwn(arns, kind)) fail('secret_loader_config');
    const { forceRefresh, expectedVersionId, signal } = loadOptions(optionsValue, {
      requirePinnedVersion: kind === 'telegram',
      defaultExpectedVersionId: pinnedVersions[kind]
    });
    const now = readClock();
    const cached = cache.get(kind);
    if (!forceRefresh && cached && now < cached.expiresAt &&
        (expectedVersionId === undefined || cached.versionId === expectedVersionId)) {
      return result(cached, 'hit');
    }
    if (cached && expectedVersionId !== undefined && cached.versionId !== expectedVersionId) {
      invalidateKinds([kind]);
    }

    let epoch = epochs.get(kind);
    let pending = inFlight.get(kind);
    if (forceRefresh) {
      if (pending?.epoch === epoch && pending.forceRefresh &&
          pending.expectedVersionId === expectedVersionId && pending.signal === signal) return pending.promise;
      invalidateKinds([kind]);
      epoch = epochs.get(kind);
      pending = undefined;
    } else if (pending?.epoch === epoch && pending.expectedVersionId === expectedVersionId && pending.signal === signal) {
      return pending.promise;
    } else if (pending?.epoch === epoch && pending.expectedVersionId !== expectedVersionId) {
      invalidateKinds([kind]);
      epoch = epochs.get(kind);
    }

    const promise = fetchSecret(kind, epoch, expectedVersionId, signal).finally(() => {
      if (inFlight.get(kind)?.promise === promise) inFlight.delete(kind);
    });
    inFlight.set(kind, { epoch, forceRefresh, expectedVersionId, signal, promise });
    return promise;
  }

  function invalidate(kind) {
    if (kind !== undefined && (typeof kind !== 'string' || !Object.hasOwn(SCHEMAS, kind))) {
      fail('secret_loader_kind');
    }
    invalidateKinds(kind === undefined ? Object.keys(SCHEMAS) : [kind]);
  }

  return Object.freeze({
    loadProvider: optionsValue => load('provider', optionsValue),
    loadDigest: optionsValue => load('digest', optionsValue),
    loadTelegram: optionsValue => load('telegram', optionsValue),
    invalidate
  });
}
