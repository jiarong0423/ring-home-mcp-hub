export class FormalRuntimeError extends Error {
  constructor(code) {
    super(code);
    this.name = 'FormalRuntimeError';
    this.code = code;
  }
}

export function denyFormalRuntime(code) {
  throw new FormalRuntimeError(code);
}

export function exactObject(value, keys, code) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) denyFormalRuntime(code);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length ||
      actual.some((key) => typeof key !== 'string' || !keys.includes(key)) ||
      keys.some((key) => !Object.hasOwn(descriptors, key)) ||
      Object.values(descriptors).some((descriptor) => !descriptor.enumerable || !Object.hasOwn(descriptor, 'value'))) {
    denyFormalRuntime(code);
  }
  return value;
}

export function safeRevision(value, minimum = 0, code = 'B02_FORMAL_REVISION_DENIED') {
  if (!Number.isSafeInteger(value) || value < minimum || value >= Number.MAX_SAFE_INTEGER) {
    denyFormalRuntime(code);
  }
  return value;
}

export function safeTime(value, code = 'B02_FORMAL_TIME_DENIED') {
  if (!Number.isSafeInteger(value) || value <= 0 || value > 8_640_000_000_000_000) {
    denyFormalRuntime(code);
  }
  return value;
}

export function safeLabel(value, code = 'B02_FORMAL_LABEL_DENIED') {
  if (typeof value !== 'string' || !/^[A-Za-z][A-Za-z0-9:._-]{2,127}$/.test(value)) {
    denyFormalRuntime(code);
  }
  return value;
}

export function safeHash(value, code = 'B02_FORMAL_HASH_DENIED') {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) denyFormalRuntime(code);
  return value;
}

export function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

export function zeroBinary(value) {
  try {
    if (Buffer.isBuffer(value)) value.fill(0);
    else if (value instanceof ArrayBuffer) new Uint8Array(value).fill(0);
    else if (ArrayBuffer.isView(value)) new Uint8Array(value.buffer, value.byteOffset, value.byteLength).fill(0);
  } catch {}
}

export function createAuthorityClock({ monotonicNowMs, wallNowMs, productionAdmitted = false } = {}) {
  if (typeof monotonicNowMs !== 'function' || typeof wallNowMs !== 'function') {
    denyFormalRuntime('B02_FORMAL_CLOCK_DENIED');
  }
  let last = -1;
  return Object.freeze({
    productionAdmitted: productionAdmitted === true,
    monotonicNowMs() {
      const value = monotonicNowMs();
      if (!Number.isSafeInteger(value) || value < 0 || value < last) denyFormalRuntime('B02_FORMAL_CLOCK_DENIED');
      last = value;
      return value;
    },
    wallNowMs() { return safeTime(wallNowMs(), 'B02_FORMAL_CLOCK_DENIED'); }
  });
}

export function createProductionAuthorityClock() {
  const origin = process.hrtime.bigint();
  const authorityEpoch = Date.now();
  return createAuthorityClock({
    productionAdmitted: true,
    monotonicNowMs: () => authorityEpoch + Number((process.hrtime.bigint() - origin) / 1_000_000n),
    wallNowMs: () => Date.now()
  });
}

export function createProcessBootEpoch({ randomBytes = crypto.randomBytes, testOnly = false, testObserver = null } = {}) {
  if (!testOnly && randomBytes !== crypto.randomBytes) denyFormalRuntime('B02_FORMAL_ENTROPY_DENIED');
  if ((!testOnly && testObserver !== null) || (testObserver !== null && typeof testObserver !== 'function')) {
    denyFormalRuntime('B02_FORMAL_ENTROPY_DENIED');
  }
  const sourceEntropy = randomBytes(32);
  if (!Buffer.isBuffer(sourceEntropy) || sourceEntropy.length !== 32) {
    zeroBinary(sourceEntropy);
    denyFormalRuntime('B02_FORMAL_ENTROPY_DENIED');
  }
  let processKey;
  try {
    processKey = crypto.createHash('sha256').update('ring-b02-formal-boot-key-v1\0').update(sourceEntropy).digest();
    const digest = crypto.createHash('sha256').update('ring-b02-formal-boot-public-v1\0').update(processKey).digest('hex');
    testObserver?.(processKey);
    let closed = false;
    return Object.freeze({
      productionAdmitted: !testOnly,
      digest,
      derive(label) {
        if (closed) denyFormalRuntime('B02_FORMAL_BOOT_EPOCH_CLOSED');
        safeLabel(label, 'B02_FORMAL_ENTROPY_DENIED');
        return crypto.createHmac('sha256', processKey).update(label).digest('base64url');
      },
      close() {
        if (!closed) { zeroBinary(processKey); closed = true; }
        return Object.freeze({ closed: true });
      },
      status() { return Object.freeze({ closed, keyResident: !closed }); }
    });
  } catch (error) {
    zeroBinary(processKey);
    throw error;
  } finally { zeroBinary(sourceEntropy); }
}

export function closeProcessBootEpoch(bootEpoch) {
  if (!bootEpoch || typeof bootEpoch.close !== 'function') denyFormalRuntime('B02_FORMAL_BOOT_EPOCH_DENIED');
  return bootEpoch.close();
}

export function deriveBootBoundEntryContext(bootEpoch, entryId) {
  if (!bootEpoch || typeof bootEpoch.digest !== 'string') denyFormalRuntime('B02_FORMAL_BOOT_EPOCH_DENIED');
  const id = safeLabel(entryId, 'B02_FORMAL_ENTRY_CONTEXT_DENIED');
  const digest = crypto.createHash('sha256').update(id).digest('hex').slice(0, 32);
  return deepFreeze({ entryId: `boot.${bootEpoch.digest.slice(0, 16)}.${digest}` });
}

export function deriveBootBoundNonce(bootEpoch, purpose) {
  if (!bootEpoch || typeof bootEpoch.derive !== 'function') denyFormalRuntime('B02_FORMAL_BOOT_EPOCH_DENIED');
  return bootEpoch.derive(safeLabel(purpose)).slice(0, 43);
}
import crypto from 'node:crypto';
