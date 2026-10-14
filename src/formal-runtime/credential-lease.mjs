import { validateDurableBindingV2 } from '../wifi/durable-binding-v2.mjs';

const CREDENTIAL_SCHEMA = 'ring-b02-telegram-credential-v1';
const CONSUMER_RESULTS = new Set(['CONSUMED', 'NOOP']);

export class CredentialLeaseError extends Error {
  constructor(code) {
    super(code);
    this.name = 'CredentialLeaseError';
    this.code = code;
  }
}

function deny(code) {
  throw new CredentialLeaseError(code);
}

function exact(value, keys, code) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny(code);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some(key => typeof key !== 'string' || !keys.includes(key)) ||
      keys.some(key => !Object.hasOwn(descriptors, key)) ||
      Object.values(descriptors).some(item => !item.enumerable || !Object.hasOwn(item, 'value'))) deny(code);
  return value;
}

function integer(value, minimum, code) {
  if (!Number.isSafeInteger(value) || value < minimum || value >= Number.MAX_SAFE_INTEGER) deny(code);
  return value;
}

function zero(value) {
  try {
    if (Buffer.isBuffer(value)) value.fill(0);
    else if (value instanceof ArrayBuffer) new Uint8Array(value).fill(0);
    else if (ArrayBuffer.isView(value)) {
      new Uint8Array(value.buffer, value.byteOffset, value.byteLength).fill(0);
    }
  } catch {}
}

function safeCode(error, allowlist, fallback) {
  try {
    const descriptor = error && typeof error === 'object' ? Object.getOwnPropertyDescriptor(error, 'code') : null;
    return descriptor && allowlist.has(descriptor.value) ? descriptor.value : fallback;
  } catch {
    return fallback;
  }
}

const DRIVER_CODES = new Set(['FAKE_AUTH_DENIED', 'FAKE_READ_DENIED', 'FAKE_CLOSED']);

function validateRecord(value) {
  const fields = exact(value, [
    'schema', 'purpose', 'ownerId', 'botId', 'bindingGeneration', 'token', 'secret'
  ], 'B02_LEASE_RECORD_DENIED');
  if (fields.schema !== CREDENTIAL_SCHEMA || fields.purpose !== 'telegram-bot' || fields.secret !== null ||
      typeof fields.ownerId !== 'string' || typeof fields.botId !== 'string' ||
      !Buffer.isBuffer(fields.token) || fields.token.length < 8 || fields.token.length > 4096) {
    deny('B02_LEASE_RECORD_DENIED');
  }
  integer(fields.bindingGeneration, 1, 'B02_LEASE_RECORD_DENIED');
  return fields;
}

function ownedDataValue(value, key) {
  if (value === null || typeof value !== 'object') return undefined;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
  } catch {
    return undefined;
  }
}

function adoptBinaryCandidate(value) {
  if (Buffer.isBuffer(value) || value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return value;
  return null;
}

function scrubReachableBinary(root) {
  const pending = [root];
  const seen = new WeakSet();
  while (pending.length > 0) {
    const value = pending.pop();
    if (Buffer.isBuffer(value) || value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
      zero(value);
      continue;
    }
    if ((typeof value !== 'object' || value === null) && typeof value !== 'function') continue;
    if (seen.has(value)) continue;
    seen.add(value);
    let descriptors;
    try { descriptors = Object.getOwnPropertyDescriptors(value); }
    catch { continue; }
    for (const key of Reflect.ownKeys(descriptors)) {
      const descriptor = descriptors[key];
      if (Object.hasOwn(descriptor, 'value')) pending.push(descriptor.value);
    }
  }
}

function validateConsumerResult(value) {
  if (typeof value === 'string' && CONSUMER_RESULTS.has(value)) return value;
  scrubReachableBinary(value);
  deny('B02_LEASE_RESULT_DENIED');
}

export async function openCredentialLease(options) {
  const submittedPassphrase = ownedDataValue(options, 'passphrase');
  const submittedLength = Buffer.isBuffer(submittedPassphrase) ? submittedPassphrase.length : -1;
  let passphrase = Buffer.isBuffer(submittedPassphrase) ? Buffer.from(submittedPassphrase) : null;
  zero(adoptBinaryCandidate(submittedPassphrase));
  let values;
  let driver;
  let floor;
  let expectedRevision;
  let binding;
  try {
    values = exact(options, [
      'encryptedDriver', 'passphrase', 'revisionFloor', 'expectedRevision', 'binding'
    ], 'B02_LEASE_CONFIGURATION_DENIED');
    driver = values.encryptedDriver;
    floor = values.revisionFloor;
    if (!driver || typeof driver.open !== 'function' || !floor || typeof floor.read !== 'function' ||
        !passphrase || submittedLength < 10 || submittedLength > 4096) deny('B02_LEASE_CONFIGURATION_DENIED');
    expectedRevision = integer(values.expectedRevision, 1, 'B02_LEASE_REVISION_DENIED');
    binding = validateDurableBindingV2(values.binding, { allowRevoked: false });
  } catch (error) {
    zero(passphrase);
    passphrase = null;
    throw error;
  }
  let session = null;
  let sourceToken = null;
  let token = null;
  let closed = false;
  let zeroized = false;
  let busy = false;
  const activeEphemerals = new Set();

  const destroy = async () => {
    for (const ephemeral of activeEphemerals) zero(ephemeral);
    activeEphemerals.clear();
    zero(sourceToken);
    sourceToken = null;
    zero(token);
    token = null;
    zero(passphrase);
    if (session && typeof session.close === 'function') {
      try { await session.close(); } catch {}
    }
    session = null;
    closed = true;
    zeroized = true;
  };

  try {
    const floorRevision = integer(await floor.read(), 0, 'B02_LEASE_FLOOR_DENIED');
    if (expectedRevision < floorRevision) deny('B02_LEASE_ROLLBACK_DENIED');
    session = await driver.open(passphrase);
    if (!session || typeof session.read !== 'function' || typeof session.close !== 'function') {
      deny('B02_LEASE_DRIVER_DENIED');
    }
    const rawResult = await session.read();
    const rawRecord = ownedDataValue(rawResult, 'record');
    sourceToken = adoptBinaryCandidate(ownedDataValue(rawRecord, 'token'));
    const result = exact(rawResult, ['revision', 'record'], 'B02_LEASE_RECORD_DENIED');
    const record = validateRecord(result.record);
    sourceToken = record.token;
    const actualRevision = integer(result.revision, 1, 'B02_LEASE_REVISION_DENIED');
    if (actualRevision < floorRevision) deny('B02_LEASE_ROLLBACK_DENIED');
    if (actualRevision !== expectedRevision) deny('B02_LEASE_REVISION_DENIED');
    if (record.ownerId !== binding.ownerId || record.botId !== binding.botId ||
        record.bindingGeneration !== binding.generation) deny('B02_LEASE_BINDING_DENIED');
    token = Buffer.from(sourceToken);
    zero(sourceToken);
    sourceToken = null;
    zero(passphrase);
    await session.close();
    session = null;
  } catch (error) {
    await destroy();
    if (error instanceof CredentialLeaseError) throw error;
    deny(safeCode(error, DRIVER_CODES, 'B02_LEASE_DRIVER_DENIED'));
  }

  const lease = {
    async withToken(consumer) {
      if (closed || !token) deny('B02_LEASE_CLOSED');
      if (typeof consumer !== 'function') {
        await destroy();
        deny('B02_LEASE_CONSUMER_DENIED');
      }
      if (busy) {
        await destroy();
        deny('B02_LEASE_REENTRANT_DENIED');
      }
      busy = true;
      const ephemeral = Buffer.from(token);
      activeEphemerals.add(ephemeral);
      try {
        const result = await consumer(ephemeral);
        if (closed) deny('B02_LEASE_CLOSED');
        return validateConsumerResult(result);
      } catch (error) {
        await destroy();
        throw error;
      } finally {
        zero(ephemeral);
        activeEphemerals.delete(ephemeral);
        busy = false;
      }
    },
    async close() {
      await destroy();
      return Object.freeze({ closed: true, zeroized: true });
    },
    status() {
      return Object.freeze({ closed, zeroized, tokenResident: Boolean(token), revision: expectedRevision,
        bindingGeneration: binding.generation });
    }
  };
  return Object.freeze(lease);
}

export const credentialLeaseConstants = Object.freeze({
  credentialSchema: CREDENTIAL_SCHEMA,
  acceptedConsumerResults: Object.freeze([...CONSUMER_RESULTS])
});

export async function openCredentialLeaseFromOperator({ credentialOperatorPort, purpose, bootEpoch }) {
  if (!credentialOperatorPort || credentialOperatorPort.productionAdmitted !== true ||
      typeof credentialOperatorPort.openLease !== 'function' || purpose !== 'telegram-mcp-admission' ||
      typeof bootEpoch !== 'string' || !/^[a-f0-9]{64}$/.test(bootEpoch)) deny('B02_LEASE_OPERATOR_DENIED');
  const lease = await credentialOperatorPort.openLease({ purpose, bootEpoch });
  if (!lease || lease.productionAdmitted !== true || lease.secretBufferBoundary !== 'mutable-buffer-v1' ||
      typeof lease.withToken !== 'function' || typeof lease.close !== 'function') {
    try { await lease?.close?.(); } catch {}
    deny('B02_LEASE_OPERATOR_DENIED');
  }
  return lease;
}
