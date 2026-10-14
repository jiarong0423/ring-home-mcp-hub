import {
  createHouseholdWifiTrust,
  recognizeHouseholdWifi,
  revokeHouseholdWifiTrust,
  rotateHouseholdWifiTrust
} from './household-wifi-trust.mjs';

const PUBLIC_STATES = Object.freeze(['disabled', 'idle', 'active', 'revoked', 'denied']);

export class WifiTrustServiceError extends Error {
  constructor(code) {
    super(code);
    this.name = 'WifiTrustServiceError';
    this.code = code;
  }
}

function deny(code) {
  throw new WifiTrustServiceError(code);
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

function safeTime(value) {
  if (!Number.isSafeInteger(value) || value <= 0 || value > 8_640_000_000_000_000) {
    deny('B02_WIFI_SERVICE_TIME_DENIED');
  }
  return value;
}

function monotonicTime(value, previous = 0) {
  const observed = safeTime(value);
  if (observed > previous) return observed;
  return safeTime(previous + 1);
}

function identity(value) {
  if (typeof value !== 'string' || !/^[A-Za-z][A-Za-z0-9:_-]{2,127}$/.test(value)) {
    deny('B02_WIFI_SERVICE_BINDING_DENIED');
  }
  return value;
}

function evidence(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9:_-]{1,128}$/.test(value)) {
    deny('B02_WIFI_SERVICE_BINDING_DENIED');
  }
  return value;
}

function validateBinding(value) {
  const fields = exact(value, [
    'active', 'ownerId', 'botId', 'householdId', 'generation', 'consentEvidence'
  ], 'B02_WIFI_SERVICE_BINDING_DENIED');
  if (fields.active !== true || !Number.isSafeInteger(fields.generation) || fields.generation < 1) {
    deny('B02_WIFI_SERVICE_BINDING_DENIED');
  }
  return Object.freeze({
    active: true,
    ownerId: identity(fields.ownerId),
    botId: identity(fields.botId),
    householdId: identity(fields.householdId),
    generation: fields.generation,
    consentEvidence: evidence(fields.consentEvidence)
  });
}

export function sanitizedStatus(state) {
  if (!PUBLIC_STATES.includes(state)) deny('B02_WIFI_SERVICE_STATUS_DENIED');
  return Object.freeze({ state });
}

function validateDependencies({ observer, store, bindingPort, clock }) {
  if (!observer || typeof observer.observeKeyedFingerprint !== 'function' ||
      !store || typeof store.readCurrent !== 'function' || typeof store.compareAndSwap !== 'function' ||
      !bindingPort || typeof bindingPort.current !== 'function' || typeof clock !== 'function') {
    deny('B02_WIFI_SERVICE_CONFIGURATION_DENIED');
  }
}

export function createDisabledWifiTrustService() {
  return Object.freeze({
    enabled: false,
    async sanitizedStatus() { return sanitizedStatus('disabled'); },
    async consentCurrentWifi() { return sanitizedStatus('disabled'); },
    async revokeCurrentWifi() { return sanitizedStatus('disabled'); },
    async recognizeForMcpEntry() { return null; }
  });
}

export function createWifiTrustService({ observer, store, bindingPort, clock = Date.now }) {
  validateDependencies({ observer, store, bindingPort, clock });
  let tail = Promise.resolve();

  function serialized(operation) {
    const result = tail.then(operation, operation);
    tail = result.then(() => undefined, () => undefined);
    return result;
  }

  async function currentBinding() {
    return validateBinding(await bindingPort.current());
  }

  async function statusOperation() {
    try {
      await currentBinding();
      const envelope = await store.readCurrent({ revisionFloor: 0 });
      if (envelope === null) return sanitizedStatus('idle');
      return sanitizedStatus(envelope.record.active ? 'active' : 'revoked');
    } catch {
      return sanitizedStatus('denied');
    }
  }

  async function consentOperation() {
    try {
      const binding = await currentBinding();
      const keyedFingerprint = await observer.observeKeyedFingerprint();
      const current = await store.readCurrent({ revisionFloor: 0 });
      const observedAt = monotonicTime(clock(), current?.record.rotatedAt ?? 0);
      let record;
      if (current === null) {
        record = createHouseholdWifiTrust({
          householdId: binding.householdId,
          generation: binding.generation,
          keyedFingerprint,
          verifiedAt: observedAt,
          rotatedAt: observedAt,
          consentEvidence: binding.consentEvidence
        });
      } else if (current.record.householdId !== binding.householdId) {
        deny('B02_WIFI_SERVICE_BINDING_DENIED');
      } else if (current.record.active && current.record.keyedFingerprint === keyedFingerprint) {
        return sanitizedStatus('active');
      } else if (current.record.active) {
        record = rotateHouseholdWifiTrust(current.record, {
          householdId: binding.householdId,
          keyedFingerprint,
          rotatedAt: observedAt,
          consentEvidence: binding.consentEvidence
        });
      } else {
        record = createHouseholdWifiTrust({
          householdId: binding.householdId,
          generation: current.record.generation + 1,
          keyedFingerprint,
          verifiedAt: observedAt,
          rotatedAt: observedAt,
          consentEvidence: binding.consentEvidence
        });
      }
      await store.compareAndSwap({
        expectedRevision: current?.revision ?? 0,
        revisionFloor: current?.revision ?? 0,
        record
      });
      return sanitizedStatus('active');
    } catch {
      return sanitizedStatus('denied');
    }
  }

  async function revokeOperation() {
    try {
      const binding = await currentBinding();
      const current = await store.readCurrent({ revisionFloor: 0 });
      if (current === null || current.record.householdId !== binding.householdId) return sanitizedStatus('denied');
      if (current.record.revoked) return sanitizedStatus('revoked');
      const revokedAt = monotonicTime(clock(), current.record.rotatedAt);
      const record = revokeHouseholdWifiTrust(current.record, {
        revokedAt,
        consentEvidence: binding.consentEvidence
      });
      await store.compareAndSwap({
        expectedRevision: current.revision,
        revisionFloor: current.revision,
        record
      });
      return sanitizedStatus('revoked');
    } catch {
      return sanitizedStatus('denied');
    }
  }

  async function recognizeOperation() {
    try {
      const binding = await currentBinding();
      const current = await store.readCurrent({ revisionFloor: 0 });
      if (current === null || !current.record.active || current.record.householdId !== binding.householdId) return null;
      const keyedFingerprint = await observer.observeKeyedFingerprint();
      return recognizeHouseholdWifi({
        trust: current.record,
        observedKeyedFingerprint: keyedFingerprint,
        observedAt: safeTime(clock())
      });
    } catch {
      return null;
    }
  }

  return Object.freeze({
    enabled: true,
    sanitizedStatus() { return serialized(statusOperation); },
    consentCurrentWifi() { return serialized(consentOperation); },
    revokeCurrentWifi() { return serialized(revokeOperation); },
    recognizeForMcpEntry() { return serialized(recognizeOperation); }
  });
}

export async function consentCurrentWifi(service) {
  if (!service || typeof service.consentCurrentWifi !== 'function') deny('B02_WIFI_SERVICE_INSTANCE_DENIED');
  return service.consentCurrentWifi();
}

export async function revokeCurrentWifi(service) {
  if (!service || typeof service.revokeCurrentWifi !== 'function') deny('B02_WIFI_SERVICE_INSTANCE_DENIED');
  return service.revokeCurrentWifi();
}

export async function recognizeForMcpEntry(service) {
  if (!service || typeof service.recognizeForMcpEntry !== 'function') deny('B02_WIFI_SERVICE_INSTANCE_DENIED');
  return service.recognizeForMcpEntry();
}
