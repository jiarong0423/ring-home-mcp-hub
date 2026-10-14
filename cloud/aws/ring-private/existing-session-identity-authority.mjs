import { types } from 'node:util';

const VIEW_FIELDS = Object.freeze([
  'productionAdmitted', 'serverNow', 'ownerEpoch', 'sessionId', 'sessionGeneration',
  'grantId', 'grantGeneration', 'sessionExpiresAt', 'idleExpiresAt', 'trustExpiresAt'
]);
const PIN_FIELDS = Object.freeze(['ownerEpoch', 'sessionId', 'sessionGeneration', 'grantId', 'grantGeneration']);
const BINDING_FIELDS = Object.freeze([
  'actorRef', 'ownerRef', 'householdRef', 'scopeRefs', 'accountIdentifier', 'epoch', 'expiresAt'
]);
const RAW_TELEGRAM_FIELDS = new Set([
  'telegram', 'telegramid', 'telegramtoken', 'tg', 'tgid', 'tgtoken',
  'userid', 'chatid', 'botid', 'bottoken', 'token'
]);
const CONTEXT_MAX_DEPTH = 4;
const CONTEXT_MAX_NODES = 64;
const CONTEXT_MAX_KEYS = 128;
const CONTEXT_MAX_ARRAY = 32;
const REFERENCE = /^[A-Za-z][A-Za-z0-9._/@-]{2,255}$/;

export class ExistingSessionIdentityAuthorityError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ExistingSessionIdentityAuthorityError';
    this.code = code;
  }
}

function deny(code) {
  throw new ExistingSessionIdentityAuthorityError(code);
}

function exact(value, fields, code) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny(code);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== fields.length || fields.some(field => !Object.hasOwn(descriptors, field)) ||
        keys.some(key => typeof key !== 'string' || !fields.includes(key) ||
          !Object.hasOwn(descriptors[key], 'value'))) deny(code);
    return Object.fromEntries(fields.map(field => [field, descriptors[field].value]));
  } catch (error) {
    if (error instanceof ExistingSessionIdentityAuthorityError) throw error;
    deny(code);
  }
}

function requireFunction(value, code, synchronous = false) {
  if (typeof value !== 'function' || types.isProxy(value) ||
      (synchronous && (types.isAsyncFunction(value) || types.isGeneratorFunction(value)))) deny(code);
  return value;
}

function requirePort(value) {
  try {
    if (!value || typeof value !== 'object' || types.isProxy(value)) deny('IDENTITY_AUTHORITY_CONFIG');
    const inspect = Object.getOwnPropertyDescriptor(value, 'inspectSession');
    const current = Object.getOwnPropertyDescriptor(value, 'withCurrentSession');
    if (!inspect || !current || !Object.hasOwn(inspect, 'value') || !Object.hasOwn(current, 'value')) {
      deny('IDENTITY_AUTHORITY_CONFIG');
    }
    return Object.freeze({
      receiver: value,
      inspectSession: requireFunction(inspect.value, 'IDENTITY_AUTHORITY_CONFIG'),
      withCurrentSession: requireFunction(current.value, 'IDENTITY_AUTHORITY_CONFIG')
    });
  } catch (error) {
    if (error instanceof ExistingSessionIdentityAuthorityError) throw error;
    deny('IDENTITY_AUTHORITY_CONFIG');
  }
}

function positiveInteger(value, code) {
  if (!Number.isSafeInteger(value) || value < 1) deny(code);
  return value;
}

function opaque(value, maximum, code) {
  if (typeof value !== 'string' || value.length < 1 || Buffer.byteLength(value) > maximum ||
      Buffer.from(value).toString('utf8') !== value || /[\x00-\x20\x7f]/.test(value)) deny(code);
  return value;
}

function reference(value, code) {
  opaque(value, 256, code);
  if (!REFERENCE.test(value)) deny(code);
  return value;
}

function scopes(value) {
  try {
    if (!Array.isArray(value) || types.isProxy(value) || value.length < 1 || value.length > 16) {
      deny('IDENTITY_BINDING_DENIED');
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some(key => key !== 'length' && (typeof key !== 'string' ||
        !/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length))) deny('IDENTITY_BINDING_DENIED');
    const result = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) deny('IDENTITY_BINDING_DENIED');
      result.push(reference(descriptor.value, 'IDENTITY_BINDING_DENIED'));
    }
    if (new Set(result).size !== result.length) deny('IDENTITY_BINDING_DENIED');
    return Object.freeze(result);
  } catch (error) {
    if (error instanceof ExistingSessionIdentityAuthorityError) throw error;
    deny('IDENTITY_BINDING_DENIED');
  }
}

function synchronous(value) {
  if (value && (typeof value === 'object' || typeof value === 'function')) {
    if (types.isProxy(value) || types.isPromise(value)) deny('IDENTITY_ASYNC_DENIED');
    for (let current = value; current; current = Object.getPrototypeOf(current)) {
      const descriptor = Object.getOwnPropertyDescriptor(current, 'then');
      if (descriptor && (!Object.hasOwn(descriptor, 'value') || typeof descriptor.value === 'function')) {
        deny('IDENTITY_ASYNC_DENIED');
      }
    }
  }
  return value;
}

function rejectRawTelegramFields(value) {
  const visited = new WeakSet();
  let nodes = 0;
  let keys = 0;
  function rawField(key) {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (RAW_TELEGRAM_FIELDS.has(normalized)) return true;
    for (const prefix of ['telegram', 'tg']) {
      if (normalized.startsWith(prefix)) {
        const suffix = normalized.slice(prefix.length);
        if (['user', 'chat', 'bot', 'token'].some(part => suffix.includes(part))) return true;
      }
    }
    return false;
  }
  function visit(current, depth) {
    if (current === null || !['object', 'function'].includes(typeof current)) return;
    if (types.isProxy(current)) deny('IDENTITY_INPUT_DENIED');
    if (visited.has(current)) deny('IDENTITY_INPUT_DENIED');
    visited.add(current);
    nodes += 1;
    if (nodes > CONTEXT_MAX_NODES || depth > CONTEXT_MAX_DEPTH) deny('IDENTITY_INPUT_DENIED');
    if (Array.isArray(current)) {
      if (current.length > CONTEXT_MAX_ARRAY) deny('IDENTITY_INPUT_DENIED');
      const descriptors = Object.getOwnPropertyDescriptors(current);
      for (const key of Reflect.ownKeys(descriptors)) {
        if (key === 'length') continue;
        if (typeof key !== 'string' || !/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= current.length ||
            !Object.hasOwn(descriptors[key], 'value')) deny('IDENTITY_INPUT_DENIED');
        keys += 1;
        if (keys > CONTEXT_MAX_KEYS) deny('IDENTITY_INPUT_DENIED');
        visit(descriptors[key].value, depth + 1);
      }
      return;
    }
    if (![Object.prototype, null].includes(Object.getPrototypeOf(current))) return;
    const descriptors = Object.getOwnPropertyDescriptors(current);
    for (const key of Reflect.ownKeys(descriptors)) {
      if (typeof key !== 'string' || !Object.hasOwn(descriptors[key], 'value')) deny('IDENTITY_INPUT_DENIED');
      keys += 1;
      if (keys > CONTEXT_MAX_KEYS || rawField(key)) deny('IDENTITY_INPUT_DENIED');
      visit(descriptors[key].value, depth + 1);
    }
  }
  try {
    if (!value || typeof value !== 'object' || types.isProxy(value)) deny('IDENTITY_INPUT_DENIED');
    visit(value, 0);
  } catch (error) {
    if (error instanceof ExistingSessionIdentityAuthorityError) throw error;
    deny('IDENTITY_INPUT_DENIED');
  }
}

function sessionView(value) {
  const current = exact(value, VIEW_FIELDS, 'IDENTITY_SESSION_DENIED');
  if (current.productionAdmitted !== true) deny('IDENTITY_SESSION_DENIED');
  positiveInteger(current.serverNow, 'IDENTITY_SESSION_DENIED');
  positiveInteger(current.ownerEpoch, 'IDENTITY_SESSION_DENIED');
  positiveInteger(current.sessionGeneration, 'IDENTITY_SESSION_DENIED');
  positiveInteger(current.grantGeneration, 'IDENTITY_SESSION_DENIED');
  opaque(current.sessionId, 256, 'IDENTITY_SESSION_DENIED');
  opaque(current.grantId, 256, 'IDENTITY_SESSION_DENIED');
  for (const field of ['sessionExpiresAt', 'idleExpiresAt', 'trustExpiresAt']) {
    positiveInteger(current[field], 'IDENTITY_SESSION_DENIED');
    if (current[field] <= current.serverNow) deny('IDENTITY_EXPIRED');
  }
  return Object.freeze(current);
}

function sessionArguments(value) {
  const args = exact(synchronous(value), ['sessionProof', 'csrf'], 'IDENTITY_SESSION_DENIED');
  opaque(args.sessionProof, 4096, 'IDENTITY_SESSION_DENIED');
  opaque(args.csrf, 4096, 'IDENTITY_SESSION_DENIED');
  return Object.freeze(args);
}

function identityBinding(value, accountId, current) {
  const binding = exact(synchronous(value), BINDING_FIELDS, 'IDENTITY_BINDING_DENIED');
  binding.actorRef = reference(binding.actorRef, 'IDENTITY_BINDING_DENIED');
  binding.ownerRef = reference(binding.ownerRef, 'IDENTITY_BINDING_DENIED');
  binding.householdRef = reference(binding.householdRef, 'IDENTITY_BINDING_DENIED');
  binding.scopeRefs = scopes(binding.scopeRefs);
  opaque(binding.accountIdentifier, 256, 'IDENTITY_BINDING_DENIED');
  positiveInteger(binding.epoch, 'IDENTITY_BINDING_DENIED');
  positiveInteger(binding.expiresAt, 'IDENTITY_BINDING_DENIED');
  if (binding.accountIdentifier !== accountId || binding.epoch !== current.ownerEpoch ||
      binding.expiresAt <= current.serverNow) deny('IDENTITY_BINDING_DENIED');
  return Object.freeze(binding);
}

function policyValues(value) {
  if (value === undefined) return Object.freeze({ maxLiveProofs: 128, maxLeaseMs: 600_000, closeTimeoutMs: 3_000 });
  if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny('IDENTITY_POLICY_DENIED');
  const supplied = exact(value, Reflect.ownKeys(Object.getOwnPropertyDescriptors(value)), 'IDENTITY_POLICY_DENIED');
  const allowed = ['maxLiveProofs', 'maxLeaseMs', 'closeTimeoutMs'];
  if (Object.keys(supplied).some(key => !allowed.includes(key))) deny('IDENTITY_POLICY_DENIED');
  const result = {
    maxLiveProofs: supplied.maxLiveProofs ?? 128,
    maxLeaseMs: supplied.maxLeaseMs ?? 600_000,
    closeTimeoutMs: supplied.closeTimeoutMs ?? 3_000
  };
  if (!Number.isSafeInteger(result.maxLiveProofs) || result.maxLiveProofs < 1 || result.maxLiveProofs > 128 ||
      !Number.isSafeInteger(result.maxLeaseMs) || result.maxLeaseMs < 1 || result.maxLeaseMs > 600_000 ||
      !Number.isSafeInteger(result.closeTimeoutMs) || result.closeTimeoutMs < 1 || result.closeTimeoutMs > 30_000) {
    deny('IDENTITY_POLICY_DENIED');
  }
  return Object.freeze(result);
}

function constructorOptions(value) {
  const required = ['sessionAuthority', 'extractSession', 'resolveAccountBinding'];
  const allowed = [...required, 'policy'];
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny('IDENTITY_AUTHORITY_CONFIG');
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (required.some(key => !Object.hasOwn(descriptors, key)) ||
        keys.some(key => typeof key !== 'string' || !allowed.includes(key) ||
          !Object.hasOwn(descriptors[key], 'value'))) deny('IDENTITY_AUTHORITY_CONFIG');
    return Object.fromEntries(keys.map(key => [key, descriptors[key].value]));
  } catch (error) {
    if (error instanceof ExistingSessionIdentityAuthorityError) throw error;
    deny('IDENTITY_AUTHORITY_CONFIG');
  }
}

function sameIdentity(left, right) {
  return ['actorRef', 'ownerRef', 'householdRef', 'accountIdentifier', 'epoch', 'bindingExpiresAt']
    .every(field => left[field] === right[field]) &&
    left.scopeRefs.length === right.scopeRefs.length &&
    left.scopeRefs.every((scope, index) => scope === right.scopeRefs[index]);
}

export function createExistingSessionIdentityAuthority(value) {
  const options = constructorOptions(value);
  const authority = requirePort(options.sessionAuthority);
  const extract = requireFunction(options.extractSession, 'IDENTITY_AUTHORITY_CONFIG', true);
  const resolveBinding = requireFunction(options.resolveAccountBinding, 'IDENTITY_AUTHORITY_CONFIG', true);
  const limits = policyValues(options.policy);
  let associations = new WeakMap();
  const live = new Set();
  const pending = new Set();
  let closed = false;
  let generation = 1;
  let closePromise;

  function alive(expected) {
    if (closed || expected !== generation) deny('IDENTITY_CLOSED');
  }

  function prune(serverNow) {
    for (const entry of live) {
      const proof = entry.reference.deref();
      if (!proof || serverNow >= entry.expiresAt) {
        if (proof) associations.delete(proof);
        live.delete(entry);
      }
    }
  }

  function operation(work) {
    if (closed) return Promise.reject(new ExistingSessionIdentityAuthorityError('IDENTITY_CLOSED'));
    const expected = generation;
    let operationPromise;
    operationPromise = Promise.resolve().then(() => {
      alive(expected);
      return work(expected);
    }).catch(error => {
      if (error instanceof ExistingSessionIdentityAuthorityError) throw error;
      throw new ExistingSessionIdentityAuthorityError('IDENTITY_AUTHORITY_UNAVAILABLE');
    }).finally(() => pending.delete(operationPromise));
    pending.add(operationPromise);
    return operationPromise;
  }

  async function locked(args, accountId, capture, expected) {
    let invocations = 0;
    let callbackError;
    let snapshot;
    try {
      await authority.withCurrentSession.call(authority.receiver, args, raw => {
        invocations += 1;
        try {
          alive(expected);
          if (invocations !== 1) deny('IDENTITY_LOCK_DENIED');
          const current = sessionView(raw);
          if (PIN_FIELDS.some(field => current[field] !== capture.pins[field]) ||
              current.serverNow < capture.lastServerNow) deny('IDENTITY_SESSION_CHANGED');
          prune(current.serverNow);
          const request = Object.freeze({ accountId, session: current });
          const binding = identityBinding(resolveBinding(request), accountId, current);
          const expiresAt = Math.min(
            capture.ceiling,
            binding.expiresAt,
            current.sessionExpiresAt,
            current.idleExpiresAt,
            current.trustExpiresAt
          );
          if (current.serverNow >= expiresAt) deny('IDENTITY_EXPIRED');
          snapshot = Object.freeze({
            actorRef: binding.actorRef,
            ownerRef: binding.ownerRef,
            householdRef: binding.householdRef,
            scopeRefs: binding.scopeRefs,
            accountIdentifier: binding.accountIdentifier,
            epoch: binding.epoch,
            expiresAt,
            bindingExpiresAt: binding.expiresAt
          });
          if (capture.baseline && (!sameIdentity(snapshot, capture.baseline) ||
              snapshot.expiresAt !== capture.baseline.expiresAt)) deny('IDENTITY_BINDING_CHANGED');
          capture.lastServerNow = current.serverNow;
          return snapshot;
        } catch (error) {
          callbackError = error;
          throw error;
        }
      });
    } catch (error) {
      if (callbackError) throw callbackError;
      throw error;
    }
    alive(expected);
    if (callbackError) throw callbackError;
    if (invocations !== 1 || !snapshot) deny('IDENTITY_LOCK_DENIED');
    return snapshot;
  }

  function publicLease(proof, snapshot) {
    return Object.freeze({
      proof,
      actorRef: snapshot.actorRef,
      ownerRef: snapshot.ownerRef,
      householdRef: snapshot.householdRef,
      scopeRefs: snapshot.scopeRefs,
      accountIdentifier: snapshot.accountIdentifier,
      epoch: snapshot.epoch,
      expiresAt: snapshot.expiresAt
    });
  }

  return Object.freeze({
    resolveMatchedRingAccount(input) {
      return operation(async expected => {
        const request = exact(input, ['accountId', 'context'], 'IDENTITY_INPUT_DENIED');
        opaque(request.accountId, 256, 'IDENTITY_INPUT_DENIED');
        rejectRawTelegramFields(request.context);
        const args = sessionArguments(extract(request.context));
        const initial = sessionView(await authority.inspectSession.call(authority.receiver, args));
        alive(expected);
        prune(initial.serverNow);
        if (live.size >= limits.maxLiveProofs) deny('IDENTITY_PROOF_CAPACITY');
        const capture = {
          args,
          pins: Object.freeze(Object.fromEntries(PIN_FIELDS.map(field => [field, initial[field]]))),
          ceiling: Math.min(
            initial.sessionExpiresAt,
            initial.idleExpiresAt,
            initial.trustExpiresAt,
            initial.serverNow + limits.maxLeaseMs
          ),
          lastServerNow: initial.serverNow,
          baseline: null,
          generation: expected,
          accountId: request.accountId
        };
        const snapshot = await locked(args, request.accountId, capture, expected);
        alive(expected);
        prune(capture.lastServerNow);
        if (live.size >= limits.maxLiveProofs) deny('IDENTITY_PROOF_CAPACITY');
        const proof = Object.freeze(Object.create(null));
        capture.baseline = snapshot;
        associations.set(proof, capture);
        live.add({ reference: new WeakRef(proof), expiresAt: snapshot.expiresAt });
        return publicLease(proof, snapshot);
      });
    },

    recheck(proof) {
      return operation(async expected => {
        if (!proof || typeof proof !== 'object' || types.isProxy(proof)) deny('IDENTITY_PROOF_DENIED');
        const capture = associations.get(proof);
        if (!capture || capture.generation !== expected) deny('IDENTITY_PROOF_DENIED');
        const snapshot = await locked(capture.args, capture.accountId, capture, expected);
        return publicLease(proof, snapshot);
      });
    },

    async close() {
      if (closePromise) return await closePromise;
      closed = true;
      generation += 1;
      closePromise = (async () => {
        let timer;
        const timeout = new Promise(resolve => {
          timer = setTimeout(() => resolve(false), limits.closeTimeoutMs);
        });
        const settled = await Promise.race([
          Promise.allSettled([...pending]).then(() => true),
          timeout
        ]);
        clearTimeout(timer);
        associations = new WeakMap();
        live.clear();
        if (!settled || pending.size !== 0) deny('IDENTITY_CLOSE_INCOMPLETE');
        return Object.freeze({ closed: true });
      })();
      return await closePromise;
    }
  });
}
