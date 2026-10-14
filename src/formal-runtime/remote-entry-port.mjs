import { types } from 'node:util';
import { randomBytes } from 'node:crypto';
import { safeHash, safeLabel } from './protocol.mjs';

export class MacRemoteEntryError extends Error {
  constructor(code) { super(code); this.name = 'MacRemoteEntryError'; this.code = code; }
}

function deny(code) { throw new MacRemoteEntryError(code); }
function record(value, keys, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny(code);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const actual = Reflect.ownKeys(descriptors);
  if (actual.length !== keys.length || actual.some(key => typeof key !== 'string' || !keys.includes(key)) ||
      keys.some(key => !Object.hasOwn(descriptors, key)) ||
      Object.values(descriptors).some(d => !d.enumerable || !Object.hasOwn(d, 'value'))) deny(code);
  return value;
}
function object(value, code) {
  if (!value || typeof value !== 'object' || types.isProxy(value)) deny(code);
  return value;
}
function methods(value, names) {
  object(value, 'REMOTE_ENTRY_CONFIG_DENIED');
  const captured = {};
  for (const name of names) {
    const d = Object.getOwnPropertyDescriptor(value, name);
    if (!d || !Object.hasOwn(d, 'value') || typeof d.value !== 'function' || types.isProxy(d.value)) {
      deny('REMOTE_ENTRY_CONFIG_DENIED');
    }
    captured[name] = d.value.bind(value);
  }
  return Object.freeze(captured);
}
function integer(value, minimum, maximum, code) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) deny(code);
  return value;
}
function scopes(value) {
  if (!Array.isArray(value) || types.isProxy(value) || value.length < 1 || value.length > 16 ||
      !Object.isFrozen(value)) deny('REMOTE_ENTRY_BINDING_DENIED');
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).length !== value.length + 1) deny('REMOTE_ENTRY_BINDING_DENIED');
  const result = [];
  for (let i = 0; i < value.length; i++) {
    const d = descriptors[String(i)];
    if (!d || !Object.hasOwn(d, 'value') || typeof d.value !== 'string' || !d.value || d.value.length > 256) {
      deny('REMOTE_ENTRY_BINDING_DENIED');
    }
    result.push(d.value);
  }
  if (new Set(result).size !== result.length || !result.includes('mcp')) deny('REMOTE_ENTRY_BINDING_DENIED');
  return Object.freeze(result);
}
function reference(value) {
  if (typeof value !== 'string' || !/^[A-Za-z][A-Za-z0-9._/@-]{2,255}$/.test(value)) {
    deny('REMOTE_ENTRY_BINDING_DENIED');
  }
  return value;
}
function immutable(value, depth = 0, seen = new WeakSet()) {
  if (value === null || ['string', 'boolean'].includes(typeof value)) return;
  if (typeof value === 'number' && Number.isFinite(value)) return;
  if (typeof value !== 'object' || types.isProxy(value) || depth > 32 || !Object.isFrozen(value) || seen.has(value)) {
    deny('REMOTE_ENTRY_COMMAND_DENIED');
  }
  seen.add(value);
  if (!Array.isArray(value) && ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    deny('REMOTE_ENTRY_COMMAND_DENIED');
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const key of Reflect.ownKeys(descriptors)) {
    if (key === 'length' && Array.isArray(value)) continue;
    if (typeof key !== 'string' || !Object.hasOwn(descriptors[key], 'value')) deny('REMOTE_ENTRY_COMMAND_DENIED');
    immutable(descriptors[key].value, depth + 1, seen);
  }
  seen.delete(value);
}
function commandInput(value) {
  record(value, ['request', 'actor', 'validatedWire', 'effectiveEnvelope'], 'REMOTE_ENTRY_CONTEXT_DENIED');
  if (!Object.isFrozen(value) || !Object.isFrozen(object(value.request, 'REMOTE_ENTRY_CONTEXT_DENIED')) ||
      !Object.isFrozen(object(value.actor, 'REMOTE_ENTRY_CONTEXT_DENIED')) ||
      !Object.isFrozen(object(value.validatedWire, 'REMOTE_ENTRY_CONTEXT_DENIED'))) deny('REMOTE_ENTRY_CONTEXT_DENIED');
  const command = record(value.effectiveEnvelope, ['jsonrpc', 'id', 'method', 'params'], 'REMOTE_ENTRY_COMMAND_DENIED');
  const params = record(command.params, ['name', 'arguments'], 'REMOTE_ENTRY_COMMAND_DENIED');
  if (command.jsonrpc !== '2.0' || command.method !== 'tools/call' ||
      !['string', 'number'].includes(typeof command.id) ||
      (typeof command.id === 'number' && !Number.isSafeInteger(command.id))) deny('REMOTE_ENTRY_COMMAND_DENIED');
  safeLabel(params.name, 'REMOTE_ENTRY_COMMAND_DENIED');
  immutable(command);
  return value;
}

const BINDING_KEYS = ['proof', 'identityInput', 'contextInput', 'actorRef', 'ownerRef', 'householdRef',
  'scopeRefs', 'epoch', 'expiresAt', 'capability', 'ownerId', 'botId', 'bindingGeneration', 'bootEpoch', 'sessionExpiresMonotonicMs', 'assertCurrentSession'];
const LEASE_KEYS = ['proof', 'actorRef', 'ownerRef', 'householdRef', 'scopeRefs', 'accountIdentifier', 'epoch', 'expiresAt'];

function bindingSnapshot(value, input) {
  const b = record(value, BINDING_KEYS, 'REMOTE_ENTRY_BINDING_DENIED');
  object(b.proof, 'REMOTE_ENTRY_BINDING_DENIED');
  const identityInput = record(b.identityInput, ['accountId', 'context'], 'REMOTE_ENTRY_BINDING_DENIED');
  if (b.contextInput !== input || !Object.isFrozen(b) || !Object.isFrozen(identityInput) ||
      typeof identityInput.accountId !== 'string' || !identityInput.accountId || identityInput.accountId.length > 256 ||
      b.capability !== input.effectiveEnvelope.params.name) deny('REMOTE_ENTRY_BINDING_DENIED');
  if (typeof b.assertCurrentSession !== 'function' || types.isProxy(b.assertCurrentSession)) deny('REMOTE_ENTRY_BINDING_DENIED');
  return Object.freeze({ proof: b.proof, identityInput, contextInput: input,
    actorRef: reference(b.actorRef), ownerRef: reference(b.ownerRef), householdRef: reference(b.householdRef),
    scopeRefs: scopes(b.scopeRefs), epoch: integer(b.epoch, 1, Number.MAX_SAFE_INTEGER, 'REMOTE_ENTRY_BINDING_DENIED'),
    expiresAt: integer(b.expiresAt, 1, 8_640_000_000_000_000, 'REMOTE_ENTRY_BINDING_DENIED'), capability: b.capability,
    ownerId: safeLabel(b.ownerId, 'REMOTE_ENTRY_BINDING_DENIED'), botId: safeLabel(b.botId, 'REMOTE_ENTRY_BINDING_DENIED'),
    bindingGeneration: integer(b.bindingGeneration, 1, Number.MAX_SAFE_INTEGER, 'REMOTE_ENTRY_BINDING_DENIED'),
    bootEpoch: safeHash(b.bootEpoch, 'REMOTE_ENTRY_BINDING_DENIED'),
    sessionExpiresMonotonicMs: integer(b.sessionExpiresMonotonicMs, 1, Number.MAX_SAFE_INTEGER, 'REMOTE_ENTRY_BINDING_DENIED'), assertCurrentSession: b.assertCurrentSession });
}
function leaseSnapshot(value, binding) {
  const lease = record(value, LEASE_KEYS, 'REMOTE_ENTRY_IDENTITY_DENIED');
  object(lease.proof, 'REMOTE_ENTRY_IDENTITY_DENIED');
  const scopeRefs = scopes(lease.scopeRefs);
  if (lease.accountIdentifier !== binding.identityInput.accountId ||
      ['actorRef', 'ownerRef', 'householdRef', 'epoch'].some(key => lease[key] !== binding[key]) ||
      scopeRefs.length !== binding.scopeRefs.length || scopeRefs.some((scope, i) => scope !== binding.scopeRefs[i]) ||
      !Number.isSafeInteger(lease.expiresAt) || binding.expiresAt > lease.expiresAt) deny('REMOTE_ENTRY_IDENTITY_DENIED');
  return Object.freeze({ proof: lease.proof, actorRef: lease.actorRef, ownerRef: lease.ownerRef,
    householdRef: lease.householdRef, scopeRefs, accountIdentifier: lease.accountIdentifier,
    epoch: lease.epoch, expiresAt: lease.expiresAt });
}
function sameBinding(a, b) {
  return ['proof', 'identityInput', 'contextInput', 'actorRef', 'ownerRef', 'householdRef', 'epoch', 'expiresAt', 'capability', 'ownerId', 'botId', 'bindingGeneration', 'bootEpoch', 'sessionExpiresMonotonicMs', 'assertCurrentSession']
    .every(key => a[key] === b[key]) && a.scopeRefs.length === b.scopeRefs.length &&
    a.scopeRefs.every((scope, i) => scope === b.scopeRefs[i]);
}
function sameLease(a, b) {
  return ['proof', 'actorRef', 'ownerRef', 'householdRef', 'accountIdentifier', 'epoch', 'expiresAt']
    .every(key => a[key] === b[key]) && a.scopeRefs.length === b.scopeRefs.length &&
    a.scopeRefs.every((scope, i) => scope === b.scopeRefs[i]);
}

export function createMacRemoteEntryPorts(options) {
  record(options, ['identityAuthority', 'requestBindingPort', 'clock', 'bootEpoch', 'limits'], 'REMOTE_ENTRY_CONFIG_DENIED');
  let identityAuthority = methods(options.identityAuthority, ['resolveMatchedRingAccount', 'recheck']);
  let requestBindingPort = methods(options.requestBindingPort, ['resolve', 'recheck']);
  let clock = methods(options.clock, ['monotonicNowMs', 'wallNowMs']);
  let bootSource = options.bootEpoch;
  let bootEpoch = methods(options.bootEpoch, ['status']);
  const digestDescriptor = Object.getOwnPropertyDescriptor(options.bootEpoch, 'digest');
  if (!digestDescriptor || !Object.hasOwn(digestDescriptor, 'value')) deny('REMOTE_ENTRY_CONFIG_DENIED');
  const bootDigest = safeHash(digestDescriptor.value, 'REMOTE_ENTRY_CONFIG_DENIED');
  const limits = record(options.limits, ['maxHandles', 'ttlMs', 'operationTimeoutMs', 'closeTimeoutMs'], 'REMOTE_ENTRY_CONFIG_DENIED');
  const maxHandles = integer(limits.maxHandles, 1, 128, 'REMOTE_ENTRY_CONFIG_DENIED');
  const ttlMs = integer(limits.ttlMs, 1, 30_000, 'REMOTE_ENTRY_CONFIG_DENIED');
  const operationTimeoutMs = integer(limits.operationTimeoutMs, 1, 30_000, 'REMOTE_ENTRY_CONFIG_DENIED');
  const closeTimeoutMs = integer(limits.closeTimeoutMs, 1, 30_000, 'REMOTE_ENTRY_CONFIG_DENIED');
  const handles = new Map();
  const sessionReceipts = new Map();
  const pending = new Set();
  const dependencies = new Set();
  const slots = new Set();
  let resolvedContexts = new WeakSet();
  let counter = 0;
  let generation = 1;
  let closed = false;
  let disabled = false;
  let lastMonotonic = -1;
  let lastWall = -1;
  let closePromise;

  function alive(expected) {
    if (closed || expected !== generation) deny('REMOTE_ENTRY_CLOSED');
    if (disabled) deny('REMOTE_ENTRY_DISABLED');
  }
  function times(expected) {
    alive(expected);
    try {
      const currentDigest = Object.getOwnPropertyDescriptor(bootSource, 'digest');
      if (!currentDigest || !Object.hasOwn(currentDigest, 'value') || currentDigest.value !== bootDigest) {
        deny('REMOTE_ENTRY_BOOT_DENIED');
      }
      const boot = record(bootEpoch.status(), ['closed', 'keyResident'], 'REMOTE_ENTRY_BOOT_DENIED');
      if (boot.closed !== false || boot.keyResident !== true) deny('REMOTE_ENTRY_BOOT_DENIED');
      const monotonic = integer(clock.monotonicNowMs(), 0, Number.MAX_SAFE_INTEGER, 'REMOTE_ENTRY_CLOCK_DENIED');
      const wall = integer(clock.wallNowMs(), 1, 8_640_000_000_000_000, 'REMOTE_ENTRY_CLOCK_DENIED');
      if (monotonic < lastMonotonic || wall < lastWall) deny('REMOTE_ENTRY_CLOCK_DENIED');
      lastMonotonic = monotonic; lastWall = wall;
      return { monotonic, wall };
    } catch {
      disabled = true; handles.clear(); sessionReceipts.clear(); deny('REMOTE_ENTRY_CLOCK_OR_BOOT_DENIED');
    }
  }
  function fresh(entry, expected) {
    const now = times(expected);
    if (entry.binding.assertCurrentSession() !== true) deny('REMOTE_SESSION_RECEIPT_DENIED');
    if (now.monotonic < entry.issuedMonotonicMs || now.monotonic >= entry.expiresMonotonicMs ||
        now.monotonic >= entry.binding.sessionExpiresMonotonicMs || entry.binding.bootEpoch !== bootDigest ||
        now.wall >= entry.binding.expiresAt || now.wall >= entry.lease.expiresAt) deny('REMOTE_ENTRY_EXPIRED');
    return now;
  }
  function prune(now) {
    for (const [handle, entry] of handles) if (now.monotonic >= entry.expiresMonotonicMs ||
      now.monotonic >= entry.binding.sessionExpiresMonotonicMs || entry.binding.bootEpoch !== bootDigest ||
        now.wall >= entry.binding.expiresAt || now.wall >= entry.lease.expiresAt) handles.delete(handle);
  }
  function pruneReceipts(now) {
    for (const [receipt, capture] of sessionReceipts) {
      if (now.monotonic >= capture.entry.expiresMonotonicMs || now.monotonic >= capture.entry.binding.sessionExpiresMonotonicMs ||
          now.wall >= capture.entry.binding.expiresAt || now.wall >= capture.entry.lease.expiresAt) sessionReceipts.delete(receipt);
    }
  }
  function reservedSlots() {
    let count = 0;
    for (const slot of slots) if (!slot.transferred) count++;
    return count;
  }
  function releaseSlot(slot) {
    if (slot.finished && slot.dependencies === 0) slots.delete(slot);
  }
  async function awaitDependency(value, expected, slot) {
    slot.dependencies++;
    function settled() {
      dependencies.delete(tracked); slot.dependencies--; releaseSlot(slot);
    }
    let tracked;
    tracked = Promise.resolve(value).then(result => { settled(); return result; },
      () => { settled(); deny('REMOTE_ENTRY_AUTHORITY_UNAVAILABLE'); });
    dependencies.add(tracked);
    let timer;
    try {
      const result = await Promise.race([tracked, new Promise((_, reject) => {
        timer = setTimeout(() => reject(new MacRemoteEntryError('REMOTE_ENTRY_AUTHORITY_TIMEOUT')), operationTimeoutMs);
      })]);
      times(expected);
      return result;
    } finally { clearTimeout(timer); }
  }
  function operation(work) {
    if (handles.size + sessionReceipts.size + reservedSlots() >= maxHandles) {
      return Promise.reject(new MacRemoteEntryError('REMOTE_ENTRY_CAPACITY'));
    }
    const slot = { dependencies: 0, finished: false, transferred: false };
    slots.add(slot);
    const expected = generation;
    let p;
    p = Promise.resolve().then(() => { alive(expected); return work(expected, slot); }).catch(error => {
      if (error instanceof MacRemoteEntryError) throw error;
      deny('REMOTE_ENTRY_AUTHORITY_UNAVAILABLE');
    }).finally(() => { pending.delete(p); slot.finished = true; releaseSlot(slot); });
    pending.add(p);
    return p;
  }
  async function resolve(input, expected, slot) {
    const binding = bindingSnapshot(await awaitDependency(requestBindingPort.resolve(input), expected, slot), input);
    times(expected);
    const lease = leaseSnapshot(await awaitDependency(identityAuthority.resolveMatchedRingAccount(binding.identityInput), expected, slot), binding);
    const currentBinding = bindingSnapshot(await awaitDependency(requestBindingPort.recheck(Object.freeze({
      proof: binding.proof, contextInput: input })), expected, slot), input);
    if (!sameBinding(binding, currentBinding)) deny('REMOTE_ENTRY_BINDING_CHANGED');
    const currentLease = leaseSnapshot(await awaitDependency(identityAuthority.recheck(lease.proof), expected, slot), binding);
    if (!sameLease(lease, currentLease)) deny('REMOTE_ENTRY_IDENTITY_CHANGED');
    const now = times(expected);
    if (binding.bootEpoch !== bootDigest || now.monotonic >= binding.sessionExpiresMonotonicMs || now.wall >= binding.expiresAt || now.wall >= lease.expiresAt) deny('REMOTE_ENTRY_EXPIRED');
    prune(now); pruneReceipts(now);
    if (handles.size >= maxHandles) deny('REMOTE_ENTRY_CAPACITY');
    counter = integer(counter + 1, 1, Number.MAX_SAFE_INTEGER, 'REMOTE_ENTRY_CAPACITY');
    const handle = Object.freeze(Object.create(null));
    const entry = Object.freeze({ binding, lease, issuedMonotonicMs: now.monotonic,
      expiresMonotonicMs: Math.min(now.monotonic + ttlMs, binding.sessionExpiresMonotonicMs, Number.MAX_SAFE_INTEGER),
      entryId: `remote.${bootDigest}.${randomBytes(16).toString('hex')}`, generation: expected });
    handles.set(handle, entry);
    slot.transferred = true;
    return Object.freeze({ source: 'remote', serverContext: Object.freeze({ intentHandle: handle }) });
  }

  async function recheckEntry(entry, expected, slot) {
    fresh(entry, expected);
    const binding = bindingSnapshot(await awaitDependency(requestBindingPort.recheck(Object.freeze({
      proof: entry.binding.proof, contextInput: entry.binding.contextInput })), expected, slot), entry.binding.contextInput);
    fresh(entry, expected);
    if (!sameBinding(entry.binding, binding)) deny('REMOTE_ENTRY_BINDING_CHANGED');
    const lease = leaseSnapshot(await awaitDependency(identityAuthority.recheck(entry.lease.proof), expected, slot), binding);
    fresh(entry, expected);
    if (!sameLease(entry.lease, lease)) deny('REMOTE_ENTRY_IDENTITY_CHANGED');
    return binding;
  }

  async function consume(entry, expected, slot) {
    const binding = await recheckEntry(entry, expected, slot);
    const sessionReceipt = Object.freeze(Object.create(null));
    sessionReceipts.set(sessionReceipt, { entry, phase: 'AVAILABLE' });
    slot.transferred = true;
    return Object.freeze({ productionAdmitted: true, singleUse: true, path: 'remote-encrypted', purpose: 'mcp-entry',
      bootEpoch: bootDigest, scope: 'mcp', capability: binding.capability, entryId: entry.entryId,
      issuedMonotonicMs: entry.issuedMonotonicMs, wifiTrust: null, sessionReceipt });
  }

  function checkedSession(value, phase, finish = false) {
    const x = record(value, ['receipt', 'entryId', 'bootEpoch', 'scope', 'capability', 'purpose'], 'REMOTE_SESSION_RECEIPT_DENIED');
    const capture = sessionReceipts.get(object(x.receipt, 'REMOTE_SESSION_RECEIPT_DENIED'));
    if (!capture || capture.phase !== phase) deny('REMOTE_SESSION_RECEIPT_DENIED');
    if (finish) sessionReceipts.delete(x.receipt);
    const b = capture.entry.binding;
    fresh(capture.entry, generation);
    if (x.entryId !== capture.entry.entryId || x.bootEpoch !== bootDigest || x.scope !== 'mcp' ||
        x.capability !== b.capability || x.purpose !== 'mcp-entry') deny('REMOTE_SESSION_RECEIPT_DENIED');
    return Object.freeze({ schema: 'validated-owner-session-v1', ownerId: b.ownerId, botId: b.botId,
      bindingGeneration: b.bindingGeneration, bootEpoch: b.bootEpoch,
      expiresMonotonicMs: Math.min(b.sessionExpiresMonotonicMs, capture.entry.expiresMonotonicMs),
      scope: x.scope, capability: b.capability, purpose: x.purpose, entryId: x.entryId });
  }

  function claimSession(value, phase, nextPhase) {
    try {
      alive(generation);
      const x = record(value, ['receipt', 'entryId', 'bootEpoch', 'scope', 'capability', 'purpose'], 'REMOTE_SESSION_RECEIPT_DENIED');
      const capture = sessionReceipts.get(object(x.receipt, 'REMOTE_SESSION_RECEIPT_DENIED'));
      if (!capture || capture.phase !== phase) deny('REMOTE_SESSION_RECEIPT_DENIED');
      sessionReceipts.delete(x.receipt);
      if (x.entryId !== capture.entry.entryId || x.bootEpoch !== bootDigest || x.scope !== 'mcp' ||
          x.capability !== capture.entry.binding.capability || x.purpose !== 'mcp-entry') deny('REMOTE_SESSION_RECEIPT_DENIED');
      return operation(async (expected, slot) => {
        const b = await recheckEntry(capture.entry, expected, slot);
        if (nextPhase) {
          sessionReceipts.set(x.receipt, { entry: capture.entry, phase: nextPhase });
          slot.transferred = true;
        }
        return Object.freeze({ schema: 'validated-owner-session-v1', ownerId: b.ownerId, botId: b.botId,
          bindingGeneration: b.bindingGeneration, bootEpoch: b.bootEpoch,
          expiresMonotonicMs: Math.min(b.sessionExpiresMonotonicMs, capture.entry.expiresMonotonicMs),
          scope: x.scope, capability: b.capability, purpose: x.purpose, entryId: x.entryId });
      });
    } catch (error) { return Promise.reject(error instanceof MacRemoteEntryError ? error : new MacRemoteEntryError('REMOTE_SESSION_RECEIPT_DENIED')); }
  }

  async function close() {
    if (closePromise) return closePromise;
    closed = true; generation++; handles.clear(); sessionReceipts.clear(); resolvedContexts = new WeakSet();
    identityAuthority = null; requestBindingPort = null; clock = null; bootEpoch = null; bootSource = null;
    closePromise = (async () => {
      let timer;
      const complete = await Promise.race([Promise.allSettled([...pending, ...dependencies]).then(() => true),
        new Promise(resolve => { timer = setTimeout(() => resolve(false), closeTimeoutMs); })]);
      clearTimeout(timer);
      if (!complete || pending.size !== 0 || dependencies.size !== 0) deny('REMOTE_ENTRY_CLOSE_INCOMPLETE');
      return Object.freeze({ closed: true });
    })();
    return closePromise;
  }

  const remoteEntryPort = Object.freeze({ productionAdmitted: true,
    consumeSealedIntent(value) {
      try {
        alive(generation);
        const fields = record(value, ['intentHandle', 'envelope'], 'REMOTE_ENTRY_HANDLE_DENIED');
        const handle = object(fields.intentHandle, 'REMOTE_ENTRY_HANDLE_DENIED');
        const entry = handles.get(handle);
        if (!entry) deny('REMOTE_ENTRY_HANDLE_DENIED');
        handles.delete(handle);
        if (fields.envelope !== entry.binding.contextInput.effectiveEnvelope) deny('REMOTE_ENTRY_COMMAND_DENIED');
        return operation((expected, slot) => consume(entry, expected, slot));
      } catch (error) { return Promise.reject(error instanceof MacRemoteEntryError ? error :
        new MacRemoteEntryError('REMOTE_ENTRY_HANDLE_DENIED')); }
    },
    consumeSessionReceipt(value) { return claimSession(value, 'AVAILABLE', 'ISSUED'); },
    recheckSessionReceipt(value) { return claimSession(value, 'ISSUED', 'CONSUMING'); },
    validateClaimedSessionReceipt(value) { return checkedSession(value, 'ISSUED'); },
    finishSessionReceipt(value) { return checkedSession(value, 'CONSUMING', true); }, close });
  const formalContextPort = Object.freeze({ productionAdmitted: true,
    resolve(value) {
      try {
        const input = commandInput(value);
        const now = times(generation); prune(now); pruneReceipts(now);
        if (resolvedContexts.has(input)) deny('REMOTE_ENTRY_CONTEXT_REPLAY');
        if (handles.size + sessionReceipts.size + reservedSlots() >= maxHandles) deny('REMOTE_ENTRY_CAPACITY');
        resolvedContexts.add(input);
        return operation((expected, slot) => resolve(input, expected, slot));
      } catch (error) { return Promise.reject(error instanceof MacRemoteEntryError ? error :
        new MacRemoteEntryError('REMOTE_ENTRY_CONTEXT_DENIED')); }
    }, close });
  return Object.freeze({ remoteEntryPort, formalContextPort, close,
    status() { return Object.freeze({ closed, disabled, activeHandles: handles.size,
      activeSessionReceipts: sessionReceipts.size, pendingOperations: pending.size, pendingDependencies: dependencies.size, reservations: reservedSlots() }); } });
}
