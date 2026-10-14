import { types } from 'node:util';

const OPAQUE_CATEGORY = /^[A-Za-z0-9_-]{43}$/;
const REF = /^[A-Za-z][A-Za-z0-9._/@-]{2,255}$/;

export class CapabilityIntentContractError extends Error {
  constructor(code) { super(code); this.name = 'CapabilityIntentContractError'; this.code = code; }
}
function deny(code) { throw new CapabilityIntentContractError(code); }
function exact(value, fields, code) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny(code);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== fields.length || fields.some(field => !Object.hasOwn(descriptors, field)) ||
        keys.some(key => typeof key !== 'string' || !fields.includes(key) || !Object.hasOwn(descriptors[key], 'value'))) deny(code);
    return Object.fromEntries(fields.map(field => [field, descriptors[field].value]));
  } catch (error) { if (error instanceof CapabilityIntentContractError) throw error; deny(code); }
}
function method(port, name) {
  try {
    if (!port || typeof port !== 'object' || types.isProxy(port)) deny('CAPABILITY_CONFIG');
    const descriptor = Object.getOwnPropertyDescriptor(port, name);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function' ||
        types.isProxy(descriptor.value)) deny('CAPABILITY_CONFIG');
    return descriptor.value.bind(port);
  } catch (error) { if (error instanceof CapabilityIntentContractError) throw error; deny('CAPABILITY_CONFIG'); }
}
function finiteCopy(value, depth = 0, budget = { nodes: 0 }, seen = new Set()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (!value || typeof value !== 'object' || types.isProxy(value) || depth > 4 || seen.has(value)) deny('CAPABILITY_INPUT');
  budget.nodes += 1;
  if (budget.nodes > 64) deny('CAPABILITY_INPUT');
  seen.add(value);
  if (Array.isArray(value)) {
    if (value.length > 32) deny('CAPABILITY_INPUT');
    const output = value.map(item => finiteCopy(item, depth + 1, budget, seen));
    seen.delete(value);
    return Object.freeze(output);
  }
  if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny('CAPABILITY_INPUT');
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.length > 32 || keys.some(key => typeof key !== 'string' || key.length > 128 ||
      !Object.hasOwn(descriptors[key], 'value'))) deny('CAPABILITY_INPUT');
  const output = Object.create(null);
  for (const key of keys) output[key] = finiteCopy(descriptors[key].value, depth + 1, budget, seen);
  seen.delete(value);
  return Object.freeze(output);
}
function registry(value) {
  if (!Array.isArray(value) || types.isProxy(value) || value.length !== 7) deny('CAPABILITY_CONFIG');
  const result = new Map();
  let named = 0;
  for (const raw of value) {
    const item = exact(raw, ['categoryRef', 'generation', 'adapter'], 'CAPABILITY_CONFIG');
    if (item.categoryRef === 'ring') named += 1;
    else if (!OPAQUE_CATEGORY.test(item.categoryRef) || Buffer.from(item.categoryRef, 'base64url').length !== 32 ||
        Buffer.from(item.categoryRef, 'base64url').toString('base64url') !== item.categoryRef) deny('CAPABILITY_CONFIG');
    if (!Number.isSafeInteger(item.generation) || item.generation < 1 || result.has(item.categoryRef)) deny('CAPABILITY_CONFIG');
    const projectIntent = method(item.adapter, 'projectIntent');
    result.set(item.categoryRef, Object.freeze({ generation: item.generation, projectIntent }));
  }
  if (named !== 1) deny('CAPABILITY_CONFIG');
  return result;
}

export function createCapabilityIntentContract(options) {
  const value = exact(options, ['categories', 'localSessionPort', 'ownMcpPort', 'capabilityChannelPort', 'clock', 'random'], 'CAPABILITY_CONFIG');
  const categories = registry(value.categories);
  const withCurrentSession = method(value.localSessionPort, 'withCurrentSession');
  const authorizeCapability = method(value.ownMcpPort, 'authorizeCapability');
  const sealIntent = method(value.capabilityChannelPort, 'sealIntent');
  const deliverSealedIntent = method(value.capabilityChannelPort, 'deliverSealedIntent');
  const verifyReceipt = method(value.capabilityChannelPort, 'verifyReceipt');
  if (typeof value.clock !== 'function' || types.isProxy(value.clock) || typeof value.random !== 'function' || types.isProxy(value.random)) {
    deny('CAPABILITY_CONFIG');
  }
  let lastNow = 0;
  const replay = new Map();
  function now() {
    let current;
    try { current = value.clock(); } catch { deny('CAPABILITY_UNAVAILABLE'); }
    if (!Number.isSafeInteger(current) || current < lastNow) deny('CAPABILITY_UNAVAILABLE');
    lastNow = current;
    for (const [id, until] of replay) if (until <= current) replay.delete(id);
    return current;
  }
  function intentId() {
    let bytes;
    try { bytes = Buffer.from(value.random(16)); } catch { deny('CAPABILITY_UNAVAILABLE'); }
    if (bytes.length !== 16) deny('CAPABILITY_UNAVAILABLE');
    return bytes.toString('base64url');
  }
  async function authorize(input) {
    const data = exact(input, ['categoryRef', 'generation', 'sessionProof', 'csrf', 'request'], 'CAPABILITY_INPUT');
    const category = categories.get(data.categoryRef);
    if (!category || data.generation !== category.generation) deny('CAPABILITY_DENIED');
    const request = finiteCopy(data.request);
    let invoked = 0;
    let output;
    try {
      await withCurrentSession(Object.freeze({ sessionProof: data.sessionProof, csrf: data.csrf }), session => {
        invoked += 1;
        if (invoked !== 1) deny('CAPABILITY_DENIED');
        const projected = category.projectIntent(Object.freeze({ categoryRef: data.categoryRef,
          generation: category.generation, request, session }));
        if (projected && typeof projected.then === 'function') deny('CAPABILITY_DENIED');
        const authorized = authorizeCapability(Object.freeze({ categoryRef: data.categoryRef,
          generation: category.generation, intent: finiteCopy(projected), session }));
        if (authorized && typeof authorized.then === 'function') deny('CAPABILITY_DENIED');
        const decision = exact(authorized, ['authorized', 'authorizationRef', 'expiresAt'], 'CAPABILITY_DENIED');
        if (decision.authorized !== true || typeof decision.authorizationRef !== 'string' || !REF.test(decision.authorizationRef) ||
            !Number.isSafeInteger(decision.expiresAt) || decision.expiresAt <= now()) deny('CAPABILITY_DENIED');
        output = Object.freeze({ categoryRef: data.categoryRef, generation: category.generation,
          authorizationRef: decision.authorizationRef, authorizationExpiresAt: decision.expiresAt,
          intent: finiteCopy(projected) });
        return output;
      });
    } catch (error) { if (error instanceof CapabilityIntentContractError) throw error; deny('CAPABILITY_DENIED'); }
    if (invoked !== 1 || !output) deny('CAPABILITY_DENIED');
    return output;
  }
  return Object.freeze({
    async authorizeLocal(input) {
      const decision = await authorize(input);
      return Object.freeze({ categoryRef: decision.categoryRef, generation: decision.generation,
        authorizationRef: decision.authorizationRef, expiresAt: decision.authorizationExpiresAt,
        authorized: true, executed: false });
    },
    async authorizeRemote(input) {
      const decision = await authorize(input);
      const issuedAt = now();
      const expiresAt = Math.min(decision.authorizationExpiresAt, issuedAt + 30_000);
      if (expiresAt <= issuedAt) deny('CAPABILITY_DENIED');
      const id = intentId();
      if (replay.has(id)) deny('CAPABILITY_REPLAY');
      replay.set(id, issuedAt + 86_400_000);
      const intent = Object.freeze({ id, categoryRef: decision.categoryRef, generation: decision.generation,
        authorizationRef: decision.authorizationRef, issuedAt, expiresAt, payload: decision.intent });
      let sealed;
      let receipt;
      try {
        sealed = await sealIntent(intent);
        const delivered = await deliverSealedIntent(sealed);
        receipt = await verifyReceipt(Object.freeze({ intent, delivered, deadline: issuedAt + 10_000 }));
      } catch { deny('CAPABILITY_REMOTE_UNKNOWN'); }
      const current = now();
      const verified = exact(receipt, ['intentId', 'receivedAt', 'accepted'], 'CAPABILITY_REMOTE_UNKNOWN');
      if (verified.intentId !== id || verified.accepted !== true || !Number.isSafeInteger(verified.receivedAt) ||
          verified.receivedAt < issuedAt - 5_000 || verified.receivedAt > issuedAt + 10_000 || current > issuedAt + 10_000) {
        deny('CAPABILITY_REMOTE_UNKNOWN');
      }
      return Object.freeze({ categoryRef: decision.categoryRef, generation: decision.generation,
        authorizationRef: decision.authorizationRef, intentId: id, expiresAt, receiptVerified: true, executed: false });
    }
  });
}
