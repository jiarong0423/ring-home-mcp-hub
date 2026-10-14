import { types } from 'node:util';

const DIGEST = /^[0-9a-f]{64}$/;
export class AccountIdentityProjectionError extends Error {
  constructor(code) { super(code); this.name = 'AccountIdentityProjectionError'; this.code = code; }
}
function deny(code) { throw new AccountIdentityProjectionError(code); }
function exact(value, fields, code = 'ACCOUNT_PROJECTION_INPUT_DENIED') {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny(code);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== fields.length || fields.some(field => !Object.hasOwn(descriptors, field)) ||
        keys.some(key => typeof key !== 'string' || !fields.includes(key) || !Object.hasOwn(descriptors[key], 'value'))) deny(code);
    return Object.fromEntries(fields.map(field => [field, descriptors[field].value]));
  } catch (error) { if (error instanceof AccountIdentityProjectionError) throw error; deny(code); }
}
function sessionKey(session) {
  return [session.ownerEpoch, session.sessionId, session.sessionGeneration, session.grantId, session.grantGeneration].join('\u0000');
}

export function createAccountIdentityProjection(options) {
  const value = exact(options, ['store', 'digest', 'decryptAccountIdentifier']);
  if (!value.store || typeof value.store.loadSessionAuthority !== 'function' || typeof value.store.projectAccount !== 'function' ||
      typeof value.digest !== 'function' || typeof value.decryptAccountIdentifier !== 'function') deny('ACCOUNT_PROJECTION_CONFIG');
  const active = new Map();
  let closed = false;
  async function digested(purpose, source) {
    try {
      const result = await value.digest(purpose, source);
      if (typeof result !== 'string' || !DIGEST.test(result)) deny('ACCOUNT_PROJECTION_UNAVAILABLE');
      return result;
    } catch (error) { if (error instanceof AccountIdentityProjectionError) throw error; deny('ACCOUNT_PROJECTION_UNAVAILABLE'); }
  }
  async function load(args) {
    if (closed) deny('ACCOUNT_PROJECTION_CLOSED');
    const input = exact(args, ['sessionProof', 'csrf']);
    if (typeof input.sessionProof !== 'string' || typeof input.csrf !== 'string' || !input.sessionProof || !input.csrf) {
      deny('ACCOUNT_PROJECTION_SESSION_DENIED');
    }
    try {
      return await value.store.loadSessionAuthority({ sessionDigest: await digested('session-proof', input.sessionProof),
        csrfDigest: await digested('session-csrf', input.csrf) });
    } catch { deny('ACCOUNT_PROJECTION_SESSION_DENIED'); }
  }
  function view(bundle) {
    return Object.freeze({ productionAdmitted: true, serverNow: bundle.serverNow, ownerEpoch: bundle.ownerEpoch,
      sessionId: bundle.sessionId, sessionGeneration: bundle.sessionGeneration, grantId: bundle.grantId,
      grantGeneration: bundle.grantGeneration, sessionExpiresAt: bundle.sessionExpiresAt,
      idleExpiresAt: bundle.idleExpiresAt, trustExpiresAt: bundle.trustExpiresAt });
  }
  const sessionAuthority = Object.freeze({
    async inspectSession(args) { return view(await load(args)); },
    async withCurrentSession(args, perform) {
      if (typeof perform !== 'function' || types.isProxy(perform)) deny('ACCOUNT_PROJECTION_INPUT_DENIED');
      const bundle = await load(args);
      let accountIdentifier;
      try { accountIdentifier = await value.decryptAccountIdentifier(bundle.accountIdentifierEnvelope, Object.freeze({
        accountDigest: bundle.accountDigest,
        ownerRef: bundle.ownerRef,
        ownerEpoch: bundle.ownerEpoch,
        accountGeneration: bundle.accountGeneration
      })); }
      catch { deny('ACCOUNT_PROJECTION_UNAVAILABLE'); }
      if (typeof accountIdentifier !== 'string' || accountIdentifier.length < 1 || accountIdentifier.length > 256 ||
          /[\x00-\x20\x7f]/.test(accountIdentifier)) deny('ACCOUNT_PROJECTION_RECORD_DENIED');
      const current = view(bundle);
      const key = sessionKey(current);
      if (active.has(key)) deny('ACCOUNT_PROJECTION_BUSY');
      active.set(key, Object.freeze({ actorRef: bundle.actorRef, ownerRef: bundle.ownerRef,
        householdRef: bundle.householdRef, scopeRefs: bundle.scopeRefs,
        accountIdentifier, epoch: bundle.ownerEpoch, expiresAt: bundle.bindingExpiresAt,
        accountGeneration: bundle.accountGeneration, projectionRevision: bundle.projectionRevision }));
      try { return await perform(current); } finally { active.delete(key); }
    }
  });
  return Object.freeze({
    sessionAuthority,
    resolveAccountBinding(input) {
      const data = exact(input, ['accountId', 'session']);
      const binding = active.get(sessionKey(data.session));
      if (!binding || data.accountId !== binding.accountIdentifier) deny('ACCOUNT_PROJECTION_DENIED');
      return Object.freeze({ actorRef: binding.actorRef, ownerRef: binding.ownerRef,
        householdRef: binding.householdRef, scopeRefs: binding.scopeRefs,
        accountIdentifier: binding.accountIdentifier, epoch: binding.epoch, expiresAt: binding.expiresAt });
    },
    async projectFirstAccount(input) {
      const data = exact(input, ['sessionProof', 'ownerRef', 'ownerEpoch', 'grantDigest', 'grantGeneration',
        'accountId', 'accountGeneration', 'accountIdentifierEnvelope', 'expiresAt']);
      return await value.store.projectAccount({ sessionDigest: await digested('session-proof', data.sessionProof),
        ownerRef: data.ownerRef, ownerEpoch: data.ownerEpoch, grantDigest: data.grantDigest,
        grantGeneration: data.grantGeneration, accountDigest: await digested('ring-account', data.accountId),
        accountGeneration: data.accountGeneration, accountIdentifierEnvelope: data.accountIdentifierEnvelope,
        expiresAt: data.expiresAt });
    },
    async close() { closed = true; active.clear(); return Object.freeze({ closed: true }); }
  });
}
