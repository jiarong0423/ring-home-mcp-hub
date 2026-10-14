import { types } from 'node:util';
import { createAccountIdentityProjection } from './account-identity-projection.mjs';
import { createExistingSessionIdentityAuthority } from './existing-session-identity-authority.mjs';

export class ProjectingIdentityAuthorityError extends Error {
  constructor(code) { super(code); this.name = 'ProjectingIdentityAuthorityError'; this.code = code; }
}
function deny(code) { throw new ProjectingIdentityAuthorityError(code); }
function exact(value, fields, code) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny(code);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== fields.length || fields.some(field => !Object.hasOwn(descriptors, field)) ||
        keys.some(key => typeof key !== 'string' || !fields.includes(key) || !Object.hasOwn(descriptors[key], 'value'))) deny(code);
    return Object.fromEntries(fields.map(field => [field, descriptors[field].value]));
  } catch (error) { if (error instanceof ProjectingIdentityAuthorityError) throw error; deny(code); }
}

export function createProjectingIdentityAuthority(options) {
  const value = exact(options, ['store', 'digest', 'identityEnvelope', 'extractSession'], 'PROJECTING_IDENTITY_CONFIG');
  if (!value.store || typeof value.store.loadSessionAuthority !== 'function' || typeof value.store.projectAccount !== 'function' ||
      typeof value.digest !== 'function' || types.isProxy(value.digest) ||
      !value.identityEnvelope || typeof value.identityEnvelope.seal !== 'function' || typeof value.identityEnvelope.open !== 'function' ||
      typeof value.extractSession !== 'function' || types.isProxy(value.extractSession)) deny('PROJECTING_IDENTITY_CONFIG');
  const projection = createAccountIdentityProjection({ store: value.store, digest: value.digest,
    decryptAccountIdentifier: (envelope, context) => value.identityEnvelope.open(envelope, context) });
  const identityAuthority = createExistingSessionIdentityAuthority({ sessionAuthority: projection.sessionAuthority,
    extractSession: value.extractSession, resolveAccountBinding: projection.resolveAccountBinding });
  let closed = false;
  return Object.freeze({
    identityAuthority,
    async projectFirstAccount(input) {
      if (closed) deny('PROJECTING_IDENTITY_CLOSED');
      const data = exact(input, ['sessionProof', 'ownerRef', 'ownerEpoch', 'grantDigest', 'grantGeneration',
        'accountId', 'accountGeneration', 'expiresAt'], 'PROJECTING_IDENTITY_INPUT');
      let accountDigest;
      try { accountDigest = await value.digest('ring-account', data.accountId); }
      catch { deny('PROJECTING_IDENTITY_UNAVAILABLE'); }
      if (typeof accountDigest !== 'string' || !/^[0-9a-f]{64}$/.test(accountDigest)) deny('PROJECTING_IDENTITY_UNAVAILABLE');
      let envelope;
      try { envelope = await value.identityEnvelope.seal(data.accountId, { accountDigest, ownerRef: data.ownerRef,
        ownerEpoch: data.ownerEpoch, accountGeneration: data.accountGeneration }); }
      catch { deny('PROJECTING_IDENTITY_UNAVAILABLE'); }
      try { return await projection.projectFirstAccount({ ...data, accountIdentifierEnvelope: envelope }); }
      catch { deny('PROJECTING_IDENTITY_UNAVAILABLE'); }
    },
    async close() {
      closed = true;
      const [identity, account] = await Promise.allSettled([identityAuthority.close(), projection.close()]);
      if (identity.status !== 'fulfilled' || account.status !== 'fulfilled') deny('PROJECTING_IDENTITY_CLOSE');
      return Object.freeze({ closed: true });
    }
  });
}
