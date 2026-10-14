import { lookupFormalVerifiedLogin } from './request-authorization-policy.mjs';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { types } from 'node:util';
import { createProjectingIdentityAuthority } from '../../cloud/aws/ring-private/projecting-identity-authority.mjs';
import { createMacSessionAssociationStore, validateMacAssociation, createAssociationWork, exactAssociation,
  associationMethods, associationDigest, associationInteger, associationScopes, associationHash, freezeAssociation,
  failAssociation } from './mac-session-association-store.mjs';

function opaqueObject(value) {
  if (!value || typeof value !== 'object' || types.isProxy(value)) failAssociation('MAC_SESSION_HANDLE_DENIED');
  return value;
}
function actorValue(value, profile) {
  const a = exactAssociation(value, ['authority', 'subject', 'resource', 'scopes'], 'MAC_SESSION_ACTOR_DENIED');
  if (!Object.isFrozen(value) || a.authority !== 'oauth-access-token' || typeof a.subject !== 'string' || a.subject.length < 1 ||
      a.subject.length > 256 || a.resource !== profile.resource || !Array.isArray(a.scopes) || types.isProxy(a.scopes) ||
      a.scopes.length !== profile.scopes.length || a.scopes.some((s, i) => s !== profile.scopes[i])) failAssociation('MAC_SESSION_ACTOR_DENIED');
  return value;
}
function sameSecret(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const a = Buffer.from(left), b = Buffer.from(right);
  try { return a.length === b.length && timingSafeEqual(a, b); } finally { a.fill(0); b.fill(0); }
}

export function createMacSessionAssociationServices(input) {
  const c = exactAssociation(input, ['storeConfig', 'ownerApprovalPort', 'identityEnvelope', 'digest', 'authorityClock',
    'bootEpoch', 'random', 'authorizationProfile', 'limits']);
  const owner = associationMethods(c.ownerApprovalPort, ['consumeAssociation', 'authorizeSession', 'verifySocket']);
  const envelope = associationMethods(c.identityEnvelope, ['seal', 'open']);
  if (typeof c.digest !== 'function' || types.isProxy(c.digest) || (c.random !== undefined && (typeof c.random !== 'function' || types.isProxy(c.random)))) failAssociation('MAC_SESSION_CONFIG_DENIED');
  const profile = exactAssociation(c.authorizationProfile, ['issuer', 'resource', 'scopes']);
  for (const k of ['issuer', 'resource']) {
    let u; try { u = new URL(profile[k]); } catch { failAssociation('MAC_SESSION_CONFIG_DENIED'); }
    if (u.protocol !== 'https:' || u.username || u.password || u.hash) failAssociation('MAC_SESSION_CONFIG_DENIED');
  }
  if (!Array.isArray(profile.scopes) || types.isProxy(profile.scopes) || profile.scopes.length < 1 || profile.scopes.length > 32 ||
      profile.scopes.some(s => typeof s !== 'string' || !/^[\x21-\x7e]{1,128}$/.test(s)) || new Set(profile.scopes).size !== profile.scopes.length) failAssociation('MAC_SESSION_CONFIG_DENIED');
  profile.scopes = Object.freeze([...profile.scopes]); Object.freeze(profile);
  const work = createAssociationWork(c);
  const sessions = new Map(), handles = new WeakMap(), contexts = new WeakMap(), challenges = new WeakMap(), liveChallenges = new Set(), requests = new WeakMap(), sockets = new WeakMap();
  const authorizedTokens = new Map();
  const random = c.random ?? randomBytes;
  let counter = 0;
  function randomProof() {
    const bytes = random(32);
    if (!Buffer.isBuffer(bytes) || bytes.length !== 32) failAssociation('MAC_SESSION_RANDOM_DENIED');
    const owned = Buffer.from(bytes); try { return owned.toString('base64url'); } finally { owned.fill(0); }
  }
  async function digest(purpose, value) { return associationDigest(await c.digest(purpose, value)); }
  function requestSocket(httpRequest) {
    const descriptor = Object.getOwnPropertyDescriptor(opaqueObject(httpRequest), 'socket');
    if (descriptor === undefined) return null;
    if (!Object.hasOwn(descriptor, 'value')) failAssociation('MAC_SESSION_SOCKET_DENIED');
    const value = descriptor.value;
    if (value === null || typeof value !== 'object') return null;
    return opaqueObject(value);
  }
  function currentSession(handle) {
    opaqueObject(handle); const s = handles.get(handle), now = work.now();
    if (!s || !sessions.has(s.sessionDigest) || s.bootEpoch !== now.epoch || s.revoked ||
        now.mono >= s.monotonicExpiresAt || now.wall >= Math.min(s.sessionExpiresAt, s.idleExpiresAt, s.trustExpiresAt)) failAssociation('MAC_SESSION_EXPIRED');
    return s;
  }
  const sessionState = Object.freeze({
    async lookup({ sessionDigest, csrfDigest }) {
      const s = sessions.get(sessionDigest);
      if (!s || !sameSecret(s.csrfDigest, csrfDigest)) failAssociation('MAC_SESSION_AUTH_DENIED');
      currentSession(s.handle); return Object.freeze({ ...s, handle: undefined });
    },
    async project(input, record) {
      const s = sessions.get(input.sessionDigest); if (!s) failAssociation('MAC_SESSION_AUTH_DENIED');
      currentSession(s.handle);
      if (s.associationRevision !== record.revision || input.grantDigest !== s.grantDigest || input.grantGeneration !== s.grantGeneration ||
          input.expiresAt > s.trustExpiresAt || input.expiresAt <= work.now().wall) failAssociation('MAC_SESSION_PROJECTION_DENIED');
      return Object.freeze({ accountDigest: record.accountDigest, accountGeneration: record.accountGeneration,
        projectionRevision: record.revision, ownerEpoch: record.ownerEpoch, expiresAt: input.expiresAt });
    }
  });
  const base = exactAssociation(c.storeConfig, ['descriptorSession', 'stateTransactionLockPort', 'currentBindingPort', 'associationAdmissionPort']);
  const backingStore = createMacSessionAssociationStore({ ...base, ownerApprovalPort: owner, sessionStatePort: sessionState,
    authorityClock: c.authorityClock, bootEpoch: c.bootEpoch, limits: c.limits, workController: work });
  function invalidateSessions() {
    for (const session of sessions.values()) session.revoked = true;
    sessions.clear();
  }
  const store = Object.freeze({ ...backingStore,
    commitApprovedAssociation(input) { invalidateSessions(); return backingStore.commitApprovedAssociation(input); },
    recoverApprovedAssociation() { invalidateSessions(); return backingStore.recoverApprovedAssociation(); }
  });
  const projection = createProjectingIdentityAuthority({ store, digest,
    identityEnvelope: envelope, extractSession(context) {
      const state = contexts.get(context); if (!state) failAssociation('MAC_SESSION_CONTEXT_DENIED');
      currentSession(state.handle); return Object.freeze({ sessionProof: state.proof, csrf: state.csrf });
    } });
  async function associationForSession(s) {
    const record = await store.readAssociation(); currentSession(s.handle);
    if (record.revision !== s.associationRevision || record.ownerEpoch !== s.ownerEpoch || record.subjectDigest !== s.subjectDigest ||
        record.issuer !== profile.issuer || record.resource !== profile.resource) failAssociation('MAC_SESSION_ASSOCIATION_CHANGED');
    return record;
  }
  async function mintSession(record, subjectDigest, ttlMs, expiresMonotonicMs, expiresWallMs = Infinity) {
      const now = work.now();
      const handle = Object.freeze(Object.create(null)), sessionProof = randomProof(), csrf = randomProof();
      const ttl = Math.min(ttlMs, expiresMonotonicMs - now.mono, expiresWallMs - now.wall);
      associationInteger(ttl);
      for (const old of sessions.values()) if (old.revoked || now.mono >= old.monotonicExpiresAt) { sessions.delete(old.sessionDigest); handles.delete(old.handle); }
      if (sessions.size >= 128) failAssociation('MAC_SESSION_CAPACITY_DENIED');
      const id = ++counter, sessionDigest = await digest('session-proof', sessionProof), csrfDigest = await digest('session-csrf', csrf);
      const s = { handle, sessionProof, csrf, sessionDigest, csrfDigest, sessionId: `Session.${id}.${sessionProof}`,
        sessionGeneration: id, grantId: `Trust.${id}`, grantGeneration: id, grantDigest: await digest('session-trust', csrf),
        associationRevision: record.revision, subjectDigest, accountDigest: record.accountDigest, ownerEpoch: record.ownerEpoch,
        bootEpoch: work.epoch, monotonicExpiresAt: now.mono + ttl, sessionExpiresAt: now.wall + ttl,
        idleExpiresAt: now.wall + ttl, trustExpiresAt: now.wall + ttl, revoked: false };
      work.now();
      const accountId = await envelope.open(record.accountIdentifierEnvelope, Object.freeze({ accountDigest: record.accountDigest,
        ownerRef: record.ownerRef, ownerEpoch: record.ownerEpoch, accountGeneration: record.accountGeneration }));
      work.now();
      if (await digest('ring-account', accountId) !== record.accountDigest) failAssociation('MAC_SESSION_ACCOUNT_DENIED');
      const checked = await store.readAssociation();
      if (associationHash(checked) !== associationHash(record)) failAssociation('MAC_SESSION_ASSOCIATION_CHANGED');
      work.now();
      if (now.mono + ttl <= work.now().mono) failAssociation('MAC_SESSION_EXPIRED');
      sessions.set(sessionDigest, s); handles.set(handle, s);
      try {
        await projection.projectFirstAccount({ sessionProof, ownerRef: record.ownerRef, ownerEpoch: record.ownerEpoch,
          grantDigest: s.grantDigest, grantGeneration: s.grantGeneration, accountId, accountGeneration: record.accountGeneration,
          expiresAt: s.trustExpiresAt });
        work.now(); currentSession(handle);
      } catch (error) { sessions.delete(sessionDigest); handles.delete(handle); s.revoked = true; throw error; }
      return Object.freeze({ sessionHandle: handle, csrf });
  }
  async function bindRequest(input) {
      const x = exactAssociation(input, ['httpRequest', 'actor', 'sessionHandle', 'csrf']); opaqueObject(x.httpRequest);
      const actor = actorValue(x.actor, profile), s = currentSession(x.sessionHandle);
      const previous = requests.get(x.httpRequest);
      if (previous?.localSocketHandle) failAssociation('MAC_SESSION_REQUEST_DENIED');
      const originalSocket = requestSocket(x.httpRequest);
      const localSocketBinding = previous ? null : sockets.get(originalSocket);
      if (localSocketBinding && localSocketBinding.sessionHandle !== s.handle) failAssociation('MAC_SESSION_SOCKET_DENIED');
      const localSocketHandle = localSocketBinding ? originalSocket : null;
      if (!sameSecret(s.csrf, x.csrf) || await digest('oauth-subject', `${profile.issuer}\u0000${actor.subject}`) !== s.subjectDigest) failAssociation('MAC_SESSION_AUTH_DENIED');
      const record = await associationForSession(s);
      const accountId = await envelope.open(record.accountIdentifierEnvelope, Object.freeze({ accountDigest: record.accountDigest,
        ownerRef: record.ownerRef, ownerEpoch: record.ownerEpoch, accountGeneration: record.accountGeneration }));
      work.now(); currentSession(s.handle);
      if (await digest('ring-account', accountId) !== record.accountDigest) failAssociation('MAC_SESSION_ACCOUNT_DENIED');
      work.now(); currentSession(s.handle);
      const context = Object.freeze(Object.create(null)); contexts.set(context, { handle: s.handle, proof: s.sessionProof, csrf: s.csrf });
      const identityInput = Object.freeze({ accountId, context });
      const sessionAuthority = Object.freeze({ ownerId: record.ownerId, botId: record.botId,
        bindingGeneration: record.bindingGeneration, bootEpoch: s.bootEpoch,
        sessionExpiresMonotonicMs: s.monotonicExpiresAt,
        assertCurrentSession() {
          currentSession(s.handle);
          if (requests.get(x.httpRequest)?.association !== association || association.actor !== actor) failAssociation('MAC_SESSION_REQUEST_DENIED');
          return true;
        } });
      const association = Object.freeze({ identityInput, association: record, sessionHandle: s.handle,
        sessionAuthority, actor, httpRequest: x.httpRequest });
      if (localSocketHandle && (requestSocket(x.httpRequest) !== localSocketHandle ||
          sockets.get(localSocketHandle) !== localSocketBinding)) failAssociation('MAC_SESSION_SOCKET_DENIED');
      if (requests.get(x.httpRequest) !== previous) failAssociation('MAC_SESSION_REQUEST_DENIED');
      requests.set(x.httpRequest, Object.freeze({ association, localSocketHandle, localSocketBinding }));
      return Object.freeze({ bound: true });
  }
  async function bindAuthorizedRequest(input) {
    const x = exactAssociation(input, ['request', 'actor', 'validatedWire', 'effectiveEnvelope']);
    const wrapper = exactAssociation(x.request, ['httpRequest']);
    const httpRequest = opaqueObject(wrapper.httpRequest);
    const previous = requests.get(httpRequest)?.association;
    if (previous) {
      if (previous.actor !== x.actor) failAssociation('MAC_SESSION_REQUEST_DENIED');
      const session = currentSession(previous.sessionHandle), record = await associationForSession(session);
      if (associationHash(record) !== associationHash(previous.association)) failAssociation('MAC_SESSION_ASSOCIATION_CHANGED');
      return Object.freeze({ bound: true });
    }
    const actor = actorValue(x.actor, profile);
    const evidence = lookupFormalVerifiedLogin({ request: httpRequest, actor });
    const now = work.now();
    if (!evidence || evidence.issuer !== profile.issuer || evidence.resource !== profile.resource ||
        evidence.issuedAtMs > now.wall || evidence.expiresAtMs <= now.wall ||
        evidence.scopes.length !== profile.scopes.length ||
        [...evidence.scopes].sort().some((scope, index) => scope !== [...profile.scopes].sort()[index])) failAssociation('MAC_SESSION_VERIFIED_LOGIN_DENIED');
    for (const [key, value] of authorizedTokens) if (value.expiresAtMs <= now.wall) authorizedTokens.delete(key);
    let token = authorizedTokens.get(evidence.tokenDigest);
    if (!token) {
      if (authorizedTokens.size >= 128) failAssociation('MAC_SESSION_CAPACITY_DENIED');
      token = { expiresAtMs: evidence.expiresAtMs, login: null, pending: null };
      authorizedTokens.set(evidence.tokenDigest, token);
      token.pending = (async () => {
        const record = await store.readAssociation();
        const subjectDigest = await digest('oauth-subject', `${profile.issuer}\u0000${actor.subject}`);
        if (record.subjectDigest !== subjectDigest || record.issuer !== profile.issuer || record.resource !== profile.resource ||
            record.scopeRefs.length !== profile.scopes.length ||
            [...record.scopeRefs].sort().some((scope, index) => scope !== [...profile.scopes].sort()[index])) failAssociation('MAC_SESSION_ACTOR_DENIED');
        const stamp = work.now(), ttl = Math.min(300000, evidence.expiresAtMs - stamp.wall);
        associationInteger(ttl);
        token.login = await mintSession(record, subjectDigest, ttl, stamp.mono + ttl, evidence.expiresAtMs);
      })();
      try { await token.pending; } finally { token.pending = null; }
    } else if (token.pending) {
      await token.pending;
    }
    if (!token.login) failAssociation('MAC_SESSION_VERIFIED_LOGIN_DENIED');
    const session = currentSession(token.login.sessionHandle);
    await associationForSession(session);
    if (work.now().wall >= evidence.expiresAtMs) failAssociation('MAC_SESSION_EXPIRED');
    return await bindRequest({ httpRequest, actor, ...token.login });
  }
  const api = {
    identityAuthority: projection.identityAuthority,
    operationController: work,
    store,
    prepareAssociation(input) { return work.run(async () => {
      const x = exactAssociation(input, ['record', 'accountId']);
      if (typeof x.accountId !== 'string' || x.accountId.length < 1 || x.accountId.length > 256 || /[\x00-\x20\x7f]/.test(x.accountId)) failAssociation('MAC_SESSION_ACCOUNT_DENIED');
      const record = exactAssociation(x.record, ['schema', 'revision', 'associationId', 'ownerId', 'botId', 'bindingGeneration',
        'actorRef', 'ownerRef', 'householdRef', 'scopeRefs', 'issuer', 'subjectDigest', 'resource', 'accountGeneration',
        'ownerEpoch', 'revoked', 'approvedAt', 'approvalEvidenceSha256']);
      if (record.issuer !== profile.issuer || record.resource !== profile.resource) failAssociation('MAC_SESSION_ASSOCIATION_DENIED');
      const accountDigest = await digest('ring-account', x.accountId); work.now();
      const accountIdentifierEnvelope = await envelope.seal(x.accountId, Object.freeze({ accountDigest,
        ownerRef: record.ownerRef, ownerEpoch: record.ownerEpoch, accountGeneration: record.accountGeneration }));
      work.now(); return validateMacAssociation({ ...record, accountDigest, accountIdentifierEnvelope });
    }); },
    beginAssociation(input) { return work.run(() => {
      const x = exactAssociation(input, ['expectedRevision', 'expectedHash', 'record']);
      associationInteger(x.expectedRevision, 0); associationDigest(x.expectedHash);
      const record = validateMacAssociation(x.record);
      if (record.issuer !== profile.issuer || record.resource !== profile.resource || record.revision !== x.expectedRevision + 1) failAssociation('MAC_SESSION_ASSOCIATION_DENIED');
      const now = work.now();
      for (const item of liveChallenges) if (!item.ref.deref() || item.expires <= now.mono) liveChallenges.delete(item);
      if (liveChallenges.size >= 128) failAssociation('MAC_SESSION_CAPACITY_DENIED');
      const handle = Object.freeze(Object.create(null));
      const reservation = { ref: new WeakRef(handle), expires: now.mono + 300000 };
      liveChallenges.add(reservation);
      challenges.set(handle, { ...x, record, expires: reservation.expires, nonce: randomProof(), reservation });
      return handle;
    }); },
    commitOwnerApprovedAssociation(input) { return work.run(async () => {
      const x = exactAssociation(input, ['challengeHandle', 'ownerProof']); const pending = challenges.get(opaqueObject(x.challengeHandle));
      challenges.delete(x.challengeHandle);
      if (pending) liveChallenges.delete(pending.reservation);
      if (!pending || pending.expires <= work.now().mono) failAssociation('MAC_SESSION_ENROLLMENT_DENIED');
      return await store.commitApprovedAssociation({ expectedRevision: pending.expectedRevision, expectedHash: pending.expectedHash,
        record: pending.record, ownerProof: x.ownerProof });
    }); },
    openSession(input) { return work.run(async () => {
      const x = exactAssociation(input, ['actor', 'ownerSessionProof', 'ttlMs']);
      const actor = actorValue(x.actor, profile); associationInteger(x.ttlMs);
      for (const s of sessions.values()) if (s.revoked || work.now().mono >= s.monotonicExpiresAt) { sessions.delete(s.sessionDigest); handles.delete(s.handle); }
      if (x.ttlMs > 600000 || sessions.size >= 128) failAssociation('MAC_SESSION_CAPACITY_DENIED');
      const record = await store.readAssociation(), subjectDigest = await digest('oauth-subject', `${profile.issuer}\u0000${actor.subject}`);
      if (record.subjectDigest !== subjectDigest || record.issuer !== profile.issuer || record.resource !== actor.resource) failAssociation('MAC_SESSION_ACTOR_DENIED');
      const proof = exactAssociation(await owner.authorizeSession({ proof: x.ownerSessionProof, associationRevision: record.revision,
        associationHash: associationHash(record), actor, bootEpoch: work.epoch }),
        ['associationRevision', 'subjectDigest', 'ownerId', 'botId', 'bindingGeneration', 'bootEpoch', 'expiresMonotonicMs', 'evidenceSha256'], 'MAC_SESSION_OWNER_APPROVAL_DENIED');
      const now = work.now();
      if (proof.associationRevision !== record.revision || proof.subjectDigest !== subjectDigest || proof.ownerId !== record.ownerId ||
          proof.botId !== record.botId || proof.bindingGeneration !== record.bindingGeneration || proof.bootEpoch !== now.epoch ||
          !Number.isSafeInteger(proof.expiresMonotonicMs) || proof.expiresMonotonicMs <= now.mono) failAssociation('MAC_SESSION_OWNER_APPROVAL_DENIED');
      associationDigest(proof.evidenceSha256); if (/^0+$/.test(proof.evidenceSha256)) failAssociation('MAC_SESSION_OWNER_APPROVAL_DENIED');
      const checked = await store.readAssociation();
      if (associationHash(checked) !== associationHash(record)) failAssociation('MAC_SESSION_ASSOCIATION_CHANGED');
      return await mintSession(record, subjectDigest, x.ttlMs, proof.expiresMonotonicMs);
    }); },
    revokeSession({ sessionHandle }) {
      const s = handles.get(opaqueObject(sessionHandle));
      if (s) { s.revoked = true; sessions.delete(s.sessionDigest); handles.delete(sessionHandle); }
      return Object.freeze({ revoked: true });
    },
    bindVerifiedRequest(input) { return work.run(() => bindRequest(input)); },
    lookupRequest(input) { return work.run(async () => {
      const x = exactAssociation(input, ['httpRequest', 'actor']), bound = requests.get(opaqueObject(x.httpRequest))?.association;
      if (!bound || bound.actor !== x.actor) failAssociation('MAC_SESSION_REQUEST_DENIED');
      const s = currentSession(bound.sessionHandle), record = await associationForSession(s);
      if (associationHash(record) !== associationHash(bound.association)) failAssociation('MAC_SESSION_ASSOCIATION_CHANGED');
      return bound;
    }); },
    bindLocalSocket(input) { return work.run(async () => {
      const x = exactAssociation(input, ['socketHandle', 'sessionHandle', 'socketProof', 'purpose']); opaqueObject(x.socketHandle);
      const s = currentSession(x.sessionHandle); if (typeof x.purpose !== 'string' || !/^[A-Za-z][A-Za-z0-9:_-]{2,127}$/.test(x.purpose)) failAssociation('MAC_SESSION_SOCKET_DENIED');
      const proof = exactAssociation(await owner.verifySocket({ proof: x.socketProof, socketHandle: x.socketHandle, bootEpoch: work.epoch }),
        ['socketHandle', 'bootEpoch', 'evidenceSha256'], 'MAC_SESSION_SOCKET_DENIED');
      if (proof.socketHandle !== x.socketHandle || proof.bootEpoch !== work.epoch) failAssociation('MAC_SESSION_SOCKET_DENIED');
      associationDigest(proof.evidenceSha256); if (/^0+$/.test(proof.evidenceSha256)) failAssociation('MAC_SESSION_SOCKET_DENIED');
      await associationForSession(s); work.now(); sockets.set(x.socketHandle, { sessionHandle: s.handle, purpose: x.purpose });
      return Object.freeze({ bound: true });
    }); },
    localSessionPort: Object.freeze({ productionAdmitted: true,
      bindAuthorizedRequest(input) { return work.run(() => bindAuthorizedRequest(input)); },
      resolveRequestContext(input) { return work.run(async () => {
        const x = exactAssociation(input, ['request', 'actor', 'validatedWire', 'effectiveEnvelope']);
        const wrapper = exactAssociation(x.request, ['httpRequest']);
        const httpRequest = opaqueObject(wrapper.httpRequest), entry = requests.get(httpRequest);
        if (!entry?.localSocketHandle) return null;
        const bound = entry.association;
        if (bound.actor !== x.actor) failAssociation('MAC_SESSION_REQUEST_DENIED');
        const socketHandle = requestSocket(httpRequest);
        if (socketHandle !== entry.localSocketHandle || sockets.get(socketHandle) !== entry.localSocketBinding ||
            entry.localSocketBinding.sessionHandle !== bound.sessionHandle) failAssociation('MAC_SESSION_SOCKET_DENIED');
        const s = currentSession(bound.sessionHandle), record = await associationForSession(s);
        if (associationHash(record) !== associationHash(bound.association)) failAssociation('MAC_SESSION_ASSOCIATION_CHANGED');
        if (requests.get(httpRequest) !== entry || requestSocket(httpRequest) !== socketHandle ||
            sockets.get(socketHandle) !== entry.localSocketBinding) failAssociation('MAC_SESSION_SOCKET_DENIED');
        currentSession(bound.sessionHandle);
        return Object.freeze({ socketHandle, sessionHandle: bound.sessionHandle });
      }); },
      resolve(input) { return work.run(async () => {
        const x = exactAssociation(input, ['socketHandle', 'sessionHandle']); const bound = sockets.get(opaqueObject(x.socketHandle)); sockets.delete(x.socketHandle);
        if (!bound || bound.sessionHandle !== x.sessionHandle) failAssociation('MAC_SESSION_SOCKET_DENIED');
        const s = currentSession(x.sessionHandle); await associationForSession(s); work.now();
        return Object.freeze({ productionAdmitted: true, singleUse: true, loopback: true, path: 'local-encrypted',
          purpose: bound.purpose, bootEpoch: work.epoch, entryId: `LocalEntry:${++counter}` });
      }); },
      close: () => api.close()
    }),
    async close() {
      for (const s of sessions.values()) s.revoked = true; sessions.clear(); liveChallenges.clear(); authorizedTokens.clear();
      const results = await Promise.allSettled([work.close(), store.close()]);
      const done = results[0].status === 'fulfilled' ? results[0].value : { closed: true, inFlight: work.status().inFlight, resourceReleased: false };
      let identityClosed = false;
      if (done.resourceReleased) { try { identityClosed = (await projection.close()).closed === true; } catch { identityClosed = false; } }
      const storeClosed = results[1].status === 'fulfilled' && results[1].value.resourceReleased === true;
      return Object.freeze({ ...done, identityClosed, storeClosed, resourceReleased: done.resourceReleased && identityClosed && storeClosed });
    },
    status: work.status
  };
  return Object.freeze(api);
}
