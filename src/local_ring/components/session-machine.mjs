import { createHash, timingSafeEqual } from 'node:crypto';

const HEX = /^[a-f0-9]{64}$/;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const COOKIE_NAME = '__Host-ring_session';

export class SessionError extends Error {
  constructor(code) {
    super(code);
    this.name = 'SessionError';
    this.code = code;
  }
}

function fail(code) { throw new SessionError(code); }
function second(value) { return Number.isSafeInteger(value) && value >= 0; }
function text(value, max = 2048) {
  return typeof value === 'string' && value.length > 0 && value.length <= max &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}
function equal(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
function ownRecord(value, allowed, code = 'invalid_input') {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) fail(code);
  const keys = Reflect.ownKeys(value);
  if (keys.some(key => typeof key !== 'string' || !allowed.includes(key))) fail(code);
  const result = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) fail(code);
    result[key] = descriptor.value;
  }
  return result;
}
function exactKeys(record, required, code) {
  if (required.some(key => !Object.hasOwn(record, key))) fail(code);
}
function randomToken(randomBytes) {
  let bytes;
  try { bytes = randomBytes(32); } catch { fail('entropy_unknown'); }
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 32) fail('entropy_unknown');
  const copy = Buffer.from(bytes);
  const result = copy.toString('base64url');
  copy.fill(0);
  if (!TOKEN.test(result)) fail('entropy_unknown');
  return result;
}
function cookie(token, maxAge) {
  return `${COOKIE_NAME}=${token}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;
}
const CLEAR_COOKIE = `${COOKIE_NAME}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`;

export function createSessionMachine({ clock, randomBytes, digest, seal, open,
  exchangeCode, verifyIdentity, store, config, audit }) {
  if (![clock, randomBytes, digest, seal, open, exchangeCode, verifyIdentity, audit]
    .every(fn => typeof fn === 'function') || !store || typeof store !== 'object' ||
    ['putTransaction','getTransaction','reserveTransaction','finalizeTransaction',
      'getSession','touchSession','rotateSession','revokeSession']
      .some(name => typeof store[name] !== 'function')) fail('invalid_config');
  const cfg = ownRecord(config, ['issuer','clientId','ownerSubject','origin','redirectUri',
    'authTransactionSeconds','sessionAbsoluteSeconds','sessionIdleSeconds',
    'ringNonceSeconds','cleanupLagSeconds'], 'invalid_config');
  exactKeys(cfg, ['issuer','clientId','ownerSubject','origin','redirectUri',
    'authTransactionSeconds','sessionAbsoluteSeconds','sessionIdleSeconds',
    'ringNonceSeconds','cleanupLagSeconds'], 'invalid_config');
  if (![cfg.issuer,cfg.clientId,cfg.ownerSubject,cfg.origin,cfg.redirectUri]
    .every(value => text(value, 1024)) ||
    cfg.authTransactionSeconds !== 300 || cfg.sessionAbsoluteSeconds !== 3600 ||
    cfg.sessionIdleSeconds !== 900 || cfg.ringNonceSeconds !== 600 ||
    cfg.cleanupLagSeconds !== 604800) fail('invalid_config');
  let origin;
  let redirect;
  try { origin = new URL(cfg.origin); redirect = new URL(cfg.redirectUri); }
  catch { fail('invalid_config'); }
  if (origin.protocol !== 'https:' || origin.origin !== cfg.origin ||
      redirect.protocol !== 'https:' || redirect.origin !== cfg.origin ||
      redirect.pathname !== '/auth/callback' || redirect.search || redirect.hash ||
      !text(cfg.issuer, 1024)) fail('invalid_config');
  const keyed = (purpose, value) => {
    let result;
    try { result = digest(purpose, value); } catch { fail('crypto_unknown'); }
    if (typeof result !== 'string' || !HEX.test(result)) fail('crypto_unknown');
    return result;
  };
  const ownerRef = keyed('owner-subject', cfg.ownerSubject);
  let lastObservedNow = -1;
  const now = (floor = -1) => {
    let value;
    try { value = clock(); } catch { fail('clock_unknown'); }
    if (!second(value)) fail('clock_unknown');
    if (value < floor || value < lastObservedNow) fail('clock_regressed');
    lastObservedNow = value;
    return value;
  };
  const emit = (event, code) => {
    try { audit({ event, code }); } catch { /* audit failure cannot change authorization */ }
  };
  const encrypted = async (purpose, plaintext) => {
    let output;
    try { output = await seal({ purpose, plaintext }); } catch { fail('crypto_unknown'); }
    if (!text(output, 16384)) fail('crypto_unknown');
    return output;
  };
  const decrypted = async (purpose, ciphertext) => {
    if (!text(ciphertext, 16384)) fail('crypto_unknown');
    let output;
    try { output = await open({ purpose, ciphertext }); } catch { fail('crypto_unknown'); }
    if (!text(output, 16384)) fail('crypto_unknown');
    return output;
  };
  const transaction = row => {
    const value = ownRecord(row, ['pk','status','created_at','expires_at','ttl_delete_after',
      'state_digest','browser_correlation_digest','oidc_nonce_digest',
      'pkce_verifier_ciphertext','ring_nonce_time_ciphertext','reservation_ref',
      'reserved_at','consumed_at'], 'state_invalid');
    exactKeys(value, ['pk','status','created_at','expires_at','state_digest',
      'browser_correlation_digest','oidc_nonce_digest','pkce_verifier_ciphertext',
      'ring_nonce_time_ciphertext'], 'state_invalid');
    if (![value.pk,value.state_digest,value.browser_correlation_digest,
      value.oidc_nonce_digest].every(v => typeof v === 'string' && HEX.test(v)) ||
      !second(value.created_at) || !second(value.expires_at) ||
      !second(value.ttl_delete_after) ||
      value.expires_at <= value.created_at ||
      value.expires_at > value.created_at + cfg.authTransactionSeconds ||
      value.ttl_delete_after !== value.expires_at + cfg.cleanupLagSeconds ||
      !equal(value.state_digest, value.pk) ||
      !text(value.pkce_verifier_ciphertext, 16384) ||
      !text(value.ring_nonce_time_ciphertext, 16384) ||
      !['pending','exchanging','consumed'].includes(value.status)) fail('state_invalid');
    if (value.status === 'pending' && (value.reservation_ref !== undefined ||
        value.reserved_at !== undefined || value.consumed_at !== undefined)) fail('state_invalid');
    if (value.status === 'exchanging' &&
        (typeof value.reservation_ref !== 'string' || !HEX.test(value.reservation_ref) ||
          !second(value.reserved_at) || value.reserved_at < value.created_at ||
          value.reserved_at >= value.expires_at || value.consumed_at !== undefined)) {
      fail('state_invalid');
    }
    if (value.status === 'consumed' &&
        (typeof value.reservation_ref !== 'string' || !HEX.test(value.reservation_ref) ||
          !second(value.reserved_at) || !second(value.consumed_at) ||
          value.reserved_at < value.created_at || value.reserved_at >= value.expires_at ||
          value.consumed_at < value.reserved_at ||
          value.consumed_at >= value.expires_at)) fail('state_invalid');
    return value;
  };
  const readTransaction = async pk => {
    let row;
    try { row = await store.getTransaction(pk); } catch { fail('store_unavailable'); }
    return row === null ? null : transaction(row);
  };
  const ringData = async row => {
    const plain = await decrypted('ring-nonce-time', row.ring_nonce_time_ciphertext);
    let parsed;
    try { parsed = JSON.parse(plain); } catch { fail('state_invalid'); }
    const data = ownRecord(parsed, ['ringNonce','ringTimeSeconds'], 'state_invalid');
    exactKeys(data, ['ringNonce','ringTimeSeconds'], 'state_invalid');
    if (!text(data.ringNonce, 512) || !second(data.ringTimeSeconds) ||
        data.ringTimeSeconds > row.created_at ||
        data.ringTimeSeconds + cfg.ringNonceSeconds <= row.created_at ||
        row.expires_at !== Math.min(row.created_at + cfg.authTransactionSeconds,
          data.ringTimeSeconds + cfg.ringNonceSeconds)) fail('state_invalid');
    return data;
  };
  const stillCurrent = (time, row, ringTime) => {
    if (row.expires_at <= time || ringTime + cfg.ringNonceSeconds <= time) fail('expired');
  };
  const session = row => {
    const value = ownRecord(row, ['pk','owner_subject_ref','version','status','created_at',
      'last_seen_at','absolute_expires_at','idle_expires_at','revoked_at','csrf_ref',
      'ttl_delete_after'], 'session_invalid');
    exactKeys(value, ['pk','owner_subject_ref','version','status','created_at',
      'last_seen_at','absolute_expires_at','idle_expires_at','csrf_ref'], 'session_invalid');
    if (typeof value.pk !== 'string' || !HEX.test(value.pk) ||
      !equal(value.owner_subject_ref, ownerRef) ||
      typeof value.csrf_ref !== 'string' || !HEX.test(value.csrf_ref) ||
      !Number.isSafeInteger(value.version) || value.version < 1 ||
      value.version >= Number.MAX_SAFE_INTEGER ||
      ![value.created_at,value.last_seen_at,value.absolute_expires_at,
        value.idle_expires_at,value.ttl_delete_after].every(second) ||
      value.absolute_expires_at !== value.created_at + cfg.sessionAbsoluteSeconds ||
      value.last_seen_at < value.created_at ||
      value.idle_expires_at > Math.min(value.last_seen_at + cfg.sessionIdleSeconds,
        value.absolute_expires_at) ||
      value.ttl_delete_after !== value.absolute_expires_at + cfg.cleanupLagSeconds ||
      !['active','revoked'].includes(value.status)) fail('session_invalid');
    if (value.status === 'active' && value.revoked_at !== undefined) fail('session_invalid');
    if (value.status === 'revoked' && (!second(value.revoked_at) ||
        value.revoked_at < value.created_at ||
        value.revoked_at >= value.absolute_expires_at)) fail('session_invalid');
    return value;
  };
  const readSession = async (sessionId, version) => {
    if (!TOKEN.test(sessionId) || !Number.isSafeInteger(version) || version < 1) fail('session_invalid');
    const pk = keyed('app-session', sessionId);
    let row;
    try { row = await store.getSession(pk); } catch { fail('store_unavailable'); }
    if (row === null) fail('session_invalid');
    const value = session(row);
    const time = now();
    if (value.status !== 'active' || value.revoked_at !== undefined ||
        value.version !== version || value.absolute_expires_at <= time ||
        value.idle_expires_at <= time || value.created_at > time ||
        value.last_seen_at > time) fail('session_invalid');
    return { pk, row: value, time };
  };
  const postProof = (row, originValue, csrfToken) => {
    if (originValue !== cfg.origin || !TOKEN.test(csrfToken) ||
        !equal(row.csrf_ref, keyed('csrf', csrfToken))) fail('origin_csrf_invalid');
  };

  return Object.freeze({
    async begin(input) {
      const value = ownRecord(input, ['ringNonce','ringTimeSeconds']);
      exactKeys(value, ['ringNonce','ringTimeSeconds'], 'invalid_input');
      if (!text(value.ringNonce, 512) || !second(value.ringTimeSeconds)) fail('invalid_input');
      const started = now();
      if (value.ringTimeSeconds > started ||
          value.ringTimeSeconds + cfg.ringNonceSeconds <= started) fail('expired');
      const state = randomToken(randomBytes);
      const browserCorrelation = randomToken(randomBytes);
      const oidcNonce = randomToken(randomBytes);
      const codeVerifier = randomToken(randomBytes);
      const codeChallenge = createHash('sha256').update(codeVerifier, 'utf8').digest('base64url');
      const expiresAt = Math.min(started + cfg.authTransactionSeconds,
        value.ringTimeSeconds + cfg.ringNonceSeconds);
      const pk = keyed('auth-state', state);
      const pkceCiphertext = await encrypted('pkce-verifier', codeVerifier);
      now(started);
      const ringCiphertext = await encrypted('ring-nonce-time', JSON.stringify(value));
      const beforeWrite = now(started);
      if (beforeWrite >= expiresAt) fail('expired');
      const row = { pk, status: 'pending', created_at: started, expires_at: expiresAt,
        ttl_delete_after: expiresAt + cfg.cleanupLagSeconds,
        state_digest: pk,
        browser_correlation_digest: keyed('browser-correlation', browserCorrelation),
        oidc_nonce_digest: keyed('oidc-nonce', oidcNonce),
        pkce_verifier_ciphertext: pkceCiphertext,
        ring_nonce_time_ciphertext: ringCiphertext };
      let inserted;
      try { inserted = await store.putTransaction(row, { decisionNow: () => now(beforeWrite) }); }
      catch { fail('store_unavailable'); }
      if (inserted !== true) fail('state_invalid');
      if (now(beforeWrite) >= expiresAt) fail('expired');
      emit('begin', 'pending');
      return { state, browserCorrelation, codeChallenge, oidcNonce, expiresAt };
    },
    async callback(input) {
      const value = ownRecord(input, ['state','browserCorrelation','code']);
      exactKeys(value, ['state','browserCorrelation','code'], 'invalid_input');
      if (!TOKEN.test(value.state) || !TOKEN.test(value.browserCorrelation) ||
          !text(value.code, 4096)) fail('invalid_input');
      const started = now();
      const pk = keyed('auth-state', value.state);
      const row = await readTransaction(pk);
      if (row === null || !equal(row.pk, pk) || !equal(row.state_digest, pk)) fail('state_invalid');
      if (!equal(row.browser_correlation_digest,
        keyed('browser-correlation', value.browserCorrelation))) fail('correlation_invalid');
      const ring = await ringData(row);
      const beforeReserve = now(started);
      stillCurrent(beforeReserve, row, ring.ringTimeSeconds);
      if (row.status !== 'pending') fail('reservation_conflict');
      const reservationRef = keyed('reservation', randomToken(randomBytes));
      let reserved;
      try { reserved = await store.reserveTransaction({ pk, reservationRef,
        now: beforeReserve, expectedExpiresAt: row.expires_at,
        originalRingDeadline: ring.ringTimeSeconds + cfg.ringNonceSeconds,
        decisionNow: () => now(beforeReserve) }); }
      catch { fail('commit_outcome_unknown'); }
      if (reserved !== true) fail('reservation_conflict');
      const afterReserve = now(beforeReserve);
      stillCurrent(afterReserve, row, ring.ringTimeSeconds);
      const codeVerifier = await decrypted('pkce-verifier', row.pkce_verifier_ciphertext);
      const beforeExchange = now(afterReserve);
      stillCurrent(beforeExchange, row, ring.ringTimeSeconds);
      let exchange;
      try { exchange = await exchangeCode({ code: value.code, codeVerifier,
        redirectUri: cfg.redirectUri, clientId: cfg.clientId }); }
      catch { fail('exchange_outcome_unknown'); }
      const result = ownRecord(exchange, ['idToken'], 'exchange_outcome_unknown');
      if (!text(result.idToken, 16384)) fail('exchange_outcome_unknown');
      const afterExchange = now(beforeExchange);
      stillCurrent(afterExchange, row, ring.ringTimeSeconds);
      let verified;
      try { verified = await verifyIdentity({ idToken: result.idToken,
        issuer: cfg.issuer, clientId: cfg.clientId }); }
      catch { fail('identity_invalid'); }
      const claims = ownRecord(verified,
        ['verified','sub','iss','aud','azp','exp','iat','tokenUse','nonce'], 'identity_invalid');
      exactKeys(claims, ['verified','sub','iss','aud','exp','iat','tokenUse','nonce'],
        'identity_invalid');
      const beforeCommit = now(afterExchange);
      stillCurrent(beforeCommit, row, ring.ringTimeSeconds);
      if (claims.verified !== true || !equal(claims.sub, cfg.ownerSubject) ||
          !equal(claims.iss, cfg.issuer) || !equal(claims.aud, cfg.clientId) ||
          (claims.azp !== undefined && !equal(claims.azp, cfg.clientId)) ||
          claims.tokenUse !== 'id' || !second(claims.exp) || !second(claims.iat) ||
          claims.exp <= beforeCommit || claims.iat > beforeCommit ||
          !text(claims.nonce, 1024) ||
          !equal(keyed('oidc-nonce', claims.nonce), row.oidc_nonce_digest)) {
        fail('identity_invalid');
      }
      const sessionId = randomToken(randomBytes);
      const csrfToken = randomToken(randomBytes);
      const absoluteExpiresAt = beforeCommit + cfg.sessionAbsoluteSeconds;
      const sessionRow = { pk: keyed('app-session', sessionId),
        owner_subject_ref: ownerRef, version: 1, status: 'active',
        created_at: beforeCommit, last_seen_at: beforeCommit,
        absolute_expires_at: absoluteExpiresAt,
        idle_expires_at: Math.min(beforeCommit + cfg.sessionIdleSeconds, absoluteExpiresAt),
        csrf_ref: keyed('csrf', csrfToken),
        ttl_delete_after: absoluteExpiresAt + cfg.cleanupLagSeconds };
      const atCommit = now(beforeCommit);
      stillCurrent(atCommit, row, ring.ringTimeSeconds);
      let committed;
      try { committed = await store.finalizeTransaction({ pk, reservationRef,
        now: atCommit, originalRingDeadline: ring.ringTimeSeconds + cfg.ringNonceSeconds,
        verifiedIdentityExpiresAt: claims.exp,
        decisionNow: () => now(atCommit), sessionRow }); }
      catch { fail('commit_outcome_unknown'); }
      if (committed !== true) fail('commit_outcome_unknown');
      let afterCommit;
      try { afterCommit = now(atCommit); }
      catch { fail('postcommit_clock_unknown'); }
      if (afterCommit >= claims.exp || afterCommit >= row.expires_at ||
          afterCommit >= ring.ringTimeSeconds + cfg.ringNonceSeconds ||
          afterCommit >= sessionRow.idle_expires_at ||
          afterCommit >= sessionRow.absolute_expires_at) fail('postcommit_expired');
      emit('callback', 'committed');
      return { cookie: cookie(sessionId, cfg.sessionAbsoluteSeconds), csrfToken,
        version: 1, expiresAt: absoluteExpiresAt };
    },
    async inspectCallback(input) {
      const value = ownRecord(input, ['state','browserCorrelation']);
      exactKeys(value, ['state','browserCorrelation'], 'invalid_input');
      if (!TOKEN.test(value.state) || !TOKEN.test(value.browserCorrelation)) fail('invalid_input');
      const pk = keyed('auth-state', value.state);
      const row = await readTransaction(pk);
      if (!row || !equal(row.state_digest, pk) ||
          !equal(row.browser_correlation_digest,
            keyed('browser-correlation', value.browserCorrelation))) {
        return { status: 'unavailable' };
      }
      now();
      return { status: row.status };
    },
    async authorize(input) {
      const value = ownRecord(input, ['sessionId','version']);
      exactKeys(value, ['sessionId','version'], 'invalid_input');
      const checked = await readSession(value.sessionId, value.version);
      if (now(checked.time) >= checked.row.idle_expires_at) fail('session_invalid');
      return { authenticated: true, version: checked.row.version,
        expiresAt: checked.row.absolute_expires_at };
    },
    async authorizePost(input) {
      const value = ownRecord(input, ['sessionId','version','origin','csrfToken']);
      exactKeys(value, ['sessionId','version','origin','csrfToken'], 'invalid_input');
      const checked = await readSession(value.sessionId, value.version);
      postProof(checked.row, value.origin, value.csrfToken);
      if (now(checked.time) >= checked.row.idle_expires_at) fail('session_invalid');
      return { authenticated: true, version: checked.row.version,
        expiresAt: checked.row.absolute_expires_at };
    },
    async touch(input) {
      const value = ownRecord(input, ['sessionId','version','origin','csrfToken']);
      exactKeys(value, ['sessionId','version','origin','csrfToken'], 'invalid_input');
      const checked = await readSession(value.sessionId, value.version);
      postProof(checked.row, value.origin, value.csrfToken);
      const atWrite = now(checked.time);
      if (atWrite >= checked.row.idle_expires_at ||
          atWrite >= checked.row.absolute_expires_at) fail('session_invalid');
      let updated;
      try { updated = await store.touchSession({ pk: checked.pk,
        expectedVersion: value.version, now: atWrite,
        idleSeconds: cfg.sessionIdleSeconds, decisionNow: () => now(atWrite) }); }
      catch { fail('commit_outcome_unknown'); }
      if (updated === null) fail('version_conflict');
      const fresh = session(updated);
      let after;
      try { after = now(atWrite); } catch { fail('postcommit_clock_unknown'); }
      if (fresh.status !== 'active' || fresh.version !== value.version + 1 ||
          fresh.created_at !== checked.row.created_at ||
          fresh.absolute_expires_at !== checked.row.absolute_expires_at ||
          fresh.idle_expires_at <= after || fresh.absolute_expires_at <= after) {
        fail('postcommit_expired');
      }
      return { version: fresh.version, expiresAt: fresh.absolute_expires_at };
    },
    async rotate(input) {
      const value = ownRecord(input, ['sessionId','version','origin','csrfToken']);
      exactKeys(value, ['sessionId','version','origin','csrfToken'], 'invalid_input');
      const checked = await readSession(value.sessionId, value.version);
      postProof(checked.row, value.origin, value.csrfToken);
      const atWrite = now(checked.time);
      if (atWrite >= checked.row.idle_expires_at ||
          atWrite >= checked.row.absolute_expires_at) fail('session_invalid');
      const newId = randomToken(randomBytes);
      const newCsrf = randomToken(randomBytes);
      const newRow = { ...checked.row, pk: keyed('app-session', newId),
        version: checked.row.version + 1, last_seen_at: atWrite,
        idle_expires_at: Math.min(atWrite + cfg.sessionIdleSeconds,
          checked.row.absolute_expires_at), csrf_ref: keyed('csrf', newCsrf) };
      let rotated;
      try { rotated = await store.rotateSession({ pk: checked.pk,
        expectedVersion: value.version, now: atWrite, newRow,
        idleSeconds: cfg.sessionIdleSeconds, decisionNow: () => now(atWrite) }); }
      catch { fail('commit_outcome_unknown'); }
      if (rotated === null) fail('version_conflict');
      const replacement = session(rotated);
      let after;
      try { after = now(atWrite); } catch { fail('postcommit_clock_unknown'); }
      if (replacement.status !== 'active' || replacement.version !== value.version + 1 ||
          replacement.created_at !== checked.row.created_at ||
          replacement.absolute_expires_at !== checked.row.absolute_expires_at ||
          after >= replacement.idle_expires_at || after >= replacement.absolute_expires_at) {
        fail('postcommit_expired');
      }
      return { cookie: cookie(newId, Math.max(0, replacement.absolute_expires_at - after)),
        csrfToken: newCsrf, version: replacement.version,
        expiresAt: replacement.absolute_expires_at };
    },
    async logout(input) {
      const value = ownRecord(input, ['sessionId','version','origin','csrfToken']);
      exactKeys(value, ['sessionId','version','origin','csrfToken'], 'invalid_input');
      const checked = await readSession(value.sessionId, value.version);
      postProof(checked.row, value.origin, value.csrfToken);
      const atWrite = now(checked.time);
      if (atWrite >= checked.row.idle_expires_at ||
          atWrite >= checked.row.absolute_expires_at) fail('session_invalid');
      let revoked;
      try { revoked = await store.revokeSession({ pk: checked.pk,
        expectedVersion: value.version, now: atWrite,
        decisionNow: () => now(atWrite) }); }
      catch { fail('commit_outcome_unknown'); }
      if (revoked !== true) fail('version_conflict');
      let after;
      try { after = now(atWrite); } catch { fail('postcommit_clock_unknown'); }
      if (after >= checked.row.idle_expires_at ||
          after >= checked.row.absolute_expires_at) fail('postcommit_expired');
      return { clearCookie: CLEAR_COOKIE };
    }
  });
}
