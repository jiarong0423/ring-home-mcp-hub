import { createHmac, timingSafeEqual } from 'node:crypto';
import { ProtocolError, requireOpaque, requireSigningKey, computeNonce, parseVerifiedWebhook } from './protocol.mjs';

const SAFE_ERRORS = new Set([
  'invalid_field', 'invalid_time', 'invalid_nonce', 'expired_link', 'link_not_found', 'ambiguous_link',
  'source_not_authorized', 'identity_not_authorized', 'identity_changed', 'identity_expired',
  'code_expired', 'code_deadline_invalid', 'code_exchange_in_progress', 'code_outcome_unknown',
  'code_conflict', 'code_store_unavailable', 'code_record_invalid', 'code_state_invalid',
  'link_conflict', 'link_expired', 'link_store_unavailable', 'link_record_invalid', 'link_state_invalid',
  'unclaimed_limit', 'provider_outcome_unknown', 'upstream_unavailable', 'upstream_status',
  'upstream_content_type', 'upstream_oversize', 'upstream_empty', 'upstream_json', 'profile_schema',
  'token_payload_invalid', 'token_envelope_unavailable', 'token_envelope_invalid', 'token_envelope_context',
  'secret_unavailable', 'secret_response_invalid', 'secret_schema_invalid', 'secret_superseded',
  'secret_loader_clock', 'secret_loader_clock_rollback', 'workflow_clock', 'workflow_state_invalid',
  'webhook_not_configured', 'invalid_signature', 'invalid_webhook', 'event_conflict',
  'relink_required', 'token_rotation_conflict', 'token_rotation_outcome_unknown'
]);
const ACCESS_REFRESH_WINDOW_MS = 300_000;
const REFRESH_TOKEN_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;
function fail(code) { throw new ProtocolError(code); }
function errorCode(error) {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(error, 'code');
    return descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
  } catch { return undefined; }
}
function sanitized(error, fallback = 'workflow_unavailable') {
  const code = errorCode(error);
  return new ProtocolError(SAFE_ERRORS.has(code) ? code : fallback);
}
function exact(value, required, optional = [], code = 'invalid_field') {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail(code);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (required.some(key => !Object.hasOwn(descriptors, key)) ||
        keys.some(key => typeof key !== 'string' || ![...required, ...optional].includes(key)) ||
        keys.some(key => !Object.hasOwn(descriptors[key], 'value'))) fail(code);
    return Object.fromEntries(keys.map(key => [key, descriptors[key].value]));
  } catch { fail(code); }
}
function text(value, limit) {
  requireOpaque(value, limit);
  if (Buffer.byteLength(value) > limit || Buffer.from(value).toString('utf8') !== value) fail('invalid_field');
  return value;
}
function proof(value, code) {
  if ((typeof value !== 'object' || value === null || Array.isArray(value)) && typeof value !== 'symbol') fail(code);
  return value;
}
function scopes(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 16) fail('identity_not_authorized');
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).some(key => key !== 'length' &&
      (typeof key !== 'string' || !/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length))) fail('identity_not_authorized');
  const result = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) fail('identity_not_authorized');
    result.push(text(descriptor.value, 256));
  }
  if (new Set(result).size !== result.length) fail('identity_not_authorized');
  return Object.freeze(result);
}
function result(status, duplicate = false) {
  return Object.freeze({ status, duplicate, bindingCompleted: status === 'completed', retryAllowed: false, productionAdmitted: false });
}
function keyedDigest(kind, value, key) {
  requireSigningKey(key);
  return createHmac('sha256', key).update(kind + '\0' + value, 'utf8').digest('hex');
}

export function createRingWorkflow({ client, store, secretLoader, tokenEnvelope, identityAuthority, clock = Date.now } = {}) {
  const ports = [
    [client, ['exchangeCode', 'refreshTokens', 'getAccountId', 'confirmLink', 'completeLink'], 'client_config'],
    [store, ['beginCodeExchange', 'commitUnclaimed', 'rotateTokenEnvelope', 'markCodeOutcomeUnknown', 'listUnclaimedForMatch', 'reserveClaim', 'beginProviderPhase', 'finishProviderPhase', 'markOutcomeUnknown'], 'store_config'],
    [secretLoader, ['loadProvider', 'loadDigest'], 'secret_loader_config'],
    [tokenEnvelope, ['seal', 'open'], 'token_envelope_config'],
    [identityAuthority, ['resolveMatchedRingAccount', 'recheck'], 'identity_authority_config']
  ];
  for (const [port, methods, code] of ports) if (methods.some(method => typeof port?.[method] !== 'function')) fail(code);
  if (typeof clock !== 'function') fail('workflow_clock');
  let previousTime = -1;
  function now() {
    let value;
    try { value = clock(); } catch { fail('workflow_clock'); }
    if (!Number.isSafeInteger(value) || value < 0 || value < previousTime) fail('workflow_clock');
    previousTime = value;
    return value;
  }
  async function secrets() {
    const provider = (await secretLoader.loadProvider())?.secret;
    const digest = (await secretLoader.loadDigest())?.secret;
    requireSigningKey(provider?.nonceKey);
    requireSigningKey(digest?.recordHmacKey);
    return { provider, digest };
  }
  function lease(value) {
    const current = exact(value, ['proof', 'actorRef', 'ownerRef', 'householdRef', 'scopeRefs', 'accountIdentifier', 'epoch', 'expiresAt'], [], 'identity_not_authorized');
    proof(current.proof, 'identity_not_authorized');
    for (const field of ['actorRef', 'ownerRef', 'householdRef', 'accountIdentifier']) text(current[field], 256);
    const scopeRefs = scopes(current.scopeRefs);
    if (!Number.isSafeInteger(current.epoch) || current.epoch < 1) fail('identity_not_authorized');
    if (!Number.isSafeInteger(current.expiresAt) || current.expiresAt <= now()) fail('identity_expired');
    return Object.freeze({ ...current, scopeRefs });
  }
  async function recheckIdentity(original) {
    let checked;
    try { checked = await identityAuthority.recheck(original.proof); } catch { fail('identity_not_authorized'); }
    const current = lease(checked);
    if (current.proof !== original.proof ||
        ['actorRef', 'ownerRef', 'householdRef', 'accountIdentifier', 'epoch', 'expiresAt'].some(field => current[field] !== original[field]) ||
        JSON.stringify(current.scopeRefs) !== JSON.stringify(original.scopeRefs)) fail('identity_changed');
    return current;
  }
  function transition(value, expectedId, expectedStatus, expectedPhase, expectedVersion) {
    if (value?.id !== expectedId || value.status !== expectedStatus || value.providerPhase !== expectedPhase || value.version !== expectedVersion) fail('workflow_state_invalid');
    return value.version;
  }

  // Shared by /ring/link and the owner bootstrap: exactly one unclaimed, unexpired link whose
  // keyed nonce matches (time, nonce). Returns decrypted link material to in-process callers only.
  async function matchUnclaimed(input) {
    try {
      const { time, nonce } = exact(input, ['time', 'nonce']);
      if (typeof time !== 'string' || !/^[1-9][0-9]{12}$/.test(time)) fail('invalid_time');
      if (typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(nonce) ||
          Buffer.from(nonce, 'base64url').toString('base64url') !== nonce) fail('invalid_nonce');
      const at = Number(time);
      if (at > now() || now() - at > 600_000) fail('expired_link');
      const { provider, digest } = await secrets();
      const candidates = await store.listUnclaimedForMatch(Math.floor(now() / 1000));
      if (!Array.isArray(candidates) || candidates.length > 25) fail('unclaimed_limit');
      const matches = [];
      for (const candidate of candidates) {
        if (candidate?.status !== 'UNCLAIMED' || candidate.identityEpoch !== 0 ||
            !Number.isSafeInteger(candidate.version) || candidate.version < 1 ||
            !Number.isSafeInteger(candidate.expiresAt) || !Number.isSafeInteger(candidate.expiresAt * 1000) ||
            candidate.expiresAt * 1000 <= now()) fail('link_record_invalid');
        text(candidate.id, 128);
        const lifecycle = candidate.tokenEnvelope.schemaVersion === 2
          ? ['refreshTokenExpiresAt', 'rotation']
          : [];
        const payload = exact(await tokenEnvelope.open(candidate.tokenEnvelope, {
          linkId: candidate.id, revision: candidate.tokenEnvelope.revision
        }), ['accountId', 'accessToken', 'refreshToken', 'tokenExpiresAt', ...lifecycle], [], 'token_payload_invalid');
        text(payload.accountId, 256); text(payload.accessToken, 8192); text(payload.refreshToken, 8192);
        if (!Number.isSafeInteger(payload.tokenExpiresAt) ||
            (lifecycle.length > 0 && (!Number.isSafeInteger(payload.refreshTokenExpiresAt) ||
              payload.refreshTokenExpiresAt <= payload.tokenExpiresAt ||
              payload.rotation !== candidate.tokenEnvelope.revision))) fail('token_payload_invalid');
        if (candidate.accountDigest !== keyedDigest('ring-account', payload.accountId, digest.recordHmacKey)) fail('link_record_invalid');
        if (timingSafeEqual(Buffer.from(computeNonce(time, payload.accountId, provider.nonceKey)), Buffer.from(nonce))) matches.push({ candidate, payload });
      }
      if (matches.length === 0) fail('link_not_found');
      if (matches.length !== 1) fail('ambiguous_link');
      const { candidate, payload } = matches[0];
      return Object.freeze({ at, candidate, payload });
    } catch (error) { throw sanitized(error); }
  }

  return Object.freeze({
    matchUnclaimed,
    async stageFromVerifiedIngress(input) {
      let intake;
      let attempted = false;
      let exchangeReturned = false;
      try {
        const { code, receivedAt, bodyDigest } = exact(input, ['code', 'receivedAt', 'bodyDigest']);
        text(code, 2048);
        if (typeof bodyDigest !== 'string' || !/^[0-9a-f]{64}$/.test(bodyDigest)) fail('invalid_field');
        const current = now();
        const deadline = receivedAt + 60_000;
        if (!Number.isSafeInteger(receivedAt) || receivedAt < 1 || receivedAt > current ||
            !Number.isSafeInteger(deadline) || current >= deadline) fail('code_expired');
        const { digest } = await secrets();
        if (now() >= deadline) fail('code_expired');
        intake = await store.beginCodeExchange({
          codeDigest: keyedDigest('code', code, digest.recordHmacKey),
          receivedAt: Math.floor(receivedAt / 1000), bodyDigest,
          exchangeDeadline: Math.floor(deadline / 1000)
        });
        if (intake?.status === 'UNCLAIMED' && intake.duplicate === true && intake.safeDuplicate === true && intake.mayCallProvider === false) return result('unclaimed', true);
        if (intake?.status !== 'EXCHANGE_STARTED' || intake.duplicate !== false || intake.safeDuplicate !== false || intake.mayCallProvider !== true) fail('workflow_state_invalid');
        text(intake.intakeId, 128);
        if (now() >= deadline) fail('code_expired');
        attempted = true;
        const token = exact(await client.exchangeCode(code, { deadline, clock: now }), ['accessToken', 'refreshToken', 'expiresIn'], [], 'token_payload_invalid');
        exchangeReturned = true;
        text(token.accessToken, 8192); text(token.refreshToken, 8192);
        if (!Number.isSafeInteger(token.expiresIn) || token.expiresIn < 1) fail('token_payload_invalid');
        const acquiredAt = now();
        const tokenExpiresAt = acquiredAt + token.expiresIn * 1000;
        const refreshTokenExpiresAt = acquiredAt + REFRESH_TOKEN_LIFETIME_MS;
        if (!Number.isSafeInteger(tokenExpiresAt) || !Number.isSafeInteger(refreshTokenExpiresAt) ||
            refreshTokenExpiresAt <= tokenExpiresAt) fail('token_payload_invalid');
        const accountId = text(await client.getAccountId(token.accessToken), 256);
        const accountDigest = keyedDigest('ring-account', accountId, digest.recordHmacKey);
        if (tokenExpiresAt <= now()) fail('link_expired');
        const linkExpiresAt = Math.floor(Math.min(refreshTokenExpiresAt, now() + 600_000) / 1000);
        const envelope = await tokenEnvelope.seal({
          accountId, accessToken: token.accessToken, refreshToken: token.refreshToken, tokenExpiresAt,
          refreshTokenExpiresAt, rotation: 1
        }, { linkId: intake.intakeId, revision: 1 });
        if (now() >= deadline) fail('code_expired');
        const committed = await store.commitUnclaimed({
          intakeId: intake.intakeId, bodyDigest, accountDigest,
          exchangeDeadline: Math.floor(deadline / 1000),
          tokenEnvelope: envelope, linkExpiresAt
        });
        if (committed?.status !== 'UNCLAIMED' || committed.intakeId !== intake.intakeId || committed.version !== 1 || typeof committed.duplicate !== 'boolean') fail('workflow_state_invalid');
        return result('unclaimed', committed.duplicate);
      } catch (error) {
        if (attempted && intake?.intakeId &&
            (exchangeReturned || !['code_expired', 'code_deadline_invalid', 'invalid_field'].includes(errorCode(error)))) {
          try { await store.markCodeOutcomeUnknown({ intakeId: intake.intakeId, reason: 'EXCHANGE_RESULT_AMBIGUOUS' }); } catch { }
          throw new ProtocolError('provider_outcome_unknown');
        }
        throw sanitized(error);
      }
    },

    async continuePasswordlessLink(input) {
      let claim;
      let phase = 'POST';
      let version;
      let reserved = false;
      let providerAttempted = false;
      let rotationAttempted = false;
      try {
        const { query, context } = exact(input, ['query'], ['context']);
        const { time, nonce } = exact(query, ['time', 'nonce']);
        const { at, candidate, payload: matchedPayload } = await matchUnclaimed({ time, nonce });
        let payload = matchedPayload;
        const refreshRequired = payload.tokenExpiresAt <= now() + ACCESS_REFRESH_WINDOW_MS;
        if (refreshRequired && (!Number.isSafeInteger(payload.refreshTokenExpiresAt) ||
            payload.refreshTokenExpiresAt <= now() ||
            !Number.isSafeInteger(payload.rotation) || payload.rotation < 1)) fail('relink_required');
        let identity;
        try { identity = lease(await identityAuthority.resolveMatchedRingAccount({ accountId: payload.accountId, context })); }
        catch (error) { throw sanitized(error, 'identity_not_authorized'); }
        await recheckIdentity(identity);
        const credentialExpiresAt = refreshRequired ? payload.refreshTokenExpiresAt : payload.tokenExpiresAt;
        const expiresAt = Math.floor(Math.min(identity.expiresAt, credentialExpiresAt, candidate.expiresAt * 1000) / 1000);
        claim = { linkId: candidate.id, accountDigest: candidate.accountDigest, currentEpoch: identity.epoch, expiresAt };
        version = candidate.version;
        let reservation;
        try {
          reservation = await store.reserveClaim({
            ...claim, actorRef: identity.actorRef, ownerRef: identity.ownerRef, householdRef: identity.householdRef,
            scopeRefs: identity.scopeRefs, expectedVersion: version
          });
        } catch (error) {
          if (!['link_conflict', 'link_expired'].includes(errorCode(error))) reserved = true;
          throw error;
        }
        reserved = true;
        version = transition(reservation, claim.linkId, 'RESERVED', 'NOT_STARTED', version + 1);
        if (refreshRequired) {
          const deadline = at + 600_000;
          if (!Number.isSafeInteger(deadline) || now() >= deadline) fail('expired_link');
          rotationAttempted = true;
          const rotated = exact(await client.refreshTokens(payload.refreshToken, { deadline, clock: now }),
            ['accessToken', 'refreshToken', 'expiresIn'], [], 'token_payload_invalid');
          text(rotated.accessToken, 8192); text(rotated.refreshToken, 8192);
          if (!Number.isSafeInteger(rotated.expiresIn) || rotated.expiresIn < 1) fail('token_payload_invalid');
          const rotatedAt = now();
          const tokenExpiresAt = rotatedAt + rotated.expiresIn * 1000;
          const refreshTokenExpiresAt = rotatedAt + REFRESH_TOKEN_LIFETIME_MS;
          const rotation = payload.rotation + 1;
          if (!Number.isSafeInteger(tokenExpiresAt) || !Number.isSafeInteger(refreshTokenExpiresAt) ||
              !Number.isSafeInteger(rotation) || refreshTokenExpiresAt <= tokenExpiresAt) fail('token_payload_invalid');
          const nextPayload = Object.freeze({
            accountId: payload.accountId,
            accessToken: rotated.accessToken,
            refreshToken: rotated.refreshToken,
            tokenExpiresAt,
            refreshTokenExpiresAt,
            rotation
          });
          const nextEnvelope = await tokenEnvelope.seal(nextPayload, { linkId: candidate.id, revision: rotation });
          const persisted = await store.rotateTokenEnvelope({
            linkId: candidate.id,
            accountDigest: candidate.accountDigest,
            expectedLinkVersion: version,
            expectedTokenRevision: payload.rotation,
            tokenEnvelope: nextEnvelope
          });
          if (persisted?.id !== candidate.id || persisted.tokenRevision !== rotation ||
              (persisted.duplicate !== true && persisted.duplicate !== false)) fail('workflow_state_invalid');
          payload = nextPayload;
        }
        for (const operation of ['POST', 'PATCH']) {
          phase = operation;
          await recheckIdentity(identity);
          if (now() - at > 600_000 || expiresAt * 1000 <= now()) fail('expired_link');
          const started = await store.beginProviderPhase({ ...claim, phase, expectedVersion: version });
          version = transition(started, claim.linkId, phase === 'POST' ? 'RESERVED' : 'AWAITING', phase + '_STARTED', version + 1);
          await recheckIdentity(identity);
          if (expiresAt * 1000 <= now()) fail('expired_link');
          providerAttempted = true;
          if (phase === 'POST') await client.confirmLink(payload.accessToken, nonce, identity.accountIdentifier);
          else await client.completeLink(payload.accessToken);
          await recheckIdentity(identity);
          const finished = await store.finishProviderPhase({ ...claim, phase, expectedVersion: version });
          version = transition(finished, claim.linkId, phase === 'POST' ? 'AWAITING' : 'COMPLETED', phase + '_SUCCEEDED', version + 1);
        }
        return result('completed');
      } catch (error) {
        if (reserved && claim) {
          const code = errorCode(error);
          try {
            await store.markOutcomeUnknown({
              linkId: claim.linkId, accountDigest: claim.accountDigest, currentEpoch: claim.currentEpoch,
              phase, expectedVersion: version,
              reason: code === 'relink_required' ? 'RELINK_REQUIRED' :
                (providerAttempted || rotationAttempted) ? 'PROVIDER_RESULT_AMBIGUOUS' : 'CLAIM_STATE_AMBIGUOUS'
            });
          } catch { }
          if (code === 'relink_required') throw new ProtocolError('relink_required');
          throw new ProtocolError('provider_outcome_unknown');
        }
        throw sanitized(error);
      }
    },

    async receiveSignedWebhook({ rawBody, signature }) {
      try {
        if (typeof store.acceptWebhook !== 'function') fail('webhook_not_configured');
        const provider = (await secretLoader.loadProvider())?.secret;
        if (!provider?.webhookSigningKey) fail('webhook_not_configured');
        const verified = parseVerifiedWebhook(rawBody, signature, provider.webhookSigningKey);
        const receipt = await store.acceptWebhook(verified.requestId, verified.accountId, rawBody);
        return Object.freeze({ accepted: true, duplicate: receipt.duplicate === true, eventType: verified.eventType });
      } catch (error) { throw sanitized(error); }
    }
  });
}
