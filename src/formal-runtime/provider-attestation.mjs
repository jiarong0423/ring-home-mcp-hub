import crypto from 'node:crypto';
import { normalizePrivateStartUpdate, validateTelegramMe, validateTelegramUpdates } from './telegram-client.mjs';
import { deepFreeze, denyFormalRuntime, exactObject, safeLabel, safeRevision, safeTime } from './protocol.mjs';

const PROOF_SCHEMA = 'ring-b02-provider-binding-proof-v1';
const MAX_FRESH_MS = 300_000;

function challengeText(value) {
  if (typeof value !== 'string' || !/^\/start [A-Za-z0-9_-]{16,128}$/.test(value)) {
    denyFormalRuntime('B02_ATTESTATION_CHALLENGE_DENIED');
  }
  return value;
}

function normalizeUpdate(value) {
  const fields = exactObject(value, ['updateId', 'ownerId', 'botId', 'text', 'observedAt'],
    'B02_ATTESTATION_UPDATE_DENIED');
  return deepFreeze({
    updateId: safeRevision(fields.updateId),
    ownerId: safeLabel(fields.ownerId, 'B02_ATTESTATION_UPDATE_DENIED'),
    botId: safeLabel(fields.botId, 'B02_ATTESTATION_UPDATE_DENIED'),
    text: challengeText(fields.text),
    observedAt: safeTime(fields.observedAt, 'B02_ATTESTATION_UPDATE_DENIED')
  });
}

export function createOneShotProviderAttestation({ client, clock = Date.now }) {
  if (!client || typeof client.getMe !== 'function' || typeof client.getUpdates !== 'function' ||
      typeof clock !== 'function') denyFormalRuntime('B02_ATTESTATION_CONFIG_DENIED');
  let state = 'fresh';
  let closed = false;

  async function attest(input) {
    if (closed || state !== 'fresh') denyFormalRuntime('B02_ATTESTATION_REPLAY_DENIED');
    state = 'in_flight';
    const fields = exactObject(input, [
      'lease', 'expectedOwnerId', 'expectedBotId', 'expectedUsername', 'cursor',
      'challenge', 'purpose', 'nonce', 'expiresAt'
    ], 'B02_ATTESTATION_INPUT_DENIED');
    if (!fields.lease || typeof fields.lease.withToken !== 'function') denyFormalRuntime('B02_ATTESTATION_LEASE_DENIED');
    const expectedOwnerId = safeLabel(fields.expectedOwnerId, 'B02_ATTESTATION_IDENTITY_DENIED');
    const expectedBotId = safeLabel(fields.expectedBotId, 'B02_ATTESTATION_IDENTITY_DENIED');
    const cursor = safeRevision(fields.cursor);
    const challenge = challengeText(fields.challenge);
    const now = safeTime(clock());
    const expiresAt = safeTime(fields.expiresAt);
    if (expiresAt <= now || expiresAt - now > MAX_FRESH_MS ||
        typeof fields.expectedUsername !== 'string' || !/^[A-Za-z][A-Za-z0-9_]{2,63}$/.test(fields.expectedUsername) ||
        !['legacy-migration', 'mcp-admission', 'binding-verification'].includes(fields.purpose) ||
        typeof fields.nonce !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(fields.nonce)) {
      state = 'denied';
      denyFormalRuntime('B02_ATTESTATION_INPUT_DENIED');
    }
    let captured;
    try {
      await fields.lease.withToken(async (token) => {
        const me = validateTelegramMe(await client.getMe({ token }));
        if (me.botId !== expectedBotId || me.username !== fields.expectedUsername) {
          denyFormalRuntime('B02_ATTESTATION_BOT_MISMATCH');
        }
        const updates = validateTelegramUpdates(await client.getUpdates({ token, offset: cursor, limit: 100 }));
        const matches = updates.map(normalizeUpdate).filter((update) =>
          update.updateId >= cursor && update.ownerId === expectedOwnerId && update.botId === expectedBotId &&
          update.text === challenge && update.observedAt <= now && now - update.observedAt <= MAX_FRESH_MS);
        if (matches.length !== 1) denyFormalRuntime('B02_ATTESTATION_AMBIGUOUS');
        const post = validateTelegramMe(await client.getMe({ token }));
        if (post.botId !== me.botId || post.username !== me.username) denyFormalRuntime('B02_ATTESTATION_BOT_DRIFT');
        const accepted = matches[0];
        captured = deepFreeze({
          proof: {
            schema: PROOF_SCHEMA,
            provider: 'telegram',
            purpose: fields.purpose,
            ownerId: expectedOwnerId,
            botId: expectedBotId,
            verifiedAt: now,
            expiresAt,
            nonce: fields.nonce,
            secret: null
          },
          nextCursor: accepted.updateId + 1,
          observedAt: accepted.observedAt
        });
        return 'CONSUMED';
      });
      state = 'consumed';
      return captured;
    } catch (error) {
      state = 'denied';
      throw error;
    }
  }

  return Object.freeze({
    attest,
    close() {
      closed = true;
      client.close?.();
      return Object.freeze({ closed: true });
    },
    status() { return Object.freeze({ state, closed }); }
  });
}

export const providerAttestationConstants = Object.freeze({ schema: PROOF_SCHEMA, maximumFreshMs: MAX_FRESH_MS });

export async function attestAndAcknowledgeCursor({ telegramTransportPort, lease, binding, cursorEnvelope,
  challenge, authorityClock, cursorAcknowledger, nonce, expiresMonotonicMs }) {
  if (!telegramTransportPort || telegramTransportPort.productionAdmitted !== true ||
      telegramTransportPort.secretBufferBoundary !== 'mutable-buffer-v1' || !lease ||
      typeof lease.withToken !== 'function' || !binding?.active || !cursorEnvelope ||
      !authorityClock || typeof authorityClock.monotonicNowMs !== 'function' || typeof authorityClock.wallNowMs !== 'function' ||
      !cursorAcknowledger || typeof cursorAcknowledger.acknowledge !== 'function') denyFormalRuntime('B02_ATTESTATION_CONFIG_DENIED');
  const nowMono = authorityClock.monotonicNowMs();
  if (!Number.isSafeInteger(expiresMonotonicMs) || expiresMonotonicMs <= nowMono || expiresMonotonicMs - nowMono > MAX_FRESH_MS) {
    denyFormalRuntime('B02_ATTESTATION_INPUT_DENIED');
  }
  const before = validateTelegramMe(await telegramTransportPort.getMeWithLease({ lease }));
  if (before.botId !== binding.botId) denyFormalRuntime('B02_ATTESTATION_BOT_MISMATCH');
  const raw = validateTelegramUpdates(await telegramTransportPort.getUpdatesWithLease({ lease, offset: cursorEnvelope.nextOffset, limit: 100 }));
  const matches = [];
  for (const update of raw) {
    try { matches.push(normalizePrivateStartUpdate(update, { expectedOwnerId: binding.ownerId, expectedText: challenge,
      cursor: cursorEnvelope.nextOffset, wallNowMs: authorityClock.wallNowMs(), maximumFreshMs: MAX_FRESH_MS })); } catch {}
  }
  if (matches.length !== 1) denyFormalRuntime('B02_ATTESTATION_AMBIGUOUS');
  const after = validateTelegramMe(await telegramTransportPort.getMeWithLease({ lease }));
  if (after.botId !== before.botId || after.username !== before.username) denyFormalRuntime('B02_ATTESTATION_BOT_DRIFT');
  const acknowledgement = await cursorAcknowledger.acknowledge({ expected: cursorEnvelope, nextOffset: matches[0].updateId + 1 });
  if (acknowledgement?.durablyWitnessed !== true || acknowledgement?.readbackExact !== true) {
    denyFormalRuntime('B02_ATTESTATION_CURSOR_ACK_DENIED');
  }
  return deepFreeze({ schema: PROOF_SCHEMA, provider: 'telegram', purpose: 'mcp-admission',
    ownerId: binding.ownerId, botId: binding.botId, verifiedAt: nowMono,
    expiresAt: expiresMonotonicMs, nonce, secret: null });
}
