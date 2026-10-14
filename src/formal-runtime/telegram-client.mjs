import { denyFormalRuntime, exactObject, safeRevision, zeroBinary } from './protocol.mjs';

function validateToken(token) {
  if (!Buffer.isBuffer(token) || token.length < 8 || token.length > 4096) {
    denyFormalRuntime('B02_TELEGRAM_TOKEN_DENIED');
  }
}

export function createTelegramAdmissionClient({ request, timeoutMs = 10_000 }) {
  if (typeof request !== 'function' || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) {
    denyFormalRuntime('B02_TELEGRAM_CLIENT_CONFIG_DENIED');
  }
  let closed = false;
  let calls = 0;

  async function invoke(method, params, token) {
    if (closed) denyFormalRuntime('B02_TELEGRAM_CLIENT_CLOSED');
    if (!['getMe', 'getUpdates'].includes(method)) denyFormalRuntime('B02_TELEGRAM_METHOD_DENIED');
    validateToken(token);
    const owned = Buffer.from(token);
    try {
      calls += 1;
      return await request(Object.freeze({ method, params: Object.freeze({ ...params }), token: owned, timeoutMs }));
    } catch {
      denyFormalRuntime('B02_TELEGRAM_PROVIDER_DENIED');
    } finally {
      zeroBinary(owned);
    }
  }

  return Object.freeze({
    async getMe({ token }) {
      return invoke('getMe', Object.freeze({}), token);
    },
    async getUpdates({ token, offset, limit = 100 }) {
      const cursor = safeRevision(offset);
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) denyFormalRuntime('B02_TELEGRAM_CURSOR_DENIED');
      return invoke('getUpdates', Object.freeze({ offset: cursor, limit }), token);
    },
    close() {
      closed = true;
      return Object.freeze({ closed: true });
    },
    status() {
      return Object.freeze({ closed, calls });
    }
  });
}

export function validateTelegramMe(value) {
  const fields = exactObject(value, ['ok', 'result'], 'B02_TELEGRAM_ME_DENIED');
  const result = exactObject(fields.result, ['id', 'isBot', 'username'], 'B02_TELEGRAM_ME_DENIED');
  if (fields.ok !== true || result.isBot !== true ||
      typeof result.id !== 'string' || !/^[A-Za-z][A-Za-z0-9:_-]{2,127}$/.test(result.id) ||
      typeof result.username !== 'string' || !/^[A-Za-z][A-Za-z0-9_]{2,63}$/.test(result.username)) {
    denyFormalRuntime('B02_TELEGRAM_ME_DENIED');
  }
  return Object.freeze({ botId: result.id, username: result.username });
}

export function validateTelegramUpdates(value) {
  const fields = exactObject(value, ['ok', 'result'], 'B02_TELEGRAM_UPDATES_DENIED');
  if (fields.ok !== true || !Array.isArray(fields.result) || fields.result.length > 100) {
    denyFormalRuntime('B02_TELEGRAM_UPDATES_DENIED');
  }
  return fields.result;
}

const FORWARDED_FIELDS = Object.freeze([
  'forward_origin', 'forward_from', 'forward_from_chat', 'forward_sender_name', 'forward_date',
  'via_bot', 'sender_chat', 'author_signature'
]);

function ownedData(object, key) {
  if (!object || typeof object !== 'object') return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (!descriptor || !Object.hasOwn(descriptor, 'value')) denyFormalRuntime('B02_TELEGRAM_UPDATE_PROVENANCE_DENIED');
  return descriptor.value;
}

export function normalizePrivateStartUpdate(value, { expectedOwnerId, expectedText, cursor, wallNowMs, maximumFreshMs = 300_000 }) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.hasOwn(value, 'edited_message')) {
    denyFormalRuntime('B02_TELEGRAM_UPDATE_PROVENANCE_DENIED');
  }
  const updateId = safeRevision(ownedData(value, 'update_id'));
  const message = ownedData(value, 'message');
  if (!message || typeof message !== 'object' || Array.isArray(message) ||
      FORWARDED_FIELDS.some((key) => Object.hasOwn(message, key))) denyFormalRuntime('B02_TELEGRAM_UPDATE_PROVENANCE_DENIED');
  const from = ownedData(message, 'from');
  const chat = ownedData(message, 'chat');
  const text = ownedData(message, 'text');
  const dateSeconds = ownedData(message, 'date');
  if (!from || !chat || ownedData(from, 'is_bot') !== false || ownedData(chat, 'type') !== 'private' ||
      ownedData(from, 'id') !== ownedData(chat, 'id') || String(ownedData(from, 'id')) !== String(expectedOwnerId) ||
      text !== expectedText || !Number.isSafeInteger(dateSeconds)) denyFormalRuntime('B02_TELEGRAM_UPDATE_PROVENANCE_DENIED');
  const observedAt = dateSeconds * 1000;
  if (updateId < safeRevision(cursor) || !Number.isSafeInteger(wallNowMs) || observedAt > wallNowMs ||
      wallNowMs - observedAt > maximumFreshMs) denyFormalRuntime('B02_TELEGRAM_UPDATE_PROVENANCE_DENIED');
  return Object.freeze({ updateId, ownerId: String(expectedOwnerId), text, observedAt });
}

export const telegramUpdateProvenanceConstants = Object.freeze({ forbiddenMessageFields: FORWARDED_FIELDS });
