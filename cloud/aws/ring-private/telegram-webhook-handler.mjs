import { timingSafeEqual } from 'node:crypto';
import { types } from 'node:util';

const HEADERS = Object.freeze({ 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store',
  'x-content-type-options': 'nosniff' });

export class TelegramWebhookHandlerError extends Error {
  constructor(code) { super(code); this.name = 'TelegramWebhookHandlerError'; this.code = code; }
}
function deny(code) { throw new TelegramWebhookHandlerError(code); }
function response(statusCode, status) {
  return Object.freeze({ statusCode, headers: HEADERS,
    body: JSON.stringify({ status, bindingCompleted: false, retryAllowed: false, productionAdmitted: false }) });
}
function exact(value, fields, code) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny(code);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== fields.length || fields.some(field => !Object.hasOwn(descriptors, field)) ||
        keys.some(key => typeof key !== 'string' || !fields.includes(key) || !Object.hasOwn(descriptors[key], 'value'))) deny(code);
    return Object.fromEntries(fields.map(field => [field, descriptors[field].value]));
  } catch (error) { if (error instanceof TelegramWebhookHandlerError) throw error; deny(code); }
}
function equalSecret(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const a = Buffer.from(left, 'utf8');
  const b = Buffer.from(right, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}
function telegramFields(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      fields.some(field => !Object.hasOwn(value, field))) deny('TELEGRAM_UPDATE_DENIED');
  return Object.fromEntries(fields.map(field => [field, value[field]]));
}
function parseUpdate(body, now) {
  let decoded;
  try { decoded = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body)); }
  catch { deny('TELEGRAM_UPDATE_DENIED'); }
  const update = exact(decoded, ['update_id', 'message'], 'TELEGRAM_UPDATE_DENIED');
  const message = telegramFields(update.message, ['message_id', 'date', 'chat', 'from', 'text']);
  if (['sender_chat', 'sender_business_bot', 'business_connection_id', 'via_bot', 'forward_origin',
    'is_automatic_forward', 'forward_from', 'forward_from_chat', 'forward_from_message_id',
    'forward_signature', 'forward_sender_name', 'forward_date'].some(field => Object.hasOwn(update.message, field))) {
    deny('TELEGRAM_UPDATE_DENIED');
  }
  const chat = telegramFields(message.chat, ['id', 'type']);
  const from = telegramFields(message.from, ['id', 'is_bot', 'first_name']);
  if (!Number.isSafeInteger(update.update_id) || update.update_id < 1 ||
      !Number.isSafeInteger(message.message_id) || message.message_id < 1 ||
      !Number.isSafeInteger(message.date) || !Number.isSafeInteger(chat.id) || !Number.isSafeInteger(from.id) ||
      chat.type !== 'private' || from.is_bot !== false || typeof from.first_name !== 'string' || chat.id !== from.id ||
      typeof message.text !== 'string' || !/^\/start [A-Za-z0-9_-]{43}$/.test(message.text)) deny('TELEGRAM_UPDATE_DENIED');
  const nonce = message.text.slice(7);
  if (Buffer.from(nonce, 'base64url').length !== 32 || Buffer.from(nonce, 'base64url').toString('base64url') !== nonce ||
      message.date > now + 5 || now - message.date > 60) deny('TELEGRAM_UPDATE_DENIED');
  return Object.freeze({ updateId: String(update.update_id), chatId: String(chat.id), userId: String(from.id),
    chatType: chat.type, enrollmentNonce: nonce });
}

export function createTelegramWebhookHandler(options) {
  const value = exact(options, ['secretLoader', 'expectedVersionId', 'createClient', 'ownerAuthority', 'clock'], 'TELEGRAM_HANDLER_CONFIG');
  if (!value.secretLoader || typeof value.secretLoader.loadTelegram !== 'function' ||
      typeof value.expectedVersionId !== 'string' || !/^[A-Za-z0-9_-]{32,64}$/.test(value.expectedVersionId) ||
      typeof value.createClient !== 'function' || types.isProxy(value.createClient) ||
      !value.ownerAuthority || typeof value.ownerAuthority.admitPrivateChat !== 'function' ||
      typeof value.clock !== 'function') deny('TELEGRAM_HANDLER_CONFIG');
  let previous = 0;
  function nowSeconds() {
    let current;
    try { current = Math.floor(value.clock() / 1000); } catch { deny('TELEGRAM_HANDLER_UNAVAILABLE'); }
    if (!Number.isSafeInteger(current) || current < previous) deny('TELEGRAM_HANDLER_UNAVAILABLE');
    previous = current;
    return current;
  }
  return Object.freeze({
    async handle(input) {
      let request;
      try { request = exact(input, ['secretToken', 'body', 'transport'], 'TELEGRAM_REQUEST_DENIED'); }
      catch { return response(400, 'denied'); }
      if (!Buffer.isBuffer(request.body)) return response(400, 'denied');
      let loaded;
      try { loaded = await value.secretLoader.loadTelegram({ expectedVersionId: value.expectedVersionId }); }
      catch { return response(503, 'unavailable'); }
      const secret = loaded?.secret;
      if (loaded?.metadata?.versionId !== value.expectedVersionId || !equalSecret(request.secretToken, secret?.webhookSecret)) {
        return response(401, 'denied');
      }
      let client;
      let identity;
      try {
        client = value.createClient(Object.freeze({ token: secret.token, botId: secret.botId,
          username: secret.username, botGeneration: secret.botGeneration }));
        identity = await client.getMe();
      } catch { return response(503, 'unavailable'); }
      if (identity?.verified !== true || identity.botId !== secret.botId || identity.username !== secret.username) {
        return response(503, 'unavailable');
      }
      let update;
      try { update = parseUpdate(request.body, nowSeconds()); }
      catch { return response(400, 'denied'); }
      try {
        const admitted = await value.ownerAuthority.admitPrivateChat({ ...update, botId: secret.botId,
          botGeneration: secret.botGeneration });
        if (!admitted || admitted.ownerEpoch !== 1) return response(503, 'unavailable');
        return response(200, 'accepted');
      } catch { return response(409, 'denied'); }
    }
  });
}
