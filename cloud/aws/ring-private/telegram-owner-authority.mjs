import { randomBytes, randomUUID } from 'node:crypto';
import { types } from 'node:util';

const DIGEST = /^[0-9a-f]{64}$/;

export class TelegramOwnerAuthorityError extends Error {
  constructor(code) { super(code); this.name = 'TelegramOwnerAuthorityError'; this.code = code; }
}
function deny(code) { throw new TelegramOwnerAuthorityError(code); }
function authorityError(error) {
  try { return !types.isProxy(error) && error instanceof TelegramOwnerAuthorityError; }
  catch { return false; }
}
function exact(value, fields) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny('TG_AUTHORITY_INPUT_DENIED');
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== fields.length || fields.some(field => !Object.hasOwn(descriptors, field)) ||
        keys.some(key => typeof key !== 'string' || !fields.includes(key) || !Object.hasOwn(descriptors[key], 'value'))) {
      deny('TG_AUTHORITY_INPUT_DENIED');
    }
    return Object.fromEntries(fields.map(field => [field, descriptors[field].value]));
  } catch (error) {
    if (authorityError(error)) throw error;
    deny('TG_AUTHORITY_INPUT_DENIED');
  }
}
function integerId(value) {
  const text = typeof value === 'number' && Number.isSafeInteger(value) ? String(value) : value;
  if (typeof text !== 'string' || !/^-?[1-9][0-9]{0,19}$/.test(text)) deny('TG_AUTHORITY_INPUT_DENIED');
  return text;
}
function opaque(value) {
  if (typeof value !== 'string' || value.length < 8 || value.length > 256 || /[\x00-\x20\x7f]/.test(value)) deny('TG_AUTHORITY_CONFIG');
  return value;
}

export function createTelegramOwnerAuthority(options) {
  const value = exact(options, ['store', 'digest', 'clock', 'createNonce', 'createRef']);
  if (!value.store || typeof value.store.createEnrollment !== 'function' || typeof value.store.admitOwner !== 'function' ||
      typeof value.digest !== 'function' || types.isProxy(value.digest) || typeof value.clock !== 'function' ||
      typeof value.createNonce !== 'function' || typeof value.createRef !== 'function') deny('TG_AUTHORITY_CONFIG');
  async function hashed(purpose, raw) {
    try {
      const result = await value.digest(purpose, raw);
      if (typeof result !== 'string' || !DIGEST.test(result)) deny('TG_AUTHORITY_UNAVAILABLE');
      return result;
    } catch (error) {
      if (authorityError(error)) throw error;
      deny('TG_AUTHORITY_UNAVAILABLE');
    }
  }
  function nowSeconds() {
    try {
      const now = value.clock();
      if (!Number.isSafeInteger(now) || now < 0) deny('TG_AUTHORITY_UNAVAILABLE');
      return Math.floor(now / 1000);
    } catch (error) {
      if (authorityError(error)) throw error;
      deny('TG_AUTHORITY_UNAVAILABLE');
    }
  }
  function minted(prefix) {
    try { return opaque(value.createRef(prefix)); } catch { deny('TG_AUTHORITY_UNAVAILABLE'); }
  }
  return Object.freeze({
    async createEnrollment(input) {
      const data = exact(input, ['botId', 'botGeneration']);
      const botId = integerId(data.botId);
      if (!Number.isSafeInteger(data.botGeneration) || data.botGeneration < 1) deny('TG_AUTHORITY_INPUT_DENIED');
      let nonce;
      try { nonce = value.createNonce(); } catch { deny('TG_AUTHORITY_UNAVAILABLE'); }
      if (typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(nonce)) deny('TG_AUTHORITY_UNAVAILABLE');
      try {
        const expiresAt = nowSeconds() + 300;
        await value.store.createEnrollment({ nonceDigest: await hashed('enrollment-nonce', nonce),
          botDigest: await hashed('telegram-bot', botId), botGeneration: data.botGeneration,
          enrollmentId: minted('enroll'), expiresAt });
        return Object.freeze({ enrollmentNonce: nonce, expiresAt });
      } catch (error) {
        if (authorityError(error)) throw error;
        deny('TG_AUTHORITY_UNAVAILABLE');
      }
    },
    async admitPrivateChat(input) {
      const data = exact(input, ['enrollmentNonce', 'updateId', 'botId', 'botGeneration', 'chatType', 'chatId', 'userId']);
      if (typeof data.enrollmentNonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(data.enrollmentNonce) ||
          data.chatType !== 'private' || !Number.isSafeInteger(data.botGeneration) || data.botGeneration < 1) {
        deny('TG_AUTHORITY_ADMISSION_DENIED');
      }
      const updateId = integerId(data.updateId);
      const botId = integerId(data.botId);
      const chatId = integerId(data.chatId);
      const userId = integerId(data.userId);
      if (chatId !== userId) deny('TG_AUTHORITY_ADMISSION_DENIED');
      try {
        return Object.freeze(await value.store.admitOwner({
          nonceDigest: await hashed('enrollment-nonce', data.enrollmentNonce),
          updateDigest: await hashed('telegram-update', updateId), botDigest: await hashed('telegram-bot', botId),
          botGeneration: data.botGeneration, actorDigest: await hashed('telegram-actor', userId),
          chatDigest: await hashed('telegram-chat', chatId), actorRef: minted('actor'),
          ownerRef: minted('owner'), householdRef: minted('household')
        }));
      } catch (error) {
        if (authorityError(error)) throw error;
        deny('TG_AUTHORITY_ADMISSION_DENIED');
      }
    }
  });
}

export function defaultTelegramOwnerAuthorityRandom() {
  return Object.freeze({ createNonce: () => randomBytes(32).toString('base64url'), createRef: prefix => `${prefix}/${randomUUID()}` });
}
