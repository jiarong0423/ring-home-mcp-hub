import { createHmac, timingSafeEqual } from 'node:crypto';
import { types } from 'node:util';

const STATES = new Set(['completed', 'denied', 'expired', 'unknown']);
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const BYTE_LENGTH = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), 'byteLength').get;
export class CompletionStateError extends Error {
  constructor(code) { super(code); this.name = 'CompletionStateError'; this.code = code; }
}
function fail(code) { throw new CompletionStateError(code); }
function exact(value, keys, optional = []) {
  try {
    if (!value || typeof value !== 'object' || types.isProxy(value) || Array.isArray(value) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('completion_config');
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const ownKeys = Reflect.ownKeys(descriptors);
    if (keys.some(key => !Object.hasOwn(descriptors, key)) ||
        ownKeys.some(key => typeof key !== 'string' || ![...keys, ...optional].includes(key)) ||
        ownKeys.some(key => !Object.hasOwn(descriptors[key], 'value'))) fail('completion_config');
    return Object.fromEntries(ownKeys.map(key => [key, descriptors[key].value]));
  } catch { fail('completion_config'); }
}
function decode(value, minimum, maximum) {
  if (typeof value !== 'string' || !BASE64URL.test(value)) fail('completion_invalid');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length < minimum || bytes.length > maximum || bytes.toString('base64url') !== value) fail('completion_invalid');
  return bytes;
}
function normalizedHmacKey(value) {
  try {
    if (types.isProxy(value) || !types.isUint8Array(value)) fail('completion_config');
    const length = BYTE_LENGTH.call(value);
    if (length < 32 || length > 4096) fail('completion_config');
    const key = Buffer.alloc(length);
    Uint8Array.prototype.set.call(key, value);
    return key;
  } catch { fail('completion_config'); }
}
export function createCompletionStateCodec(options) {
  const values = exact(options, ['hmacKey', 'clock', 'random'], ['ttlSeconds']);
  const { clock, random } = values;
  const ttlSeconds = values.ttlSeconds ?? 120;
  if (typeof clock !== 'function' || types.isProxy(clock) || typeof random !== 'function' || types.isProxy(random) ||
      !Number.isSafeInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > 120) fail('completion_config');
  const key = normalizedHmacKey(values.hmacKey);
  let lastNow = -1;
  function now() {
    let value;
    try { value = clock(); } catch { fail('completion_clock'); }
    if (!Number.isSafeInteger(value) || value < 0) fail('completion_clock');
    if (value < lastNow) fail('completion_clock_rollback');
    lastNow = value;
    return value;
  }
  function mac(payload) { return createHmac('sha256', key).update('ring-completion-v1\0' + payload).digest(); }
  return Object.freeze({
    issue(state) {
      if (typeof state !== 'string' || !STATES.has(state)) fail('completion_state_invalid');
      const expiresAt = now() + ttlSeconds * 1000;
      if (!Number.isSafeInteger(expiresAt)) fail('completion_clock');
      let nonce;
      try {
        const bytes = random(32);
        if (types.isProxy(bytes) || !(Buffer.isBuffer(bytes) || bytes instanceof Uint8Array) || bytes.byteLength !== 32) fail('completion_random');
        nonce = Buffer.from(bytes).toString('base64url');
      } catch { fail('completion_random'); }
      const payload = Buffer.from(JSON.stringify({ version: 1, state, expiresAt, nonce })).toString('base64url');
      return payload + '.' + mac(payload).toString('base64url');
    },
    verify(ticket) {
      const current = now();
      if (typeof ticket !== 'string' || ticket.length < 1 || ticket.length > 1024) fail('completion_invalid');
      const parts = ticket.split('.');
      if (parts.length !== 2) fail('completion_invalid');
      const payloadBytes = decode(parts[0], 1, 512);
      const signature = decode(parts[1], 32, 32);
      if (!timingSafeEqual(mac(parts[0]), signature)) fail('completion_invalid');
      let source;
      let value;
      try {
        source = new TextDecoder('utf-8', { fatal: true }).decode(payloadBytes);
        value = exact(JSON.parse(source), ['version', 'state', 'expiresAt', 'nonce']);
      } catch { fail('completion_invalid'); }
      if (value.version !== 1 || typeof value.state !== 'string' || !STATES.has(value.state) ||
          !Number.isSafeInteger(value.expiresAt) || value.expiresAt < 1) fail('completion_invalid');
      decode(value.nonce, 32, 32);
      if (source !== JSON.stringify({ version: 1, state: value.state, expiresAt: value.expiresAt, nonce: value.nonce })) fail('completion_invalid');
      if (value.expiresAt <= current) fail('completion_expired');
      if (!Number.isSafeInteger(current + ttlSeconds * 1000) || value.expiresAt > current + ttlSeconds * 1000) fail('completion_invalid');
      // A ticket is an authenticated display value only. Verification grants no operation authority.
      return Object.freeze({ version: 1, state: value.state, expiresAt: value.expiresAt, nonce: value.nonce });
    }
  });
}
