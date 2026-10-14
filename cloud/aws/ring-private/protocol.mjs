import { createHmac, timingSafeEqual } from 'node:crypto';

export class ProtocolError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ProtocolError';
    this.code = code;
  }
}

function opaque(value, max = 4096) {
  return typeof value === 'string' && value.length > 0 && value.length <= max && !/[\x00-\x1f\x7f]/.test(value);
}

export function requireOpaque(value, max = 4096) {
  if (!opaque(value, max)) throw new ProtocolError('invalid_field');
  return value;
}

export function requireSigningKey(value) {
  requireOpaque(value, 4096);
  if (Buffer.byteLength(value, 'utf8') < 32) throw new ProtocolError('signing_key_config');
  return value;
}

export function validateLinkQuery(time, nonce, now = Date.now()) {
  if (typeof time !== 'string' || !/^(0|[1-9][0-9]{0,15})$/.test(time)) throw new ProtocolError('invalid_time');
  if (typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(nonce)) throw new ProtocolError('invalid_nonce');
  const at = Number(time);
  if (!Number.isSafeInteger(at) || !Number.isFinite(now) || at > now || now - at > 600_000) {
    throw new ProtocolError('expired_link');
  }
  return { time, nonce };
}

export function computeNonce(time, accountId, signingKey) {
  requireOpaque(time, 16);
  requireOpaque(accountId, 256);
  requireSigningKey(signingKey);
  return createHmac('sha256', signingKey).update(`${time}:${accountId}`, 'utf8').digest('base64url');
}

export function matchUnclaimedNonce(query, records, signingKey, now = Date.now()) {
  const { time, nonce } = validateLinkQuery(query.time, query.nonce, now);
  if (!Array.isArray(records) || records.length > 100) throw new ProtocolError('unclaimed_limit');
  const received = Buffer.from(nonce, 'ascii');
  let match = null;
  for (const record of records) {
    if (!record || record.status !== 'unclaimed' || !opaque(record.accountId, 256)) continue;
    const expected = Buffer.from(computeNonce(time, record.accountId, signingKey), 'ascii');
    if (timingSafeEqual(expected, received)) {
      if (match) throw new ProtocolError('ambiguous_link');
      match = record;
    }
  }
  if (!match) throw new ProtocolError('link_not_found');
  return match;
}

export function verifyWebhookSignature(rawBody, signature, signingKey) {
  if (!Buffer.isBuffer(rawBody) || rawBody.length === 0 || rawBody.length > 65_536) return false;
  if (typeof signature !== 'string' || !/^sha256=[a-fA-F0-9]{64}$/.test(signature)) return false;
  if (!opaque(signingKey, 4096) || Buffer.byteLength(signingKey, 'utf8') < 32) return false;
  const received = Buffer.from(signature.slice(7), 'hex');
  const expected = createHmac('sha256', signingKey).update(rawBody).digest();
  return timingSafeEqual(expected, received);
}

export function parseVerifiedWebhook(rawBody, signature, signingKey) {
  if (!verifyWebhookSignature(rawBody, signature, signingKey)) throw new ProtocolError('invalid_signature');
  let payload;
  try {
    payload = JSON.parse(rawBody.toString('utf8'));
  } catch {
    throw new ProtocolError('invalid_webhook');
  }
  const meta = payload?.meta;
  const data = payload?.data;
  if (meta?.version !== '1.1' || !opaque(meta?.request_id, 256) || !opaque(meta?.account_id, 256) ||
      !opaque(meta?.time, 64) || !Number.isFinite(Date.parse(meta.time)) ||
      !opaque(data?.id, 512) || !opaque(data?.type, 100)) {
    throw new ProtocolError('invalid_webhook');
  }
  return { requestId: meta.request_id, accountId: meta.account_id, eventType: data.type, eventId: data.id, payload };
}
