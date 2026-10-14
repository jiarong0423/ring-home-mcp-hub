import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

const MAX_BODY_BYTES = 16_384;
const MAX_IDENTIFIER_LENGTH = 256;
const MAX_TIME_LENGTH = 64;
const SIGNATURE_PATTERN = /^sha256=([0-9a-fA-F]{64})$/;
const ISO_TIME_PATTERN = /^(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?(?:Z|[+-](?:0\d|1[0-4]):[0-5]\d)$/;

class RingEventError extends Error {
  constructor(code, status) {
    super(code);
    this.name = 'RingEventError';
    this.code = code;
    this.status = status;
  }
}

function requireRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new RingEventError('RING_PAYLOAD_INVALID', 400);
  }
  return value;
}

function requireString(value, maxLength = MAX_IDENTIFIER_LENGTH) {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > maxLength ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new RingEventError('RING_PAYLOAD_INVALID', 400);
  }
  return value;
}

function parseSentAt(value) {
  const sentAt = requireString(value, MAX_TIME_LENGTH);
  const match = ISO_TIME_PATTERN.exec(sentAt);
  if (match === null) {
    throw new RingEventError('RING_PAYLOAD_INVALID', 400);
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const calendarDate = new Date(0);
  calendarDate.setUTCFullYear(year, month - 1, day);
  if (
    calendarDate.getUTCFullYear() !== year ||
    calendarDate.getUTCMonth() !== month - 1 ||
    calendarDate.getUTCDate() !== day
  ) {
    throw new RingEventError('RING_PAYLOAD_INVALID', 400);
  }
  const sentAtMs = Date.parse(sentAt);
  if (!Number.isSafeInteger(sentAtMs)) {
    throw new RingEventError('RING_PAYLOAD_INVALID', 400);
  }
  return sentAtMs;
}

function parseEventAt(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RingEventError('RING_PAYLOAD_INVALID', 400);
  }
  return value;
}

export function verifyAndNormalizeRingEvent({ rawBody, signature, secret } = {}) {
  if (typeof secret !== 'string' || secret.length === 0) {
    throw new RingEventError('RING_SECRET_UNAVAILABLE', 503);
  }
  if (!(rawBody instanceof Uint8Array)) {
    throw new RingEventError('RING_PAYLOAD_INVALID', 400);
  }
  if (rawBody.byteLength > MAX_BODY_BYTES) {
    throw new RingEventError('RING_BODY_TOO_LARGE', 413);
  }

  const bytes = Buffer.from(rawBody);
  const match = typeof signature === 'string' ? SIGNATURE_PATTERN.exec(signature) : null;
  if (match === null) {
    throw new RingEventError('RING_SIGNATURE_INVALID', 401);
  }
  const received = Buffer.from(match[1], 'hex');
  const expected = createHmac('sha256', secret).update(bytes).digest();
  if (!timingSafeEqual(expected, received)) {
    throw new RingEventError('RING_SIGNATURE_INVALID', 401);
  }

  let payload;
  try {
    payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new RingEventError('RING_PAYLOAD_INVALID', 400);
  }

  const root = requireRecord(payload);
  const meta = requireRecord(root.meta);
  const data = requireRecord(root.data);
  const attributes = requireRecord(data.attributes);
  const version = requireString(meta.version, 16);
  if (version !== '1.1') {
    throw new RingEventError('RING_PAYLOAD_INVALID', 400);
  }

  return {
    version,
    sentAtMs: parseSentAt(meta.time),
    requestId: requireString(meta.request_id),
    accountId: requireString(meta.account_id),
    eventId: requireString(data.id),
    eventType: requireString(data.type),
    sourceId: requireString(attributes.source),
    sourceType: requireString(attributes.source_type),
    eventAtMs: parseEventAt(attributes.timestamp),
    bodyDigest: createHash('sha256').update(bytes).digest('hex'),
  };
}
