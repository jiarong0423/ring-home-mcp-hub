import { ProtocolError, requireOpaque, requireSigningKey, parseVerifiedWebhook } from './protocol.mjs';

const MAX_EVENT_AGE_MS = 300_000;
const MAX_FUTURE_SKEW_MS = 60_000;
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-](?:0\d|1[0-4]):[0-5]\d)$/;

function oneSignature(rawHeaders) {
  if (!Array.isArray(rawHeaders) || rawHeaders.length === 0 || rawHeaders.length > 128 || rawHeaders.length % 2 !== 0) {
    throw new ProtocolError('invalid_headers');
  }
  let signature = null;
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index];
    const value = rawHeaders[index + 1];
    if (typeof name !== 'string' || typeof value !== 'string') throw new ProtocolError('invalid_headers');
    if (name.toLowerCase() === 'x-signature') {
      if (signature !== null) throw new ProtocolError('duplicate_signature');
      signature = value;
    }
  }
  if (signature === null) throw new ProtocolError('missing_signature');
  return signature;
}

function eventTime(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new ProtocolError('invalid_event_time');
  return value;
}

function sentTime(value) {
  if (typeof value !== 'string' || !ISO_TIME.test(value)) throw new ProtocolError('invalid_event_time');
  const parsed = Date.parse(value);
  if (!Number.isSafeInteger(parsed)) throw new ProtocolError('invalid_event_time');
  return parsed;
}

function requireFresh(at, now) {
  if (at > now + MAX_FUTURE_SKEW_MS || now - at > MAX_EVENT_AGE_MS) {
    throw new ProtocolError('stale_event');
  }
}

export function createWebhookDeliveryAdapter({ signingKey, authorizeDevice, store, clock = () => Date.now() } = {}) {
  requireSigningKey(signingKey);
  if (typeof store?.acceptWebhook !== 'function' || typeof clock !== 'function' ||
      typeof authorizeDevice !== 'function') {
    throw new ProtocolError('adapter_config');
  }

  return Object.freeze({
    async receive({ rawBody, rawHeaders } = {}, { signal } = {}) {
      if (signal !== undefined && (typeof AbortSignal === 'undefined' || !(signal instanceof AbortSignal))) {
        throw new ProtocolError('adapter_config');
      }
      if (signal?.aborted) throw new ProtocolError('ledger_unavailable');
      const operation = signal === undefined ? undefined : { signal };
      const signature = oneSignature(rawHeaders);
      const verified = parseVerifiedWebhook(rawBody, signature, signingKey);
      const attributes = verified.payload.data?.attributes;
      const source = requireOpaque(attributes?.source, 256);
      if (verified.eventType !== 'motion_detected' || attributes?.source_type !== 'devices') {
        throw new ProtocolError('event_not_allowed');
      }
      const authorized = await authorizeDevice(verified.accountId, source, operation);
      if (authorized !== true) throw new ProtocolError('device_not_linked');
      const now = clock();
      if (!Number.isSafeInteger(now)) throw new ProtocolError('clock_unavailable');
      const sentAt = sentTime(verified.payload.meta.time);
      const occurredAt = eventTime(attributes.timestamp);
      try {
        requireFresh(sentAt, now);
        requireFresh(occurredAt, now);
      } catch (error) {
        if (!(error instanceof ProtocolError) || error.code !== 'stale_event' ||
            typeof store.lookupWebhook !== 'function') throw error;
        const known = await store.lookupWebhook(verified.requestId, verified.accountId, rawBody, operation);
        if (known?.duplicate !== true && known?.duplicate !== false) throw new ProtocolError('store_receipt_invalid');
        if (!known.duplicate) throw error;
        return Object.freeze({ status: 'accepted_delivery_only', duplicate: true, deviceObserved: false });
      }
      const accepted = await store.acceptWebhook(verified.requestId, verified.accountId, rawBody, operation);
      if (accepted?.duplicate !== true && accepted?.duplicate !== false) {
        throw new ProtocolError('store_receipt_invalid');
      }
      return Object.freeze({ status: 'accepted_delivery_only', duplicate: accepted.duplicate, deviceObserved: false });
    }
  });
}
