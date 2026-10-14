import { ProtocolError, requireSigningKey } from './protocol.mjs';
import { parseRestApiWebhookEvent } from './api-gateway-event.mjs';
import { createWebhookDeliveryAdapter } from './webhook-adapter.mjs';

function reply(statusCode, status) {
  return {
    statusCode,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff'
    },
    body: JSON.stringify({ status })
  };
}

function failure(error) {
  if (!(error instanceof ProtocolError)) return reply(503, 'unavailable');
  if (error.code === 'invalid_signature' || error.code === 'missing_signature' ||
      error.code === 'missing_x_signature') {
    return reply(401, 'invalid_delivery');
  }
  if (error.code === 'device_not_linked' || error.code === 'event_not_allowed') {
    return reply(403, 'delivery_not_allowed');
  }
  if (error.code === 'event_conflict' || error.code === 'ledger_conflict') {
    return reply(409, 'delivery_conflict');
  }
  if (error.code === 'ledger_unavailable' || error.code === 'ledger_clock' ||
      error.code === 'linked_devices_config' || error.code === 'adapter_config' ||
      error.code === 'store_receipt_invalid' || error.code === 'linked_store_unavailable' ||
      error.code === 'linked_record_invalid' || error.code === 'linked_clock_unavailable') {
    return reply(503, 'unavailable');
  }
  return reply(400, 'invalid_delivery');
}

export function createWebhookHttpHandler({ signingKey, isLinkedDevice, ledger, clock = () => Date.now() } = {}) {
  requireSigningKey(signingKey);
  if (typeof isLinkedDevice !== 'function' || typeof ledger?.acceptWebhook !== 'function' ||
      typeof clock !== 'function') {
    throw new ProtocolError('handler_config');
  }
  const adapter = createWebhookDeliveryAdapter({
    signingKey, authorizeDevice: isLinkedDevice, store: ledger, clock
  });

  return async function handleWebhook(event, { signal } = {}) {
    if (event?.path !== '/ring/webhook' || event?.resource !== '/ring/webhook') {
      return reply(404, 'not_found');
    }
    let delivery;
    try {
      delivery = parseRestApiWebhookEvent(event);
      await adapter.receive(delivery, { signal });
      return reply(200, 'accepted_delivery_only');
    } catch (error) {
      return failure(error);
    }
  };
}
