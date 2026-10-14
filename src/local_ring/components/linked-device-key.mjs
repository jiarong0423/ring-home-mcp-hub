import { createHmac } from 'node:crypto';
import { ProtocolError, requireOpaque } from './protocol.mjs';

export function requireLinkedHashKey(hashKey) {
  if (!(typeof hashKey === 'string' || Buffer.isBuffer(hashKey)) ||
      Buffer.byteLength(hashKey) < 32 || Buffer.byteLength(hashKey) > 4096) {
    throw new ProtocolError('linked_hash_key_config');
  }
  return Buffer.from(hashKey);
}

export function deriveLinkedDeviceKey(accountId, deviceId, hashKey) {
  requireOpaque(accountId, 256);
  requireOpaque(deviceId, 256);
  const digestKey = requireLinkedHashKey(hashKey);
  return createHmac('sha256', digestKey)
    .update('ring-linked-device\0', 'utf8')
    .update(JSON.stringify([accountId, deviceId]), 'utf8')
    .digest('hex');
}

export function deriveLinkedEvidenceDigest(domain, value, hashKey) {
  requireOpaque(domain, 64);
  requireOpaque(value, 256);
  const digestKey = requireLinkedHashKey(hashKey);
  return createHmac('sha256', digestKey)
    .update(`ring-link-evidence:${domain}\0`, 'utf8')
    .update(value, 'utf8')
    .digest('hex');
}
