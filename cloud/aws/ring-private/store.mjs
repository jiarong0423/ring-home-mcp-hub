import { randomUUID, createHash } from 'node:crypto';
import { ProtocolError, requireOpaque } from './protocol.mjs';

export class MemoryRingStore {
  #tokens = new Map();
  #events = new Map();

  constructor({ clock = () => Date.now() } = {}) {
    this.clock = clock;
  }

  async putUnclaimed(record) {
    requireOpaque(record?.accountId, 256);
    requireOpaque(record?.accessToken, 8192);
    requireOpaque(record?.refreshToken, 8192);
    if (!Number.isSafeInteger(record.expiresAt) || record.expiresAt <= this.clock()) throw new ProtocolError('token_expired');
    const id = randomUUID();
    this.#tokens.set(id, { ...record, id, status: 'unclaimed' });
    return id;
  }

  async listUnclaimed(now = Date.now()) {
    const records = [...this.#tokens.values()].filter(record => record.status === 'unclaimed' && record.expiresAt > now);
    if (records.length > 100) throw new ProtocolError('unclaimed_limit');
    return records.map(record => ({ ...record }));
  }

  async reserveClaim(id, actorId, now = Date.now()) {
    requireOpaque(id, 64);
    requireOpaque(actorId, 256);
    const record = this.#tokens.get(id);
    if (!record || record.status !== 'unclaimed' || record.expiresAt <= now) throw new ProtocolError('claim_conflict');
    record.status = 'reserved';
    record.actorId = actorId;
    return { ...record };
  }

  async advanceClaim(id, actorId, expected, next) {
    const record = this.#tokens.get(id);
    if (!record || record.actorId !== actorId || record.status !== expected ||
        !((expected === 'reserved' && next === 'awaiting') ||
          (expected === 'awaiting' && next === 'completed'))) {
      throw new ProtocolError('claim_conflict');
    }
    record.status = next;
    return { id, status: next };
  }

  async acceptWebhook(requestId, accountId, rawBody) {
    requireOpaque(requestId, 256);
    requireOpaque(accountId, 256);
    if (!Buffer.isBuffer(rawBody)) throw new ProtocolError('invalid_webhook');
    const hash = createHash('sha256').update(rawBody).digest('hex');
    const existing = this.#events.get(requestId);
    if (existing) {
      if (existing.hash !== hash || existing.accountId !== accountId) throw new ProtocolError('event_conflict');
      return { duplicate: true };
    }
    this.#events.set(requestId, { hash, accountId });
    return { duplicate: false };
  }

  async lookupWebhook(requestId, accountId, rawBody) {
    requireOpaque(requestId, 256);
    requireOpaque(accountId, 256);
    if (!Buffer.isBuffer(rawBody)) throw new ProtocolError('invalid_webhook');
    const existing = this.#events.get(requestId);
    if (!existing) return { duplicate: false };
    const hash = createHash('sha256').update(rawBody).digest('hex');
    if (existing.hash !== hash || existing.accountId !== accountId) throw new ProtocolError('event_conflict');
    return { duplicate: true };
  }

  getSummary() {
    return { tokens: this.#tokens.size, events: this.#events.size };
  }
}

export class AwsRingStoreBlocked {
  constructor() {
    this.reason = 'AWS KMS encryption, DynamoDB conditional transactions, IAM and TTL have not passed review';
  }

  async putUnclaimed() { throw new ProtocolError('aws_store_not_ready'); }
  async listUnclaimed() { throw new ProtocolError('aws_store_not_ready'); }
  async reserveClaim() { throw new ProtocolError('aws_store_not_ready'); }
  async advanceClaim() { throw new ProtocolError('aws_store_not_ready'); }
  async acceptWebhook() { throw new ProtocolError('aws_store_not_ready'); }
}
