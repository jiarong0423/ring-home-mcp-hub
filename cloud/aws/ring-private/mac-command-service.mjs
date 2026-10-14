import { randomBytes as cryptoRandomBytes } from 'node:crypto';
import { COMMAND_ID, COMMAND_TTL_MS, command, commandId, envelope, receipt, hash, port, record, time, text, deny, freeze } from '../../../src/formal-runtime/mac-command-contract.mjs';

export function createMacCommandService({ store, authorize, macProofAuthority, clock = Date.now, randomBytes = cryptoRandomBytes } = {}) {
  const data = port(store, ['enqueue', 'claim', 'complete', 'read']);
  const proof = port(macProofAuthority, ['verify']);
  if (typeof authorize !== 'function' || typeof clock !== 'function' || typeof randomBytes !== 'function') deny('MAC_COMMAND_SERVICE_CONFIG');
  async function authority(operation, request, actor, e) {
    const a = record(await authorize({ operation, request, actor, ...(e ? { envelope: e } : {}) }),
      ['ownerRef', 'associationRevision', 'sessionRef', 'expiresAt', 'assertCurrent'], 'MAC_COMMAND_AUTHORITY');
    text(a.ownerRef); text(a.sessionRef); time(a.expiresAt);
    const now = time(clock());
    if (!Number.isSafeInteger(a.associationRevision) || a.associationRevision < 1 || typeof a.assertCurrent !== 'function' ||
        a.expiresAt <= now || a.expiresAt > now + 300_000) deny('MAC_COMMAND_AUTHORITY');
    const assert = () => { if (time(clock()) >= a.expiresAt || a.assertCurrent() !== true) deny('MAC_COMMAND_AUTHORITY_REVOKED'); };
    assert(); return { ...a, assert };
  }
  function publicResult(value, a) {
    if (!value) deny('MAC_COMMAND_NOT_FOUND');
    const c = command(value.command);
    if (c.ownerRef !== a.ownerRef || c.associationRevision !== a.associationRevision) deny('MAC_COMMAND_OWNER');
    const status = value.state === 'SUCCEEDED' ? 'SUCCEEDED' : time(clock()) >= c.expiresAt ?
      value.state === 'CLAIMED' ? 'UNKNOWN' : 'EXPIRED' : 'PENDING';
    return freeze({ commandId: c.commandId, status, executed: status === 'SUCCEEDED', result: status === 'SUCCEEDED' ? value.result.result : null });
  }
  return Object.freeze({
    async submit({ request, actor, envelope: input }) {
      const e = envelope(input); const a = await authority('submit', request, actor, input); const now = time(clock());
      const c = command({ schema: 'ring-mac-command-v1', commandId: commandId(a.ownerRef, a.sessionRef, e.id), ownerRef: a.ownerRef,
        associationRevision: a.associationRevision, sessionRef: a.sessionRef, sessionExpiresAt: a.expiresAt,
        issuedAt: now, expiresAt: Math.min(now + COMMAND_TTL_MS, a.expiresAt), envelope: e, envelopeSha256: hash(JSON.stringify(e)) });
      a.assert(); const value = await data.enqueue(c); a.assert(); return publicResult(value, a);
    },
    async fetch({ request, actor }) {
      const a = await authority('fetch', request, actor);
      const mac = await proof.verify({ request, authority: a, operation: 'fetch', payload: {} }); a.assert();
      const bytes = randomBytes(32);
      if (!Buffer.isBuffer(bytes) || bytes.length !== 32) deny('MAC_COMMAND_RANDOM');
      const claimToken = bytes.toString('base64url'); a.assert();
      const value = await data.claim({ ownerRef: a.ownerRef, associationRevision: a.associationRevision, claimToken, mac });
      a.assert(); if (!value) return freeze({ status: 'EMPTY' });
      const c = command(value);
      if (c.ownerRef !== a.ownerRef || c.associationRevision !== a.associationRevision || time(clock()) >= c.expiresAt) deny('MAC_COMMAND_OWNER');
      return freeze({ status: 'CLAIMED', command: c, claimToken });
    },
    async receipt({ request, actor, receipt: input }) {
      const r = receipt(input); const a = await authority('receipt', request, actor); a.assert();
      const mac = await proof.verify({ request, authority: a, operation: 'receipt', payload: r }); a.assert();
      const value = await data.complete({ ownerRef: a.ownerRef, associationRevision: a.associationRevision, value: r, mac });
      a.assert(); return freeze({ commandId: r.commandId, status: 'SUCCEEDED', executed: true, result: value.result });
    },
    async read({ request, actor, commandId: id }) {
      if (typeof id !== 'string' || !COMMAND_ID.test(id)) deny('MAC_COMMAND_ID');
      const a = await authority('read', request, actor); a.assert();
      const value = await data.read({ ownerRef: a.ownerRef, commandId: id }); a.assert(); return publicResult(value, a);
    }
  });
}
