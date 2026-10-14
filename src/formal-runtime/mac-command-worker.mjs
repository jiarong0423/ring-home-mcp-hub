import { command, receipt, commandResult, resultMatches, port, record, time, text, deny, freeze } from './mac-command-contract.mjs';

export function createMacCommandWorker({ transport, authorizeCommand, dispatchFormal, journal, clock = Date.now } = {}) {
  const wire = port(transport, ['fetch', 'receipt']); const local = port(journal, ['claim', 'complete', 'readReceipt', 'readCommand']);
  if (typeof authorizeCommand !== 'function' || typeof dispatchFormal !== 'function' || typeof clock !== 'function') deny('MAC_WORKER_CONFIG');
  let running = false;
  async function authority(c) {
    if (time(clock()) >= c.expiresAt) deny('MAC_COMMAND_EXPIRED');
    if (time(clock()) < c.issuedAt) deny('MAC_COMMAND_CLOCK');   // Mac clock behind the cloud: refuse before any side effect
    const a = record(await authorizeCommand(c), ['ownerRef', 'associationRevision', 'assertCurrent']);
    text(a.ownerRef);
    const check = () => {
      if (time(clock()) >= c.expiresAt || a.ownerRef !== c.ownerRef || a.associationRevision !== c.associationRevision ||
          typeof a.assertCurrent !== 'function' || a.assertCurrent() !== true) deny('MAC_WORKER_AUTHORITY');
    };
    check(); return check;
  }
  function acknowledgement(value, r) {
    const a = record(value, ['commandId', 'status', 'executed', 'result']);
    if (a.commandId !== r.commandId || a.status !== 'SUCCEEDED' || a.executed !== true || JSON.stringify(commandResult(a.result)) !== JSON.stringify(r.result)) deny('MAC_WORKER_ACK');
    return freeze(a);
  }
  async function exclusive(fn) {
    if (running) deny('MAC_WORKER_BUSY'); running = true;
    try { return await fn(); } finally { running = false; }
  }
  return Object.freeze({
    runOnce() { return exclusive(async () => {
      const fetched = await wire.fetch();
      if (fetched?.status === 'EMPTY') { record(fetched, ['status']); return freeze({ status: 'EMPTY', executed: false }); }
      const entry = record(fetched, ['status', 'command', 'claimToken']);
      if (entry.status !== 'CLAIMED') deny('MAC_WORKER_RESPONSE');
      const c = command(entry.command);
      if (typeof entry.claimToken !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(entry.claimToken) || Buffer.from(entry.claimToken, 'base64url').toString('base64url') !== entry.claimToken) deny('MAC_WORKER_CLAIM');
      const check = await authority(c);
      if (!await local.claim(c)) return freeze({ commandId: c.commandId, status: 'UNKNOWN', executed: false });
      check();
      let result;
      try {
        // The integrating owner must call the existing grant issue/consume dispatcher here.
        // This worker has no capability adapter reference and cannot bypass that dispatcher.
        const response = await dispatchFormal({ command: c, envelope: c.envelope });
        const rpc = record(response, ['jsonrpc', 'id', 'result']);
        if (rpc.jsonrpc !== '2.0' || rpc.id !== c.envelope.id) deny('MAC_WORKER_RESPONSE');
        result = commandResult(rpc.result);
        if (!resultMatches(result, c.envelope) || result.observedAt < c.issuedAt || result.observedAt >= c.expiresAt) deny('MAC_WORKER_RESPONSE');
        check();
      } catch { return freeze({ commandId: c.commandId, status: 'UNKNOWN', executed: false }); }
      const r = receipt({ schema: 'ring-mac-receipt-v1', commandId: c.commandId, envelopeSha256: c.envelopeSha256,
        claimToken: entry.claimToken, status: 'SUCCEEDED', result });
      await local.complete(r); check();
      try { const accepted = acknowledgement(await wire.receipt(r), r); check(); return accepted; }
      catch { return freeze({ commandId: c.commandId, status: 'RECEIPT_PENDING', executed: false }); }
    }); },
    retryReceipt(commandId) { return exclusive(async () => {
      const c = await local.readCommand(commandId); const r = await local.readReceipt(commandId);
      if (!c || !r) deny('MAC_JOURNAL_NO_RECEIPT');
      const check = await authority(command(c)); check();
      const accepted = acknowledgement(await wire.receipt(receipt(r)), r); check(); return accepted;
    }); }
  });
}
