import { openCredentialLease } from './credential-lease.mjs';
import { validateDurableBindingV2 } from '../wifi/durable-binding-v2.mjs';
import { exactObject, denyFormalRuntime, zeroBinary } from './protocol.mjs';

const PURPOSE = 'telegram-mcp-admission';
const HASH = /^[a-f0-9]{64}$/;

export function createCredentialOperatorPort({ leaseInputPort, currentBindingPort, bootEpoch,
  timeoutMs = 10_000, maxCapacity = 8 }) {
  if (!leaseInputPort || typeof leaseInputPort.requestLeaseInputs !== 'function' ||
      !currentBindingPort || typeof currentBindingPort.readCurrent !== 'function' ||
      !bootEpoch || typeof bootEpoch.digest !== 'string' || !HASH.test(bootEpoch.digest) ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000 ||
      !Number.isSafeInteger(maxCapacity) || maxCapacity < 1 || maxCapacity > 64) {
    denyFormalRuntime('B02_OPERATOR_CONFIG_DENIED');
  }
  const epoch = bootEpoch.digest;
  const slots = new Set();
  const work = new Set();
  let closed = false;

  function alive(slot) {
    if (closed || slot.cancelled || bootEpoch.digest !== epoch) denyFormalRuntime('B02_OPERATOR_CLOSED');
  }
  function track(promise) {
    const actual = Promise.resolve(promise);
    work.add(actual);
    actual.then(() => work.delete(actual), () => work.delete(actual));
    return actual;
  }
  async function current(slot) {
    alive(slot);
    const values = exactObject(await currentBindingPort.readCurrent(), ['binding', 'credentialRevision'],
      'B02_OPERATOR_BINDING_DENIED');
    alive(slot);
    const binding = validateDurableBindingV2(values.binding, { allowRevoked: false });
    if (!Number.isSafeInteger(values.credentialRevision) || values.credentialRevision < 1) {
      denyFormalRuntime('B02_OPERATOR_REVISION_DENIED');
    }
    return Object.freeze({ binding, credentialRevision: values.credentialRevision });
  }
  function same(left, right) {
    if (left.credentialRevision !== right.credentialRevision || JSON.stringify(left.binding) !== JSON.stringify(right.binding)) {
      denyFormalRuntime('B02_OPERATOR_BINDING_DRIFT');
    }
  }
  async function dispose(slot) {
    slot.cancelled = true;
    if (slot.lease && !slot.disposing) {
      slot.disposing = track(Promise.resolve().then(() => slot.lease.close()));
      await slot.disposing;
    }
    slot.finished = true;
    if (slot.pending === 0) slots.delete(slot);
  }
  async function bounded(actual, slot, cleanup = true) {
    let timer;
    const limit = new Promise((_, reject) => {
      timer = setTimeout(() => {
        slot.cancelled = true;
        if (cleanup) track(dispose(slot)).catch(() => {});
        reject(new Error('B02_OPERATOR_TIMEOUT'));
      }, timeoutMs);
    });
    try { return await Promise.race([actual, limit]); }
    finally { clearTimeout(timer); }
  }
  function run(slot, action) {
    slot.pending += 1;
    return track(Promise.resolve().then(action).finally(() => {
      slot.pending -= 1;
      if (slot.finished && slot.pending === 0) slots.delete(slot);
    }));
  }
  const port = {
    productionAdmitted: true,
    async openLease(input) {
      const fields = exactObject(input, ['purpose', 'bootEpoch'], 'B02_OPERATOR_INPUT_DENIED');
      if (fields.purpose !== PURPOSE || fields.bootEpoch !== epoch || closed || bootEpoch.digest !== epoch) {
        denyFormalRuntime('B02_OPERATOR_INPUT_DENIED');
      }
      if (slots.size >= maxCapacity) denyFormalRuntime('B02_OPERATOR_CAPACITY_DENIED');
      const slot = { cancelled: false, finished: false, pending: 0, lease: null, disposing: null };
      slots.add(slot);
      const actual = run(slot, async () => {
        let options;
        let submitted = null;
        try {
          const before = await current(slot);
          options = await leaseInputPort.requestLeaseInputs(Object.freeze({ purpose: PURPOSE, bootEpoch: epoch,
            binding: before.binding, expectedRevision: before.credentialRevision }));
          const descriptor = options && typeof options === 'object' ? Object.getOwnPropertyDescriptor(options, 'passphrase') : null;
          submitted = descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : null;
          alive(slot);
          const values = exactObject(options, ['encryptedDriver', 'passphrase', 'revisionFloor', 'expectedRevision', 'binding'],
            'B02_OPERATOR_LEASE_INPUT_DENIED');
          same(before, { binding: validateDurableBindingV2(values.binding, { allowRevoked: false }),
            credentialRevision: values.expectedRevision });
          slot.lease = await openCredentialLease(values);
          alive(slot);
          same(before, await current(slot));
          async function checkFloor() {
            const revision = await values.revisionFloor.read();
            alive(slot);
            if (!Number.isSafeInteger(revision) || revision < 0 || revision >= Number.MAX_SAFE_INTEGER ||
                before.credentialRevision < revision) denyFormalRuntime('B02_OPERATOR_REVISION_DENIED');
          }
          await checkFloor();
          const lease = {
            productionAdmitted: true,
            secretBufferBoundary: 'mutable-buffer-v1',
            async withToken(consumer) {
              if (typeof consumer !== 'function') denyFormalRuntime('B02_OPERATOR_CONSUMER_DENIED');
              alive(slot);
              if (slot.pending !== 0) denyFormalRuntime('B02_OPERATOR_BUSY');
              const consumed = run(slot, async () => {
                try {
                  same(before, await current(slot));
                  await checkFloor();
                  const result = await slot.lease.withToken(async token => {
                    alive(slot);
                    const value = await consumer(token);
                    alive(slot);
                    same(before, await current(slot));
                    await checkFloor();
                    return value;
                  });
                  alive(slot);
                  return result;
                } catch {
                  await dispose(slot);
                  denyFormalRuntime('B02_OPERATOR_CONSUMER_DENIED');
                }
              });
              try { return await bounded(consumed, slot); }
              catch { denyFormalRuntime('B02_OPERATOR_CONSUMER_DENIED'); }
            },
            async close() {
              try { await bounded(track(dispose(slot)), slot, false); }
              catch { return Object.freeze({ closed: true, zeroized: false, resourceReleased: false }); }
              return Object.freeze({ closed: true, zeroized: slot.lease.status().zeroized,
                resourceReleased: slot.pending === 0 });
            },
            status() {
              return Object.freeze({ ...slot.lease.status(), inFlight: slot.pending,
                resourceReleased: slot.finished && slot.pending === 0 });
            }
          };
          return Object.freeze(lease);
        } catch {
          zeroBinary(submitted);
          await dispose(slot);
          denyFormalRuntime('B02_OPERATOR_LEASE_DENIED');
        }
      });
      try { return await bounded(actual, slot); }
      catch { denyFormalRuntime('B02_OPERATOR_LEASE_DENIED'); }
    },
    async close() {
      closed = true;
      for (const slot of slots) track(dispose(slot)).catch(() => {});
      let timer;
      await Promise.race([Promise.allSettled([...work]), new Promise(resolve => { timer = setTimeout(resolve, timeoutMs); })]);
      clearTimeout(timer);
      return Object.freeze({ closed: true, inFlight: work.size, capacityHeld: slots.size,
        resourceReleased: work.size === 0 && slots.size === 0 });
    },
    status() { return Object.freeze({ closed, inFlight: work.size, capacityHeld: slots.size }); }
  };
  return Object.freeze(port);
}
