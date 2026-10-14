import { denyFormalRuntime, exactObject, safeLabel } from './protocol.mjs';

const METHODS = Object.freeze(['openRootNoFollow', 'readAt', 'createTempAt', 'renameAt', 'unlinkAt',
  'statAt', 'fsyncFile', 'fsyncDirectory', 'close']);

export function createDescriptorStateIoPort(port) {
  if (!port || port.productionAdmitted !== true || port.descriptorRelative !== true ||
      METHODS.some((name) => typeof port[name] !== 'function')) denyFormalRuntime('B02_FORMAL_DESCRIPTOR_IO_DENIED');
  return Object.freeze(Object.fromEntries([
    ['productionAdmitted', true], ['descriptorRelative', true],
    ...METHODS.map((name) => [name, port[name].bind(port)])
  ]));
}

export async function acquireFormalStateTransactionLock({ lockPort, ownerNonce, purpose }) {
  if (!lockPort || lockPort.productionAdmitted !== true || typeof lockPort.acquireExclusive !== 'function' ||
      typeof lockPort.releaseOwned !== 'function') denyFormalRuntime('B02_FORMAL_LOCK_PORT_DENIED');
  const nonce = safeLabel(ownerNonce, 'B02_FORMAL_LOCK_NONCE_DENIED');
  const label = safeLabel(purpose, 'B02_FORMAL_LOCK_PURPOSE_DENIED');
  const acquired = await lockPort.acquireExclusive({ ownerNonce: nonce, purpose: label });
  if (acquired?.acquired !== true || acquired.ownerNonce !== nonce) denyFormalRuntime('B02_FORMAL_LOCK_BUSY');
  let released = false;
  return Object.freeze({
    ownerNonce: nonce,
    async release() {
      if (released) return Object.freeze({ released: true });
      const result = await lockPort.releaseOwned({ ownerNonce: nonce });
      if (result?.released !== true) denyFormalRuntime('B02_FORMAL_LOCK_RELEASE_DENIED');
      released = true;
      return Object.freeze({ released: true });
    }
  });
}

export async function withFormalStateTransaction(input, operation) {
  const fields = exactObject(input, ['lockPort', 'ownerNonce', 'purpose'], 'B02_FORMAL_TRANSACTION_INPUT_DENIED');
  if (typeof operation !== 'function') denyFormalRuntime('B02_FORMAL_TRANSACTION_INPUT_DENIED');
  const lock = await acquireFormalStateTransactionLock(fields);
  try { return await operation(lock); } finally { await lock.release(); }
}

export const privateStateTransactionConstants = Object.freeze({ requiredDescriptorMethods: METHODS });
