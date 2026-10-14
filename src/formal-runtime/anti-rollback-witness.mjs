import { deepFreeze, denyFormalRuntime, exactObject, safeHash, safeRevision, safeLabel } from './protocol.mjs';

const KEYS = Object.freeze([
  'bindingRevision', 'bindingHash', 'cursorRevision', 'cursorHash', 'journalRevision', 'journalHash'
]);

export function validateWitnessCommitment(value) {
  const fields = exactObject(value, KEYS, 'B02_FORMAL_WITNESS_COMMITMENT_DENIED');
  return deepFreeze({
    bindingRevision: safeRevision(fields.bindingRevision), bindingHash: safeHash(fields.bindingHash),
    cursorRevision: safeRevision(fields.cursorRevision), cursorHash: safeHash(fields.cursorHash),
    journalRevision: safeRevision(fields.journalRevision), journalHash: safeHash(fields.journalHash)
  });
}

export function createAntiRollbackWitnessGate(port) {
  if (!port || port.productionAdmitted !== true || typeof port.readCurrent !== 'function' ||
      typeof port.compareAndAdvance !== 'function' || typeof port.confirm !== 'function' ||
      typeof port.close !== 'function') denyFormalRuntime('B02_FORMAL_WITNESS_PORT_DENIED');
  let closed = false;
  async function readCurrent() {
    if (closed) denyFormalRuntime('B02_FORMAL_WITNESS_CLOSED');
    return validateWitnessCommitment(await port.readCurrent());
  }
  async function compareAndAdvance({ expectedCommitment, nextCommitment, transactionId }) {
    if (closed) denyFormalRuntime('B02_FORMAL_WITNESS_CLOSED');
    const result = await port.compareAndAdvance({
      expectedCommitment: validateWitnessCommitment(expectedCommitment),
      nextCommitment: validateWitnessCommitment(nextCommitment),
      transactionId: safeLabel(transactionId, 'B02_FORMAL_WITNESS_TRANSACTION_DENIED')
    });
    if (result?.advanced !== true) denyFormalRuntime('B02_FORMAL_WITNESS_ADVANCE_DENIED');
    return Object.freeze({ advanced: true });
  }
  async function confirm({ commitment, transactionId }) {
    if (closed) denyFormalRuntime('B02_FORMAL_WITNESS_CLOSED');
    const result = await port.confirm({ commitment: validateWitnessCommitment(commitment),
      transactionId: safeLabel(transactionId, 'B02_FORMAL_WITNESS_TRANSACTION_DENIED') });
    if (result?.confirmed !== true) denyFormalRuntime('B02_FORMAL_WITNESS_CONFIRM_DENIED');
    return Object.freeze({ confirmed: true });
  }
  async function close() { if (!closed) { closed = true; await port.close(); } return Object.freeze({ closed: true }); }
  return Object.freeze({ productionAdmitted: true, readCurrent, compareAndAdvance, confirm, close });
}

export function witnessCommitmentEquals(left, right) {
  const a = validateWitnessCommitment(left); const b = validateWitnessCommitment(right);
  return KEYS.every((key) => a[key] === b[key]);
}

export const antiRollbackWitnessConstants = Object.freeze({ keys: KEYS });
