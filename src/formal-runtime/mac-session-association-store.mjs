import { types } from 'node:util';
import { createHash } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { validateDurableBindingV2 } from '../wifi/durable-binding-v2.mjs';
import { isFormalStateDescriptorSession } from './private-durable-binding-store.mjs';
import { withFormalStateTransaction } from './private-state-transaction.mjs';

export class MacSessionAssociationError extends Error {
  constructor(code) { super(code); this.name = 'MacSessionAssociationError'; this.code = code; }
}
export const failAssociation = code => { throw new MacSessionAssociationError(code); };
export function exactAssociation(value, keys, code = 'MAC_ASSOCIATION_INPUT_DENIED') {
  if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) failAssociation(code);
  const d = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(d).length !== keys.length || keys.some(k => !Object.hasOwn(d, k)) ||
      Reflect.ownKeys(d).some(k => typeof k !== 'string' || !keys.includes(k) || !Object.hasOwn(d[k], 'value'))) failAssociation(code);
  return Object.fromEntries(keys.map(k => [k, d[k].value]));
}
export function associationMethods(value, keys) {
  if (!value || types.isProxy(value)) failAssociation('MAC_ASSOCIATION_CONFIG_DENIED');
  return Object.freeze(Object.fromEntries(keys.map(k => {
    const d = Object.getOwnPropertyDescriptor(value, k);
    if (!d || !Object.hasOwn(d, 'value') || typeof d.value !== 'function' || types.isProxy(d.value)) failAssociation('MAC_ASSOCIATION_CONFIG_DENIED');
    return [k, d.value.bind(value)];
  })));
}
export function associationHash(value) { return createHash('sha256').update(JSON.stringify(value)).digest('hex'); }
export function associationDigest(value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) failAssociation('MAC_ASSOCIATION_DIGEST_DENIED');
  return value;
}
export function associationRef(value) {
  if (typeof value !== 'string' || !/^[A-Za-z][A-Za-z0-9._/@-]{2,255}$/.test(value)) failAssociation('MAC_ASSOCIATION_REFERENCE_DENIED');
  return value;
}
export function associationInteger(value, min = 1) {
  if (!Number.isSafeInteger(value) || value < min || value >= Number.MAX_SAFE_INTEGER) failAssociation('MAC_ASSOCIATION_NUMBER_DENIED');
  return value;
}
export function associationScopes(value) {
  if (!Array.isArray(value) || types.isProxy(value) || value.length < 1 || value.length > 16 ||
      Reflect.ownKeys(value).length !== value.length + 1) failAssociation('MAC_ASSOCIATION_SCOPE_DENIED');
  const result = [];
  for (let i = 0; i < value.length; i++) {
    const d = Object.getOwnPropertyDescriptor(value, String(i));
    if (!d || !Object.hasOwn(d, 'value')) failAssociation('MAC_ASSOCIATION_SCOPE_DENIED');
    result.push(associationRef(d.value));
  }
  if (new Set(result).size !== result.length || !result.includes('mcp')) failAssociation('MAC_ASSOCIATION_SCOPE_DENIED');
  return Object.freeze(result);
}
export function freezeAssociation(value, depth = 0) {
  if (value === null || ['string', 'boolean', 'number'].includes(typeof value)) return value;
  if (!value || types.isProxy(value) || depth > 16 || (!Array.isArray(value) && ![Object.prototype, null].includes(Object.getPrototypeOf(value)))) failAssociation('MAC_ASSOCIATION_INPUT_DENIED');
  const d = Object.getOwnPropertyDescriptors(value);
  for (const k of Reflect.ownKeys(d)) {
    if (k === 'length' && Array.isArray(value)) continue;
    if (typeof k !== 'string' || !Object.hasOwn(d[k], 'value')) failAssociation('MAC_ASSOCIATION_INPUT_DENIED');
    freezeAssociation(d[k].value, depth + 1);
  }
  return Object.freeze(value);
}
const WORK_CONTROLLERS = new WeakSet();
export const isAssociationWork = value => WORK_CONTROLLERS.has(value);
export function createAssociationWork({ authorityClock, bootEpoch, limits }) {
  const clock = associationMethods(authorityClock, ['wallNowMs', 'monotonicNowMs']);
  const epoch = associationDigest(bootEpoch.digest);
  const bound = limits === undefined ? { maxCapacity: 8, operationTimeoutMs: 5000, closeTimeoutMs: 1000 } :
    exactAssociation(limits, ['maxCapacity', 'operationTimeoutMs', 'closeTimeoutMs']);
  for (const k of Object.keys(bound)) associationInteger(bound[k]);
  if (bound.maxCapacity > 128 || bound.operationTimeoutMs > 30000 || bound.closeTimeoutMs > 30000) failAssociation('MAC_ASSOCIATION_CONFIG_DENIED');
  let closed = false, lastMono = -1, lastWall = -1;
  const pending = new Set();
  const contexts = new AsyncLocalStorage();
  function now() {
    if (closed || bootEpoch.digest !== epoch) failAssociation('MAC_ASSOCIATION_CLOSED');
    for (let state = contexts.getStore(); state; state = state.parent) {
      if (state.cancelled || !state.active) failAssociation('MAC_ASSOCIATION_TIMEOUT');
    }
    const mono = associationInteger(clock.monotonicNowMs(), 0), wall = associationInteger(clock.wallNowMs());
    if (mono < lastMono || wall < lastWall) failAssociation('MAC_ASSOCIATION_CLOCK_ROLLBACK');
    lastMono = mono; lastWall = wall;
    return Object.freeze({ mono, wall, epoch });
  }
  function run(fn) {
    try { now(); } catch (error) { return Promise.reject(error); }
    if (pending.size >= bound.maxCapacity) return Promise.reject(new MacSessionAssociationError('MAC_ASSOCIATION_CAPACITY_DENIED'));
    const state = { parent: contexts.getStore(), active: true, cancelled: false };
    const actual = contexts.run(state, () => Promise.resolve().then(() => { now(); return fn(now); }).then(v => { now(); return v; }, e => {
      if (e instanceof MacSessionAssociationError || typeof e?.code === 'string' && /^[A-Z0-9_]+$/.test(e.code)) throw e;
      throw new MacSessionAssociationError('MAC_ASSOCIATION_UNAVAILABLE');
    }).finally(() => { state.active = false; }));
    pending.add(actual); actual.then(() => pending.delete(actual), () => pending.delete(actual));
    let timer;
    return Promise.race([actual, new Promise((_, reject) => { timer = setTimeout(() => {
      state.cancelled = true; reject(new MacSessionAssociationError('MAC_ASSOCIATION_TIMEOUT'));
    }, bound.operationTimeoutMs); })]).finally(() => clearTimeout(timer));
  }
  async function close() {
    closed = true;
    let timer;
    await Promise.race([Promise.allSettled([...pending]), new Promise(resolve => { timer = setTimeout(resolve, bound.closeTimeoutMs); })]);
    clearTimeout(timer);
    return Object.freeze({ closed, inFlight: pending.size, resourceReleased: pending.size === 0 });
  }
  const controller = Object.freeze({ run, now, close, status: () => Object.freeze({ closed, inFlight: pending.size, resourceReleased: closed && pending.size === 0 }), epoch });
  WORK_CONTROLLERS.add(controller); return controller;
}

const SCHEMA = 'ring-mac-session-association-v1';
const CURRENT = 'binding/identity-association.json';
const RECOVERY = 'binding/identity-association-recovery.json';
const EMPTY = '0'.repeat(64);
const FIELDS = ['schema', 'revision', 'associationId', 'ownerId', 'botId', 'bindingGeneration', 'actorRef', 'ownerRef',
  'householdRef', 'scopeRefs', 'issuer', 'subjectDigest', 'resource', 'accountDigest', 'accountGeneration',
  'accountIdentifierEnvelope', 'ownerEpoch', 'revoked', 'approvedAt', 'approvalEvidenceSha256'];
export function validateMacAssociation(value) {
  const x = exactAssociation(value, FIELDS, 'MAC_ASSOCIATION_RECORD_DENIED');
  if (x.schema !== SCHEMA || typeof x.revoked !== 'boolean') failAssociation('MAC_ASSOCIATION_RECORD_DENIED');
  for (const k of ['revision', 'bindingGeneration', 'accountGeneration', 'ownerEpoch', 'approvedAt']) associationInteger(x[k]);
  for (const k of ['associationId', 'actorRef', 'ownerRef', 'householdRef']) associationRef(x[k]);
  for (const k of ['ownerId', 'botId']) if (typeof x[k] !== 'string' || !/^[A-Za-z][A-Za-z0-9:_-]{2,127}$/.test(x[k])) failAssociation('MAC_ASSOCIATION_RECORD_DENIED');
  for (const k of ['subjectDigest', 'accountDigest', 'approvalEvidenceSha256']) associationDigest(x[k]);
  for (const k of ['issuer', 'resource']) {
    if (typeof x[k] !== 'string' || x[k].length > 1024) failAssociation('MAC_ASSOCIATION_RECORD_DENIED');
    let u; try { u = new URL(x[k]); } catch { failAssociation('MAC_ASSOCIATION_RECORD_DENIED'); }
    if (u.protocol !== 'https:' || u.username || u.password || u.hash) failAssociation('MAC_ASSOCIATION_RECORD_DENIED');
  }
  x.scopeRefs = associationScopes(x.scopeRefs);
  x.accountIdentifierEnvelope = exactAssociation(x.accountIdentifierEnvelope,
    ['version', 'purpose', 'keyId', 'encryptedDataKey', 'nonce', 'authTag', 'ciphertext'], 'MAC_ASSOCIATION_ENVELOPE_DENIED');
  const e = x.accountIdentifierEnvelope;
  if (e.version !== 1 || e.purpose !== 'RING_ACCOUNT_IDENTITY' || typeof e.keyId !== 'string' || e.keyId.length < 3 || e.keyId.length > 255 ||
      ['encryptedDataKey', 'nonce', 'authTag', 'ciphertext'].some(k => typeof e[k] !== 'string' || !/^[A-Za-z0-9_-]{1,8192}$/.test(e[k]))) failAssociation('MAC_ASSOCIATION_ENVELOPE_DENIED');
  return freezeAssociation(x);
}
function bindingEnvelope(value) {
  const x = exactAssociation(value, ['schema', 'revision', 'record']);
  if (x.schema !== 'ring-b02-private-durable-binding-store-v1') failAssociation('MAC_ASSOCIATION_BINDING_DENIED');
  associationInteger(x.revision);
  return Object.freeze({ ...x, record: validateDurableBindingV2(x.record, { allowRevoked: false }) });
}
function matchingBinding(record, binding) {
  if (!binding.active || binding.revoked || ['ownerId', 'botId'].some(k => record[k] !== binding[k]) || record.bindingGeneration !== binding.generation) failAssociation('MAC_ASSOCIATION_BINDING_DENIED');
}
function recoveryIntent(value) {
  const x = exactAssociation(value, ['schema', 'transactionId', 'beforeRevision', 'beforeHash', 'nextRevision', 'nextHash',
    'bindingRevision', 'bindingHash', 'approvalEvidenceSha256', 'preparedPath', 'nextRecord'], 'MAC_ASSOCIATION_RECOVERY_DENIED');
  if (x.schema !== 'ring-mac-association-recovery-v1' || typeof x.preparedPath !== 'string' ||
      !/^binding\/identity-association-next-[1-9][0-9]*\.json$/.test(x.preparedPath)) failAssociation('MAC_ASSOCIATION_RECOVERY_DENIED');
  associationRef(x.transactionId); associationInteger(x.beforeRevision, 0); associationInteger(x.nextRevision); associationInteger(x.bindingRevision);
  for (const k of ['beforeHash', 'nextHash', 'bindingHash', 'approvalEvidenceSha256']) associationDigest(x[k]);
  x.nextRecord = validateMacAssociation(x.nextRecord);
  if (x.nextRevision !== x.beforeRevision + 1 || x.nextRecord.revision !== x.nextRevision || associationHash(x.nextRecord) !== x.nextHash ||
      x.nextRecord.approvalEvidenceSha256 !== x.approvalEvidenceSha256) failAssociation('MAC_ASSOCIATION_RECOVERY_DENIED');
  return freezeAssociation(x);
}

export function createMacSessionAssociationStore(input) {
  const c = exactAssociation(input, ['descriptorSession', 'stateTransactionLockPort', 'currentBindingPort', 'associationAdmissionPort',
    'ownerApprovalPort', 'sessionStatePort', 'authorityClock', 'bootEpoch', 'limits', 'workController']);
  if (!isFormalStateDescriptorSession(c.descriptorSession)) failAssociation('MAC_ASSOCIATION_DESCRIPTOR_DENIED');
  const current = associationMethods(c.currentBindingPort, ['readCurrent']);
  const admission = associationMethods(c.associationAdmissionPort, ['readCurrent', 'compareAndAdvance', 'confirm']);
  const approval = associationMethods(c.ownerApprovalPort, ['consumeAssociation']);
  const sessions = associationMethods(c.sessionStatePort, ['lookup', 'project']);
  if (c.workController !== undefined && !isAssociationWork(c.workController)) failAssociation('MAC_ASSOCIATION_CONFIG_DENIED');
  const work = c.workController ?? createAssociationWork(c);
  let sequence = 0, descriptorClosed = false;
  async function readProtected() {
    const a = exactAssociation(await admission.readCurrent(), ['revision', 'sha256', 'floor', 'evidenceSha256'], 'MAC_ASSOCIATION_COMMITMENT_DENIED');
    associationInteger(a.revision, 0); associationInteger(a.floor, 0); associationDigest(a.sha256); associationDigest(a.evidenceSha256);
    if (a.evidenceSha256 === EMPTY || a.floor !== a.revision) failAssociation('MAC_ASSOCIATION_COMMITMENT_DENIED');
    return Object.freeze(a);
  }
  async function protectedCurrent(record) {
    const revision = record?.revision ?? 0, sha256 = record ? associationHash(record) : EMPTY, a = await readProtected();
    if (a.revision !== revision || a.sha256 !== sha256) failAssociation('MAC_ASSOCIATION_COMMITMENT_DENIED');
    return a;
  }
  async function underLock(purpose, fn, recovering = false) {
    const before = exactAssociation(await current.readCurrent(), ['binding', 'credentialRevision']);
    const beforeBinding = validateDurableBindingV2(before.binding, { allowRevoked: false });
    work.now();
    return await withFormalStateTransaction({ lockPort: c.stateTransactionLockPort,
      ownerNonce: `MacAssociation:${++sequence}`, purpose }, async () => {
      work.now();
      const onDisk = await c.descriptorSession.readValidated('binding/current.json', 32768, bindingEnvelope);
      if (associationHash(beforeBinding) !== associationHash(onDisk.record)) failAssociation('MAC_ASSOCIATION_BINDING_DRIFT');
      const record = await c.descriptorSession.readValidated(CURRENT, 32768, validateMacAssociation, true);
      const intent = await c.descriptorSession.readValidated(RECOVERY, 32768, recoveryIntent, true);
      if (intent && !recovering) failAssociation('MAC_ASSOCIATION_RECOVERY_REQUIRED');
      const commitment = recovering ? await readProtected() : await protectedCurrent(record);
      work.now();
      return await fn({ binding: onDisk, record, commitment, intent });
    });
  }
  const api = {
    readAssociation() { return work.run(() => underLock('association-read', async ({ binding, record }) => {
      if (!record || record.revoked) failAssociation('MAC_ASSOCIATION_NOT_ACTIVE');
      matchingBinding(record, binding.record); return record;
    })); },
    commitApprovedAssociation(input) { return work.run(() => underLock('association-commit', async ({ binding, record, commitment }) => {
      const x = exactAssociation(input, ['expectedRevision', 'expectedHash', 'record', 'ownerProof']);
      const next = validateMacAssociation(x.record);
      if (x.expectedRevision !== (record?.revision ?? 0) || x.expectedHash !== commitment.sha256 || next.revision !== x.expectedRevision + 1) failAssociation('MAC_ASSOCIATION_CAS_DENIED');
      matchingBinding(next, binding.record);
      const proof = exactAssociation(await approval.consumeAssociation({ proof: x.ownerProof, recordDigest: associationHash(next),
        bindingRevision: binding.revision, bindingHash: associationHash(binding), bootEpoch: work.epoch }),
      ['approvalId', 'recordDigest', 'bindingRevision', 'bindingHash', 'bootEpoch', 'expiresMonotonicMs', 'evidenceSha256'], 'MAC_ASSOCIATION_OWNER_APPROVAL_DENIED');
      const stamp = work.now();
      if (proof.recordDigest !== associationHash(next) || proof.bindingRevision !== binding.revision || proof.bindingHash !== associationHash(binding) ||
          proof.bootEpoch !== stamp.epoch || proof.expiresMonotonicMs <= stamp.mono || proof.evidenceSha256 !== next.approvalEvidenceSha256) failAssociation('MAC_ASSOCIATION_OWNER_APPROVAL_DENIED');
      associationRef(proof.approvalId); associationInteger(proof.expiresMonotonicMs, 0); associationDigest(proof.evidenceSha256);
      const afterApprovalBinding = await c.descriptorSession.readValidated('binding/current.json', 32768, bindingEnvelope);
      if (associationHash(afterApprovalBinding) !== associationHash(binding)) failAssociation('MAC_ASSOCIATION_BINDING_DRIFT');
      const temp = `binding/identity-association-next-${sequence}.json`;
      const intentTemp = `binding/identity-association-recovery-next-${sequence}.json`;
      let prepared = false, intentPrepared = false, intentPersisted = false;
      try {
        await c.descriptorSession.createPrepared(temp, next); prepared = true; work.now();
        const intent = recoveryIntent({ schema: 'ring-mac-association-recovery-v1', transactionId: proof.approvalId,
          beforeRevision: commitment.revision, beforeHash: commitment.sha256, nextRevision: next.revision,
          nextHash: associationHash(next), bindingRevision: binding.revision, bindingHash: associationHash(binding),
          approvalEvidenceSha256: proof.evidenceSha256, preparedPath: temp, nextRecord: next });
        await c.descriptorSession.createPrepared(intentTemp, intent); intentPrepared = true; work.now();
        await c.descriptorSession.renamePrepared(intentTemp, RECOVERY); intentPrepared = false; intentPersisted = true; work.now();
        const advance = exactAssociation(await admission.compareAndAdvance({ expectedRevision: commitment.revision,
          expectedHash: commitment.sha256, nextRevision: next.revision, nextHash: associationHash(next), transactionId: proof.approvalId }),
        ['revision', 'sha256', 'floor', 'evidenceSha256'], 'MAC_ASSOCIATION_COMMITMENT_DENIED');
        if (advance.revision !== next.revision || advance.floor !== next.revision || advance.sha256 !== associationHash(next)) failAssociation('MAC_ASSOCIATION_COMMITMENT_DENIED');
        associationDigest(advance.evidenceSha256); if (advance.evidenceSha256 === EMPTY) failAssociation('MAC_ASSOCIATION_COMMITMENT_DENIED');
        work.now(); await c.descriptorSession.renamePrepared(temp, CURRENT); prepared = false;
        const confirmed = exactAssociation(await admission.confirm({ revision: next.revision, sha256: associationHash(next), transactionId: proof.approvalId }),
          ['revision', 'sha256', 'floor', 'evidenceSha256'], 'MAC_ASSOCIATION_COMMITMENT_DENIED');
        if (confirmed.revision !== next.revision || confirmed.floor !== next.revision || confirmed.sha256 !== associationHash(next)) failAssociation('MAC_ASSOCIATION_COMMITMENT_DENIED');
        associationDigest(confirmed.evidenceSha256); work.now();
        const installed = await c.descriptorSession.readValidated(CURRENT, 32768, validateMacAssociation);
        if (associationHash(installed) !== associationHash(next)) failAssociation('MAC_ASSOCIATION_READBACK_DENIED');
        await protectedCurrent(installed); work.now(); await c.descriptorSession.removePrepared(RECOVERY); return installed;
      } finally {
        if (!intentPersisted && prepared) await c.descriptorSession.removePrepared(temp);
        if (intentPrepared) await c.descriptorSession.removePrepared(intentTemp);
      }
    })); },
    recoverApprovedAssociation() { return work.run(() => underLock('association-recover', async ({ binding, record, commitment, intent }) => {
      if (!intent || intent.bindingRevision !== binding.revision || intent.bindingHash !== associationHash(binding)) failAssociation('MAC_ASSOCIATION_RECOVERY_DENIED');
      matchingBinding(intent.nextRecord, binding.record);
      const currentRevision = record?.revision ?? 0, currentHash = record ? associationHash(record) : EMPTY;
      const isBefore = currentRevision === intent.beforeRevision && currentHash === intent.beforeHash;
      const isNext = currentRevision === intent.nextRevision && currentHash === intent.nextHash;
      const protectedBefore = commitment.revision === intent.beforeRevision && commitment.sha256 === intent.beforeHash;
      const protectedNext = commitment.revision === intent.nextRevision && commitment.sha256 === intent.nextHash;
      if ((!isBefore && !isNext) || (!protectedBefore && !protectedNext)) failAssociation('MAC_ASSOCIATION_RECOVERY_DENIED');
      const prepared = await c.descriptorSession.readValidated(intent.preparedPath, 32768, validateMacAssociation, true);
      if (prepared && associationHash(prepared) !== intent.nextHash) failAssociation('MAC_ASSOCIATION_RECOVERY_DENIED');
      if (protectedBefore) {
        if (!isBefore || !prepared) failAssociation('MAC_ASSOCIATION_RECOVERY_DENIED');
        work.now(); await c.descriptorSession.removePrepared(intent.preparedPath);
        await c.descriptorSession.removePrepared(RECOVERY);
        return Object.freeze({ recovered: true, disposition: 'CANCELLED_UNADVANCED_INTENT', revision: currentRevision });
      }
      if (isBefore) {
        if (!prepared) failAssociation('MAC_ASSOCIATION_RECOVERY_DENIED');
        work.now(); await c.descriptorSession.renamePrepared(intent.preparedPath, CURRENT);
      }
      work.now();
      const confirmed = exactAssociation(await admission.confirm({ revision: intent.nextRevision, sha256: intent.nextHash,
        transactionId: intent.transactionId }), ['revision', 'sha256', 'floor', 'evidenceSha256'], 'MAC_ASSOCIATION_COMMITMENT_DENIED');
      if (confirmed.revision !== intent.nextRevision || confirmed.floor !== intent.nextRevision || confirmed.sha256 !== intent.nextHash) failAssociation('MAC_ASSOCIATION_COMMITMENT_DENIED');
      associationDigest(confirmed.evidenceSha256); if (confirmed.evidenceSha256 === EMPTY) failAssociation('MAC_ASSOCIATION_COMMITMENT_DENIED');
      const installed = await c.descriptorSession.readValidated(CURRENT, 32768, validateMacAssociation);
      if (associationHash(installed) !== intent.nextHash) failAssociation('MAC_ASSOCIATION_READBACK_DENIED');
      await protectedCurrent(installed); work.now();
      if (isNext && prepared) await c.descriptorSession.removePrepared(intent.preparedPath);
      await c.descriptorSession.removePrepared(RECOVERY);
      return Object.freeze({ recovered: true, disposition: 'CONFIRMED_APPROVED_FORWARD_COMMIT', revision: installed.revision });
    }, true)); },
    loadSessionAuthority(input) { return work.run(async () => {
      const x = exactAssociation(input, ['sessionDigest', 'csrfDigest']); associationDigest(x.sessionDigest); associationDigest(x.csrfDigest);
      const state = await sessions.lookup(x), record = await api.readAssociation(); work.now();
      if (!state || state.associationRevision !== record.revision || state.bootEpoch !== work.epoch ||
          state.ownerEpoch !== record.ownerEpoch || state.subjectDigest !== record.subjectDigest || state.accountDigest !== record.accountDigest) failAssociation('MAC_ASSOCIATION_SESSION_CHANGED');
      const now = work.now().wall;
      if ([state.sessionExpiresAt, state.idleExpiresAt, state.trustExpiresAt].some(v => !Number.isSafeInteger(v) || v <= now)) failAssociation('MAC_ASSOCIATION_SESSION_EXPIRED');
      return freezeAssociation({ productionAdmitted: true, serverNow: now, ownerEpoch: record.ownerEpoch,
        sessionId: state.sessionId, sessionGeneration: state.sessionGeneration, grantId: state.grantId, grantGeneration: state.grantGeneration,
        sessionExpiresAt: state.sessionExpiresAt, idleExpiresAt: state.idleExpiresAt, trustExpiresAt: state.trustExpiresAt,
        actorRef: record.actorRef, ownerRef: record.ownerRef, householdRef: record.householdRef, scopeRefs: record.scopeRefs,
        accountDigest: record.accountDigest, accountGeneration: record.accountGeneration, projectionRevision: record.revision,
        accountIdentifierEnvelope: record.accountIdentifierEnvelope, bindingExpiresAt: state.trustExpiresAt });
    }); },
    projectAccount(input) { return work.run(async () => {
      const x = exactAssociation(input, ['sessionDigest', 'ownerRef', 'ownerEpoch', 'grantDigest', 'grantGeneration', 'accountDigest', 'accountGeneration', 'accountIdentifierEnvelope', 'expiresAt']);
      const record = await api.readAssociation();
      if (x.ownerRef !== record.ownerRef || x.ownerEpoch !== record.ownerEpoch || x.accountDigest !== record.accountDigest || x.accountGeneration !== record.accountGeneration) failAssociation('MAC_ASSOCIATION_ACCOUNT_DENIED');
      return await sessions.project(x, record);
    }); },
    async close() {
      const result = await work.close();
      if (result.resourceReleased && !descriptorClosed) { await c.descriptorSession.close(); descriptorClosed = true; }
      return Object.freeze({ ...result, descriptorClosed, resourceReleased: result.resourceReleased && descriptorClosed });
    },
    status: work.status
  };
  return Object.freeze(api);
}
export const macSessionAssociationConstants = Object.freeze({ schema: SCHEMA, currentPath: CURRENT, recoveryPath: RECOVERY, emptyHash: EMPTY });
