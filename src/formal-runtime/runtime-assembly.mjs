import crypto from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { migrateLegacyBindingV1, validateDurableBindingV2 } from '../wifi/durable-binding-v2.mjs';
import { createMcpEntryAdmissionPort } from '../wifi/mcp-entry-admission.mjs';
import { createAntiRollbackWitnessGate, validateWitnessCommitment, witnessCommitmentEquals } from './anti-rollback-witness.mjs';
import { validateProductionPortSet } from './production-ports.mjs';
import { openFormalStateDescriptorSession, createDescriptorBoundDurableBindingStore } from './private-durable-binding-store.mjs';
import { createDescriptorBoundProviderCursorStore } from './private-provider-cursor-store.mjs';
import { withFormalStateTransaction } from './private-state-transaction.mjs';
import {
  deepFreeze,
  denyFormalRuntime,
  exactObject,
  safeHash,
  safeLabel,
  safeRevision,
  safeTime,
  zeroBinary
} from './protocol.mjs';

const CONFIG_SCHEMA = 'ring-b02-formal-runtime-config-v1';
const EMPTY_HASH = '0'.repeat(64);

function validateConfig(value) {
  const fields = exactObject(value, [
    'schema', 'enabled', 'profile', 'stateRoot', 'maximumGrantTtlMs', 'providerCallsOnConstruction',
    'externalWitnessRequired'
  ], 'B02_FORMAL_CONFIG_DENIED');
  if (fields.schema !== CONFIG_SCHEMA || typeof fields.enabled !== 'boolean' ||
      fields.profile !== 'FORMAL' || fields.stateRoot !== 'var/private/formal-runtime' ||
      fields.maximumGrantTtlMs !== 300_000 || fields.providerCallsOnConstruction !== false ||
      fields.externalWitnessRequired !== true) denyFormalRuntime('B02_FORMAL_CONFIG_DENIED');
  return deepFreeze({ ...fields });
}

function hashObject(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function migrationJournal(input) {
  return deepFreeze({
    schema: 'ring-b02-formal-migration-journal-v1',
    revision: input.revision,
    stage: input.stage,
    priorBindingHash: input.priorBindingHash,
    nextBindingHash: input.nextBindingHash,
    priorBindingRevision: input.priorBindingRevision,
    nextBindingRevision: input.nextBindingRevision,
    priorCursorHash: input.priorCursorHash,
    nextCursorHash: input.nextCursorHash,
    priorCursorRevision: input.priorCursorRevision,
    nextCursorRevision: input.nextCursorRevision,
    preparedAt: input.preparedAt,
    updatedAt: input.updatedAt,
    recoveryRequired: input.stage === 'RECOVERY_REQUIRED',
    secret: null
  });
}

export async function migrateLegacyRuntimeState(input) {
  const fields = exactObject(input, [
    'bindingStore', 'cursorStore', 'legacyOwner', 'botId', 'providerProof', 'providerCursor',
    'observedAt', 'evidenceVersion', 'custodyHashBefore', 'custodyHashAfter', 'crashAfter'
  ], 'B02_FORMAL_MIGRATION_INPUT_DENIED');
  if (!fields.bindingStore || typeof fields.bindingStore.readCurrent !== 'function' ||
      typeof fields.bindingStore.compareAndSwap !== 'function' ||
      typeof fields.bindingStore.readRevisionFloor !== 'function' ||
      typeof fields.bindingStore.advanceRevisionFloor !== 'function' ||
      typeof fields.bindingStore.readJournal !== 'function' ||
      typeof fields.bindingStore.compareAndSwapJournal !== 'function' ||
      !fields.cursorStore || typeof fields.cursorStore.readCurrent !== 'function' ||
      typeof fields.cursorStore.compareAndSwap !== 'function') {
    denyFormalRuntime('B02_FORMAL_MIGRATION_PORT_DENIED');
  }
  const custodyBefore = safeHash(fields.custodyHashBefore);
  if (custodyBefore !== safeHash(fields.custodyHashAfter)) denyFormalRuntime('B02_FORMAL_CUSTODY_DRIFT_DENIED');
  if (![null, 'BINDING_RENAME', 'CURSOR_RENAME'].includes(fields.crashAfter)) {
    denyFormalRuntime('B02_FORMAL_MIGRATION_INPUT_DENIED');
  }
  const observedAt = safeTime(fields.observedAt);
  const currentBinding = await fields.bindingStore.readCurrent();
  const currentCursor = await fields.cursorStore.readCurrent();
  const existingJournal = await fields.bindingStore.readJournal();
  if (existingJournal?.stage === 'COMPLETE') return Object.freeze({ outcome: 'NOOP', stage: 'COMPLETE' });
  const migrated = migrateLegacyBindingV1(fields.legacyOwner, {
    botId: fields.botId,
    observedAt,
    evidenceVersion: fields.evidenceVersion,
    providerProof: fields.providerProof
  });
  if (migrated.verificationStatus !== 'active' || migrated.candidate === null) {
    denyFormalRuntime('B02_FORMAL_MIGRATION_ATTESTATION_DENIED');
  }
  const candidate = migrated.candidate;
  if (existingJournal?.stage === 'RECOVERY_REQUIRED') {
    const currentBindingHash = currentBinding ? hashObject(currentBinding) : EMPTY_HASH;
    const currentCursorHash = currentCursor ? hashObject(currentCursor) : EMPTY_HASH;
    if (currentBindingHash !== existingJournal.nextBindingHash ||
        ![existingJournal.priorCursorHash, existingJournal.nextCursorHash].includes(currentCursorHash)) {
      denyFormalRuntime('B02_FORMAL_MIGRATION_RECOVERY_DENIED');
    }
    if (currentCursorHash === existingJournal.priorCursorHash) {
      const recoveredCursor = await fields.cursorStore.compareAndSwap({
        expectedRevision: existingJournal.priorCursorRevision,
        expectedHash: existingJournal.priorCursorHash,
        botId: fields.botId,
        nextOffset: fields.providerCursor,
        observedAt
      });
      if (recoveredCursor.hash !== existingJournal.nextCursorHash) {
        denyFormalRuntime('B02_FORMAL_MIGRATION_RECOVERY_DENIED');
      }
    }
    const floor = await fields.bindingStore.readRevisionFloor();
    if (floor < existingJournal.nextBindingRevision) {
      await fields.bindingStore.advanceRevisionFloor({
        expectedRevision: floor,
        nextRevision: existingJournal.nextBindingRevision
      });
    }
    const complete = migrationJournal({
      ...existingJournal,
      revision: existingJournal.revision + 1,
      stage: 'COMPLETE',
      updatedAt: observedAt
    });
    await fields.bindingStore.compareAndSwapJournal({ expectedRevision: existingJournal.revision, journal: complete });
    return Object.freeze({ outcome: 'RECOVERED', stage: 'COMPLETE', custodyUnchanged: true });
  }
  if (existingJournal !== null || currentBinding !== null) denyFormalRuntime('B02_FORMAL_MIGRATION_RECOVERY_REQUIRED');
  const priorBindingRevision = 0;
  const priorCursorRevision = currentCursor?.revision ?? 0;
  const nextBindingRevision = 1;
  const nextCursorRevision = priorCursorRevision + 1;
  const priorCursorHash = currentCursor ? hashObject(currentCursor) : EMPTY_HASH;
  const nextBindingHash = hashObject({
    schema: 'ring-b02-private-durable-binding-store-v1',
    revision: nextBindingRevision,
    record: candidate.record
  });
  const nextCursorShape = {
    schema: 'ring-b02-private-provider-cursor-v1',
    revision: nextCursorRevision,
    provider: 'telegram',
    botId: fields.botId,
    nextOffset: safeRevision(fields.providerCursor),
    observedAt,
    secret: null
  };
  const nextCursorHash = hashObject(nextCursorShape);
  let journalRevision = 1;
  let journal = migrationJournal({
    revision: journalRevision,
    stage: 'PREPARED',
    priorBindingHash: EMPTY_HASH,
    nextBindingHash,
    priorBindingRevision,
    nextBindingRevision,
    priorCursorHash,
    nextCursorHash,
    priorCursorRevision,
    nextCursorRevision,
    preparedAt: observedAt,
    updatedAt: observedAt
  });
  await fields.bindingStore.compareAndSwapJournal({ expectedRevision: 0, journal });

  const bindingWrite = await fields.bindingStore.compareAndSwap({
    expectedRevision: priorBindingRevision,
    expectedHash: EMPTY_HASH,
    record: candidate.record
  });
  if (bindingWrite.hash !== nextBindingHash) denyFormalRuntime('B02_FORMAL_MIGRATION_HASH_DENIED');
  journal = migrationJournal({ ...journal, revision: ++journalRevision, stage: 'BINDING_COMMITTED', updatedAt: observedAt });
  await fields.bindingStore.compareAndSwapJournal({ expectedRevision: journalRevision - 1, journal });
  if (fields.crashAfter === 'BINDING_RENAME') {
    const recovery = migrationJournal({ ...journal, revision: ++journalRevision, stage: 'RECOVERY_REQUIRED', updatedAt: observedAt });
    await fields.bindingStore.compareAndSwapJournal({ expectedRevision: journalRevision - 1, journal: recovery });
    denyFormalRuntime('B02_FORMAL_MIGRATION_INJECTED_CRASH');
  }

  const cursorWrite = await fields.cursorStore.compareAndSwap({
    expectedRevision: priorCursorRevision,
    expectedHash: priorCursorHash,
    botId: fields.botId,
    nextOffset: fields.providerCursor,
    observedAt
  });
  if (cursorWrite.hash !== nextCursorHash) denyFormalRuntime('B02_FORMAL_MIGRATION_HASH_DENIED');
  journal = migrationJournal({ ...journal, revision: ++journalRevision, stage: 'CURSOR_COMMITTED', updatedAt: observedAt });
  await fields.bindingStore.compareAndSwapJournal({ expectedRevision: journalRevision - 1, journal });
  if (fields.crashAfter === 'CURSOR_RENAME') {
    const recovery = migrationJournal({ ...journal, revision: ++journalRevision, stage: 'RECOVERY_REQUIRED', updatedAt: observedAt });
    await fields.bindingStore.compareAndSwapJournal({ expectedRevision: journalRevision - 1, journal: recovery });
    denyFormalRuntime('B02_FORMAL_MIGRATION_INJECTED_CRASH');
  }

  await fields.bindingStore.advanceRevisionFloor({ expectedRevision: 0, nextRevision: nextBindingRevision });
  journal = migrationJournal({ ...journal, revision: ++journalRevision, stage: 'COMPLETE', updatedAt: observedAt });
  await fields.bindingStore.compareAndSwapJournal({ expectedRevision: journalRevision - 1, journal });
  return deepFreeze({ outcome: 'MIGRATED', stage: 'COMPLETE', custodyUnchanged: true });
}

export function createDisabledFormalRuntimeComposition({ configured = false, code = 'B02_FORMAL_RUNTIME_DISABLED' } = {}) {
  let closed = false;
  return Object.freeze({
    enabled: false,
    configured,
    ready: false,
    async start() { return Object.freeze({ state: 'DISABLED' }); },
    async readCurrentBinding() { denyFormalRuntime(code); },
    async migrateLegacyRuntimeState() { denyFormalRuntime(code); },
    async issueMcpEntry() { denyFormalRuntime(code); },
    async consumeMcpEntry() { denyFormalRuntime(code); },
    async close() { closed = true; return Object.freeze({ closed: true }); },
    status() { return Object.freeze({ state: closed ? 'CLOSED' : 'DISABLED', configured, ready: false }); }
  });
}

function hashJson(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function commitmentFromSnapshot(snapshot) {
  return validateWitnessCommitment({
    bindingRevision: snapshot.binding.revision,
    bindingHash: hashJson(snapshot.binding),
    cursorRevision: snapshot.cursor.revision,
    cursorHash: hashJson(snapshot.cursor),
    journalRevision: snapshot.journal.revision,
    journalHash: hashJson(snapshot.journal)
  });
}

function validateAuthoritySnapshot(value) {
  const fields = exactObject(value, ['binding', 'cursor', 'journal', 'revisionFloor', 'custodyRevision'],
    'B02_FORMAL_AUTHORITY_SNAPSHOT_DENIED');
  if (!fields.binding || !fields.cursor || !fields.journal || fields.journal.stage !== 'COMPLETE' ||
      fields.journal.recoveryRequired !== false || fields.binding.revision < safeRevision(fields.revisionFloor) ||
      fields.binding.record.botId !== fields.cursor.botId || !fields.binding.record.active) {
    denyFormalRuntime('B02_FORMAL_AUTHORITY_SNAPSHOT_DENIED');
  }
  validateDurableBindingV2(fields.binding.record, { allowRevoked: false });
  safeRevision(fields.custodyRevision, 1);
  return deepFreeze(fields);
}

export function createFormalRuntimeComposition(options) {
  const fields = exactObject(options, [
    'config', 'statePathMetadata', 'wifiTrustService', 'wifiTrustStore', 'ringReferencePort',
    'productionPorts', 'authorityClock', 'bootEpoch'
  ], 'B02_FORMAL_COMPOSITION_INPUT_DENIED');
  const config = validateConfig(fields.config);
  if (!config.enabled) return createDisabledFormalRuntimeComposition({ configured: false });
  const ports = validateProductionPortSet(fields.productionPorts);
  const stateMetadata = exactObject(fields.statePathMetadata, ['stateRoot'], 'B02_FORMAL_COMPOSITION_PORT_DENIED');
  if (stateMetadata.stateRoot !== config.stateRoot || !fields.ringReferencePort ||
      fields.ringReferencePort.productionAdmitted !== true || typeof fields.ringReferencePort.current !== 'function' ||
      !fields.wifiTrustService || typeof fields.wifiTrustService.recognizeForMcpEntry !== 'function' ||
      !fields.wifiTrustStore || typeof fields.wifiTrustStore.readCurrent !== 'function' ||
      !fields.authorityClock || fields.authorityClock.productionAdmitted !== true ||
      typeof fields.authorityClock.monotonicNowMs !== 'function' || typeof fields.authorityClock.wallNowMs !== 'function' ||
      !fields.bootEpoch || fields.bootEpoch.productionAdmitted !== true || typeof fields.bootEpoch.derive !== 'function' ||
      !/^[a-f0-9]{64}$/.test(fields.bootEpoch.digest)) denyFormalRuntime('B02_FORMAL_COMPOSITION_PORT_DENIED');
  const witness = createAntiRollbackWitnessGate(ports.antiRollbackWitnessPort);
  let admission = createMcpEntryAdmissionPort({ clock: () => fields.authorityClock.monotonicNowMs(), sessionAuthority: ports.remoteEntryPort });
  let state = 'CONSTRUCTED';
  let baseline = null;
  let closed = false;
  let descriptorSession = null;
  let bindingStore = null;
  let cursorStore = null;
  let transactionSequence = 0;
  const ownedAuthorityContext = new AsyncLocalStorage();
  const privateRuntimeIdentity = Object.freeze({});

  const DRIFT_CODES = new Set(['B02_ATTESTATION_BOT_DRIFT', 'B02_ATTESTATION_BOT_MISMATCH',
    'B02_FORMAL_WITNESS_DRIFT_DENIED', 'B02_FORMAL_BINDING_DRIFT_DENIED',
    'B02_FORMAL_CURSOR_DRIFT_DENIED', 'B02_FORMAL_CUSTODY_DRIFT_DENIED',
    'B02_FORMAL_RING_DRIFT_DENIED', 'B02_FORMAL_WIFI_DRIFT_DENIED', 'B02_FORMAL_BOOT_EPOCH_DENIED',
    'B02_CURSOR_TRANSACTION_DENIED']);

  async function closeProductionPorts() {
    const closers = [witness, ports.telegramTransportPort, ports.credentialOperatorPort, ports.localSessionPort,
      ports.remoteEntryPort, ports.formalCapabilityPort];
    await Promise.allSettled(closers.map((port) => port?.close?.()));
    await descriptorSession?.close?.().catch(() => {});
    descriptorSession = null;
    fields.bootEpoch.close?.();
  }

  async function latchAuthorityDrift() {
    if (state !== 'CLOSED') state = 'DISABLED_DRIFT';
    admission = createMcpEntryAdmissionPort({ clock: () => fields.authorityClock.monotonicNowMs(), sessionAuthority: ports.remoteEntryPort });
    await closeProductionPorts();
    return Object.freeze({ state: 'DISABLED_DRIFT' });
  }

  async function withRuntimeAuthorityTransaction(purpose, operation) {
    const sequence = ++transactionSequence;
    const ownerNonce = `Owner_${fields.bootEpoch.derive(`lock:${sequence}:${purpose}`).slice(0, 32)}`;
    return withFormalStateTransaction({ lockPort: ports.stateTransactionLockPort, ownerNonce, purpose }, async lock => {
      const context = { owner: privateRuntimeIdentity, active: true };
      return ownedAuthorityContext.run(context, async () => {
        try { return await operation(lock); }
        finally { context.active = false; }
      });
    });
  }

  async function currentLocalAuthoritySnapshotUnderLock() {
    if (!bindingStore || !cursorStore) denyFormalRuntime('B02_FORMAL_DESCRIPTOR_IO_DENIED');
    const floor = await bindingStore.readRevisionFloor();
    const snapshot = validateAuthoritySnapshot({
      binding: await bindingStore.readCurrent({ revisionFloor: floor }),
      cursor: await cursorStore.readCurrent(),
      journal: await bindingStore.readJournal(),
      revisionFloor: floor,
      custodyRevision: await bindingStore.currentCustodyRevision()
    });
    const commitment = commitmentFromSnapshot(snapshot);
    return deepFreeze({ snapshot, commitment });
  }

  async function currentAuthoritySnapshotUnderLock() {
    const local = await currentLocalAuthoritySnapshotUnderLock();
    const witnessed = await witness.readCurrent();
    if (!witnessCommitmentEquals(local.commitment, witnessed)) denyFormalRuntime('B02_FORMAL_WITNESS_DRIFT_DENIED');
    return local;
  }

  async function readCurrentBinding() {
    if (closed || state !== 'READY') denyFormalRuntime('B02_FORMAL_RUNTIME_NOT_READY');
    return withAuthorityDriftLatch(async () => {
      const read = async () => {
        if (closed || state !== 'READY') denyFormalRuntime('B02_FORMAL_RUNTIME_NOT_READY');
        const ownership = ownedAuthorityContext.getStore();
        if (ownership?.owner !== privateRuntimeIdentity || ownership.active !== true) {
          denyFormalRuntime('B02_FORMAL_OWNED_CONTEXT_EXPIRED');
        }
        let authority;
        try { authority = await currentAuthoritySnapshotUnderLock(); }
        catch (error) {
          if (ownership.active !== true) denyFormalRuntime('B02_FORMAL_OWNED_CONTEXT_EXPIRED');
          throw error;
        }
        if (ownership.active !== true) denyFormalRuntime('B02_FORMAL_OWNED_CONTEXT_EXPIRED');
        if (closed || state !== 'READY') denyFormalRuntime('B02_FORMAL_RUNTIME_NOT_READY');
        return Object.freeze({ binding: authority.snapshot.binding.record,
          credentialRevision: authority.snapshot.custodyRevision });
      };
      const context = ownedAuthorityContext.getStore();
      if (context?.owner === privateRuntimeIdentity && context.active === true) return read();
      return withRuntimeAuthorityTransaction('binding-read', read);
    });
  }

  async function reconcileCursorWitnessBeforeAuthority() {
    const prepared = await cursorStore.inspectPreparedCursorAdvance();
    const local = await currentLocalAuthoritySnapshotUnderLock();
    const witnessed = await witness.readCurrent();
    if (prepared === null) {
      if (!witnessCommitmentEquals(local.commitment, witnessed)) denyFormalRuntime('B02_FORMAL_WITNESS_DRIFT_DENIED');
      return local;
    }
    if (prepared.botId !== local.snapshot.binding.record.botId) denyFormalRuntime('B02_CURSOR_TRANSACTION_DENIED');
    const priorCommitment = validateWitnessCommitment({ ...local.commitment,
      cursorRevision: prepared.priorRevision, cursorHash: prepared.priorHash });
    const nextCommitment = validateWitnessCommitment({ ...local.commitment,
      cursorRevision: prepared.nextRevision, cursorHash: prepared.nextHash });
    const localIsPrior = witnessCommitmentEquals(local.commitment, priorCommitment);
    const localIsNext = witnessCommitmentEquals(local.commitment, nextCommitment);
    const witnessIsPrior = witnessCommitmentEquals(witnessed, priorCommitment);
    const witnessIsNext = witnessCommitmentEquals(witnessed, nextCommitment);
    if (localIsPrior && !prepared.preparedFilePresent) denyFormalRuntime('B02_CURSOR_TRANSACTION_DENIED');
    if (localIsPrior && witnessIsPrior) {
      await cursorStore.abortPreparedCursor(prepared);
    } else if (localIsPrior && witnessIsNext) {
      const readback = await cursorStore.recoverWitnessedCursorAdvance({ prepared, witnessNext: nextCommitment });
      if (!readback.readbackExact || readback.hash !== nextCommitment.cursorHash) {
        denyFormalRuntime('B02_FORMAL_CURSOR_DRIFT_DENIED');
      }
      await witness.confirm({ commitment: nextCommitment, transactionId: prepared.transactionId });
      await cursorStore.finishPreparedCursor(prepared);
    } else if (localIsNext && witnessIsNext) {
      const readback = await cursorStore.readBackCursorCommitment(prepared);
      if (!readback.readbackExact || readback.hash !== nextCommitment.cursorHash) {
        denyFormalRuntime('B02_FORMAL_CURSOR_DRIFT_DENIED');
      }
      await witness.confirm({ commitment: nextCommitment, transactionId: prepared.transactionId });
      await cursorStore.finishPreparedCursor(prepared);
    } else {
      denyFormalRuntime('B02_FORMAL_WITNESS_DRIFT_DENIED');
    }
    const reconciled = await currentLocalAuthoritySnapshotUnderLock();
    const confirmed = await witness.readCurrent();
    if (!witnessCommitmentEquals(reconciled.commitment, confirmed)) {
      denyFormalRuntime('B02_FORMAL_WITNESS_DRIFT_DENIED');
    }
    return reconciled;
  }

  async function withAuthorityDriftLatch(operation) {
    try { return await operation(); }
    catch (error) {
      if (DRIFT_CODES.has(error?.code) || DRIFT_CODES.has(error?.message)) await latchAuthorityDrift();
      throw error;
    }
  }

  async function start() {
    if (closed) denyFormalRuntime('B02_FORMAL_RUNTIME_CLOSED');
    if (state === 'DISABLED_DRIFT') denyFormalRuntime('B02_FORMAL_RUNTIME_DRIFT_LATCHED');
    return withAuthorityDriftLatch(async () => {
      descriptorSession = await openFormalStateDescriptorSession({
        descriptorStateIoPort: ports.descriptorStateIoPort, stateRoot: stateMetadata.stateRoot
      });
      bindingStore = createDescriptorBoundDurableBindingStore({ session: descriptorSession });
      cursorStore = createDescriptorBoundProviderCursorStore({ session: descriptorSession });
      baseline = await withRuntimeAuthorityTransaction('runtime-start', reconcileCursorWitnessBeforeAuthority);
      state = 'READY';
      return Object.freeze({ state: 'READY' });
    });
  }

  async function currentPackageUnderLock(path) {
    if (closed || state !== 'READY') denyFormalRuntime('B02_FORMAL_RUNTIME_NOT_READY');
    const authority = await currentAuthoritySnapshotUnderLock();
    const ringReference = await fields.ringReferencePort.current();
    if (ringReference.ownerId !== authority.snapshot.binding.record.ownerId || !ringReference.active) {
      denyFormalRuntime('B02_FORMAL_RING_DRIFT_DENIED');
    }
    let trustPackage = null;
    if (path === 'local-encrypted') {
      const receipt = await fields.wifiTrustService.recognizeForMcpEntry();
      const stored = await fields.wifiTrustStore.readCurrent({ revisionFloor: 0 });
      if (!receipt || !stored?.record?.active) denyFormalRuntime('B02_FORMAL_WIFI_DRIFT_DENIED');
      trustPackage = deepFreeze({ record: stored.record, receipt });
    }
    return deepFreeze({ authority, binding: authority.snapshot.binding.record, ringReference, trustPackage });
  }

  async function issueMcpEntry(input) {
    if (closed || !['READY', 'RECOVERY_REQUIRED'].includes(state)) denyFormalRuntime('B02_FORMAL_RUNTIME_NOT_READY');
    const values = exactObject(input, ['transport', 'scope', 'capability', 'purpose'], 'B02_FORMAL_MCP_INPUT_DENIED');
    const transport = exactObject(values.transport, values.transport?.path === 'remote-encrypted'
      ? ['path', 'entryId', 'wifiTrust', 'sessionReceipt'] : ['path', 'entryId', 'wifiTrust'], 'B02_FORMAL_MCP_TRANSPORT_DENIED');
    if (!['local-encrypted', 'remote-encrypted'].includes(transport.path) ||
        (transport.path === 'remote-encrypted' && transport.wifiTrust !== null) ||
        (transport.path === 'local-encrypted' && transport.wifiTrust !== 'required')) denyFormalRuntime('B02_FORMAL_MCP_TRANSPORT_DENIED');
    if (transport.path === 'remote-encrypted') await ports.remoteEntryPort.consumeSessionReceipt({
      receipt: transport.sessionReceipt, entryId: transport.entryId, bootEpoch: fields.bootEpoch.digest,
      scope: values.scope, capability: values.capability, purpose: values.purpose });
    return withAuthorityDriftLatch(() => withRuntimeAuthorityTransaction('mcp-issue', async () => {
      await reconcileCursorWitnessBeforeAuthority();
      state = 'READY';
      const current = await currentPackageUnderLock(transport.path);
      const now = fields.authorityClock.monotonicNowMs();
      const nonce = fields.bootEpoch.derive(`mcp-entry:${now}:${transactionSequence}:${transport.entryId}`).slice(0, 43);
      baseline = current.authority;
      const session = transport.path === 'remote-encrypted';
      const issuer = session ? admission.issueSessionMcpEntryGrant : admission.issueMcpEntryGrant;
      return issuer({ binding: current.binding, ...(session ? {
        sessionReceipt: transport.sessionReceipt, sessionEntryId: transport.entryId, sessionBootEpoch: fields.bootEpoch.digest
      } : { providerProof: null }),
      ringReference: current.ringReference, householdId: current.ringReference.householdId,
      scope: safeLabel(values.scope), capability: safeLabel(values.capability), purpose: safeLabel(values.purpose),
      path: transport.path, wifiTrust: current.trustPackage,
      entryContext: { schema: 'ring-b02-mcp-entry-context-v1',
        entryId: `boot.${fields.bootEpoch.digest.slice(0, 16)}.${hashJson(transport.entryId).slice(0, 32)}`,
        observedAt: fields.authorityClock.monotonicNowMs(), secret: null },
        nonce, expiresAt: now + config.maximumGrantTtlMs });
    }));
  }

  async function consumeMcpEntry(input) {
    if (closed || state !== 'READY') denyFormalRuntime('B02_FORMAL_RUNTIME_NOT_READY');
    const values = exactObject(input, ['grant', 'transport'], 'B02_FORMAL_MCP_CONSUME_DENIED');
    const transport = exactObject(values.transport, values.transport?.path === 'remote-encrypted'
      ? ['path', 'entryId', 'wifiTrust', 'sessionReceipt'] : ['path', 'entryId', 'wifiTrust'], 'B02_FORMAL_MCP_TRANSPORT_DENIED');
    if (!['local-encrypted', 'remote-encrypted'].includes(transport.path) || transport.path !== values.grant?.path ||
        (transport.path === 'remote-encrypted' && transport.wifiTrust !== null) ||
        (transport.path === 'local-encrypted' && transport.wifiTrust !== 'required')) {
      denyFormalRuntime('B02_FORMAL_MCP_TRANSPORT_DENIED');
    }
    const expectedEntryId = `boot.${fields.bootEpoch.digest.slice(0, 16)}.${hashJson(transport.entryId).slice(0, 32)}`;
    if (values.grant?.entryContext?.entryId !== expectedEntryId) denyFormalRuntime('B02_FORMAL_BOOT_EPOCH_DENIED');
    if (transport.path === 'remote-encrypted') await ports.remoteEntryPort.recheckSessionReceipt({
      receipt: transport.sessionReceipt, entryId: transport.entryId, bootEpoch: fields.bootEpoch.digest,
      scope: values.grant.scope, capability: values.grant.capability, purpose: values.grant.purpose });
    return withAuthorityDriftLatch(() => withRuntimeAuthorityTransaction('mcp-consume', async () => {
      const current = await currentPackageUnderLock(transport.path);
      const session = transport.path === 'remote-encrypted';
      const consumer = session ? admission.consumeSessionMcpEntryGrant : admission.consumeMcpEntryGrant;
      return consumer({ grant: values.grant, binding: current.binding,
        ringReference: current.ringReference, wifiTrust: current.trustPackage?.record ?? null,
        ...(session ? { sessionReceipt: transport.sessionReceipt, sessionEntryId: transport.entryId,
          sessionBootEpoch: fields.bootEpoch.digest } : {}) });
    }));
  }

  async function close() {
    if (!closed) { closed = true; state = 'CLOSED'; admission = createMcpEntryAdmissionPort({ clock: () => fields.authorityClock.monotonicNowMs(), sessionAuthority: ports.remoteEntryPort }); await closeProductionPorts(); }
    return Object.freeze({ closed: true });
  }

  return Object.freeze({ enabled: true, configured: true, get ready() { return state === 'READY'; }, start,
    issueMcpEntry, consumeMcpEntry, latchAuthorityDrift, readCurrentBinding,
    currentAuthoritySnapshot: () => withAuthorityDriftLatch(() => withRuntimeAuthorityTransaction('authority-read', currentAuthoritySnapshotUnderLock)), close,
    status() { return Object.freeze({ state, configured: true, ready: state === 'READY', grants: admission.status(),
      bootEpoch: fields.bootEpoch.digest.slice(0, 16) }); } });
}

export const formalRuntimeConstants = Object.freeze({ configSchema: CONFIG_SCHEMA, emptyHash: EMPTY_HASH,
  states: Object.freeze(['CONSTRUCTED', 'READY', 'RECOVERY_REQUIRED', 'DISABLED_DRIFT', 'CLOSED']) });
