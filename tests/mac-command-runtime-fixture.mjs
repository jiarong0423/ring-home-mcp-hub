import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createDurableBindingV2, rotateDurableBindingV2 } from '../src/wifi/durable-binding-v2.mjs';
import { createHouseholdWifiTrust, recognizeHouseholdWifi } from '../src/wifi/household-wifi-trust.mjs';
import { createMcpEntryAdmissionPort, createRingReference } from '../src/wifi/mcp-entry-admission.mjs';
import { createMacRemoteEntryPorts } from '../src/formal-runtime/remote-entry-port.mjs';
import { deriveFormalEntryTransport } from '../src/formal-runtime/production-ports.mjs';
import { createAuthorityClock } from '../src/formal-runtime/protocol.mjs';
import { createDisabledFormalRuntimeComposition, createFormalRuntimeComposition } from '../src/formal-runtime/runtime-assembly.mjs';

const ownerId = 'Owner_fixture';
const botId = 'Bot_fixture';
const householdId = 'household.fixture';
const wall = 1_800_000_000_000;
const mono = wall;
const empty = '0'.repeat(64);
const hash = (value) => crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');

export function inMemoryRuntimeInputs({ postBotId = botId, postUsername = 'Homemcphub_bot', transientTimeout = false,
  confirmDenied = false, renameDenied = false, sharedState = null } = {}) {
  const shared = sharedState ?? { files: new Map(), witnessed: null, initialized: false };
  const faults = { confirmDenied, renameDenied };
  let binding = { revision: 1, record: createDurableBindingV2({ ownerId, botId, generation: 1,
    verifiedAt: wall, rotatedAt: wall, evidenceVersion: 'fixture-v1' }) };
  let cursor = { schema: 'ring-b02-private-provider-cursor-v1', revision: 1, provider: 'telegram', botId,
    nextOffset: 42, observedAt: wall, secret: null };
  const journal = { schema: 'ring-b02-formal-migration-journal-v1', revision: 1, stage: 'COMPLETE',
    priorBindingHash: empty, nextBindingHash: empty, priorBindingRevision: 0, nextBindingRevision: 1,
    priorCursorHash: empty, nextCursorHash: empty, priorCursorRevision: 0, nextCursorRevision: 1,
    preparedAt: wall, updatedAt: wall, recoveryRequired: false, secret: null };
  const trust = createHouseholdWifiTrust({ householdId, generation: 1,
    keyedFingerprint: `wfk1.${'A'.repeat(43)}`, verifiedAt: wall, rotatedAt: wall, consentEvidence: 'fixture-v1' });
  const ringReference = createRingReference({ schema: 'ring-b02-ring-reference-v1', active: true, revoked: false,
    ownerId, householdId, revision: 1, rotatedAt: wall, revokedAt: null, secret: null });
  let bootClosed = false;
  let sessionRevoked = false;
  let sessionOwnerId = ownerId, sessionBotId = botId;
  let monotonic = mono;
  const bootEpoch = Object.freeze({ productionAdmitted: true, digest: 'a'.repeat(64),
    derive(label) { if (bootClosed) throw new Error('B02_FORMAL_BOOT_EPOCH_CLOSED');
      return crypto.createHash('sha256').update(`fixture:${label}`).digest('base64url'); },
    status() { return { closed: bootClosed, keyResident: !bootClosed }; },
    close() { bootClosed = true; return { closed: true }; } });
  const clock = createAuthorityClock({ productionAdmitted: true, monotonicNowMs: () => monotonic, wallNowMs: () => wall });
  const bindingEnvelope = () => ({ schema: 'ring-b02-private-durable-binding-store-v1', ...binding });
  const commitment = () => ({ bindingRevision: binding.revision, bindingHash: hash(bindingEnvelope()),
    cursorRevision: cursor.revision, cursorHash: hash(cursor), journalRevision: journal.revision, journalHash: hash(journal) });
  let witnessed = commitment();
  let grantCount = 0;
  let credentialCalls = 0;
  let transportCalls = 0;
  let witnessAdvance = 0;
  let witnessConfirm = 0;
  let lockAcquire = 0;
  let lockRelease = 0;
  let meCalls = 0;
  const closeCounts = new Map();
  const closePort = (name, extra = {}) => ({ productionAdmitted: true, ...extra,
    async close() { closeCounts.set(name, (closeCounts.get(name) ?? 0) + 1); } });
  const witnessPort = closePort('witness', {
    async readCurrent() { return shared.witnessed; },
    async compareAndAdvance({ expectedCommitment, nextCommitment }) {
      assert.deepEqual(expectedCommitment, shared.witnessed); witnessAdvance += 1; shared.witnessed = nextCommitment;
      return { advanced: true };
    },
    async confirm({ commitment }) { assert.deepEqual(commitment, shared.witnessed); witnessConfirm += 1;
      return { confirmed: !faults.confirmDenied }; }
  });
  const completeJournal = journal;
  const files = shared.files;
  const put = (name, value) => files.set(name, { bytes: Buffer.from(`${JSON.stringify(value)}\n`), ino: files.size + 10 });
  if (!shared.initialized) {
    put('binding/current.json', { schema: 'ring-b02-private-durable-binding-store-v1', ...binding });
    put('binding/revision-floor.json', { schema: 'ring-b02-binding-revision-floor-v1', revision: 1 });
    put('migration/current.json', completeJournal);
    put('custody/revision.json', { schema: 'ring-b02-formal-custody-meta-v1', revision: 1 });
    put('provider-cursor/current.json', cursor);
    shared.witnessed = commitment();
    shared.initialized = true;
  }
  witnessed = shared.witnessed;
  const rootHandle = Object.freeze({ opaque: true });
  const descriptorStateIoPort = closePort('descriptor', { descriptorRelative: true,
    async openRootNoFollow() { return rootHandle; },
    async readAt({ relativePath }) { return Buffer.from(files.get(relativePath).bytes); },
    async createTempAt({ relativePath, bytes }) { if (files.has(relativePath)) throw new Error('EEXIST');
      files.set(relativePath, { bytes: Buffer.from(bytes), ino: files.size + 100 }); },
    async renameAt({ fromRelativePath, toRelativePath }) { if (faults.renameDenied) throw new Error('RENAME_DENIED');
      const value = files.get(fromRelativePath);
      if (!value) throw new Error('ENOENT'); files.set(toRelativePath, value); files.delete(fromRelativePath); },
    async unlinkAt({ relativePath }) { if (!files.delete(relativePath)) throw new Error('ENOENT'); },
    async statAt({ relativePath, allowMissing }) { if (relativePath === '.') return { type: 'directory', dev: 1, ino: 1, nlink: 1, mode: 0o700, size: 0 };
      const value = files.get(relativePath); if (!value && allowMissing) return null; if (!value) throw new Error('ENOENT');
      return { type: 'file', dev: 1, ino: value.ino, nlink: 1, mode: 0o600, size: value.bytes.length }; },
    async fsyncFile() {}, async fsyncDirectory() {} });
  let lockOwner = null;
  const stateTransactionLockPort = { productionAdmitted: true, async acquireExclusive({ ownerNonce }) {
    if (lockOwner !== null) return { acquired: false, ownerNonce }; lockOwner = ownerNonce; lockAcquire += 1;
    return { acquired: true, ownerNonce }; },
    async releaseOwned({ ownerNonce }) { assert.equal(ownerNonce, lockOwner); lockOwner = null; lockRelease += 1;
      return { released: true }; } };
  const credentialOperatorPort = closePort('credential', { async openLease() { credentialCalls += 1; return { productionAdmitted: true,
    secretBufferBoundary: 'mutable-buffer-v1', async withToken(consumer) { return consumer(Buffer.from('temporary-token')); }, async close() {} }; } });
  const challenge = `/start ${bootEpoch.derive(`tg:${mono}`).slice(0, 32)}`;
  const telegramTransportPort = closePort('telegram', { secretBufferBoundary: 'mutable-buffer-v1',
    async getMeWithLease() { transportCalls += 1; meCalls += 1; return { ok: true, result: {
      id: meCalls === 1 ? botId : postBotId, isBot: true,
      username: meCalls === 1 ? 'Homemcphub_bot' : postUsername } }; },
    async getUpdatesWithLease() { transportCalls += 1; if (transientTimeout) throw new Error('TG_TIMEOUT');
      const currentOffset = JSON.parse(files.get('provider-cursor/current.json').bytes.toString('utf8')).nextOffset;
      return { ok: true, result: [{ update_id: currentOffset, message: {
      message_id: 1, date: wall / 1000, chat: { id: ownerId, type: 'private' },
      from: { id: ownerId, is_bot: false }, text: challenge
    } }] }; }
  });
  const localSessionPort = closePort('local', { async resolve() { return { productionAdmitted: true, singleUse: true,
    loopback: true, path: 'local-encrypted', purpose: 'mcp-entry', bootEpoch: bootEpoch.digest, entryId: 'entry.fixture' }; } });
  const remoteEntryPort = null;
  const formalCapabilityPort = closePort('capability', { async list() { return { tools: [] }; }, async execute() { return { ok: true }; } });
  const runtimeOptions = { config: { schema: 'ring-b02-formal-runtime-config-v1', enabled: true,
    profile: 'FORMAL', stateRoot: 'var/private/formal-runtime', maximumGrantTtlMs: 300_000,
    providerCallsOnConstruction: false, externalWitnessRequired: true },
    statePathMetadata: { stateRoot: 'var/private/formal-runtime' },
    wifiTrustService: { async recognizeForMcpEntry() { return recognizeHouseholdWifi({ trust,
      observedKeyedFingerprint: trust.keyedFingerprint, observedAt: wall }); } },
    wifiTrustStore: { async readCurrent() { return { revision: 1, record: trust }; } },
    ringReferencePort: { productionAdmitted: true, async current() { return ringReference; } },
    productionPorts: { antiRollbackWitnessPort: witnessPort, descriptorStateIoPort, stateTransactionLockPort,
      credentialOperatorPort, telegramTransportPort, localSessionPort, remoteEntryPort, formalCapabilityPort },
    authorityClock: clock, bootEpoch };
  return { runtimeOptions, clock, bootEpoch, binding: binding.record, ringReference,
    currentBindingPort: { async readCurrent() { return { binding: binding.record, credentialRevision: 1 }; } },
    counts: () => ({ credentialCalls, transportCalls, lockAcquire, lockRelease }),
    revoke() { sessionRevoked = true; },
    sessionCurrent() { if (sessionRevoked) throw new Error('SYNTHETIC_SESSION_REVOKED'); return true; }
  };
}
