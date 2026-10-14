import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import crypto from 'node:crypto';
import { validateDurableBindingV2 } from '../wifi/durable-binding-v2.mjs';
import {
  deepFreeze,
  denyFormalRuntime,
  exactObject,
  safeHash,
  safeRevision,
  safeTime,
  zeroBinary
} from './protocol.mjs';

const STORE_SCHEMA = 'ring-b02-private-durable-binding-store-v1';
const FLOOR_SCHEMA = 'ring-b02-binding-revision-floor-v1';
const JOURNAL_SCHEMA = 'ring-b02-formal-migration-journal-v1';
const MAX_BYTES = 32_768;
const STAGES = Object.freeze(['PREPARED', 'BINDING_COMMITTED', 'CURSOR_COMMITTED', 'COMPLETE', 'RECOVERY_REQUIRED']);

function hashBytes(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function rejectDuplicateKeys(text) {
  const stack = [];
  let index = 0;
  let expectingKey = false;
  while (index < text.length) {
    const char = text[index];
    if (/\s/.test(char)) { index += 1; continue; }
    if (char === '{') { stack.push(new Set()); expectingKey = true; index += 1; continue; }
    if (char === '}') { stack.pop(); expectingKey = false; index += 1; continue; }
    if (char === '[') { stack.push(null); expectingKey = false; index += 1; continue; }
    if (char === ']') { stack.pop(); expectingKey = false; index += 1; continue; }
    if (char === ',') { expectingKey = stack.at(-1) instanceof Set; index += 1; continue; }
    if (char === ':') { expectingKey = false; index += 1; continue; }
    if (char === '"') {
      const start = index;
      index += 1;
      while (index < text.length) {
        if (text[index] === '\\') { index += 2; continue; }
        if (text[index] === '"') { index += 1; break; }
        index += 1;
      }
      if (index > text.length || text[index - 1] !== '"') denyFormalRuntime('B02_BINDING_STORE_JSON_DENIED');
      if (expectingKey && stack.at(-1) instanceof Set) {
        const key = JSON.parse(text.slice(start, index));
        if (stack.at(-1).has(key)) denyFormalRuntime('B02_BINDING_STORE_JSON_DENIED');
        stack.at(-1).add(key);
      }
      continue;
    }
    index += 1;
  }
  if (stack.length !== 0) denyFormalRuntime('B02_BINDING_STORE_JSON_DENIED');
}

async function privateDirectory(rootPath, fsApi) {
  await fsApi.mkdir(rootPath, { recursive: true, mode: 0o700 });
  let handle;
  try {
    handle = await fsApi.open(rootPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_DIRECTORY);
    const before = await handle.stat();
    if (!before.isDirectory() || before.nlink < 1) denyFormalRuntime('B02_BINDING_STORE_DIRECTORY_DENIED');
    await handle.chmod(0o700);
    const after = await handle.stat();
    if (!after.isDirectory() || after.dev !== before.dev || after.ino !== before.ino ||
        (after.mode & 0o777) !== 0o700) denyFormalRuntime('B02_BINDING_STORE_DIRECTORY_DENIED');
  } catch (error) {
    if (error?.code?.startsWith('B02_')) throw error;
    denyFormalRuntime('B02_BINDING_STORE_DIRECTORY_DENIED');
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function inspectFile(path, fsApi, allowMissing = true) {
  let stats;
  try { stats = await fsApi.lstat(path); }
  catch (error) {
    if (allowMissing && error?.code === 'ENOENT') return null;
    throw error;
  }
  if (!stats.isFile() || stats.isSymbolicLink() || stats.nlink !== 1 ||
      (stats.mode & 0o777) !== 0o600 || stats.size <= 0 || stats.size > MAX_BYTES) {
    denyFormalRuntime('B02_BINDING_STORE_FILE_DENIED');
  }
  return stats;
}

async function readJson(path, fsApi, validator) {
  if (await inspectFile(path, fsApi) === null) return null;
  const handle = await fsApi.open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  let bytes;
  try {
    const stats = await handle.stat();
    if (!stats.isFile() || stats.nlink !== 1 || (stats.mode & 0o777) !== 0o600 ||
        stats.size <= 0 || stats.size > MAX_BYTES) denyFormalRuntime('B02_BINDING_STORE_FILE_DENIED');
    bytes = await handle.readFile();
    const text = bytes.toString('utf8');
    rejectDuplicateKeys(text);
    return validator(JSON.parse(text));
  } catch (error) {
    if (error?.code?.startsWith('B02_')) throw error;
    denyFormalRuntime('B02_BINDING_STORE_JSON_DENIED');
  } finally {
    zeroBinary(bytes);
    await handle.close();
  }
}

async function atomicJson(rootPath, path, value, fsApi, sequence) {
  await privateDirectory(rootPath, fsApi);
  const tempPath = resolve(rootPath, `.formal.${process.pid}.${sequence}.tmp`);
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  let handle;
  try {
    handle = await fsApi.open(tempPath, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL |
      fsConstants.O_NOFOLLOW, 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = null;
    await inspectFile(tempPath, fsApi, false);
    await inspectFile(path, fsApi, true);
    await fsApi.rename(tempPath, path);
    await fsApi.chmod(path, 0o600);
    const directory = await fsApi.open(dirname(path), fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW |
      fsConstants.O_DIRECTORY);
    try { await directory.sync(); } finally { await directory.close(); }
  } finally {
    zeroBinary(bytes);
    await handle?.close().catch(() => {});
    await fsApi.unlink(tempPath).catch((error) => { if (error?.code !== 'ENOENT') throw error; });
  }
}

function validateEnvelope(value) {
  const fields = exactObject(value, ['schema', 'revision', 'record'], 'B02_BINDING_STORE_FORMAT_DENIED');
  if (fields.schema !== STORE_SCHEMA) denyFormalRuntime('B02_BINDING_STORE_FORMAT_DENIED');
  return deepFreeze({
    schema: STORE_SCHEMA,
    revision: safeRevision(fields.revision, 1),
    record: validateDurableBindingV2(fields.record)
  });
}

function validateFloor(value) {
  const fields = exactObject(value, ['schema', 'revision'], 'B02_BINDING_FLOOR_FORMAT_DENIED');
  if (fields.schema !== FLOOR_SCHEMA) denyFormalRuntime('B02_BINDING_FLOOR_FORMAT_DENIED');
  return deepFreeze({ schema: FLOOR_SCHEMA, revision: safeRevision(fields.revision) });
}

function validateJournal(value) {
  const fields = exactObject(value, [
    'schema', 'revision', 'stage', 'priorBindingHash', 'nextBindingHash', 'priorBindingRevision',
    'nextBindingRevision', 'priorCursorHash', 'nextCursorHash', 'priorCursorRevision',
    'nextCursorRevision', 'preparedAt', 'updatedAt', 'recoveryRequired', 'secret'
  ], 'B02_MIGRATION_JOURNAL_FORMAT_DENIED');
  if (fields.schema !== JOURNAL_SCHEMA || !STAGES.includes(fields.stage) || fields.secret !== null ||
      typeof fields.recoveryRequired !== 'boolean' ||
      fields.recoveryRequired !== (fields.stage === 'RECOVERY_REQUIRED')) {
    denyFormalRuntime('B02_MIGRATION_JOURNAL_FORMAT_DENIED');
  }
  const preparedAt = safeTime(fields.preparedAt);
  const updatedAt = safeTime(fields.updatedAt);
  if (updatedAt < preparedAt) denyFormalRuntime('B02_MIGRATION_JOURNAL_FORMAT_DENIED');
  return deepFreeze({
    schema: JOURNAL_SCHEMA,
    revision: safeRevision(fields.revision, 1),
    stage: fields.stage,
    priorBindingHash: safeHash(fields.priorBindingHash),
    nextBindingHash: safeHash(fields.nextBindingHash),
    priorBindingRevision: safeRevision(fields.priorBindingRevision),
    nextBindingRevision: safeRevision(fields.nextBindingRevision, 1),
    priorCursorHash: safeHash(fields.priorCursorHash),
    nextCursorHash: safeHash(fields.nextCursorHash),
    priorCursorRevision: safeRevision(fields.priorCursorRevision),
    nextCursorRevision: safeRevision(fields.nextCursorRevision, 1),
    preparedAt,
    updatedAt,
    recoveryRequired: fields.recoveryRequired,
    secret: null
  });
}

export function createPrivateDurableBindingStore({ rootPath, journalRootPath, fsApi = fs }) {
  if (typeof rootPath !== 'string' || typeof journalRootPath !== 'string' ||
      !isAbsolute(rootPath) || !isAbsolute(journalRootPath)) denyFormalRuntime('B02_BINDING_STORE_ROOT_DENIED');
  const root = resolve(rootPath);
  const journalRoot = resolve(journalRootPath);
  const bindingPath = resolve(root, 'current.json');
  const floorPath = resolve(root, 'revision-floor.json');
  const journalPath = resolve(journalRoot, 'current.json');
  let tail = Promise.resolve();
  let sequence = 0;

  function serial(operation) {
    const result = tail.then(operation, operation);
    tail = result.then(() => undefined, () => undefined);
    return result;
  }

  async function readRevisionFloor() {
    await privateDirectory(root, fsApi);
    const floor = await readJson(floorPath, fsApi, validateFloor);
    return floor?.revision ?? 0;
  }

  async function readCurrent({ revisionFloor = 0 } = {}) {
    await privateDirectory(root, fsApi);
    const effectiveFloor = Math.max(safeRevision(revisionFloor), await readRevisionFloor());
    const current = await readJson(bindingPath, fsApi, validateEnvelope);
    if (current !== null && current.revision < effectiveFloor) denyFormalRuntime('B02_BINDING_STORE_ROLLBACK_DENIED');
    return current;
  }

  function compareAndSwap(input) {
    return serial(async () => {
      const fields = exactObject(input, ['expectedRevision', 'expectedHash', 'record'], 'B02_BINDING_STORE_CAS_DENIED');
      const expectedRevision = safeRevision(fields.expectedRevision);
      const current = await readCurrent();
      const currentRevision = current?.revision ?? 0;
      const currentHash = current === null ? '0'.repeat(64) : hashBytes(Buffer.from(JSON.stringify(current)));
      if (currentRevision !== expectedRevision || safeHash(fields.expectedHash) !== currentHash) {
        denyFormalRuntime('B02_BINDING_STORE_CAS_DENIED');
      }
      const record = validateDurableBindingV2(fields.record);
      if (current && (record.generation < current.record.generation ||
          current.record.revoked && record.active || current.record.ownerId !== record.ownerId ||
          current.record.botId !== record.botId)) denyFormalRuntime('B02_BINDING_STORE_TRANSITION_DENIED');
      const next = validateEnvelope({ schema: STORE_SCHEMA, revision: currentRevision + 1, record });
      await atomicJson(root, bindingPath, next, fsApi, ++sequence);
      return deepFreeze({ envelope: next, hash: hashBytes(Buffer.from(JSON.stringify(next))) });
    });
  }

  function advanceRevisionFloor(input) {
    return serial(async () => {
      const fields = exactObject(input, ['expectedRevision', 'nextRevision'], 'B02_BINDING_FLOOR_CAS_DENIED');
      const current = await readRevisionFloor();
      const expected = safeRevision(fields.expectedRevision);
      const next = safeRevision(fields.nextRevision);
      if (current !== expected || next < current) denyFormalRuntime('B02_BINDING_FLOOR_CAS_DENIED');
      const record = validateFloor({ schema: FLOOR_SCHEMA, revision: next });
      await atomicJson(root, floorPath, record, fsApi, ++sequence);
      return record;
    });
  }

  async function readJournal() {
    await privateDirectory(journalRoot, fsApi);
    return readJson(journalPath, fsApi, validateJournal);
  }

  function compareAndSwapJournal(input) {
    return serial(async () => {
      const fields = exactObject(input, ['expectedRevision', 'journal'], 'B02_MIGRATION_JOURNAL_CAS_DENIED');
      const current = await readJournal();
      const expected = safeRevision(fields.expectedRevision);
      if ((current?.revision ?? 0) !== expected) denyFormalRuntime('B02_MIGRATION_JOURNAL_CAS_DENIED');
      const journal = validateJournal(fields.journal);
      if (journal.revision !== expected + 1) denyFormalRuntime('B02_MIGRATION_JOURNAL_CAS_DENIED');
      if (current && journal.preparedAt !== current.preparedAt) denyFormalRuntime('B02_MIGRATION_JOURNAL_CAS_DENIED');
      const allowed = current === null
        ? journal.stage === 'PREPARED'
        : ({
            PREPARED: ['BINDING_COMMITTED'],
            BINDING_COMMITTED: ['CURSOR_COMMITTED', 'RECOVERY_REQUIRED'],
            CURSOR_COMMITTED: ['COMPLETE', 'RECOVERY_REQUIRED'],
            RECOVERY_REQUIRED: ['COMPLETE'],
            COMPLETE: []
          }[current.stage] ?? []).includes(journal.stage);
      if (!allowed) denyFormalRuntime('B02_MIGRATION_JOURNAL_TRANSITION_DENIED');
      await atomicJson(journalRoot, journalPath, journal, fsApi, ++sequence);
      return journal;
    });
  }

  return Object.freeze({
    productionAdmitted: false,
    descriptorRelative: false,
    readCurrent,
    compareAndSwap,
    readRevisionFloor,
    advanceRevisionFloor,
    readJournal,
    compareAndSwapJournal
  });
}

export const privateDurableBindingStoreConstants = Object.freeze({
  storeSchema: STORE_SCHEMA,
  floorSchema: FLOOR_SCHEMA,
  journalSchema: JOURNAL_SCHEMA,
  stages: STAGES,
  maximumBytes: MAX_BYTES,
  emptyHash: '0'.repeat(64)
});

const DESCRIPTOR_SESSIONS = new WeakSet();

export function isFormalStateDescriptorSession(value) {
  return Boolean(value && DESCRIPTOR_SESSIONS.has(value));
}

function sameDescriptorIdentity(left, right) {
  return left && right && left.type === right.type && left.dev === right.dev && left.ino === right.ino &&
    left.nlink === right.nlink && left.mode === right.mode;
}

export async function openFormalStateDescriptorSession({ descriptorStateIoPort, stateRoot }) {
  if (!descriptorStateIoPort || descriptorStateIoPort.productionAdmitted !== true ||
      descriptorStateIoPort.descriptorRelative !== true || stateRoot !== 'var/private/formal-runtime') {
    denyFormalRuntime('B02_FORMAL_DESCRIPTOR_SESSION_DENIED');
  }
  const root = await descriptorStateIoPort.openRootNoFollow({ stateRoot });
  if (root === null || root === undefined) denyFormalRuntime('B02_FORMAL_DESCRIPTOR_SESSION_DENIED');
  const rootIdentity = await descriptorStateIoPort.statAt({ root, relativePath: '.', noFollow: true });
  if (!rootIdentity || rootIdentity.type !== 'directory') {
    await descriptorStateIoPort.close({ root }).catch(() => {});
    denyFormalRuntime('B02_FORMAL_DESCRIPTOR_SESSION_DENIED');
  }
  let closed = false;
  async function verifyDescriptorContinuity() {
    if (closed) denyFormalRuntime('B02_FORMAL_DESCRIPTOR_SESSION_CLOSED');
    const current = await descriptorStateIoPort.statAt({ root, relativePath: '.', noFollow: true });
    if (!sameDescriptorIdentity(rootIdentity, current)) denyFormalRuntime('B02_FORMAL_DESCRIPTOR_IDENTITY_DRIFT');
    return current;
  }
  async function readValidated(relativePath, maximumBytes, validator, allowMissing = false) {
    await verifyDescriptorContinuity();
    const before = await descriptorStateIoPort.statAt({ root, relativePath, noFollow: true, allowMissing });
    if (before === null && allowMissing) return null;
    if (!before || before.type !== 'file' || before.nlink !== 1 || before.mode !== 0o600 ||
        !Number.isSafeInteger(before.size) || before.size <= 0 || before.size > maximumBytes) {
      denyFormalRuntime('B02_FORMAL_DESCRIPTOR_CHILD_DENIED');
    }
    let bytes = await descriptorStateIoPort.readAt({ root, relativePath, maximumBytes, noFollow: true });
    try {
      if (!Buffer.isBuffer(bytes) || bytes.length !== before.size) denyFormalRuntime('B02_FORMAL_DESCRIPTOR_READ_DENIED');
      const after = await descriptorStateIoPort.statAt({ root, relativePath, noFollow: true });
      if (!sameDescriptorIdentity(before, after)) denyFormalRuntime('B02_FORMAL_DESCRIPTOR_IDENTITY_DRIFT');
      await verifyDescriptorContinuity();
      return validator(JSON.parse(bytes.toString('utf8')));
    } catch (error) {
      if (error?.code?.startsWith('B02_')) throw error;
      denyFormalRuntime('B02_FORMAL_DESCRIPTOR_READ_DENIED');
    } finally { zeroBinary(bytes); bytes = null; }
  }
  async function createPrepared(relativePath, value) {
    await verifyDescriptorContinuity();
    const bytes = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
    try {
      await descriptorStateIoPort.createTempAt({ root, relativePath, bytes, mode: 0o600, exclusive: true, noFollow: true });
      await descriptorStateIoPort.fsyncFile({ root, relativePath });
      await verifyDescriptorContinuity();
    } finally { zeroBinary(bytes); }
  }
  async function renamePrepared(fromRelativePath, toRelativePath) {
    await verifyDescriptorContinuity();
    await descriptorStateIoPort.renameAt({ root, fromRelativePath, toRelativePath, noReplace: false });
    await descriptorStateIoPort.fsyncDirectory({ root, relativePath: dirname(toRelativePath) });
    await verifyDescriptorContinuity();
  }
  async function removePrepared(relativePath) {
    await verifyDescriptorContinuity();
    await descriptorStateIoPort.unlinkAt({ root, relativePath, noFollow: true });
    await descriptorStateIoPort.fsyncDirectory({ root, relativePath: dirname(relativePath) });
    await verifyDescriptorContinuity();
  }
  async function close() {
    if (!closed) { closed = true; await descriptorStateIoPort.close({ root }); }
    return Object.freeze({ closed: true });
  }
  const session = Object.freeze({ productionAdmitted: true, descriptorRelative: true, readValidated,
    createPrepared, renamePrepared, removePrepared, verifyDescriptorContinuity, close });
  DESCRIPTOR_SESSIONS.add(session);
  return session;
}

export function createDescriptorBoundDurableBindingStore({ session }) {
  if (!session || !DESCRIPTOR_SESSIONS.has(session)) denyFormalRuntime('B02_FORMAL_DESCRIPTOR_STORE_DENIED');
  const custodyValidator = (value) => {
    const fields = exactObject(value, ['schema', 'revision'], 'B02_FORMAL_CUSTODY_META_DENIED');
    if (fields.schema !== 'ring-b02-formal-custody-meta-v1') denyFormalRuntime('B02_FORMAL_CUSTODY_META_DENIED');
    return deepFreeze({ schema: fields.schema, revision: safeRevision(fields.revision, 1) });
  };
  return Object.freeze({
    productionAdmitted: true,
    descriptorRelative: true,
    readCurrent: async ({ revisionFloor = 0 } = {}) => {
      const current = await session.readValidated('binding/current.json', MAX_BYTES, validateEnvelope);
      if (current.revision < safeRevision(revisionFloor)) denyFormalRuntime('B02_BINDING_STORE_ROLLBACK_DENIED');
      return current;
    },
    readRevisionFloor: async () => (await session.readValidated('binding/revision-floor.json', MAX_BYTES, validateFloor)).revision,
    readJournal: async () => session.readValidated('migration/current.json', MAX_BYTES, validateJournal),
    currentCustodyRevision: async () => (await session.readValidated('custody/revision.json', MAX_BYTES, custodyValidator)).revision,
    verifyDescriptorContinuity: session.verifyDescriptorContinuity,
    close: session.close
  });
}
