import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import { isAbsolute, resolve } from 'node:path';
import crypto from 'node:crypto';
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
import { isFormalStateDescriptorSession } from './private-durable-binding-store.mjs';

const CURSOR_SCHEMA = 'ring-b02-private-provider-cursor-v1';
const MAX_BYTES = 8192;

function validateCursor(value) {
  const fields = exactObject(value, [
    'schema', 'revision', 'provider', 'botId', 'nextOffset', 'observedAt', 'secret'
  ], 'B02_CURSOR_FORMAT_DENIED');
  if (fields.schema !== CURSOR_SCHEMA || fields.provider !== 'telegram' || fields.secret !== null) {
    denyFormalRuntime('B02_CURSOR_FORMAT_DENIED');
  }
  return deepFreeze({
    schema: CURSOR_SCHEMA,
    revision: safeRevision(fields.revision, 1),
    provider: 'telegram',
    botId: safeLabel(fields.botId, 'B02_CURSOR_FORMAT_DENIED'),
    nextOffset: safeRevision(fields.nextOffset),
    observedAt: safeTime(fields.observedAt),
    secret: null
  });
}

function hash(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

async function ensureRoot(root, fsApi) {
  await fsApi.mkdir(root, { recursive: true, mode: 0o700 });
  let handle;
  try {
    handle = await fsApi.open(root, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_DIRECTORY);
    const before = await handle.stat();
    if (!before.isDirectory()) denyFormalRuntime('B02_CURSOR_DIRECTORY_DENIED');
    await handle.chmod(0o700);
    const after = await handle.stat();
    if (!after.isDirectory() || after.dev !== before.dev || after.ino !== before.ino ||
        (after.mode & 0o777) !== 0o700) denyFormalRuntime('B02_CURSOR_DIRECTORY_DENIED');
  } catch (error) {
    if (error?.code?.startsWith('B02_')) throw error;
    denyFormalRuntime('B02_CURSOR_DIRECTORY_DENIED');
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function inspect(path, fsApi) {
  let stats;
  try { stats = await fsApi.lstat(path); }
  catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
  if (!stats.isFile() || stats.isSymbolicLink() || stats.nlink !== 1 ||
      (stats.mode & 0o777) !== 0o600 || stats.size <= 0 || stats.size > MAX_BYTES) {
    denyFormalRuntime('B02_CURSOR_FILE_DENIED');
  }
  return stats;
}

async function readCurrentFile(path, fsApi) {
  if (await inspect(path, fsApi) === null) return null;
  const handle = await fsApi.open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  let bytes;
  try {
    const stats = await handle.stat();
    if (!stats.isFile() || stats.nlink !== 1 || (stats.mode & 0o777) !== 0o600 ||
        stats.size <= 0 || stats.size > MAX_BYTES) denyFormalRuntime('B02_CURSOR_FILE_DENIED');
    bytes = await handle.readFile();
    const text = bytes.toString('utf8');
    for (const key of ['schema', 'revision', 'provider', 'botId', 'nextOffset', 'observedAt', 'secret']) {
      const matches = text.match(new RegExp(`"${key}"\\s*:`, 'g')) ?? [];
      if (matches.length !== 1) denyFormalRuntime('B02_CURSOR_FORMAT_DENIED');
    }
    return validateCursor(JSON.parse(text));
  } catch (error) {
    if (error?.code?.startsWith('B02_')) throw error;
    denyFormalRuntime('B02_CURSOR_FORMAT_DENIED');
  } finally {
    zeroBinary(bytes);
    await handle.close();
  }
}

async function writeAtomic(root, path, value, fsApi, sequence) {
  const temp = resolve(root, `.cursor.${process.pid}.${sequence}.tmp`);
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  let handle;
  try {
    handle = await fsApi.open(temp, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL |
      fsConstants.O_NOFOLLOW, 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = null;
    await inspect(path, fsApi);
    await fsApi.rename(temp, path);
    await fsApi.chmod(path, 0o600);
    const directory = await fsApi.open(root, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_DIRECTORY);
    try { await directory.sync(); } finally { await directory.close(); }
  } finally {
    zeroBinary(bytes);
    await handle?.close().catch(() => {});
    await fsApi.unlink(temp).catch((error) => { if (error?.code !== 'ENOENT') throw error; });
  }
}

export function createPrivateProviderCursorStore({ rootPath, fsApi = fs }) {
  if (typeof rootPath !== 'string' || !isAbsolute(rootPath)) denyFormalRuntime('B02_CURSOR_ROOT_DENIED');
  const root = resolve(rootPath);
  const path = resolve(root, 'current.json');
  let tail = Promise.resolve();
  let sequence = 0;

  async function readCurrent({ revisionFloor = 0 } = {}) {
    await ensureRoot(root, fsApi);
    const current = await readCurrentFile(path, fsApi);
    if (current && current.revision < safeRevision(revisionFloor)) denyFormalRuntime('B02_CURSOR_ROLLBACK_DENIED');
    return current;
  }

  function compareAndSwap(input) {
    const operation = async () => {
      const fields = exactObject(input, [
        'expectedRevision', 'expectedHash', 'botId', 'nextOffset', 'observedAt'
      ], 'B02_CURSOR_CAS_DENIED');
      const current = await readCurrent();
      const currentRevision = current?.revision ?? 0;
      const currentHash = current === null ? '0'.repeat(64) : hash(current);
      if (currentRevision !== safeRevision(fields.expectedRevision) || currentHash !== safeHash(fields.expectedHash)) {
        denyFormalRuntime('B02_CURSOR_CAS_DENIED');
      }
      const botId = safeLabel(fields.botId, 'B02_CURSOR_CAS_DENIED');
      const nextOffset = safeRevision(fields.nextOffset);
      const observedAt = safeTime(fields.observedAt);
      if (current && (current.botId !== botId || nextOffset < current.nextOffset || observedAt < current.observedAt)) {
        denyFormalRuntime('B02_CURSOR_TRANSITION_DENIED');
      }
      const next = validateCursor({
        schema: CURSOR_SCHEMA,
        revision: currentRevision + 1,
        provider: 'telegram',
        botId,
        nextOffset,
        observedAt,
        secret: null
      });
      await writeAtomic(root, path, next, fsApi, ++sequence);
      return deepFreeze({ envelope: next, hash: hash(next) });
    };
    const result = tail.then(operation, operation);
    tail = result.then(() => undefined, () => undefined);
    return result;
  }

  return Object.freeze({ productionAdmitted: false, descriptorRelative: false, readCurrent, compareAndSwap });
}

export const privateProviderCursorStoreConstants = Object.freeze({
  schema: CURSOR_SCHEMA,
  maximumBytes: MAX_BYTES,
  emptyHash: '0'.repeat(64)
});

const TRANSACTION_SCHEMA = 'ring-b02-cursor-transaction-v1';
const MARKER_PATH = 'provider-cursor/transaction.json';
const PREPARED_PATH = 'provider-cursor/next.json';
const INSPECTED = new WeakSet();

function validateTransactionMarker(value) {
  const fields = exactObject(value, [
    'schema', 'transactionId', 'stage', 'priorHash', 'nextHash', 'priorRevision',
    'nextRevision', 'botId', 'nextOffset', 'secret'
  ], 'B02_CURSOR_TRANSACTION_DENIED');
  if (fields.schema !== TRANSACTION_SCHEMA || fields.stage !== 'PREPARED' || fields.secret !== null) {
    denyFormalRuntime('B02_CURSOR_TRANSACTION_DENIED');
  }
  const priorRevision = safeRevision(fields.priorRevision, 1);
  const nextRevision = safeRevision(fields.nextRevision, 1);
  if (nextRevision !== priorRevision + 1) denyFormalRuntime('B02_CURSOR_TRANSACTION_DENIED');
  return deepFreeze({
    schema: TRANSACTION_SCHEMA,
    transactionId: safeLabel(fields.transactionId, 'B02_CURSOR_TRANSACTION_DENIED'),
    stage: 'PREPARED',
    priorHash: safeHash(fields.priorHash),
    nextHash: safeHash(fields.nextHash),
    priorRevision,
    nextRevision,
    botId: safeLabel(fields.botId, 'B02_CURSOR_TRANSACTION_DENIED'),
    nextOffset: safeRevision(fields.nextOffset),
    secret: null
  });
}

export function createDescriptorBoundProviderCursorStore({ session }) {
  if (!isFormalStateDescriptorSession(session)) denyFormalRuntime('B02_FORMAL_DESCRIPTOR_STORE_DENIED');
  const currentPath = 'provider-cursor/current.json';

  async function readCurrent({ revisionFloor = 0 } = {}) {
    const value = await session.readValidated(currentPath, MAX_BYTES, validateCursor);
    if (value && value.revision < safeRevision(revisionFloor)) denyFormalRuntime('B02_CURSOR_ROLLBACK_DENIED');
    return value;
  }

  async function prepareCursorAdvance(input) {
    const fields = exactObject(input, ['expectedCursor', 'nextOffset', 'observedAt', 'transactionId'],
      'B02_CURSOR_TRANSACTION_DENIED');
    const current = await readCurrent();
    const expected = validateCursor(fields.expectedCursor);
    if (!current || hash(current) !== hash(expected)) denyFormalRuntime('B02_FORMAL_CURSOR_DRIFT_DENIED');
    const nextOffset = safeRevision(fields.nextOffset);
    const observedAt = safeTime(fields.observedAt);
    if (nextOffset < current.nextOffset || observedAt < current.observedAt) {
      denyFormalRuntime('B02_CURSOR_TRANSITION_DENIED');
    }
    const next = validateCursor({ ...current, revision: current.revision + 1, nextOffset, observedAt });
    const marker = validateTransactionMarker({ schema: TRANSACTION_SCHEMA, transactionId: fields.transactionId,
      stage: 'PREPARED', priorHash: hash(current), nextHash: hash(next),
      priorRevision: current.revision, nextRevision: next.revision, botId: current.botId,
      nextOffset, secret: null });
    await session.createPrepared(MARKER_PATH, marker);
    try { await session.createPrepared(PREPARED_PATH, next); }
    catch (error) { await session.removePrepared(MARKER_PATH).catch(() => {}); throw error; }
    return inspectPreparedCursorAdvance();
  }

  async function inspectPreparedCursorAdvance() {
    const marker = await session.readValidated(MARKER_PATH, MAX_BYTES, validateTransactionMarker, true);
    const nextFile = await session.readValidated(PREPARED_PATH, MAX_BYTES, validateCursor, true);
    if (marker === null) {
      if (nextFile !== null) denyFormalRuntime('B02_CURSOR_TRANSACTION_DENIED');
      return null;
    }
    if (nextFile && (nextFile.botId !== marker.botId || nextFile.revision !== marker.nextRevision ||
        nextFile.nextOffset !== marker.nextOffset || hash(nextFile) !== marker.nextHash)) {
      denyFormalRuntime('B02_CURSOR_TRANSACTION_DENIED');
    }
    const prepared = Object.freeze({
      transactionId: marker.transactionId,
      next: nextFile,
      botId: marker.botId,
      priorHash: marker.priorHash,
      nextHash: marker.nextHash,
      priorRevision: marker.priorRevision,
      nextRevision: marker.nextRevision,
      markerPath: MARKER_PATH,
      preparedPath: PREPARED_PATH,
      preparedFilePresent: nextFile !== null
    });
    INSPECTED.add(prepared);
    return prepared;
  }

  async function requireStoredPrepared(prepared) {
    exactObject(prepared, [
      'transactionId', 'next', 'botId', 'priorHash', 'nextHash', 'priorRevision',
      'nextRevision', 'markerPath', 'preparedPath', 'preparedFilePresent'
    ], 'B02_CURSOR_TRANSACTION_DENIED');
    if (!INSPECTED.has(prepared) || prepared.markerPath !== MARKER_PATH || prepared.preparedPath !== PREPARED_PATH) {
      denyFormalRuntime('B02_CURSOR_TRANSACTION_DENIED');
    }
    return prepared;
  }

  async function commitPreparedCursor(prepared) {
    const stored = await requireStoredPrepared(prepared);
    if (!stored.preparedFilePresent || !stored.next) denyFormalRuntime('B02_CURSOR_TRANSACTION_DENIED');
    await session.renamePrepared(PREPARED_PATH, currentPath);
    return deepFreeze({ committed: true, revision: stored.nextRevision, alreadyCommitted: false });
  }

  async function readBackCursorCommitment(prepared) {
    const stored = await requireStoredPrepared(prepared);
    const current = await readCurrent({ revisionFloor: stored.nextRevision });
    if (!current || hash(current) !== stored.nextHash) denyFormalRuntime('B02_FORMAL_CURSOR_DRIFT_DENIED');
    return deepFreeze({ envelope: current, hash: stored.nextHash, readbackExact: true });
  }

  async function finishPreparedCursor(prepared) {
    await requireStoredPrepared(prepared);
    await session.removePrepared(MARKER_PATH);
    INSPECTED.delete(prepared);
    return Object.freeze({ finished: true });
  }

  async function abortPreparedCursor(prepared) {
    const stored = await requireStoredPrepared(prepared);
    if (!stored.preparedFilePresent) denyFormalRuntime('B02_CURSOR_TRANSACTION_DENIED');
    await session.removePrepared(PREPARED_PATH);
    await session.removePrepared(MARKER_PATH);
    INSPECTED.delete(prepared);
    return Object.freeze({ aborted: true });
  }

  async function recoverWitnessedCursorAdvance(input) {
    const fields = exactObject(input, ['prepared', 'witnessNext'], 'B02_CURSOR_TRANSACTION_DENIED');
    const stored = await requireStoredPrepared(fields.prepared);
    if (stored.nextHash !== safeHash(fields.witnessNext.cursorHash) ||
        stored.nextRevision !== safeRevision(fields.witnessNext.cursorRevision, 1) || !stored.preparedFilePresent) {
      denyFormalRuntime('B02_CURSOR_TRANSACTION_DENIED');
    }
    await commitPreparedCursor(stored);
    return readBackCursorCommitment(stored);
  }

  return Object.freeze({ productionAdmitted: true, descriptorRelative: true, readCurrent,
    prepareCursorAdvance, inspectPreparedCursorAdvance, commitPreparedCursor, readBackCursorCommitment, finishPreparedCursor,
    abortPreparedCursor, recoverWitnessedCursorAdvance });
}
