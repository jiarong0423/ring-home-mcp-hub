import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import { validateHouseholdWifiTrust } from './household-wifi-trust.mjs';

const STORE_SCHEMA = 'ring-b02-private-wifi-trust-store-v1';
const FILE_NAME = 'current.json';
const MAX_BYTES = 16_384;

export class PrivateWifiTrustStoreError extends Error {
  constructor(code) {
    super(code);
    this.name = 'PrivateWifiTrustStoreError';
    this.code = code;
  }
}

function deny(code) {
  throw new PrivateWifiTrustStoreError(code);
}

function exact(value, keys, code) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny(code);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some(key => typeof key !== 'string' || !keys.includes(key)) ||
      keys.some(key => !Object.hasOwn(descriptors, key)) ||
      Object.values(descriptors).some(item => !item.enumerable || !Object.hasOwn(item, 'value'))) deny(code);
  return value;
}

function revision(value, code = 'B02_WIFI_STORE_REVISION_DENIED') {
  if (!Number.isSafeInteger(value) || value < 0 || value >= Number.MAX_SAFE_INTEGER) deny(code);
  return value;
}

function validateEnvelope(value) {
  const fields = exact(value, ['schema', 'revision', 'record'], 'B02_WIFI_STORE_FORMAT_DENIED');
  if (fields.schema !== STORE_SCHEMA) deny('B02_WIFI_STORE_FORMAT_DENIED');
  return Object.freeze({
    schema: STORE_SCHEMA,
    revision: revision(fields.revision),
    record: validateHouseholdWifiTrust(fields.record)
  });
}

async function ensurePrivateDirectory(rootPath, fsApi) {
  await fsApi.mkdir(rootPath, { recursive: true, mode: 0o700 });
  let handle = null;
  try {
    handle = await fsApi.open(rootPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW |
      fsConstants.O_DIRECTORY);
    const before = await handle.stat();
    if (!before.isDirectory()) deny('B02_WIFI_STORE_DIRECTORY_DENIED');
    await handle.chmod(0o700);
    const after = await handle.stat();
    if (!after.isDirectory() || after.dev !== before.dev || after.ino !== before.ino ||
        (after.mode & 0o777) !== 0o700) deny('B02_WIFI_STORE_DIRECTORY_DENIED');
  } catch (error) {
    if (error instanceof PrivateWifiTrustStoreError) throw error;
    deny('B02_WIFI_STORE_DIRECTORY_DENIED');
  } finally {
    if (handle) await handle.close().catch(() => {});
  }
}

async function inspectExistingFile(filePath, fsApi) {
  let stats;
  try { stats = await fsApi.lstat(filePath); }
  catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
  if (!stats.isFile() || stats.isSymbolicLink() || stats.nlink !== 1 || (stats.mode & 0o777) !== 0o600 ||
      stats.size <= 0 || stats.size > MAX_BYTES) deny('B02_WIFI_STORE_FILE_DENIED');
  return stats;
}

async function readEnvelope(filePath, fsApi) {
  const stats = await inspectExistingFile(filePath, fsApi);
  if (stats === null) return null;
  const handle = await fsApi.open(filePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const currentStats = await handle.stat();
    if (!currentStats.isFile() || currentStats.nlink !== 1 || (currentStats.mode & 0o777) !== 0o600 ||
        currentStats.size <= 0 || currentStats.size > MAX_BYTES) deny('B02_WIFI_STORE_FILE_DENIED');
    const bytes = await handle.readFile();
    try {
      if (bytes.length === 0 || bytes.length > MAX_BYTES) deny('B02_WIFI_STORE_FILE_DENIED');
      return validateEnvelope(JSON.parse(bytes.toString('utf8')));
    } catch (error) {
      if (error instanceof PrivateWifiTrustStoreError) throw error;
      deny('B02_WIFI_STORE_FORMAT_DENIED');
    } finally {
      bytes.fill(0);
    }
  } finally {
    await handle.close();
  }
}

async function atomicWrite(rootPath, filePath, envelope, fsApi, sequence) {
  const tempPath = resolve(rootPath, `.current.${process.pid}.${sequence}.tmp`);
  const bytes = Buffer.from(`${JSON.stringify(envelope)}\n`, 'utf8');
  let handle = null;
  try {
    handle = await fsApi.open(tempPath, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL |
      fsConstants.O_NOFOLLOW, 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = null;
    await inspectExistingFile(tempPath, fsApi);
    const existing = await inspectExistingFile(filePath, fsApi);
    if (existing?.isSymbolicLink()) deny('B02_WIFI_STORE_FILE_DENIED');
    await fsApi.rename(tempPath, filePath);
    await fsApi.chmod(filePath, 0o600);
    const directory = await fsApi.open(dirname(filePath), fsConstants.O_RDONLY);
    try { await directory.sync(); }
    finally { await directory.close(); }
  } finally {
    bytes.fill(0);
    if (handle) await handle.close().catch(() => {});
    await fsApi.unlink(tempPath).catch(error => { if (error?.code !== 'ENOENT') throw error; });
  }
}

export function createPrivateWifiTrustStore({ rootPath, fsApi = fs }) {
  if (typeof rootPath !== 'string' || rootPath.length === 0 || !isAbsolute(rootPath)) {
    deny('B02_WIFI_STORE_ROOT_DENIED');
  }
  const privateRoot = resolve(rootPath);
  const filePath = resolve(privateRoot, FILE_NAME);
  let tail = Promise.resolve();
  let sequence = 0;

  async function readCurrent({ revisionFloor = 0 } = {}) {
    await ensurePrivateDirectory(privateRoot, fsApi);
    const current = await readEnvelope(filePath, fsApi);
    if (current !== null && current.revision < revision(revisionFloor)) deny('B02_WIFI_STORE_ROLLBACK_DENIED');
    return current;
  }

  function compareAndSwap(input) {
    const operation = async () => {
      const fields = exact(input, ['expectedRevision', 'revisionFloor', 'record'], 'B02_WIFI_STORE_CAS_DENIED');
      const expectedRevision = revision(fields.expectedRevision, 'B02_WIFI_STORE_CAS_DENIED');
      const revisionFloor = revision(fields.revisionFloor, 'B02_WIFI_STORE_CAS_DENIED');
      const record = validateHouseholdWifiTrust(fields.record);
      const current = await readCurrent({ revisionFloor });
      const currentRevision = current?.revision ?? 0;
      if (currentRevision !== expectedRevision || currentRevision < revisionFloor) deny('B02_WIFI_STORE_CAS_DENIED');
      const next = Object.freeze({ schema: STORE_SCHEMA, revision: currentRevision + 1, record });
      await atomicWrite(privateRoot, filePath, next, fsApi, ++sequence);
      return next;
    };
    const result = tail.then(operation, operation);
    tail = result.then(() => undefined, () => undefined);
    return result;
  }

  return Object.freeze({ readCurrent, compareAndSwap });
}

export const privateWifiTrustStoreConstants = Object.freeze({
  schema: STORE_SCHEMA,
  fileName: FILE_NAME,
  directoryMode: 0o700,
  fileMode: 0o600,
  maximumBytes: MAX_BYTES
});
