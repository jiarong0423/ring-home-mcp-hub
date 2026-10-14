import fs from 'node:fs';
import path from 'node:path';
import { createCipheriv, createDecipheriv, scryptSync } from 'node:crypto';
import { types } from 'node:util';
import { validateLocalPassphraseBytes } from './credential-policy.mjs';

const MAGIC = Buffer.from('RB02CTV2', 'ascii');
const HEADER_BYTES = 50;
const TAG_BYTES = 16;
const RECORD_HEADER_BYTES = 22;
const MAX_TOKEN_BYTES = 4096;
const MAX_PLAINTEXT_BYTES = RECORD_HEADER_BYTES + 256 + MAX_TOKEN_BYTES;
const MAX_FILE_BYTES = HEADER_BYTES + MAX_PLAINTEXT_BYTES + TAG_BYTES;
const KDF = Object.freeze({ N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
const CREDENTIAL_SCHEMA = 'ring-b02-telegram-credential-v1';

export class BinaryCredentialFileError extends Error {
  constructor(code) { super(code); this.name = 'BinaryCredentialFileError'; this.code = code; }
}
function deny(code) { throw new BinaryCredentialFileError(code); }
function need(value, code) { if (!value) deny(code); }
function exact(value, keys, code = 'B02_BINARY_FORMAT_DENIED') {
  need(value && typeof value === 'object' && !Array.isArray(value) && !types.isProxy(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)), code);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const actual = Reflect.ownKeys(descriptors);
  need(actual.length === keys.length && keys.every(key => Object.hasOwn(descriptors, key)) &&
    actual.every(key => typeof key === 'string' && keys.includes(key) && descriptors[key].enumerable &&
      Object.hasOwn(descriptors[key], 'value')), code);
  return value;
}
function integer(value) {
  need(Number.isSafeInteger(value) && value >= 1 && value < Number.MAX_SAFE_INTEGER, 'B02_BINARY_RECORD_DENIED');
  return value;
}
function identity(value) {
  need(typeof value === 'string' && /^[A-Za-z][A-Za-z0-9:_-]{2,127}$/.test(value), 'B02_BINARY_RECORD_DENIED');
  return value;
}
function passphrase(value) {
  need(Buffer.isBuffer(value) && validateLocalPassphraseBytes(value), 'B02_BINARY_PASSPHRASE_DENIED');
  return Buffer.from(value);
}
function record(value) {
  const fields = exact(value, ['schema', 'purpose', 'ownerId', 'botId', 'bindingGeneration', 'token', 'secret'],
    'B02_BINARY_RECORD_DENIED');
  need(fields.schema === CREDENTIAL_SCHEMA && fields.purpose === 'telegram-bot' && fields.secret === null &&
    Buffer.isBuffer(fields.token) && fields.token.length >= 8 && fields.token.length <= MAX_TOKEN_BYTES,
    'B02_BINARY_RECORD_DENIED');
  identity(fields.ownerId); identity(fields.botId); integer(fields.bindingGeneration);
  return fields;
}
function keyFor(ownedPassphrase, salt) {
  try { return scryptSync(ownedPassphrase, salt, 32, KDF); }
  catch { deny('B02_BINARY_KDF_DENIED'); }
}

// Pure binary encoding utility; callers must supply fresh salt/nonce for a real migration.
// This module does not write stores or authorize a migration.
export function encodeBinaryCredentialFile(input) {
  const fields = exact(input, ['passphrase', 'revision', 'record', 'salt', 'nonce']);
  let ownedPassphrase = null;
  let key = null;
  let plaintext = null;
  let ciphertext = null;
  let header = null;
  let tag = null;
  try {
    ownedPassphrase = passphrase(fields.passphrase);
    const value = record(fields.record);
    const revision = integer(fields.revision);
    need(Buffer.isBuffer(fields.salt) && fields.salt.length === 16 && Buffer.isBuffer(fields.nonce) && fields.nonce.length === 12,
      'B02_BINARY_FORMAT_DENIED');
    const owner = Buffer.from(value.ownerId, 'utf8');
    const bot = Buffer.from(value.botId, 'utf8');
    plaintext = Buffer.alloc(RECORD_HEADER_BYTES + owner.length + bot.length + value.token.length);
    plaintext.writeBigUInt64BE(BigInt(revision), 0);
    plaintext.writeBigUInt64BE(BigInt(value.bindingGeneration), 8);
    plaintext.writeUInt16BE(owner.length, 16); plaintext.writeUInt16BE(bot.length, 18);
    plaintext.writeUInt16BE(value.token.length, 20);
    owner.copy(plaintext, RECORD_HEADER_BYTES); bot.copy(plaintext, RECORD_HEADER_BYTES + owner.length);
    value.token.copy(plaintext, RECORD_HEADER_BYTES + owner.length + bot.length);
    header = Buffer.alloc(HEADER_BYTES);
    MAGIC.copy(header); header[8] = 2; header[9] = 1;
    header.writeUInt32BE(KDF.N, 10); header.writeUInt16BE(KDF.r, 14); header.writeUInt16BE(KDF.p, 16);
    fields.salt.copy(header, 18); fields.nonce.copy(header, 34); header.writeUInt32BE(plaintext.length, 46);
    key = keyFor(ownedPassphrase, fields.salt);
    const cipher = createCipheriv('aes-256-gcm', key, fields.nonce, { authTagLength: TAG_BYTES });
    cipher.setAAD(header);
    ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    tag = cipher.getAuthTag();
    return Buffer.concat([header, ciphertext, tag]);
  } finally {
    ownedPassphrase?.fill(0); key?.fill(0); plaintext?.fill(0); ciphertext?.fill(0); header?.fill(0); tag?.fill(0);
  }
}

export function decodeBinaryCredentialFile(input) {
  const fields = exact(input, ['bytes', 'passphrase']);
  let ownedPassphrase = null;
  let key = null;
  let plaintext = null;
  let interim = null;
  let token = null;
  try {
    ownedPassphrase = passphrase(fields.passphrase);
    const bytes = fields.bytes;
    need(Buffer.isBuffer(bytes) && bytes.length >= HEADER_BYTES + RECORD_HEADER_BYTES + 6 + 8 + TAG_BYTES &&
      bytes.length <= MAX_FILE_BYTES, 'B02_BINARY_FORMAT_DENIED');
    need(bytes.subarray(0, 8).equals(MAGIC) && bytes[8] === 2 && bytes[9] === 1 &&
      bytes.readUInt32BE(10) === KDF.N && bytes.readUInt16BE(14) === KDF.r && bytes.readUInt16BE(16) === KDF.p,
      'B02_BINARY_FORMAT_DENIED');
    const length = bytes.readUInt32BE(46);
    need(length >= RECORD_HEADER_BYTES + 6 + 8 && length <= MAX_PLAINTEXT_BYTES &&
      bytes.length === HEADER_BYTES + length + TAG_BYTES, 'B02_BINARY_FORMAT_DENIED');
    key = keyFor(ownedPassphrase, bytes.subarray(18, 34));
    const decipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(34, 46), { authTagLength: TAG_BYTES });
    decipher.setAAD(bytes.subarray(0, HEADER_BYTES));
    decipher.setAuthTag(bytes.subarray(HEADER_BYTES + length));
    try {
      interim = decipher.update(bytes.subarray(HEADER_BYTES, HEADER_BYTES + length));
      const final = decipher.final();
      plaintext = Buffer.concat([interim, final]); final.fill(0);
    } catch { deny('B02_BINARY_AUTH_DENIED'); }
    const revision = integer(Number(plaintext.readBigUInt64BE(0)));
    const generation = integer(Number(plaintext.readBigUInt64BE(8)));
    const ownerLength = plaintext.readUInt16BE(16);
    const botLength = plaintext.readUInt16BE(18);
    const tokenLength = plaintext.readUInt16BE(20);
    need(ownerLength >= 3 && ownerLength <= 128 && botLength >= 3 && botLength <= 128 && tokenLength >= 8 &&
      tokenLength <= MAX_TOKEN_BYTES && RECORD_HEADER_BYTES + ownerLength + botLength + tokenLength === plaintext.length,
      'B02_BINARY_RECORD_DENIED');
    const ownerId = identity(plaintext.subarray(RECORD_HEADER_BYTES, RECORD_HEADER_BYTES + ownerLength).toString('utf8'));
    const botId = identity(plaintext.subarray(RECORD_HEADER_BYTES + ownerLength, RECORD_HEADER_BYTES + ownerLength + botLength).toString('utf8'));
    token = Buffer.from(plaintext.subarray(RECORD_HEADER_BYTES + ownerLength + botLength));
    const result = Object.freeze({ revision, record: Object.freeze({ schema: CREDENTIAL_SCHEMA, purpose: 'telegram-bot',
      ownerId, botId, bindingGeneration: generation, token, secret: null }) });
    token = null;
    return result;
  } finally { ownedPassphrase?.fill(0); key?.fill(0); plaintext?.fill(0); interim?.fill(0); token?.fill(0); }
}

function metadata(value, directory = false) {
  need((directory ? value.isDirectory() : value.isFile()) && value.uid === process.getuid() &&
    (value.mode & 0o7777) === (directory ? 0o700 : 0o600) && (directory ? value.nlink >= 1 : value.nlink === 1),
    'B02_BINARY_PERMISSION_DENIED');
}
function same(left, right) {
  need(left.dev === right.dev && left.ino === right.ino && left.uid === right.uid && left.gid === right.gid &&
    left.mode === right.mode && left.nlink === right.nlink && left.size === right.size &&
    left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs, 'B02_BINARY_READBACK_DENIED');
}
function checkRoot(rootPath, expected = null) {
  let current = path.parse(rootPath).root;
  for (const part of rootPath.slice(current.length).split(path.sep)) {
    current = path.join(current, part);
    const value = fs.lstatSync(current);
    need(value.isDirectory() && !value.isSymbolicLink(), 'B02_BINARY_PERMISSION_DENIED');
  }
  need(fs.realpathSync(rootPath) === rootPath, 'B02_BINARY_PERMISSION_DENIED');
  const value = fs.lstatSync(rootPath); metadata(value, true);
  if (expected) same(expected, value);
  return value;
}
function closeDescriptor(fd, descriptors) {
  try {
    const current = fs.fstatSync(fd);
    const expected = descriptors.get(fd);
    if (expected?.dev !== undefined && (current.dev !== expected.dev || current.ino !== expected.ino)) return false;
    fs.closeSync(fd);
    descriptors.delete(fd);
    return true;
  } catch (error) {
    if (error?.code === 'EBADF') { descriptors.delete(fd); return true; }
    return false;
  }
}
function readFile(rootPath, fileName, descriptors) {
  let directoryFd = null;
  let fileFd = null;
  let bytes = null;
  try {
    const root = checkRoot(rootPath);
    directoryFd = fs.openSync(rootPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_DIRECTORY);
    descriptors.set(directoryFd, {});
    descriptors.set(directoryFd, fs.fstatSync(directoryFd));
    same(root, fs.fstatSync(directoryFd));
    const target = path.join(rootPath, fileName);
    const before = fs.lstatSync(target); metadata(before); need(!before.isSymbolicLink(), 'B02_BINARY_PERMISSION_DENIED');
    need(before.size > 0 && before.size <= MAX_FILE_BYTES, 'B02_BINARY_FORMAT_DENIED');
    checkRoot(rootPath, root);
    fileFd = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    descriptors.set(fileFd, {});
    descriptors.set(fileFd, fs.fstatSync(fileFd));
    const opened = fs.fstatSync(fileFd); metadata(opened); same(before, opened);
    checkRoot(rootPath, root);
    bytes = Buffer.alloc(opened.size + 1);
    let used = 0;
    while (used < bytes.length) {
      const read = fs.readSync(fileFd, bytes, used, bytes.length - used, used);
      if (read === 0) break;
      used += read;
    }
    need(used === opened.size, 'B02_BINARY_READBACK_DENIED');
    const after = fs.fstatSync(fileFd); metadata(after); same(opened, after);
    const named = fs.lstatSync(target); metadata(named); same(after, named);
    checkRoot(rootPath, root); same(root, fs.fstatSync(directoryFd));
    const result = Buffer.from(bytes.subarray(0, used));
    return result;
  } catch (error) {
    if (error instanceof BinaryCredentialFileError) throw error;
    deny('B02_BINARY_IO_DENIED');
  } finally {
    bytes?.fill(0);
    let released = true;
    if (fileFd !== null) released = closeDescriptor(fileFd, descriptors) && released;
    if (directoryFd !== null) released = closeDescriptor(directoryFd, descriptors) && released;
    if (!released) deny('B02_BINARY_CLOSE_DENIED');
  }
}

export function createBinaryCredentialFileDriver(input) {
  const fields = exact(input, ['rootPath', 'fileName'], 'B02_BINARY_CONFIG_DENIED');
  need(typeof fields.rootPath === 'string' && path.isAbsolute(fields.rootPath) && path.normalize(fields.rootPath) === fields.rootPath &&
    fields.rootPath !== path.parse(fields.rootPath).root && !fields.rootPath.includes('\0') &&
    !fields.rootPath.endsWith(path.sep) &&
    typeof fields.fileName === 'string' && /^[A-Za-z][A-Za-z0-9._-]{0,63}$/.test(fields.fileName) &&
    typeof process.getuid === 'function' && typeof fs.constants.O_NOFOLLOW === 'number', 'B02_BINARY_CONFIG_DENIED');
  const rootPath = fields.rootPath;
  const fileName = fields.fileName;
  let closed = false;
  const sessions = new Set();
  const descriptors = new Map();
  return Object.freeze({
    async open(submittedPassphrase) {
      need(!closed, 'B02_BINARY_CLOSED');
      need(descriptors.size === 0, 'B02_BINARY_CLOSE_DENIED');
      need(sessions.size < 8, 'B02_BINARY_CAPACITY_DENIED');
      let ownedPassphrase = null;
      let bytes = null;
      let result = null;
      try {
        ownedPassphrase = passphrase(submittedPassphrase);
        bytes = readFile(rootPath, fileName, descriptors);
        result = decodeBinaryCredentialFile({ bytes, passphrase: ownedPassphrase });
        let sessionClosed = false;
        let consumed = false;
        const session = Object.freeze({
          async read() {
            need(!closed && !sessionClosed && !consumed, 'B02_BINARY_CLOSED');
            consumed = true;
            return result;
          },
          close() { sessionClosed = true; result.record.token.fill(0); sessions.delete(session);
            return Object.freeze({ closed: true, zeroized: true }); },
          status() { return Object.freeze({ closed: sessionClosed, readOnce: consumed,
            tokenResident: !sessionClosed && result.record.token.some(value => value !== 0) }); }
        });
        sessions.add(session);
        return session;
      } catch (error) {
        result?.record.token.fill(0);
        if (error instanceof BinaryCredentialFileError) throw error;
        deny('B02_BINARY_OPEN_DENIED');
      } finally { ownedPassphrase?.fill(0); bytes?.fill(0); }
    },
    close() { closed = true; for (const session of sessions) session.close();
      for (const fd of descriptors.keys()) closeDescriptor(fd, descriptors);
      return Object.freeze({ closed: true, sessions: sessions.size, openDescriptors: descriptors.size,
        resourceReleased: sessions.size === 0 && descriptors.size === 0 }); },
    status() { return Object.freeze({ closed, sessions: sessions.size, openDescriptors: descriptors.size }); }
  });
}

export const binaryCredentialFileConstants = Object.freeze({ schema: 'ring-b02-binary-credential-file-v2',
  version: 2, credentialSchema: CREDENTIAL_SCHEMA, headerBytes: HEADER_BYTES, tagBytes: TAG_BYTES,
  maximumTokenBytes: MAX_TOKEN_BYTES, maximumFileBytes: MAX_FILE_BYTES, kdf: KDF,
  readonly: true, actualMigration: false });
