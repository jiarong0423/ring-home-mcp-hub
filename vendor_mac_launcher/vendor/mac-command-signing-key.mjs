import { constants } from 'node:fs';
import { open, lstat, realpath } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { generateKeyPairSync, createPrivateKey } from 'node:crypto';
import { validateLocalPassphraseBytes } from './credential-policy.mjs';
import { createMacCommandProofSigner } from './mac-command-proof.mjs';
import { deny } from './mac-command-contract.mjs';
const NAME = 'mac-command-signing-key.pem';
async function location(directory) {
  if (typeof directory !== 'string' || resolve(directory) !== directory || await realpath(directory) !== directory) deny('MAC_KEY_DIRECTORY');
  const stat = await lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700 || stat.uid !== process.getuid()) deny('MAC_KEY_DIRECTORY');
  return join(directory, NAME);
}
function pass(value) { if (!Buffer.isBuffer(value) || !validateLocalPassphraseBytes(value)) deny('MAC_KEY_PASSPHRASE'); return Buffer.from(value); }
function validFile(stat) { if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o600 || stat.uid !== process.getuid() || stat.size < 100 || stat.size > 4096) deny('MAC_KEY_FILE'); }
// Explicit operator action only. Opening an absent identity never creates one.
export async function initializeMacCommandSigningKey({ directory, passphrase, ownerRef, associationRevision, audience, clock } = {}) {
  const path = await location(directory); const password = pass(passphrase); let fd;
  try {
    const { privateKey } = generateKeyPairSync('ed25519');
    const signer = createMacCommandProofSigner({ privateKey, ownerRef, associationRevision, audience, clock });
    const encoded = privateKey.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: password });
    fd = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    await fd.writeFile(encoded); await fd.sync(); validFile(await fd.stat()); await fd.close(); fd = null;
    const parent = await open(directory, constants.O_RDONLY | constants.O_NOFOLLOW); try { await parent.sync(); } finally { await parent.close(); }
    const descriptor = Object.freeze({ keyId: signer.keyId, publicKeySpki: signer.publicKeySpki, ownerRef: signer.ownerRef, associationRevision: signer.associationRevision });
    signer.close(); return descriptor;
  } finally { password.fill(0); await fd?.close(); }
}
export async function openMacCommandSigningKey({ directory, passphrase, ownerRef, associationRevision, audience, clock } = {}) {
  const path = await location(directory); const password = pass(passphrase); let fd; let bytes;
  try {
    fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW); validFile(await fd.stat()); bytes = await fd.readFile();
    if (!bytes.subarray(0, Buffer.byteLength('-----BEGIN ENCRYPTED PRIVATE KEY-----\n')).equals(Buffer.from('-----BEGIN ENCRYPTED PRIVATE KEY-----\n'))) deny('MAC_KEY_UNAVAILABLE');
    const key = createPrivateKey({ key: bytes, format: 'pem', passphrase: password });
    return createMacCommandProofSigner({ privateKey: key, ownerRef, associationRevision, audience, clock });
  } catch { deny('MAC_KEY_UNAVAILABLE'); }
  finally { password.fill(0); bytes?.fill(0); await fd?.close(); }
}
