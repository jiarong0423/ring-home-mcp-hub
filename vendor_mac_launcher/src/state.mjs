import { constants, mkdirSync, chmodSync, lstatSync, realpathSync, readdirSync } from 'node:fs';
import { open } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { coded } from './config.mjs';

export function defaultStateDir(env = process.env) { return env.RING_MAC_STATE_DIR || join(homedir(), '.ring-mac-worker'); }
function check700(path) {
  const s = lstatSync(path);
  if (!s.isDirectory() || s.isSymbolicLink() || s.uid !== process.getuid() || (s.mode & 0o777) !== 0o700) throw coded('STATE_DIR_PERMISSIONS');
}
// Creates (if absent) the 0700 state directory and its 0700 subdirectories; returns resolved absolute paths.
export function ensureState(stateDir) { return ensureStateInner(stateDir); }
function ensureStateInner(stateDir) {
  if (typeof stateDir !== 'string' || !stateDir.startsWith('/')) throw coded('STATE_DIR_ABSOLUTE_REQUIRED');
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const root = realpathSync(stateDir); chmodSync(root, 0o700); check700(root);
  const dirs = { root };
  for (const k of ['keys', 'journal', 'oauth']) {
    const p = join(root, k);
    try { mkdirSync(p, { mode: 0o700 }); } catch (e) { if (e.code !== 'EEXIST') throw e; }
    chmodSync(p, 0o700); check700(p); dirs[k] = p;
  }
  return Object.freeze(dirs);
}
export async function writeSecretFile(path, text, { exclusive = false } = {}) {
  const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_NOFOLLOW | (exclusive ? constants.O_EXCL : constants.O_TRUNC);
  const fd = await open(path, flags, 0o600);
  try { await fd.chmod(0o600); await fd.writeFile(text); await fd.sync(); } finally { await fd.close(); }
}
export async function readSecretFile(path, maxBytes = 16384) {
  let fd;
  try { fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW); }
  catch (e) { if (e.code === 'ENOENT') return null; throw coded('STATE_FILE_UNREADABLE'); }
  try {
    const s = await fd.stat();
    if (!s.isFile() || s.nlink !== 1 || s.uid !== process.getuid() || (s.mode & 0o777) !== 0o600 || s.size > maxBytes) throw coded('STATE_FILE_PERMISSIONS');
    return await fd.readFile('utf8');
  } finally { await fd.close(); }
}
export function listDir(path) { try { return readdirSync(path); } catch { return []; } }
