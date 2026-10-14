import { isAbsolute, relative, resolve, sep } from 'node:path';
import { deepFreeze, denyFormalRuntime, exactObject } from './protocol.mjs';

const RELATIVE_PATHS = Object.freeze({
  root: 'var/private/formal-runtime',
  bindingRoot: 'var/private/formal-runtime/binding',
  bindingCurrent: 'var/private/formal-runtime/binding/current.json',
  bindingFloor: 'var/private/formal-runtime/binding/revision-floor.json',
  custody: 'var/private/formal-runtime/custody/telegram-token.enc.json',
  cursorRoot: 'var/private/formal-runtime/provider-cursor',
  cursorCurrent: 'var/private/formal-runtime/provider-cursor/current.json',
  migrationRoot: 'var/private/formal-runtime/migration',
  migrationJournal: 'var/private/formal-runtime/migration/current.json',
  migrationLock: 'var/private/formal-runtime/migration/active.lock',
  wifiTrust: 'var/private/wifi-trust/current.json'
});

function beneath(projectRoot, candidate) {
  const rel = relative(projectRoot, candidate);
  return rel !== '' && rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}

export function createFormalRuntimeStatePathContract(input) {
  const fields = exactObject(input, ['projectRoot'], 'B02_FORMAL_PATH_INPUT_DENIED');
  if (typeof fields.projectRoot !== 'string' || !isAbsolute(fields.projectRoot)) {
    denyFormalRuntime('B02_FORMAL_PATH_ROOT_DENIED');
  }
  const projectRoot = resolve(fields.projectRoot);
  const absolute = {};
  for (const [key, path] of Object.entries(RELATIVE_PATHS)) {
    absolute[key] = resolve(projectRoot, path);
    if (!beneath(projectRoot, absolute[key])) denyFormalRuntime('B02_FORMAL_PATH_ESCAPE_DENIED');
  }
  return deepFreeze({
    schema: 'ring-b02-formal-runtime-paths-v1',
    projectRoot,
    relative: { ...RELATIVE_PATHS },
    absolute,
    directoryMode: 0o700,
    fileMode: 0o600
  });
}

export const formalRuntimePathConstants = Object.freeze({ ...RELATIVE_PATHS });
