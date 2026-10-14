import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import { createHash } from 'node:crypto';
import { isAbsolute, normalize, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { types } from 'node:util';
import { exactObject, denyFormalRuntime, FormalRuntimeError } from './protocol.mjs';

const ROOT = 'var/private/formal-runtime';
const MAX_BYTES = 65_536;
const MAX_QUEUE = 16;
const TIMEOUT = 5_000;
const HELPER_PINS = Object.freeze([
  { name: 'run_state_io', mode: 0o755, sha256: 'e189b410db602f7dca8983e951e8cbe0e894bf862d919b7b44b6e8ada6a30a0d' },
  { name: 'state_io.py', mode: 0o644, sha256: '581d4c90f31bbda55b19d0742f466a149c83d0d5319957f257ba5446d1c4c6f4' }
]);
const helperPath = name => fileURLToPath(new URL(`../../tools/formal-state-io/${name}`, import.meta.url));
const error = code => new FormalRuntimeError(code);
function fields(value, required, optional = []) {
  if (!value || types.isProxy(value)) denyFormalRuntime('B02_NATIVE_STATE_INPUT_DENIED');
  const keys = Reflect.ownKeys(value);
  if (required.some(key => !keys.includes(key)) || keys.some(key => ![...required, ...optional].includes(key))) {
    denyFormalRuntime('B02_NATIVE_STATE_INPUT_DENIED');
  }
  return exactObject(value, keys, 'B02_NATIVE_STATE_INPUT_DENIED');
}
function path(value, dot = false) {
  if (dot && value === '.') return value;
  if (typeof value !== 'string' || value.length > 256 || value.split('/').length > 8 ||
      value.split('/').some(part => !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(part) || ['.', '..'].includes(part))) {
    denyFormalRuntime('B02_NATIVE_STATE_PATH_DENIED');
  }
  return value;
}
function label(value) {
  if (typeof value !== 'string' || !/^[A-Za-z][A-Za-z0-9:._-]{2,127}$/.test(value)) {
    denyFormalRuntime('B02_NATIVE_STATE_INPUT_DENIED');
  }
  return value;
}
function absolute(value) {
  if (typeof value !== 'string' || !isAbsolute(value) || normalize(value) !== value || value === '/' || value.endsWith('/')) {
    denyFormalRuntime('B02_NATIVE_STATE_CONFIG_DENIED');
  }
  return value;
}
async function verifyHelper() {
  for (const pin of HELPER_PINS) {
    const file = await fs.open(helperPath(pin.name), constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const stat = await file.stat();
      if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== process.getuid() || (stat.mode & 0o777) !== pin.mode ||
          createHash('sha256').update(await file.readFile()).digest('hex') !== pin.sha256) {
        denyFormalRuntime('B02_NATIVE_STATE_HELPER_PIN_DENIED');
      }
    } finally { await file.close(); }
  }
}

export function createNativeStatePorts(input) {
  const config = fields(input, ['baseDirectory'], ['pythonBin']);
  const baseDirectory = absolute(config.baseDirectory);
  const pythonBin = absolute(Object.hasOwn(config, 'pythonBin') ? config.pythonBin : '/usr/local/bin/python3');
  if (!/^python3(?:\.\d{1,2})?$/.test(basename(pythonBin))) denyFormalRuntime('B02_NATIVE_STATE_CONFIG_DENIED');
  let child = null;
  let alive = false;
  let closed = false;
  let failed = false;
  let startPromise = null;
  let exitPromise = null;
  let resolveExit;
  let nextId = 1;
  let current = null;
  let output = '';
  let stderrBytes = 0;
  let exitObserved = false;
  let exitCode = null;
  let initialized = false;
  const queue = [];
  const pending = new Map();
  const roots = new WeakMap();
  const activeRoots = new Set();
  function status() {
    return Object.freeze({ closed, inFlight: pending.size, helperRunning: alive, helperPid: alive ? child.pid : null,
      openRoots: activeRoots.size, exitObserved, exitCode, resourceReleased: closed && !alive && pending.size === 0 });
  }
  function fail(code) {
    if (failed) return;
    failed = true;
    for (const item of pending.values()) {
      clearTimeout(item.timer);
      if (!item.settled) { item.settled = true; item.reject(error(code)); }
    }
    queue.length = 0;
    if (alive) { child.stdin.destroy(); child.kill('SIGTERM'); }
  }
  function drain() {
    if (current || failed || !alive) return;
    current = queue.shift() ?? null;
    if (!current) return;
    const item = current;
    item.timer = setTimeout(() => fail('B02_NATIVE_STATE_TIMEOUT'), TIMEOUT);
    child.stdin.write(JSON.stringify({ id: item.id, op: item.op, values: item.values }) + '\n', err => {
      if (err) fail('B02_NATIVE_STATE_HELPER_DENIED');
    });
  }
  function schedule(op, values, internal = false) {
    if ((closed && !internal) || failed || !alive) return Promise.reject(error('B02_NATIVE_STATE_CLOSED'));
    if (pending.size >= MAX_QUEUE) return Promise.reject(error('B02_NATIVE_STATE_CAPACITY_DENIED'));
    return new Promise((resolve, reject) => {
      const item = { id: nextId++, op, values, resolve, reject, settled: false, timer: null };
      pending.set(item.id, item); queue.push(item); drain();
    });
  }
  function receive(line) {
    try {
      const packet = JSON.parse(line);
      fields(packet, ['id', 'ok'], packet.ok === true ? ['result'] : ['error']);
      if (!current || packet.id !== current.id || typeof packet.ok !== 'boolean' ||
          (packet.ok ? !Object.hasOwn(packet, 'result') : typeof packet.error !== 'string' || !/^B02_NATIVE_STATE_[A-Z_]+$/.test(packet.error))) {
        throw error('B02_NATIVE_STATE_HELPER_DENIED');
      }
      const item = current;
      clearTimeout(item.timer);
      current = null; pending.delete(item.id);
      if (!item.settled) {
        item.settled = true;
        if (packet.ok) item.resolve(packet.result); else item.reject(error(packet.error));
      }
      drain();
    } catch { fail('B02_NATIVE_STATE_HELPER_DENIED'); }
  }
  function start() {
    if (startPromise) return startPromise;
    startPromise = (async () => {
      await verifyHelper();
      if (closed) throw error('B02_NATIVE_STATE_CLOSED');
      child = spawn(helperPath('run_state_io'), [], { stdio: ['pipe', 'pipe', 'pipe'],
        env: { ...process.env, RING_STATE_PYTHON_BIN: pythonBin } });
      alive = true;
      exitPromise = new Promise(resolve => { resolveExit = resolve; });
      child.on('error', () => fail('B02_NATIVE_STATE_RUNNER_PREREQUISITE'));
      child.stdin.on('error', () => fail(initialized ? 'B02_NATIVE_STATE_HELPER_DENIED' : 'B02_NATIVE_STATE_RUNNER_PREREQUISITE'));
      child.stdout.setEncoding('utf8');
      child.stdout.on('data', data => {
        if (failed) return;
        output += data;
        if (output.length > 200_000) { fail('B02_NATIVE_STATE_HELPER_DENIED'); return; }
        let at;
        while ((at = output.indexOf('\n')) !== -1) {
          const line = output.slice(0, at); output = output.slice(at + 1); receive(line);
        }
      });
      child.stderr.on('data', data => { stderrBytes += data.length; if (stderrBytes > 4096) fail('B02_NATIVE_STATE_HELPER_DENIED'); });
      child.on('close', code => {
        alive = false; exitObserved = true; exitCode = code;
        for (const item of pending.values()) {
          clearTimeout(item.timer);
          if (!item.settled) { item.settled = true; item.reject(error(code === 78 ? 'B02_NATIVE_STATE_RUNNER_PREREQUISITE' : 'B02_NATIVE_STATE_HELPER_DENIED')); }
        }
        pending.clear(); queue.length = 0; activeRoots.clear(); current = null; output = '';
        resolveExit();
      });
      const ready = await schedule('init', { baseDirectory });
      fields(ready, ['ready', 'pid', 'pythonVersion']);
      if (ready.ready !== true || ready.pid !== child.pid || typeof ready.pythonVersion !== 'string') {
        fail('B02_NATIVE_STATE_HELPER_DENIED'); throw error('B02_NATIVE_STATE_HELPER_DENIED');
      }
      initialized = true;
    })().catch(caught => {
      if (child) fail(caught?.code ?? 'B02_NATIVE_STATE_HELPER_DENIED');
      throw caught?.code?.startsWith('B02_NATIVE_STATE_') ? caught : error('B02_NATIVE_STATE_RUNNER_PREREQUISITE');
    });
    return startPromise;
  }
  async function call(op, values, canStart = false) {
    if (closed || failed) throw error('B02_NATIVE_STATE_CLOSED');
    if (canStart) await start();
    if (!alive) throw error('B02_NATIVE_STATE_NOT_OPEN');
    return schedule(op, values);
  }
  function handle(value) {
    if (!value || types.isProxy(value) || !roots.has(value) || !activeRoots.has(value)) {
      denyFormalRuntime('B02_NATIVE_STATE_HANDLE_DENIED');
    }
    return roots.get(value);
  }
  async function closeAll() {
    if (!closed) {
      closed = true;
      if (alive) {
        if (pending.size) fail('B02_NATIVE_STATE_CLOSED');
        else { try { await schedule('shutdown', {}, true); } catch { fail('B02_NATIVE_STATE_CLOSED'); } }
      }
    }
    if (startPromise && !child) await startPromise.catch(() => {});
    if (alive && exitPromise) {
      let timer;
      await Promise.race([exitPromise, new Promise(resolve => { timer = setTimeout(resolve, 3000); })]);
      clearTimeout(timer);
    }
    return status();
  }
  const descriptorStateIoPort = Object.freeze({
    productionAdmitted: true, descriptorRelative: true,
    async openRootNoFollow(input) {
      const f = fields(input, ['stateRoot']);
      if (f.stateRoot !== ROOT) denyFormalRuntime('B02_NATIVE_STATE_ROOT_DENIED');
      const result = await call('openRootNoFollow', { stateRoot: ROOT }, true);
      fields(result, ['handle']);
      if (typeof result.handle !== 'string' || !/^[a-f0-9]{32}$/.test(result.handle)) throw error('B02_NATIVE_STATE_HELPER_DENIED');
      const opaque = Object.freeze(Object.create(null)); roots.set(opaque, result.handle); activeRoots.add(opaque); return opaque;
    },
    async statAt(input) {
      const f = fields(input, ['root', 'relativePath', 'noFollow'], ['allowMissing']);
      if (f.noFollow !== true || (Object.hasOwn(f, 'allowMissing') && typeof f.allowMissing !== 'boolean')) denyFormalRuntime('B02_NATIVE_STATE_INPUT_DENIED');
      const result = await call('statAt', { root: handle(f.root), relativePath: path(f.relativePath, true), noFollow: true, allowMissing: f.allowMissing ?? false });
      if (result === null && f.allowMissing === true) return null;
      fields(result, ['type', 'dev', 'ino', 'uid', 'gid', 'nlink', 'mode', 'size']);
      if (!['file', 'directory'].includes(result.type) || Object.entries(result).some(([key, value]) => key !== 'type' && (!Number.isSafeInteger(value) || value < 0))) {
        throw error('B02_NATIVE_STATE_HELPER_DENIED');
      }
      return Object.freeze(result);
    },
    async readAt(input) {
      const f = fields(input, ['root', 'relativePath', 'maximumBytes', 'noFollow']);
      if (f.noFollow !== true || !Number.isSafeInteger(f.maximumBytes) || f.maximumBytes < 1 || f.maximumBytes > MAX_BYTES) denyFormalRuntime('B02_NATIVE_STATE_INPUT_DENIED');
      const result = await call('readAt', { root: handle(f.root), relativePath: path(f.relativePath), maximumBytes: f.maximumBytes, noFollow: true });
      fields(result, ['bytes']);
      if (typeof result.bytes !== 'string' || result.bytes.length > 87_384) throw error('B02_NATIVE_STATE_HELPER_DENIED');
      const bytes = Buffer.from(result.bytes, 'base64');
      if (bytes.length > f.maximumBytes || bytes.toString('base64') !== result.bytes) { bytes.fill(0); throw error('B02_NATIVE_STATE_HELPER_DENIED'); }
      return bytes;
    },
    async createTempAt(input) {
      const f = fields(input, ['root', 'relativePath', 'bytes', 'mode', 'exclusive', 'noFollow']);
      if (f.mode !== 0o600 || f.exclusive !== true || f.noFollow !== true || types.isProxy(f.bytes) || !Buffer.isBuffer(f.bytes) || !f.bytes.length || f.bytes.length > MAX_BYTES) denyFormalRuntime('B02_NATIVE_STATE_INPUT_DENIED');
      return call('createTempAt', { root: handle(f.root), relativePath: path(f.relativePath), bytes: f.bytes.toString('base64'), mode: 0o600, exclusive: true, noFollow: true });
    },
    async renameAt(input) {
      const f = fields(input, ['root', 'fromRelativePath', 'toRelativePath', 'noReplace']);
      if (f.noReplace !== false) denyFormalRuntime('B02_NATIVE_STATE_INPUT_DENIED');
      return call('renameAt', { root: handle(f.root), fromRelativePath: path(f.fromRelativePath), toRelativePath: path(f.toRelativePath), noReplace: false });
    },
    async unlinkAt(input) {
      const f = fields(input, ['root', 'relativePath', 'noFollow']);
      if (f.noFollow !== true) denyFormalRuntime('B02_NATIVE_STATE_INPUT_DENIED');
      return call('unlinkAt', { root: handle(f.root), relativePath: path(f.relativePath), noFollow: true });
    },
    async fsyncFile(input) { const f = fields(input, ['root', 'relativePath']); return call('fsyncFile', { root: handle(f.root), relativePath: path(f.relativePath) }); },
    async fsyncDirectory(input) { const f = fields(input, ['root', 'relativePath']); return call('fsyncDirectory', { root: handle(f.root), relativePath: path(f.relativePath, true) }); },
    async close(input) {
      const f = fields(input, ['root']); const token = handle(f.root);
      const result = await call('close', { root: token }); activeRoots.delete(f.root); return result;
    }
  });
  const stateTransactionLockPort = Object.freeze({
    productionAdmitted: true,
    async acquireExclusive(input) { const f = fields(input, ['ownerNonce', 'purpose']); return call('acquireExclusive', { ownerNonce: label(f.ownerNonce), purpose: label(f.purpose) }, true); },
    async releaseOwned(input) { const f = fields(input, ['ownerNonce']); return call('releaseOwned', { ownerNonce: label(f.ownerNonce) }); },
    close: closeAll
  });
  return Object.freeze({ descriptorStateIoPort, stateTransactionLockPort, close: closeAll, status });
}

export const nativeStateIoConstants = Object.freeze({ stateRoot: ROOT, maximumBytes: MAX_BYTES, maximumPending: MAX_QUEUE,
  rpcTimeoutMs: TIMEOUT, defaultPythonBin: '/usr/local/bin/python3', fixedRunner: 'tools/formal-state-io/run_state_io',
  admissionQualification: 'Concrete native port interface only; formal state activation/witness/assembly not admitted' });
