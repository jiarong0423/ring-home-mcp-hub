// Face HINT for the door approval screen (DOOR_APPROVAL_PLAN_zh.md §3.6). It never opens anything: it only tells the admin
// "looks like <enrolled name>" or "not enrolled"; the admin still presses Approve or Deny.
//
// Ring Appstore content policy, as built here:
//   - only people the admin enrolled, each with a separate "this person agreed" consent (consent === true, timestamped)
//   - only the 128-number SFace feature is kept, never the photo; the store is AES-256-GCM encrypted (key in a separate 0600 file)
//   - delete one person or everyone at any time (the file is rewritten / removed)
//   - local only: no cloud, no email, no logs; the hint is shown on the admin phone's approval banner and nowhere else
// Face finding and features run in a separate local Python process (src/face_worker.py, OpenCV YuNet + SFace).
import { spawn } from 'node:child_process';
import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalizePhoneName } from './phone_pairing.mjs';

export const COSINE_MATCH = 0.363;          // OpenCV's SFace guidance: cosine >= 0.363 -> same person
export const MAX_PEOPLE = 20;
export const MAX_IMAGE_BYTES = 1_500_000;
const SCHEMA = 'home-mcp-faces-v1';
const FEATURE_LEN = 128;

export class FaceHintError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}
const deny = (status, code) => { throw new FaceHintError(status, code); };

const encodeFeature = (values) => Buffer.from(new Float32Array(values).buffer).toString('base64');
const decodeFeature = (b64) => { const buf = Buffer.from(b64, 'base64'); return Array.from(new Float32Array(buf.buffer, buf.byteOffset, buf.length / 4)); };
export function cosine(a, b) {
  let dot = 0; let na = 0; let nb = 0;
  for (let i = 0; i < a.length; i += 1) { dot += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i]; }
  return na === 0 || nb === 0 ? 0 : dot / Math.sqrt(na * nb);
}
const validFeature = (f) => Array.isArray(f) && f.length === FEATURE_LEN && f.every((v) => Number.isFinite(v));

// ---- Encrypted store: { people: [{ id, name, feature(base64 float32), consentAt, enrolledAt }] } ----
export function createFaceStore({ storePath, keyPath, clock = Date.now }) {
  if (!isAbsolute(storePath) || !isAbsolute(keyPath)) throw new Error('face store and key paths must be absolute');
  if (dirname(storePath) === dirname(keyPath)) throw new Error('face key must live outside the store folder');
  let people = [];
  const ensureDir = (dir) => { mkdirSync(dir, { recursive: true, mode: 0o700 }); chmodSync(dir, 0o700); };
  const atomicWrite = (path, data) => { const tmp = `${path}.${process.pid}.tmp`; writeFileSync(tmp, data, { mode: 0o600 }); chmodSync(tmp, 0o600); renameSync(tmp, path); };
  function key({ create }) {
    if (existsSync(keyPath)) {
      const k = readFileSync(keyPath);
      if (k.length !== 32 || (statSync(keyPath).mode & 0o077) !== 0) throw new Error('face key unreadable or not private');
      return k;
    }
    if (!create) return null;
    ensureDir(dirname(keyPath));
    const k = randomBytes(32);
    atomicWrite(keyPath, k);
    return k;
  }
  function load() {
    if (!existsSync(storePath)) { people = []; return; }
    const k = key({ create: false });
    if (!k) throw new Error('face store exists but its key is missing');
    const box = JSON.parse(readFileSync(storePath, 'utf8'));
    if (box.schema !== SCHEMA) throw new Error('face store schema');
    const decipher = createDecipheriv('aes-256-gcm', k, Buffer.from(box.iv, 'base64'));
    decipher.setAAD(Buffer.from(SCHEMA)); decipher.setAuthTag(Buffer.from(box.tag, 'base64'));
    const plain = JSON.parse(Buffer.concat([decipher.update(Buffer.from(box.data, 'base64')), decipher.final()]).toString('utf8'));
    people = Array.isArray(plain.people) ? plain.people : [];
  }
  function persist() {
    ensureDir(dirname(storePath));
    const k = key({ create: true });
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', k, iv); cipher.setAAD(Buffer.from(SCHEMA));
    const data = Buffer.concat([cipher.update(JSON.stringify({ people })), cipher.final()]);
    atomicWrite(storePath, JSON.stringify({ schema: SCHEMA, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') }));
  }
  load();
  return Object.freeze({
    list: () => people.map(({ id, name, consentAt, enrolledAt }) => ({ id, name, consentAt: new Date(consentAt).toISOString(), enrolledAt: new Date(enrolledAt).toISOString() })),
    features: () => people.map((p) => ({ id: p.id, name: p.name, feature: decodeFeature(p.feature) })),
    add({ name, feature }) {
      if (people.length >= MAX_PEOPLE) deny(409, 'FACE_LIMIT');
      if (people.some((p) => p.name === name)) deny(409, 'FACE_NAME_TAKEN');
      const now = clock();
      const person = { id: randomUUID(), name, feature: encodeFeature(feature), consentAt: now, enrolledAt: now };
      people = [...people, person]; persist();
      return { id: person.id, name };
    },
    remove(id) {
      if (!people.some((p) => p.id === id)) deny(404, 'FACE_UNKNOWN');
      people = people.filter((p) => p.id !== id); persist();
      return { removed: 1 };
    },
    // Everyone: remove the encrypted file and its key; the next enrolment starts with a new key.
    removeAll() {
      const n = people.length; people = [];
      rmSync(storePath, { force: true }); rmSync(keyPath, { force: true });
      return { removed: n };
    }
  });
}

// ---- Local OpenCV worker (one request at a time; restarted on demand) ----
const WORKER_SCRIPT = join(dirname(fileURLToPath(import.meta.url)), 'face_worker.py');
export function createFaceWorker({ python, detModel, recModel, spawnImpl = spawn, timeoutMs = 15_000, readyMs = 20_000, script = WORKER_SCRIPT }) {
  let child = null; let ready = null; let buffer = ''; let seq = 0;
  const waiting = new Map();
  let chain = Promise.resolve();
  function stop() {
    if (child) { child.kill('SIGTERM'); child = null; }
    ready = null; buffer = '';
    for (const [, w] of waiting) w.reject(new FaceHintError(503, 'FACE_WORKER_STOPPED'));
    waiting.clear();
  }
  function start() {
    if (ready) return ready;
    child = spawnImpl(python, ['-I', script, detModel, recModel], { stdio: ['pipe', 'pipe', 'ignore'] });
    const proc = child;
    ready = new Promise((resolve, reject) => {
      const timer = setTimeout(() => { reject(new FaceHintError(503, 'FACE_WORKER_START_TIMEOUT')); stop(); }, readyMs);
      proc.stdout.on('data', (chunk) => {
        buffer += chunk;
        if (buffer.length > 8_000_000) { stop(); return; }
        let nl;
        while ((nl = buffer.indexOf('\n')) >= 0) {
          const line = buffer.slice(0, nl); buffer = buffer.slice(nl + 1);
          let msg; try { msg = JSON.parse(line); } catch { continue; }
          if (msg.ready === true) { clearTimeout(timer); resolve(); continue; }
          const w = waiting.get(msg.id); if (!w) continue;
          waiting.delete(msg.id); w.resolve(msg);
        }
      });
      proc.once('exit', () => { clearTimeout(timer); if (child === proc) stop(); reject(new FaceHintError(503, 'FACE_WORKER_EXITED')); });
      proc.once('error', () => { clearTimeout(timer); if (child === proc) stop(); reject(new FaceHintError(503, 'FACE_WORKER_UNAVAILABLE')); });
    });
    ready.catch(() => {});
    return ready;
  }
  async function analyseNow(bytes) {
    await start();
    const id = ++seq;
    const answer = new Promise((resolve, reject) => {
      const timer = setTimeout(() => { waiting.delete(id); reject(new FaceHintError(504, 'FACE_WORKER_TIMEOUT')); stop(); }, timeoutMs);
      waiting.set(id, { resolve: (m) => { clearTimeout(timer); resolve(m); }, reject: (e) => { clearTimeout(timer); reject(e); } });
    });
    child.stdin.write(JSON.stringify({ id, image: bytes.toString('base64') }) + '\n');
    const msg = await answer;
    if (msg.error) deny(msg.error === 'IMAGE_INVALID' ? 400 : 503, msg.error);
    const faces = Array.isArray(msg.faces) ? msg.faces.filter((f) => validFeature(f.feature)) : [];
    return { faces: faces.map((f) => ({ score: Number(f.score) || 0, feature: f.feature })) };
  }
  return Object.freeze({
    analyse(bytes) { const run = chain.then(() => analyseNow(bytes)); chain = run.catch(() => {}); return run; },
    close: stop
  });
}

// ---- The hint service ----
export function looksLikeImage(bytes) {
  return Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= MAX_IMAGE_BYTES
    && ((bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) || bytes.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])));
}
export function createFaceHint({ store = null, worker = null, disabledReason = null }) {
  const enabled = Boolean(store && worker && !disabledReason);
  const need = () => { if (!enabled) deny(503, 'FACE_HINT_DISABLED'); };
  function compare(faces) {
    const known = store.features();
    return faces.map((f) => {
      let best = null;
      for (const p of known) { const s = cosine(f.feature, p.feature); if (!best || s > best.score) best = { name: p.name, score: s }; }
      return best && best.score >= COSINE_MATCH ? { match: true, name: best.name, score: Math.round(best.score * 100) / 100 } : { match: false };
    });
  }
  return Object.freeze({
    enabled,
    status: () => ({ enabled, reason: enabled ? null : (disabledReason ?? 'not_configured'), people: enabled ? store.list().length : 0, threshold: COSINE_MATCH }),
    list() { need(); return store.list(); },
    async enroll({ name, consent, image }) {
      need();
      if (consent !== true) deny(400, 'FACE_CONSENT_REQUIRED');
      let clean;
      try { clean = normalizePhoneName(name); } catch { deny(400, 'FACE_NAME_INVALID'); }
      if (!looksLikeImage(image)) deny(400, 'IMAGE_INVALID');
      const { faces } = await worker.analyse(image);
      if (faces.length === 0) deny(422, 'NO_FACE');
      if (faces.length > 1) deny(422, 'MULTIPLE_FACES');
      return store.add({ name: clean, feature: faces[0].feature });
    },
    remove(id) { need(); if (typeof id !== 'string' || !/^[0-9a-f-]{36}$/u.test(id)) deny(400, 'FACE_ID_INVALID'); return store.remove(id); },
    removeAll() { need(); return store.removeAll(); },
    // Hint for one image. Never throws: the approval flow must work with or without it.
    async hint(image) {
      if (!enabled) return { state: 'disabled', reason: disabledReason ?? 'not_configured' };
      if (!looksLikeImage(image)) return { state: 'no_image' };
      try {
        const { faces } = await worker.analyse(image);
        if (faces.length === 0) return { state: 'no_face' };
        const results = compare(faces);
        return { state: results.some((r) => r.match) ? 'match' : 'unknown', faces: results };
      } catch (error) { return { state: 'error', reason: typeof error?.code === 'string' ? error.code : 'FACE_HINT_FAILED' }; }
    }
  });
}

// Reads HOME_MCP_FACE_PYTHON (absolute python of the face venv) and HOME_MCP_FACE_MODELS (folder with the two .onnx files).
export function readFaceConfig(env, home) {
  const python = env.HOME_MCP_FACE_PYTHON; const models = env.HOME_MCP_FACE_MODELS;
  if (!python && !models) return { disabledReason: 'not_configured' };
  if (!python || !models || !isAbsolute(python) || !isAbsolute(models)) return { disabledReason: 'config_invalid' };
  const detModel = join(models, 'face_detection_yunet_2023mar.onnx'); const recModel = join(models, 'face_recognition_sface_2021dec.onnx');
  if (![python, detModel, recModel].every((p) => existsSync(p))) return { disabledReason: 'files_missing' };
  return { python, detModel, recModel,
    storePath: env.HOME_MCP_FACE_STORE || join(home, '.home-mcp-console', 'faces', 'faces.enc'),
    keyPath: env.HOME_MCP_FACE_KEY || join(home, '.home-mcp-console', 'face.key') };
}
