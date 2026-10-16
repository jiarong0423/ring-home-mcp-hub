// Phone pairing for the local console: a one-time 8-digit code + an explicit owner "y" on the Mac terminal gives a phone its
// own device credential. Once trusted it stays valid until an admin removes the phone (or a copied credential is detected);
// it is rotated on every use. The credential is only exchanged
// for a normal one-hour console session; it never authorizes an action by itself. Roles: admin (the owner) and member (family).
//
// Nothing here touches the network. Only SHA-256 digests of codes and credentials are stored; raw values exist in memory
// just long enough to hand them to the phone once.
import { createHash, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync, chmodSync } from 'node:fs';
import { dirname } from 'node:path';

export const PAIR_CODE_TTL_MS = 10 * 60_000;
export const CONFIRM_TTL_MS = 120_000;
export const USED_TOKEN_HISTORY = 5;
export const ROLES = Object.freeze(['admin', 'member']);
const MAX_FAILURES_PER_MINUTE = 5;
const MAX_DEVICES = 20;
const NAME = /^[\p{L}\p{N}][\p{L}\p{N} ]{0,19}$/u;

export class PhonePairingError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}
const deny = (status, code) => { throw new PhonePairingError(status, code); };
const digest = (purpose, value) => createHash('sha256').update(purpose + '\0' + value).digest('hex');
const same = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const token = random => random(32).toString('base64url');
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;

export function normalizePhoneName(value) {
  if (typeof value !== 'string') deny(400, 'PHONE_NAME_INVALID');
  const name = value.normalize('NFC').trim().replace(/ {2,}/gu, ' ');
  if (!NAME.test(name)) deny(400, 'PHONE_NAME_INVALID');
  return name;
}

// confirm({ name, role, expiresAt, check }) -> Promise<boolean>: the owner's answer AT THE MAC (system dialog or terminal). It must
// not be reachable from the phone. Family (member) requests can also be decided by a paired admin phone (decideMember), which is
// how a family member gets added without anyone touching the computer. Admin requests are only ever decided at the Mac.
export function createPhoneRegistry({ storePath, confirm, clock = Date.now, random = randomBytes, randomDigits = () => randomInt(0, 100_000_000),
  onRevoke = () => {} }) {
  if (typeof storePath !== 'string' || !storePath.startsWith('/')) throw new Error('phone store path must be absolute');
  if (typeof confirm !== 'function') throw new Error('confirm function required');
  let devices = load();
  const codes = new Map();      // codeDigest -> { role, expiresAt }
  const requests = new Map();   // requestDigest -> { name, role, status, expiresAt, approvalId, check, deviceToken?, deviceId? }
  let failures = [];
  let confirmChain = Promise.resolve();

  function load() {
    let text;
    try { text = readFileSync(storePath, 'utf8'); } catch (error) { if (error.code === 'ENOENT') return []; throw error; }
    const data = JSON.parse(text);
    if (data?.schema !== 'home-mcp-phones-v1' || !Array.isArray(data.devices)) throw new Error('phone store is corrupt');
    for (const d of data.devices) {
      if (typeof d.deviceId !== 'string' || !ROLES.includes(d.role) || typeof d.tokenHash !== 'string' || !/^[a-f0-9]{64}$/u.test(d.tokenHash)) throw new Error('phone store is corrupt');
      if (!Array.isArray(d.usedTokenHashes)) d.usedTokenHashes = typeof d.previousTokenHash === 'string' ? [d.previousTokenHash] : [];
      delete d.previousTokenHash;
    }
    return data.devices;
  }
  function persist() {
    mkdirSync(dirname(storePath), { recursive: true, mode: 0o700 });
    const tmp = storePath + '.' + random(6).toString('hex') + '.tmp';
    writeFileSync(tmp, JSON.stringify({ schema: 'home-mcp-phones-v1', devices }, null, 2) + '\n', { mode: 0o600 });
    chmodSync(tmp, 0o600);
    renameSync(tmp, storePath);
  }
  function limit() {
    const now = clock();
    failures = failures.filter(t => now - t < 60_000);
    if (failures.length >= MAX_FAILURES_PER_MINUTE) deny(429, 'PAIR_RATE_LIMIT');
  }
  const fail = code => { failures.push(clock()); deny(403, code); };
  const active = d => !d.revokedAt;   // trusted until removed: no inactivity expiry
  const publicDevice = d => ({ deviceId: d.deviceId, name: d.name, role: d.role, pairedAt: new Date(d.pairedAt).toISOString(),
    lastUsedAt: new Date(d.lastUsedAt).toISOString(), active: active(d) });

  function hasAdmin() { return devices.some(d => d.role === 'admin' && active(d)); }

  function createPairCode({ role }) {
    if (!ROLES.includes(role)) deny(400, 'PHONE_ROLE_INVALID');
    if (devices.filter(active).length >= MAX_DEVICES) deny(409, 'PHONE_LIMIT_REACHED');
    for (const [key, c] of codes) if (clock() >= c.expiresAt) codes.delete(key);
    let code;
    do { code = String(randomDigits()).padStart(8, '0'); } while (codes.has(digest('pair-code', code)));
    const expiresAt = clock() + PAIR_CODE_TTL_MS;
    codes.set(digest('pair-code', code), { role, expiresAt });
    return { code, role, expiresAt: new Date(expiresAt).toISOString() };
  }

  // Spends the code immediately (single use, even if the owner later says no) and asks the owner on the Mac terminal.
  function requestPairing({ code, name }) {
    limit();
    const cleanName = normalizePhoneName(name);
    if (typeof code !== 'string' || !/^\d{8}$/u.test(code.replace(/[\s-]/gu, ''))) fail('PAIR_CODE_INVALID');
    const key = digest('pair-code', code.replace(/[\s-]/gu, ''));
    const entry = codes.get(key);
    // One family request waits at a time, so the admin never has to tell two look-alike requests apart (the code stays usable).
    if (entry && entry.role === 'member' && [...requests.values()].some(r => r.role === 'member' && r.status === 'pending' && clock() < r.expiresAt)) deny(409, 'PAIR_BUSY');
    codes.delete(key);
    if (!entry || clock() >= entry.expiresAt) fail('PAIR_CODE_INVALID');
    failures = [];
    const requestId = token(random);
    // check: two digits shown on the asking phone AND on the approving screen; different digits mean "not the phone you think".
    const check = String(parseInt(digest('pair-check', requestId).slice(0, 8), 16) % 90 + 10);
    const record = { name: cleanName, role: entry.role, status: 'pending', expiresAt: clock() + CONFIRM_TTL_MS, approvalId: token(random), check, decide: null };
    requests.set(digest('pair-request', requestId), record);
    confirmChain = confirmChain.then(() => askOwner(record));
    return { requestId, name: cleanName, role: entry.role, check, expiresAt: new Date(record.expiresAt).toISOString() };
  }
  async function askOwner(record) {
    if (record.status !== 'pending') return;
    let approved = false;
    const settled = new AbortController();
    const remaining = record.expiresAt - clock();
    if (remaining > 0) {
      let timer;
      try {
        // signal: aborted once the request is settled any other way (admin phone, timeout), so the Mac prompt goes away too.
        const answers = [Promise.resolve(confirm({ name: record.name, role: record.role, expiresAt: record.expiresAt, check: record.check, signal: settled.signal })).then(v => v === true),
          new Promise(resolve => { timer = setTimeout(() => resolve('timeout'), remaining); timer.unref?.(); })];
        if (record.role === 'member') answers.push(new Promise(resolve => { record.decide = resolve; }));
        approved = await Promise.race(answers);
      } catch { approved = false; } finally { clearTimeout(timer); record.decide = null; settled.abort(); }
    } else approved = 'timeout';
    if (approved === 'timeout' || clock() >= record.expiresAt) { record.status = 'timeout'; return; }
    if (approved !== true) { record.status = 'rejected'; return; }
    if (record.role === 'member' && !hasAdmin()) { record.status = 'rejected'; return; }
    const rawToken = token(random);
    const now = clock();
    const device = { deviceId: 'phone_' + random(8).toString('hex'), name: record.name, role: record.role, tokenHash: digest('device', rawToken),
      usedTokenHashes: [], pairedAt: now, lastUsedAt: now, revokedAt: null };
    devices.push(device); persist();
    Object.assign(record, { status: 'approved', deviceToken: rawToken, deviceId: device.deviceId });
  }

  // The raw credential is handed out exactly once, then forgotten.
  function pairStatus({ requestId }) {
    if (typeof requestId !== 'string' || !TOKEN.test(requestId)) deny(400, 'PAIR_REQUEST_INVALID');
    const key = digest('pair-request', requestId);
    const record = requests.get(key);
    if (!record) deny(404, 'PAIR_REQUEST_UNKNOWN');
    if (record.status === 'pending') {
      if (clock() >= record.expiresAt) record.status = 'timeout';
      else return { status: 'pending', check: record.check, approver: record.role === 'admin' ? 'mac' : 'admin_phone',
        secondsLeft: Math.max(0, Math.ceil((record.expiresAt - clock()) / 1000)) };
    }
    requests.delete(key);
    if (record.status === 'approved') {
      return { status: 'approved', deviceToken: record.deviceToken, deviceId: record.deviceId, role: record.role, name: record.name,
        expiresAt: null };
    }
    deny(record.status === 'timeout' ? 410 : 403, record.status === 'timeout' ? 'PAIR_CONFIRM_TIMEOUT' : 'PAIR_REJECTED');
  }

  // Exchange: valid credential -> rotated credential. Strict rotation, no reuse window: presenting any of the last
  // USED_TOKEN_HISTORY rotated-out credentials means a copy exists, so the whole phone is revoked. (The phone page serializes
  // its own exchanges with a browser lock, so two tabs on the same phone do not trip this.)
  // requireRole: checked BEFORE rotating, so a member phone that asks for an admin-only step keeps its working credential.
  // expectDeviceId: the credential must belong to this phone (the one the caller's session came from), also checked before rotating.
  function exchange({ deviceToken, requireRole = null, expectDeviceId = null }) {
    if (typeof deviceToken !== 'string' || !TOKEN.test(deviceToken)) deny(401, 'DEVICE_TOKEN_INVALID');
    const h = digest('device', deviceToken);
    const now = clock();
    const current = devices.find(d => same(d.tokenHash, h));
    if (!current) {
      const reused = devices.find(d => d.usedTokenHashes.some(u => same(u, h)));
      if (reused && !reused.revokedAt) { revokeDevice(reused, 'reuse'); deny(401, 'DEVICE_REVOKED'); }
      deny(401, reused ? 'DEVICE_REVOKED' : 'DEVICE_TOKEN_INVALID');
    }
    if (current.revokedAt) deny(401, 'DEVICE_REVOKED');
    if (requireRole && current.role !== requireRole) deny(403, 'DEVICE_ROLE_DENIED');
    if (expectDeviceId && current.deviceId !== expectDeviceId) deny(403, 'DEVICE_SESSION_MISMATCH');
    const rawToken = token(random);
    current.usedTokenHashes = [current.tokenHash, ...current.usedTokenHashes].slice(0, USED_TOKEN_HISTORY);
    current.tokenHash = digest('device', rawToken);
    current.lastUsedAt = now;
    delete current.expiresAt;   // older stores carried a 30-day expiry; it no longer applies
    persist();
    return { deviceId: current.deviceId, name: current.name, role: current.role, deviceToken: rawToken, deviceExpiresAt: null };
  }

  function revokeDevice(device, reason) {
    device.revokedAt = clock();
    persist();
    onRevoke(device.deviceId, reason);
  }
  function revoke({ deviceId }) {
    const d = devices.find(x => x.deviceId === deviceId && !x.revokedAt);
    if (!d) deny(404, 'PHONE_UNKNOWN');
    if (d.role === 'admin' && devices.filter(x => x.role === 'admin' && active(x)).length <= 1) deny(409, 'LAST_ADMIN');
    revokeDevice(d, 'owner');
    return { revoked: true, deviceId };
  }
  // Family requests waiting for an admin phone (the admin sees name, role and the check digits; never the requester's secret id).
  function pendingMembers() {
    return [...requests.values()].filter(r => r.role === 'member' && r.status === 'pending' && r.decide && clock() < r.expiresAt)
      .map(r => ({ approvalId: r.approvalId, name: r.name, role: r.role, check: r.check, secondsLeft: Math.max(0, Math.ceil((r.expiresAt - clock()) / 1000)) }));
  }
  function decideMember({ approvalId, decision }) {
    if (decision !== 'approve' && decision !== 'deny') deny(400, 'PAIR_DECISION_INVALID');
    if (typeof approvalId !== 'string' || !TOKEN.test(approvalId)) deny(400, 'PAIR_APPROVAL_INVALID');
    const record = [...requests.values()].find(r => same(r.approvalId, approvalId));
    if (!record || record.role !== 'member') deny(404, 'PAIR_APPROVAL_UNKNOWN');
    if (record.status !== 'pending' || !record.decide || clock() >= record.expiresAt) deny(409, 'PAIR_APPROVAL_CLOSED');
    const resolve = record.decide; record.decide = null;
    resolve(decision === 'approve');
    return { decided: decision, name: record.name };
  }
  function isActive(deviceId) { const d = devices.find(x => x.deviceId === deviceId); return Boolean(d && active(d)); }

  return Object.freeze({ hasAdmin, createPairCode, requestPairing, pairStatus, exchange, revoke, isActive, pendingMembers, decideMember,
    list: () => devices.map(publicDevice), settled: () => confirmChain });
}
