import { join } from 'node:path';
import { initializeMacCommandSigningKey, openMacCommandSigningKey } from '../vendor/mac-command-signing-key.mjs';
import { createMacCommandHttpsClient } from '../vendor/mac-command-https-client.mjs';
import { createMacCommandJournal } from '../vendor/mac-command-journal.mjs';
import { createMacCommandWorker } from '../vendor/mac-command-worker.mjs';
import { text as opaqueText, homeDeviceAllowed } from '../vendor/mac-command-contract.mjs';
import { coded } from './config.mjs';
import { ensureState, writeSecretFile, readSecretFile, listDir } from './state.mjs';
import { buildLogin, savePending, readPending, consumePending, parseCallbackUrl, exchangeCode } from './oauth.mjs';
import { callJson, genericStatus, summarizeMe, summarizeDevices, sha256Hex } from './api.mjs';
import { callMcpTool } from './mcp-client.mjs';
import { randomBytes } from 'node:crypto';
import { createDirectExecutor } from './direct-executor.mjs';

const IDENTITY = 'identity.json';
export async function readIdentity(dirs) {
  const t = await readSecretFile(join(dirs.root, IDENTITY)); if (t === null) return null;
  const i = JSON.parse(t);
  if (i.schema !== 'ring-mac-identity-v1') throw coded('IDENTITY_CORRUPT');
  return i;
}
export async function keygen({ stateDir, passphrase, ownerRef, associationRevision, cfg, clock }) {
  const dirs = ensureState(stateDir);
  opaqueText(ownerRef);
  if (!Number.isSafeInteger(associationRevision) || associationRevision < 1) throw coded('ASSOCIATION_REVISION_INVALID');
  if (await readIdentity(dirs)) throw coded('IDENTITY_EXISTS');
  const d = await initializeMacCommandSigningKey({ directory: dirs.keys, passphrase, ownerRef, associationRevision, audience: cfg.audience, clock });
  await writeSecretFile(join(dirs.root, IDENTITY), JSON.stringify({ schema: 'ring-mac-identity-v1', ownerRef, associationRevision,
    keyId: d.keyId, publicKeySpki: d.publicKeySpki }), { exclusive: true });
  return { keyId: d.keyId, publicKeySpki: d.publicKeySpki,
    // expiresAt deliberately omitted: operator adds epoch ms with now < expiresAt <= now+86400000 when POST /mac/enroll runs.
    approvalSkeleton: { schema: 'ring-mac-enrollment-approval-v1', ownerRef, associationRevision, keyId: d.keyId,
      publicKeySpki: d.publicKeySpki, expectedRevision: 0, revision: 1 } };
}
export async function loginUrl({ stateDir, cfg, now, random }) {
  const dirs = ensureState(stateDir);
  const { url, record } = buildLogin(cfg, { now, random });
  await savePending(dirs, record);
  return { url, expiresAt: record.expiresAt };
}
// Shared: validate callback, open the key BEFORE spending the single-use code, exchange once, build the worker.
// A caller that already holds a token from an earlier exchange (`token`, the local console reusing one login for its
// lifetime) skips the callback entirely; `onToken` hands a fresh token back to such a caller.
async function withWorkerSession({ stateDir, cfg, passphrase, callbackUrl, token: given = null, onToken = () => {}, polls, clock,
  tokenRequest, httpsRequest, timeoutMs, applyHomeDevice }, body) {
  const dirs = ensureState(stateDir);
  const identity = await readIdentity(dirs); if (!identity) throw coded('NO_IDENTITY_RUN_KEYGEN_FIRST');
  if (!Number.isSafeInteger(polls) || polls < 1 || polls > 20) throw coded('POLLS_RANGE');
  let cb = null, pending = null;
  if (given === null) {
    cb = parseCallbackUrl(callbackUrl, cfg);
    pending = await consumePending(dirs, { now: clock() });
    if (pending.state !== cb.state) throw coded('CALLBACK_STATE_MISMATCH');
  } else if (typeof given?.accessToken !== 'string' || !Number.isSafeInteger(given.expiresAtMs) || clock() >= given.expiresAtMs - 3000) {
    throw coded('OAUTH_TOKEN_EXPIRED');
  }
  const signer = await openMacCommandSigningKey({ directory: dirs.keys, passphrase, ownerRef: identity.ownerRef,
    associationRevision: identity.associationRevision, audience: cfg.audience, clock });
  try {
    if (signer.keyId !== identity.keyId) throw coded('KEY_IDENTITY_MISMATCH');
    const token = given ?? await exchangeCode(cfg, { code: cb.code, verifier: pending.verifier }, { requestImpl: tokenRequest, now: clock });
    if (given === null) onToken(token);
    const getAccessToken = async () => { if (clock() >= token.expiresAtMs - 3000) throw coded('OAUTH_TOKEN_EXPIRED'); return token.accessToken; };
    const client = createMacCommandHttpsClient({ baseUrl: cfg.apiBase, expectedHostname: cfg.expectedHostname, getAccessToken,
      proofSigner: signer, timeoutMs, ...(httpsRequest ? { request: httpsRequest } : {}) });
    const journal = await createMacCommandJournal({ directory: dirs.journal });
    const exec = createDirectExecutor({ identity, clock, applyHomeDevice });
    const worker = createMacCommandWorker({ transport: client, journal, clock, authorizeCommand: exec.authorizeCommand, dispatchFormal: exec.dispatchFormal });
    return await body({ token, getAccessToken, worker, reused: given !== null });
  } finally { signer.close(); }
}
async function pollWorker(worker, polls, intervalMs, sleep, log = () => {}) {
  const results = [];
  for (let i = 0; i < polls; i++) {
    if (i) await sleep(intervalMs);
    const r = await worker.runOnce(); results.push(r);
    log('worker poll ' + (i + 1) + ': ' + r.status + (r.commandId ? ' ' + r.commandId : ''));
    if (r.status !== 'EMPTY') break;
  }
  return results;
}
// One or more polls: exchange callback code -> fetch -> verify -> execute (in-memory software switch) -> receipt.
export async function run({ polls = 1, intervalMs = 1000, clock = Date.now, timeoutMs = 2500, sleep = ms => new Promise(r => setTimeout(r, ms)), ...o }) {
  return withWorkerSession({ ...o, polls, clock, timeoutMs }, async ({ token, worker }) => {
    const results = await pollWorker(worker, polls, intervalMs, sleep);
    return { mode: 'software-direct', results, tokenSecondsRemaining: Math.max(0, Math.floor((token.expiresAtMs - clock()) / 1000)) };
  });
}
const stamp = line => process.stderr.write(new Date().toISOString() + ' ' + line + '\n');
// One Cognito exchange: MCP tools/call set -> worker fetch/verify/execute/receipt -> MCP tools/call result.
export async function demoSwitch({ enabled, polls = 5, intervalMs = 1000, clock = Date.now, timeoutMs = 2500, mcpTimeoutMs = 8000,
  log = stamp, sleep = ms => new Promise(r => setTimeout(r, ms)), random = randomBytes, ...o }) {
  if (typeof enabled !== 'boolean') throw coded('ENABLED_BOOLEAN_REQUIRED');
  log('demo-switch start mode=software-direct enabled=' + enabled);
  return withWorkerSession({ ...o, polls, clock, timeoutMs }, async ({ getAccessToken, worker, reused }) => {
    log(reused ? 'cognito session reused (not shown)' : 'cognito token exchanged (not shown)');
    const mcp = (name, args) => getAccessToken().then(t => callMcpTool(o.cfg, { token: t, name, arguments: args,
      id: 'demo-' + random(9).toString('hex'), requestImpl: o.httpsRequest, timeoutMs: mcpTimeoutMs }));
    const set = await mcp('software_test_switch.set', { enabled });
    if (typeof set.commandId !== 'string' || !/^cmd_[a-f0-9]{64}$/u.test(set.commandId)) throw coded('MCP_SET_NO_COMMAND_ID');
    log('mcp software_test_switch.set -> ' + set.status + ' ' + set.commandId);
    const results = await pollWorker(worker, polls, intervalMs, sleep, log);
    const w = results.at(-1);
    if (w.status === 'EMPTY') throw coded('WORKER_NO_COMMAND_FETCHED');
    if (w.commandId !== set.commandId) throw coded('WORKER_COMMAND_MISMATCH');
    const r = await mcp('software_test_switch.result', { commandId: set.commandId });
    log('mcp software_test_switch.result -> ' + r.status + ' executed=' + r.executed);
    const sw = r.result && typeof r.result === 'object' ? r.result : {};
    return { mode: 'software-direct',
      set: { status: set.status, commandId: set.commandId },
      worker: { status: w.status, executed: w.executed === true },
      result: { status: r.status, executed: r.executed === true,
        enabled: typeof sw.enabled === 'boolean' ? sw.enabled : null, revision: Number.isSafeInteger(sw.revision) ? sw.revision : null },
      ok: r.executed === true && sw.enabled === enabled && w.executed === true };
  });
}
// Same chain for one SIMULATED home device: MCP home_device.command -> worker fetch/verify/apply/receipt -> home_device.result.
// applyHomeDevice must be supplied by the local owner console (it owns the simulator and its pairing gates).
export async function demoDevice({ deviceId, action, applyHomeDevice, polls = 5, intervalMs = 1000, clock = Date.now, timeoutMs = 2500, mcpTimeoutMs = 8000,
  log = stamp, sleep = ms => new Promise(r => setTimeout(r, ms)), random = randomBytes, ...o }) {
  if (!homeDeviceAllowed(deviceId, action)) throw coded('HOME_DEVICE_ACTION_NOT_ALLOWED');
  if (typeof applyHomeDevice !== 'function') throw coded('HOME_DEVICE_UNAVAILABLE');
  log('demo-device start mode=software-direct device=' + deviceId + ' action=' + action);
  return withWorkerSession({ ...o, polls, clock, timeoutMs, applyHomeDevice }, async ({ getAccessToken, worker, reused }) => {
    log(reused ? 'cognito session reused (not shown)' : 'cognito token exchanged (not shown)');
    const mcp = (name, args) => getAccessToken().then(t => callMcpTool(o.cfg, { token: t, name, arguments: args,
      id: 'demo-' + random(9).toString('hex'), requestImpl: o.httpsRequest, timeoutMs: mcpTimeoutMs }));
    const set = await mcp('home_device.command', { deviceId, action });
    if (typeof set.commandId !== 'string' || !/^cmd_[a-f0-9]{64}$/u.test(set.commandId)) throw coded('MCP_SET_NO_COMMAND_ID');
    log('mcp home_device.command -> ' + set.status + ' ' + set.commandId);
    const results = await pollWorker(worker, polls, intervalMs, sleep, log);
    const w = results.at(-1);
    if (w.status === 'EMPTY') throw coded('WORKER_NO_COMMAND_FETCHED');
    if (w.commandId !== set.commandId) throw coded('WORKER_COMMAND_MISMATCH');
    const r = await mcp('home_device.result', { commandId: set.commandId });
    log('mcp home_device.result -> ' + r.status + ' executed=' + r.executed);
    const d = r.result && typeof r.result === 'object' ? r.result : {};
    const matches = d.kind === 'home-device' && d.deviceId === deviceId && d.action === action;
    return { mode: 'software-direct',
      set: { status: set.status, commandId: set.commandId },
      worker: { status: w.status, executed: w.executed === true },
      result: { status: r.status, executed: r.executed === true, deviceId: matches ? d.deviceId : null, action: matches ? d.action : null,
        deviceStatus: matches && d.status === 'simulated_applied' ? d.status : null, revision: Number.isSafeInteger(d.revision) ? d.revision : null },
      ok: r.executed === true && matches && d.status === 'simulated_applied' && w.executed === true };
  });
}
// Mac side only: waits for ONE command sent by another MCP client (e.g. the agent bridge) and runs fetch/verify/apply/receipt.
// It never calls MCP itself; the sender reads home_device.result. applyHomeDevice comes from the local owner console.
export async function listenDevice({ applyHomeDevice, polls = 15, intervalMs = 2000, clock = Date.now, timeoutMs = 2500,
  log = stamp, sleep = ms => new Promise(r => setTimeout(r, ms)), ...o }) {
  if (typeof applyHomeDevice !== 'function') throw coded('HOME_DEVICE_UNAVAILABLE');
  log('listen-device start mode=software-direct polls=' + polls);
  return withWorkerSession({ ...o, polls, clock, timeoutMs, applyHomeDevice }, async ({ worker, reused }) => {
    log(reused ? 'cognito session reused (not shown)' : 'cognito token exchanged (not shown)');
    const w = (await pollWorker(worker, polls, intervalMs, sleep, log)).at(-1);
    return { mode: 'software-direct', worker: { status: w.status, executed: w.executed === true, commandId: w.commandId ?? null },
      ok: w.status !== 'EMPTY' && w.executed === true };
  });
}
export async function status({ stateDir, cfg, clock = Date.now }) {
  const dirs = ensureState(stateDir); const identity = await readIdentity(dirs); const p = await readPending(dirs);
  const files = listDir(dirs.journal);
  const claims = files.filter(f => f.endsWith('.claim.json')), receipts = new Set(files.filter(f => f.endsWith('.receipt.json')).map(f => f.split('.')[0]));
  return { stateDir: dirs.root, audience: cfg.audience, enrolledIdentity: identity ? { ownerRef: identity.ownerRef, associationRevision: identity.associationRevision, keyId: identity.keyId } : null,
    pkcePending: p ? { consumed: p.consumed === true, expired: clock() >= p.expiresAt } : null,
    journal: { claimed: claims.length, receiptWritten: receipts.size, claimedWithoutReceipt: claims.map(f => f.split('.')[0]).filter(id => !receipts.has(id)) } };
}

async function cognitoToken({ stateDir, cfg, callbackUrl, clock, tokenRequest }) {
  const dirs = ensureState(stateDir); const cb = parseCallbackUrl(callbackUrl, cfg);
  const pending = await consumePending(dirs, { now: clock() });
  if (pending.state !== cb.state) throw coded('CALLBACK_STATE_MISMATCH');
  return exchangeCode(cfg, { code: cb.code, verifier: pending.verifier }, { requestImpl: tokenRequest, now: clock });
}
async function ownerCall({ path, label, okStatus, body, stateDir, cfg, callbackUrl, clock = Date.now, tokenRequest, httpsRequest }) {
  const token = await cognitoToken({ stateDir, cfg, callbackUrl, clock, tokenRequest });
  if (clock() >= token.expiresAtMs - 3000) throw coded('OAUTH_TOKEN_EXPIRED');
  const r = await callJson(cfg.apiBase + path, { method: 'POST', bearer: token.accessToken, body, requestImpl: httpsRequest });
  const out = { operation: label, httpStatus: r.status, status: genericStatus(r.json) };
  out.ok = r.status === 200 && (okStatus === undefined || (Array.isArray(okStatus) ? okStatus.includes(out.status) : out.status === okStatus));
  return out;
}
// Agent bridge login: one PKCE exchange and no Mac key (the bridge never signs). The token stays in this closure.
export async function openBridgeSession({ stateDir, cfg, callbackUrl, clock = Date.now, tokenRequest }) {
  const token = await cognitoToken({ stateDir, cfg, callbackUrl, clock, tokenRequest });
  if (clock() >= token.expiresAtMs - 3000) throw coded('OAUTH_TOKEN_EXPIRED');
  return Object.freeze({ expiresAtMs: token.expiresAtMs,
    getAccessToken: async () => { if (clock() >= token.expiresAtMs - 3000) throw coded('OAUTH_TOKEN_EXPIRED'); return token.accessToken; } });
}
// body contains the Ring Playground token; it is sent once and never returned or logged.
export const bootstrap = ({ ringToken, ...o }) => ownerCall({ ...o, path: '/owner/bootstrap', label: 'owner_bootstrap', okStatus: ['owner_bootstrapped', 'owner_renewed'], body: { ringAccessToken: ringToken } });
export const enroll = o => ownerCall({ ...o, path: '/mac/enroll', label: 'mac_enroll' });
export async function ringDemo({ cfg, ringToken, httpsRequest }) {
  const me = await callJson(cfg.ringApi + '/v1/users/me', { method: 'GET', bearer: ringToken, requestImpl: httpsRequest });
  const dev = await callJson(cfg.ringApi + '/v1/devices', { method: 'GET', bearer: ringToken, requestImpl: httpsRequest });
  return { readOnly: true, me: summarizeMe(me), devices: summarizeDevices(dev), ok: me.status === 200 && dev.status === 200 };
}
export const accountIdSha256 = id => sha256Hex(id.replace(/\r?\n$/u, ''));
