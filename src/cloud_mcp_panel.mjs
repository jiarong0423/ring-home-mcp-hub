// Cloud MCP (AWS) panel: drives the mac launcher's demo-switch flow (one Cognito PKCE exchange ->
// cloud MCP software_test_switch.set -> Mac worker fetch/verify/execute/receipt (software-direct) ->
// software_test_switch.result) from the local owner UI.
//
// Boundaries (all enforced here or in src/server.mjs, which owns the owner-session and operator gates):
// * Disabled unless HOME_MCP_CLOUD_PANEL=1. The launcher code is imported lazily only when enabled.
// * The Mac key passphrase is typed ONCE at server start in the launching Terminal (hidden, no echo, via the
//   vendored launcher's hiddenPrompt) and kept only as a Buffer in this closure. It is never read from the OS
//   environment in normal use and never crosses the browser boundary. Test-only fallback: RING_MAC_KEY_PASSPHRASE
//   is accepted only when HOME_MCP_CLOUD_PANEL_PASSPHRASE_SOURCE=env-test is also set (both are always deleted
//   from the env object; without the flag the value is discarded).
// * Nothing returned by this module contains tokens, authorization codes, PKCE verifiers, the passphrase,
//   ownerRef/keyId/account identifiers, or full command ids (truncated to 8 hex characters).
import { lstatSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { pathToFileURL } from 'node:url';

const DEFAULT_LAUNCHER_DIR = new URL('../vendor_mac_launcher/', import.meta.url);
const DEFAULT_STATE_DIR_NAME = '.ring-mac-worker';
const CODE = /^[A-Z][A-Z0-9_-]{1,96}$/u;
const LISTEN_POLLS = 15, LISTEN_INTERVAL_MS = 2000;   // ~30 s: one cloud command TTL; within the launcher's 20-poll cap

export class CloudPanelError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}
const deny = (status, code) => { throw new CloudPanelError(status, code); };
export const shortCommandId = id => typeof id === 'string' && /^cmd_[a-f0-9]{64}$/u.test(id) ? id.slice(0, 12) + '…' : null;
// Known lowercase-suffixed launcher codes are mapped to fixed allowlisted labels; any other non-uppercase code collapses.
const OAUTH_TOKEN_ERRORS = new Map([['invalid_grant', 'INVALID_GRANT'], ['invalid_request', 'INVALID_REQUEST'], ['invalid_client', 'INVALID_CLIENT'],
  ['unauthorized_client', 'UNAUTHORIZED_CLIENT'], ['unsupported_grant_type', 'UNSUPPORTED_GRANT_TYPE'], ['invalid_scope', 'INVALID_SCOPE']]);
const LOGIN_ERRORS = new Map([['access_denied', 'ACCESS_DENIED'], ['invalid_request', 'INVALID_REQUEST'], ['unauthorized_client', 'UNAUTHORIZED_CLIENT'],
  ['unsupported_response_type', 'UNSUPPORTED_RESPONSE_TYPE'], ['invalid_scope', 'INVALID_SCOPE'], ['server_error', 'SERVER_ERROR'],
  ['temporarily_unavailable', 'TEMPORARILY_UNAVAILABLE'], ['unknown', 'UNKNOWN']]);
export function safeCode(error) {
  const code = typeof error === 'string' ? error : error?.code;
  if (typeof code !== 'string') return 'CLOUD_STEP_FAILED';
  let m = /^OAUTH_TOKEN_HTTP_([1-5][0-9]{2})(?:_([a-z_]{1,40}))?$/u.exec(code);
  if (m) return 'OAUTH_TOKEN_HTTP_' + m[1] + (m[2] && OAUTH_TOKEN_ERRORS.has(m[2]) ? '_' + OAUTH_TOKEN_ERRORS.get(m[2]) : '');
  m = /^CALLBACK_LOGIN_ERROR_([a-z_]{1,40})$/u.exec(code);
  if (m) return LOGIN_ERRORS.has(m[1]) ? 'CALLBACK_LOGIN_ERROR_' + LOGIN_ERRORS.get(m[1]) : 'CALLBACK_LOGIN_ERROR';
  m = /^MCP_HTTP_([1-5][0-9]{2})(?:_(.*))?$/u.exec(code);
  if (m) return 'MCP_HTTP_' + m[1] + (m[2] !== undefined && /^[A-Z0-9_-]{1,64}$/u.test(m[2]) ? '_' + m[2] : '');
  return CODE.test(code) ? code : 'CLOUD_STEP_FAILED';
}

// Allowlist of demo-switch log lines -> stable step codes { key, params }. The browser renders the text from the
// UI mapping table (public/i18n-map.mjs, keys cloud.step.*). Params hold only the regex-captured allowlisted values.
// Unknown lines are redacted entirely.
const step = (key, params = {}) => Object.freeze({ key, params: Object.freeze(params) });
const REDACTED = step('cloud.step.redacted');
const STEP_PATTERNS = [
  [/^demo-switch start mode=software-direct enabled=(true|false)$/u, m => step('cloud.step.start', { enabled: m[1] })],
  [/^cognito token exchanged \(not shown\)$/u, () => step('cloud.step.cognito')],
  [/^cognito session reused \(not shown\)$/u, () => step('cloud.step.cognitoReused')],
  [/^mcp software_test_switch\.set -> ([A-Z_]{1,32}) (cmd_[a-f0-9]{64})$/u, m => step('cloud.step.set', { status: m[1], commandId: shortCommandId(m[2]) })],
  [/^worker poll ([0-9]{1,2}): ([A-Z_]{1,32})(?: (cmd_[a-f0-9]{64}))?$/u, m => m[3]
    ? step('cloud.step.pollWithCommand', { n: m[1], status: m[2], commandId: shortCommandId(m[3]) })
    : step('cloud.step.poll', { n: m[1], status: m[2] })],
  [/^mcp software_test_switch\.result -> ([A-Z_]{1,32}) executed=(true|false)$/u, m => step('cloud.step.result', { status: m[1], executed: m[2] })],
  [/^demo-device start mode=software-direct device=([a-z_]{1,32}) action=([a-z_]{1,16})$/u, m => step('cloud.step.deviceStart', { device: m[1], action: m[2] })],
  [/^mcp home_device\.command -> ([A-Z_]{1,32}) (cmd_[a-f0-9]{64})$/u, m => step('cloud.step.deviceSet', { status: m[1], commandId: shortCommandId(m[2]) })],
  [/^mcp home_device\.result -> ([A-Z_]{1,32}) executed=(true|false)$/u, m => step('cloud.step.deviceResult', { status: m[1], executed: m[2] })],
  [/^listen-device start mode=software-direct polls=([0-9]{1,2})$/u, m => step('cloud.step.listenStart', { polls: m[1] })],
  [/^listen-device applied device=([a-z_]{1,32}) action=([a-z_]{1,16}) status=([a-z_]{1,32})$/u, m => step('cloud.step.listenApplied', { device: m[1], action: m[2], status: m[3] })]
];
export function sanitizeStep(line) {
  if (typeof line !== 'string') return REDACTED;
  for (const [re, fmt] of STEP_PATTERNS) { const m = re.exec(line); if (m) return fmt(m); }
  return REDACTED;
}

export function readCloudPanelEnv(env) {
  const flag = env.HOME_MCP_CLOUD_PANEL;
  if (flag !== undefined && flag !== '0' && flag !== '1') throw new Error('HOME_MCP_CLOUD_PANEL must be 0 or 1');
  return flag === '1';
}

const validLength = b => b.length >= 10 && b.length <= 1024;

// applyHomeDevice (optional) is supplied by src/server.mjs, which owns the simulator; without it device jobs are refused.
export async function createCloudMcpPanel({ env = process.env, launcherDir = DEFAULT_LAUNCHER_DIR, clock = Date.now,
  stdin = process.stdin, stderr = process.stderr, applyHomeDevice = null } = {}) {
  const envSecret = typeof env.RING_MAC_KEY_PASSPHRASE === 'string' ? env.RING_MAC_KEY_PASSPHRASE : null;
  const envTestSource = env.HOME_MCP_CLOUD_PANEL_PASSPHRASE_SOURCE === 'env-test';
  delete env.RING_MAC_KEY_PASSPHRASE; delete env.HOME_MCP_CLOUD_PANEL_PASSPHRASE_SOURCE;
  if (!readCloudPanelEnv(env)) return Object.freeze({ enabled: false });
  const stateDir = env.RING_MAC_STATE_DIR || join(env.HOME || homedir(), DEFAULT_STATE_DIR_NAME);
  if (!isAbsolute(stateDir)) throw new Error('RING_MAC_STATE_DIR must be absolute');

  const base = launcherDir instanceof URL ? launcherDir : pathToFileURL(String(launcherDir).replace(/\/?$/u, '/'));
  const [launcher, config, oauth, state, signingKey, prompt] = await Promise.all([
    import(new URL('src/launcher.mjs', base).href), import(new URL('src/config.mjs', base).href),
    import(new URL('src/oauth.mjs', base).href), import(new URL('src/state.mjs', base).href),
    import(new URL('vendor/mac-command-signing-key.mjs', base).href), import(new URL('src/passphrase.mjs', base).href)]);
  const cfg = config.resolveConfig(config.DEFAULT_CONFIG);
  const { homeDeviceAllowed } = await import(new URL('vendor/mac-command-contract.mjs', base).href);

  // Passphrase: hidden single prompt on the server's own Terminal; env only with the explicit test flag.
  let passphrase = null;
  let passphraseSource = 'none';
  if (envSecret !== null && envTestSource) {
    const raw = Buffer.from(envSecret, 'utf8');
    if (validLength(raw)) { passphrase = raw; passphraseSource = 'env-test'; } else raw.fill(0);
  } else if (stdin?.isTTY === true) {
    let raw;
    try { raw = await prompt.hiddenPrompt('Mac key passphrase for the Cloud MCP panel (hidden, 10..1024 bytes; Enter to skip): ', { stdin, stderr }); }
    catch { throw new Error('Cloud MCP passphrase prompt aborted'); }   // Ctrl-C in raw mode: stop startup
    if (validLength(raw)) { passphrase = raw; passphraseSource = 'tty'; }
    else if (raw.length === 0) stderr.write('WARN cloud-mcp passphrase skipped; panel stays key-not-ready\n');
    else { raw.fill(0); stderr.write('ERROR cloud-mcp passphrase not accepted (length must be 10..1024 bytes); panel stays key-not-ready\n'); }
  }

  let keyState = null;           // cached only once 'ready'
  let staged = null;             // { callbackUrl, expiresAt, source } - single use, memory only
  let session = null;            // { accessToken, expiresAtMs } from the first job after a login; reused until it expires, memory only
  let busy = false;
  let lastRun = null;

  const stateDirExists = () => { try { return lstatSync(stateDir).isDirectory(); } catch { return false; } };
  async function probeKey() {
    if (keyState === 'ready') return keyState;
    if (!stateDirExists()) return 'state_dir_missing';
    let dirs, identity;
    try { dirs = state.ensureState(stateDir); identity = await launcher.readIdentity(dirs); }
    catch { return 'state_dir_invalid'; }
    if (!identity) return 'identity_missing';
    if (!passphrase) return 'passphrase_missing';
    const copy = Buffer.from(passphrase);
    try {
      const signer = await signingKey.openMacCommandSigningKey({ directory: dirs.keys, passphrase: copy, ownerRef: identity.ownerRef,
        associationRevision: identity.associationRevision, audience: cfg.audience, clock });
      const match = signer.keyId === identity.keyId; signer.close();
      if (!match) return 'key_identity_mismatch';
      keyState = 'ready'; return keyState;
    } catch { return 'key_unlock_failed'; }
    finally { copy.fill(0); }
  }
  async function pendingInfo() {
    if (!stateDirExists()) return null;
    try {
      const p = await oauth.readPending(state.ensureState(stateDir));
      if (!p) return null;
      return { pending: p.consumed !== true && clock() < p.expiresAt, expiresAt: new Date(p.expiresAt).toISOString() };
    } catch { return { pending: false, expiresAt: null }; }
  }
  const stagedValid = () => staged !== null && clock() < staged.expiresAt;
  const sessionValid = () => session !== null && clock() < session.expiresAtMs - 3000;

  async function status() {
    if (staged && !stagedValid()) staged = null;
    if (session && !sessionValid()) session = null;
    return { enabled: true, mode: 'software-direct', ringSide: 'playground_sandbox', key: await probeKey(), passphraseSource,
      login: await pendingInfo(), callbackStaged: staged !== null,
      cloudSession: session ? { active: true, expiresAt: new Date(session.expiresAtMs).toISOString() } : { active: false, expiresAt: null }, busy, lastRun };
  }
  // Busy is claimed synchronously (no await before the check-and-set) so concurrent requests cannot interleave.
  function claimBusy() { if (busy) deny(429, 'CLOUD_MCP_BUSY'); busy = true; }

  async function loginUrl() {
    claimBusy();
    try {
      if (await probeKey() !== 'ready') deny(503, 'MAC_KEY_NOT_READY');
      staged = null; session = null;   // a new login replaces the old one
      const r = await launcher.loginUrl({ stateDir, cfg, now: clock() });
      return { authorizeUrl: r.url, expiresAt: new Date(r.expiresAt).toISOString() };
    } finally { busy = false; }
  }

  // Accepts only the exact callback URL shape for this deployment AND the state of the current pending login.
  // Never consumes the PKCE record and never echoes any part of the URL.
  async function stageCallback(value, source) {
    claimBusy();
    try { return await stageCallbackInner(value, source); } finally { busy = false; }
  }
  async function stageCallbackInner(value, source) {
    if (typeof value !== 'string' || value.length === 0 || value.length > 4096) deny(400, 'CALLBACK_URL_INVALID');
    // WHATWG URL parsing silently trims surrounding whitespace/control characters; the exact shape forbids them.
    if (/[\s\x00-\x1f\x7f]/u.test(value)) deny(422, 'CALLBACK_URL_INVALID');
    let cb;
    try { cb = oauth.parseCallbackUrl(value, cfg); }
    catch (error) { deny(422, /^CALLBACK_LOGIN_ERROR_/u.test(error?.code ?? '') ? safeCode(error) : 'CALLBACK_URL_INVALID'); }
    const p = stateDirExists() ? await oauth.readPending(state.ensureState(stateDir)).catch(() => null) : null;
    if (!p || p.consumed === true || typeof p.state !== 'string') deny(409, 'LOGIN_NOT_PENDING');
    if (!Number.isSafeInteger(p.expiresAt) || clock() >= p.expiresAt) deny(409, 'LOGIN_EXPIRED');
    if (p.state !== cb.state) deny(422, 'CALLBACK_STATE_MISMATCH');
    staged = { callbackUrl: value, expiresAt: p.expiresAt, source };
    return { staged: true, source, expiresAt: new Date(p.expiresAt).toISOString() };
  }

  // Phase 1 (synchronous checks, may throw a normal HTTP error); phase 2 `start()` runs the chain and reports steps.
  // The returned job owns `busy` and a passphrase copy until start() settles or abort() is called (exactly one of them).
  async function prepareJob(runInfo, onStep, run) {
    claimBusy();
    let copy = null;
    try {
      if (await probeKey() !== 'ready') deny(503, 'MAC_KEY_NOT_READY');
      if (session && !sessionValid()) session = null;
      if (!session && !stagedValid()) { staged = null; deny(409, 'CALLBACK_NOT_STAGED'); }
      copy = Buffer.from(passphrase);
    } catch (error) { busy = false; throw error; }
    // One login serves every job until its token expires: the first job spends the staged callback (single use, even on
    // failure) and keeps the token; later jobs reuse it. MFA is asked again only after expiry or a new login.
    const login = session ? { token: session } : { callbackUrl: staged.callbackUrl, onToken: t => { session = t; } };
    staged = null;
    const emitStep = ({ key, params }) => onStep({ at: new Date(clock()).toISOString(), key, params });
    let phase = 'prepared';
    const release = () => { copy.fill(0); busy = false; };
    return {
      // Releases the job if start() was never reached (e.g. the response could not be opened). No-op afterwards.
      abort() {
        if (phase !== 'prepared') return false;
        phase = 'aborted'; release();
        lastRun = { at: new Date(clock()).toISOString(), ok: false, ...runInfo, error: 'CLOUD_ABORTED_BEFORE_START' };
        return true;
      },
      async start() {
        if (phase !== 'prepared') throw new CloudPanelError(409, 'CLOUD_JOB_NOT_STARTABLE');
        phase = 'started';
        try {
          emitStep(step(passphraseSource === 'env-test' ? 'cloud.step.gateTestSource' : 'cloud.step.gate'));
          const out = await run({ stateDir, cfg, passphrase: copy, ...login, polls: 5, intervalMs: 1000, clock, log: line => emitStep(sanitizeStep(line)) });
          lastRun = { at: new Date(clock()).toISOString(), ok: out.ok, ...runInfo, executed: out.result.executed };
          return out;
        } catch (error) {
          const code = safeCode(error);
          if (/^(OAUTH_TOKEN_|MCP_HTTP_401|MCP_BEARER)/u.test(code)) session = null;   // a rejected token is never reused
          lastRun = { at: new Date(clock()).toISOString(), ok: false, ...runInfo, error: code };
          throw new CloudPanelError(502, code);
        } finally { phase = 'done'; release(); }
      }
    };
  }
  const common = r => ({ ok: r.ok === true, mode: r.mode === 'software-direct' ? 'software-direct' : 'unknown',
    set: { status: String(r.set?.status ?? 'UNKNOWN').slice(0, 32), commandId: shortCommandId(r.set?.commandId) },
    worker: { status: String(r.worker?.status ?? 'UNKNOWN').slice(0, 32), executed: r.worker?.executed === true } });
  async function prepareSwitch(enabled, onStep = () => {}) {
    if (typeof enabled !== 'boolean') deny(400, 'ENABLED_BOOLEAN_REQUIRED');
    return prepareJob({ enabled }, onStep, async o => {
      const r = await launcher.demoSwitch({ ...o, enabled });
      const base = common(r);
      return { ...base, result: { status: String(r.result?.status ?? 'UNKNOWN').slice(0, 32), executed: r.result?.executed === true,
        enabled: typeof r.result?.enabled === 'boolean' ? r.result.enabled : null,
        revision: Number.isSafeInteger(r.result?.revision) ? r.result.revision : null } };
    });
  }
  // One SIMULATED home device through the same cloud chain; allowlist enforced here, in the launcher and in the cloud.
  async function prepareDevice(deviceId, action, onStep = () => {}) {
    if (!homeDeviceAllowed(deviceId, action)) deny(400, 'HOME_DEVICE_ACTION_NOT_ALLOWED');
    if (typeof applyHomeDevice !== 'function') deny(503, 'HOME_DEVICE_UNAVAILABLE');
    return prepareJob({ deviceId, action }, onStep, async o => {
      const r = await launcher.demoDevice({ ...o, deviceId, action, applyHomeDevice });
      const base = common(r); const ok = base.ok && r.result?.deviceId === deviceId && r.result?.action === action;
      return { ...base, ok, result: { status: String(r.result?.status ?? 'UNKNOWN').slice(0, 32), executed: r.result?.executed === true,
        deviceId: r.result?.deviceId === deviceId ? deviceId : null, action: r.result?.action === action ? action : null,
        deviceStatus: r.result?.deviceStatus === 'simulated_applied' ? 'simulated_applied' : null,
        revision: Number.isSafeInteger(r.result?.revision) ? r.result.revision : null } };
    });
  }

  // Waits one ~30 s window (the cloud command TTL) for ONE home_device.command sent by another MCP client, e.g. an AI agent
  // through vendor_mac_launcher/mcp-bridge.mjs. The panel sends nothing itself; the same simulator gates apply.
  async function prepareListen(onStep = () => {}) {
    if (typeof applyHomeDevice !== 'function') deny(503, 'HOME_DEVICE_UNAVAILABLE');
    return prepareJob({ listen: true }, onStep, async o => {
      let applied = null;
      const capture = async input => {
        const out = await applyHomeDevice(input);
        applied = { deviceId: input.deviceId, action: input.action, status: out?.status === 'simulated_applied' ? 'simulated_applied' : 'not_applied' };
        o.log('listen-device applied device=' + applied.deviceId + ' action=' + applied.action + ' status=' + applied.status);
        return out;
      };
      const r = await launcher.listenDevice({ ...o, applyHomeDevice: capture, polls: LISTEN_POLLS, intervalMs: LISTEN_INTERVAL_MS });
      const known = applied !== null && homeDeviceAllowed(applied.deviceId, applied.action);
      const executed = r.worker?.executed === true && known && applied.status === 'simulated_applied';
      return { ok: executed, mode: r.mode === 'software-direct' ? 'software-direct' : 'unknown',
        set: { status: 'EXTERNAL', commandId: shortCommandId(r.worker?.commandId) },
        worker: { status: String(r.worker?.status ?? 'UNKNOWN').slice(0, 32), executed: r.worker?.executed === true },
        result: { status: String(r.worker?.status ?? 'UNKNOWN').slice(0, 32), executed, deviceId: known ? applied.deviceId : null,
          action: known ? applied.action : null, deviceStatus: executed ? 'simulated_applied' : null } };
    });
  }

  return Object.freeze({ enabled: true, stateDirDefaultName: DEFAULT_STATE_DIR_NAME, status, loginUrl, stageCallback, prepareSwitch, prepareDevice, prepareListen,
    keyStatus: probeKey, passphraseSource: () => passphraseSource });
}
