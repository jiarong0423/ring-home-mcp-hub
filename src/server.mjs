import http from 'node:http';
import crypto from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { execFile } from 'node:child_process';
import { createInterface } from 'node:readline';
import { homedir } from 'node:os';
import { promisify, types } from 'node:util';
import { createSimulator } from './core.mjs';
import { createLocalRingRuntime } from './local_ring/runtime.mjs';
import { verifyAndNormalizeRingEvent } from './ring_event.mjs';
import { createRingOfficialClient } from './ring_official_client.mjs';
import { createRingHistoryClient } from './ring_official_history_client.mjs';
import { createLoopbackOfficialReceiptCapture, ReceiptCaptureError } from './ring_official_receipt.mjs';
import { createDisabledWifiTrustService } from './wifi/wifi-trust-service.mjs';
import { createDisabledFormalRuntimeComposition } from './formal-runtime/entrypoint.mjs';
import { createCloudMcpPanel, readCloudPanelEnv, CloudPanelError } from './cloud_mcp_panel.mjs';
import { createPhoneRegistry, PhonePairingError } from './phone_pairing.mjs';
import { createMacDialog, macDialogEnabled } from './mac_dialog.mjs';
import { createGuardian } from './guardian.mjs';
import { createDoorRequests, DoorRequestError } from './door_requests.mjs';
import { createRingSnapshot, simulatedDoorSnapshot } from './ring_snapshot.mjs';
import { createRingDoorbell } from './ring_doorbell.mjs';
import { createRemoteRelay, loadOrCreateRelayKey, relayPublicKeySpki } from './remote_relay.mjs';
import { createVoiceNotice } from './voice_notice.mjs';
import { createRingLive, RingLiveError } from './ring_live.mjs';
import { buildDayFacts, createCareSummary, createDayLog } from './care_summary.mjs';
import { createFaceHint, createFaceStore, createFaceWorker, readFaceConfig, FaceHintError } from './face_hint.mjs';
import { createSnsNotifier, resolveAwsCli } from './notify_sns.mjs';
import {
  assertAssemblyRouteAllowed,
  createExecutableServerAssembly,
  dispatchExecutableFormalRequest,
  routeIdForRequest
} from './formal-runtime/server-composition.mjs';
import {
  LEGACY_MCP_PROTOCOL_VERSION,
  formalWireErrorResponse,
  modernDiscoverResponse,
  modernDispatchEnvelope,
  modernListResponse,
  modernResultResponse,
  validateFormalMcpWireRequest
} from './formal-runtime/stateless-wire.mjs';

const protocolVersion = LEGACY_MCP_PROTOCOL_VERSION;
const sourceDir = dirname(fileURLToPath(import.meta.url));
const htmlPath = join(sourceDir, '..', 'public', 'index.html');
const wifiConfigPath = join(sourceDir, '..', 'configs', 'wifi-trust.json');
const formalRuntimeConfigPath = join(sourceDir, '..', 'configs', 'formal-runtime.json');
const staticAssets = new Map([
  ['/assets/wifi-permission-app.mjs', Object.freeze({
    path: join(sourceDir, '..', 'public', 'wifi-permission-app.mjs'),
    type: 'text/javascript; charset=utf-8'
  })],
  ['/assets/wifi-permission-controller.mjs', Object.freeze({
    path: join(sourceDir, '..', 'public', 'wifi-permission-controller.mjs'),
    type: 'text/javascript; charset=utf-8'
  })],
  ['/assets/cloud-mcp-panel.mjs', Object.freeze({
    path: join(sourceDir, '..', 'public', 'cloud-mcp-panel.mjs'),
    type: 'text/javascript; charset=utf-8'
  })],
  ['/assets/guardian.mjs', Object.freeze({
    path: join(sourceDir, '..', 'public', 'guardian.mjs'),
    type: 'text/javascript; charset=utf-8'
  })],
  ['/assets/door.mjs', Object.freeze({
    path: join(sourceDir, '..', 'public', 'door.mjs'),
    type: 'text/javascript; charset=utf-8'
  })],
  ['/assets/ring-connect.mjs', Object.freeze({
    path: join(sourceDir, '..', 'public', 'ring-connect.mjs'),
    type: 'text/javascript; charset=utf-8'
  })],
  ['/assets/remote-approval.mjs', Object.freeze({
    path: join(sourceDir, '..', 'public', 'remote-approval.mjs'),
    type: 'text/javascript; charset=utf-8'
  })],
  ['/assets/faces.mjs', Object.freeze({
    path: join(sourceDir, '..', 'public', 'faces.mjs'),
    type: 'text/javascript; charset=utf-8'
  })],
  ['/assets/phone-pair.mjs', Object.freeze({
    path: join(sourceDir, '..', 'public', 'phone-pair.mjs'),
    type: 'text/javascript; charset=utf-8'
  })],
  ['/assets/i18n-map.mjs', Object.freeze({
    path: join(sourceDir, '..', 'public', 'i18n-map.mjs'),
    type: 'text/javascript; charset=utf-8'
  })]
]);
const execFileAsync = promisify(execFile);
const wifiTrustConfig = await readWifiTrustConfig();
const formalRuntimeConfig = await readFormalRuntimeConfig();
const portValue = Number(process.env.HOME_MCP_PORT ?? 8765);
if (!Number.isSafeInteger(portValue) || portValue < 0 || portValue > 65535) {
  throw new Error('HOME_MCP_PORT must be a valid TCP port');
}
const listenEnabled = process.env.HOME_MCP_LISTEN !== '0';

const generatedPasscode = !process.env.HOME_MCP_DEMO_PASS;
const passcode = process.env.HOME_MCP_DEMO_PASS || crypto.randomBytes(18).toString('base64url');
if (passcode.length < 12) throw new Error('HOME_MCP_DEMO_PASS must be at least 12 characters');
const passcodeDigest = sha256(passcode);
let ringOperatorPasscode = process.env.HOME_MCP_RING_OPERATOR_PASS;
const ringOperatorConfigured = typeof ringOperatorPasscode === 'string'
  && ringOperatorPasscode.length >= 24
  && ringOperatorPasscode.length <= 256
  && ringOperatorPasscode !== passcode;
const ringOperatorDigest = ringOperatorConfigured ? sha256(ringOperatorPasscode) : null;
ringOperatorPasscode = undefined;
const localMode = process.env.HOME_MCP_LOCAL_RING_SIMULATION;
if (localMode !== undefined && localMode !== '1' && localMode !== '0') throw new Error('Invalid local simulation mode');
const ringTest = readRingTestConfig();
if (localMode === '1' && ringTest.enabled) throw new Error('Choose one synthetic ingress mode');
const directEntry = typeof process.argv[1] === 'string' && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
const demoMcpEnabled = formalRuntimeConfig.enabled === false;
let serverMcpConsumer = null;
let executableAssembly = null;
let mcpProfile = null;
const localRing = directEntry && demoMcpEnabled && localMode === '1' ? createLocalRingRuntime() : null;
const simulator = directEntry && demoMcpEnabled
  ? (localRing?.simulator ?? createSimulator({ now: () => Date.now(), ringAutomation: ringTest.automation }))
  : null;
// Cloud MCP (AWS) panel: off unless HOME_MCP_CLOUD_PANEL=1; never combined with the local simulation mode.
if (readCloudPanelEnv(process.env) && localMode === '1') throw new Error('Cloud MCP panel is outside local simulation');
// home_device.command lands here after the cloud chain verified owner, session and Mac proof. The simulator's own owner/
// pairing/allowlist gates apply; immediateOnly means it is applied now or refused (gateway set offline, device fault) and is
// never queued for later. No heartbeat is sent, so local queues and the stale-gateway gate are untouched. Anything but an
// immediate, non-replayed simulated_applied is reported as not applied.
const applyCloudHomeDevice = simulator ? async ({ deviceId, action, commandId }) => {
  if (typeof commandId !== 'string' || !/^cmd_[a-f0-9]{64}$/u.test(commandId)) throw Object.assign(new Error('id'), { code: 'HOME_DEVICE_COMMAND_ID' });
  // Local audit id derived from (never equal to) the cloud commandId, so the full cloud id never appears in local state.
  const localId = 'cloud_' + crypto.createHash('sha256').update('home-device-local-id\0' + commandId).digest('hex').slice(0, 32);
  const result = simulator.perform({ actor: 'owner', deviceId, action, origin: 'cloud_mcp', commandId: localId, immediateOnly: true });
  console.log(`cloud-mcp device ${deviceId} ${action} -> ${result.status}${result.replayed ? ' (replay)' : ''}`);
  return { status: result.status === 'simulated_applied' && result.replayed !== true ? 'simulated_applied' : 'not_applied' };
} : null;
const cloudPanel = directEntry && demoMcpEnabled ? await createCloudMcpPanel({ env: process.env, applyHomeDevice: applyCloudHomeDevice }) : Object.freeze({ enabled: false });
let ringProviderToken = null;
let ringTokenLoadedAt = null;   // when the current Playground token was handed over (for the UI's 30-minute estimate)
const ringOfficialClient = createRingOfficialClient({
  tokenProvider: () => ringProviderToken,
});
const ringHistoryClient = createRingHistoryClient({
  tokenProvider: () => ringProviderToken,
});
const sessions = new Map();
const loginAttempts = new Map();
const verifiedRingEvents = new WeakSet();
let ringOperatorFailures = [];
let activePort = portValue;
let ringDiscoveryInFlight = false;
let ringImportInFlight = false;
let ringHistoryInFlight = false;
// Phone pairing (src/phone_pairing.mjs): a one-time code plus the owner's "y" typed on THIS process's terminal gives a phone
// its own revocable credential. The phone can reach the HTTP port (adb reverse) but never this stdin.
const phoneStorePath = process.env.HOME_MCP_PHONE_STORE || join(process.env.HOME || homedir(), '.home-mcp-console', 'phones.json');
let phonePromptReader = null;
// Owner approval AT THE MAC: a system dialog (admin phones; no terminal skills needed) and, as a fallback, "y" on this terminal.
// Whichever answers first counts. Family phones are normally approved on the admin phone (/api/phones/decide); the terminal
// still works for them as a fallback.
const macDialog = directEntry && macDialogEnabled() ? createMacDialog() : null;
function ownerPhoneConfirm({ name, role, expiresAt, check, signal }) {
  const showDialog = Boolean(macDialog) && role === 'admin';
  if (!process.stdin.readable && !showDialog) return Promise.resolve(false);
  return new Promise((resolveAnswer) => {
    let done = false; let onLine = null; let dialog = null;
    const finish = (yes, where) => {
      if (done) return;
      done = true;
      if (onLine) phonePromptReader?.removeListener('line', onLine);
      dialog?.close();
      if (Number.isSafeInteger(expiresAt) && Date.now() >= expiresAt) console.log(`phone pairing "${name}": answer arrived after 120 s; nothing approved. Ask for a new code.`);
      else console.log(`phone pairing "${name}": ${yes ? 'APPROVED' : 'refused'} ${where}`);
      resolveAnswer(yes);
    };
    if (process.stdin.readable) {
      phonePromptReader ??= createInterface({ input: process.stdin, crlfDelay: Infinity });
      const where = showDialog ? ' (or press Allow in the Mac dialog)' : role === 'member' ? ' (or Allow on the admin phone)' : '';
      process.stderr.write(`\nPAIR PHONE "${name}" as ${role.toUpperCase()}? check ${check ?? '--'}. Type y then Enter to approve${where}, anything else refuses (120 s): `);
      onLine = (line) => finish(/^\s*y(es)?\s*$/iu.test(line), 'on this terminal');
      phonePromptReader.once('line', onLine);
    }
    // Settled elsewhere (admin phone, timeout): drop this prompt silently, so a later "y" cannot be logged against it.
    signal?.addEventListener('abort', () => {
      if (done) return;
      done = true;
      if (onLine) phonePromptReader?.removeListener('line', onLine);
      dialog?.close();
      resolveAnswer(false);
    }, { once: true });
    if (showDialog) {
      const seconds = Math.max(1, Math.round((expiresAt - Date.now()) / 1000));
      dialog = macDialog.ask({ title: 'Home MCP — pair a phone', deny: 'Deny', allow: 'Allow', seconds,
        message: `Phone "${name}" wants to become the ADMIN of this home hub.\n\nCheck digits: ${check} (the phone shows the same two digits).\n\nIf you did not just start this on your phone, press Deny.\nValid for ${seconds} seconds.` });
      dialog.answer.then((a) => {
        if (a === 'allow') finish(true, 'in the Mac dialog');
        else if (a === 'deny') finish(false, 'in the Mac dialog');
        else if (a === 'unavailable') console.error('ERROR Mac pairing dialog unavailable; type y on this terminal instead');
      });
    }
  });
}
let phones = null;
if (directEntry && demoMcpEnabled) {
  try {
    phones = createPhoneRegistry({ storePath: phoneStorePath, confirm: ownerPhoneConfirm,
      onRevoke: (deviceId) => { for (const [key, entry] of sessions) if (entry.deviceId === deviceId) sessions.delete(key); } });
  } catch {
    console.error('ERROR phone store unreadable; phone pairing disabled until it is fixed or removed');
  }
}
// Face hint for the door approval screen (src/face_hint.mjs): on only when HOME_MCP_FACE_PYTHON + HOME_MCP_FACE_MODELS point
// at the local OpenCV venv and the two models. Off (or broken) never blocks door approval.
let faceWorker = null;
const faceHint = (() => {
  if (!directEntry || !demoMcpEnabled) return createFaceHint({ disabledReason: 'not_available' });
  const config = readFaceConfig(process.env, process.env.HOME || homedir());
  if (config.disabledReason) return createFaceHint({ disabledReason: config.disabledReason });
  try {
    const store = createFaceStore({ storePath: config.storePath, keyPath: config.keyPath });
    faceWorker = createFaceWorker({ python: config.python, detModel: config.detModel, recModel: config.recModel });
    return createFaceHint({ store, worker: faceWorker });
  } catch {
    console.error('ERROR face store unreadable; face hint disabled until it is fixed or removed');
    return createFaceHint({ disabledReason: 'store_unreadable' });
  }
})();
// Members (family phones) may read state and run everyday actions; everything else stays with the admin.
const MEMBER_ROUTES = new Set(['GET /api/state', 'POST /api/action', 'POST /api/logout', 'GET /api/guardian/status', 'POST /api/guardian/retry',
  'POST /api/door/request', 'POST /api/door/status']);
// Door unlock is never run directly by anyone: it becomes a request the admin phone approves (src/door_requests.mjs).
const memberForbiddenAction = (deviceId, action) => deviceId === 'camera' && action === 'disarm';
const isDoorUnlock = (deviceId, action) => deviceId === 'front_door' && action === 'unlock';
// A Playground token can also be handed in once at start (like other Ring entries); no token means simulated Ring.
if (typeof process.env.RING_ACCESS_TOKEN === 'string' && process.env.RING_ACCESS_TOKEN.length > 0) {
  const startupToken = process.env.RING_ACCESS_TOKEN;
  if (validRingProviderToken(startupToken)) { ringProviderToken = startupToken; ringTokenLoadedAt = Date.now(); }
  else console.error('ERROR RING_ACCESS_TOKEN has an invalid shape; Ring stays simulated');
}
delete process.env.RING_ACCESS_TOKEN;

// Elderly guardian (src/guardian.mjs). Its clock may run faster for a demo (HOME_MCP_CLOCK_SPEED, HOME_MCP_CLOCK_START=HH:MM);
// the simulator, sessions and every code/TTL keep real time.
function readGuardianClock(env) {
  const rawSpeed = env.HOME_MCP_CLOCK_SPEED;
  if (rawSpeed !== undefined && !/^\d{1,4}$/u.test(rawSpeed)) throw new Error('HOME_MCP_CLOCK_SPEED must be a whole number 1..1440');
  const speed = rawSpeed === undefined ? 1 : Number(rawSpeed);
  if (speed < 1 || speed > 1440) throw new Error('HOME_MCP_CLOCK_SPEED must be 1..1440');
  const start = env.HOME_MCP_CLOCK_START;
  if (start !== undefined && !/^([01]\d|2[0-3]):[0-5]\d$/u.test(start)) throw new Error('HOME_MCP_CLOCK_START must be HH:MM');
  const realStart = Date.now();
  let virtualStart = realStart;
  if (start) { const d = new Date(realStart); const [h, m] = start.split(':').map(Number); d.setHours(h, m, 0, 0); virtualStart = d.getTime(); }
  return { speed, start: start ?? null, now: speed === 1 && !start ? Date.now : () => virtualStart + (Date.now() - realStart) * speed };
}
const guardianClock = readGuardianClock(process.env);
const RING_API_ORIGIN = 'https://api.amazonvision.com';
// One status probe per call: list devices, then GET /v1/devices/{id}/status for the first one. Token stays in memory.
async function ringCameraStatus() {
  if (!ringProviderToken) return { state: 'token_missing' };
  const get = (path) => fetch(RING_API_ORIGIN + path, { headers: { Authorization: 'Bearer ' + ringProviderToken,
    Accept: 'application/vnd.api+json, application/json' }, redirect: 'error', signal: AbortSignal.timeout(5000) });
  try {
    const list = await get('/v1/devices');
    if (list.status === 401) return { state: 'token_expired' };
    if (!list.ok) return { state: 'error' };
    const first = (await list.json())?.data?.[0];
    if (typeof first?.id !== 'string' || !/^[A-Za-z0-9._:-]{1,128}$/u.test(first.id)) return { state: 'error' };
    const st = await get('/v1/devices/' + encodeURIComponent(first.id) + '/status');
    if (st.status === 401) return { state: 'token_expired' };
    if (!st.ok) return { state: 'error' };
    return { state: (await st.json())?.data?.attributes?.online === true ? 'online' : 'offline' };
  } catch { return { state: 'error' }; }
}
// HOME_MCP_RING_PROBE=off (tests, offline demos) keeps every Ring call off, snapshots included.
const ringNetworkOff = process.env.HOME_MCP_RING_PROBE === 'off';
const ringDoorSnapshot = createRingSnapshot({ origin: RING_API_ORIGIN, getToken: () => (ringNetworkOff ? null : ringProviderToken) });
async function attachDoorSnapshot(requestId, at) {
  const shot = await ringDoorSnapshot({ at }).catch(() => ({ reason: 'ring_error', detail: 'unexpected' }));
  if (!shot.bytes && shot.reason !== 'token_missing') console.log(`ring snapshot: not available (${shot.reason}${shot.detail ? `; ${shot.detail}` : ''}); showing the SIMULATED stand-in`);
  doors?.attachSnapshot(requestId, shot.bytes ? shot : simulatedDoorSnapshot(shot.reason));
  // Face hint on the real Ring image only (the stand-in has no face). Memory only; shown to the admin phone with the snapshot.
  const hint = shot.bytes ? await faceHint.hint(shot.bytes) : { state: faceHint.enabled ? 'no_image' : 'disabled' };
  doors?.attachFaceHint(requestId, hint);
}
// Every "open the door" (UI, family phone, AI agent over MCP) lands here: a request, never an unlock.
function requestDoorOpen(kind, name, { at } = {}) {
  if (!doors) throw fail(404, 'DOOR_APPROVAL_DISABLED', 'Door approval is not available');
  const front = simulator.getState().devices.find((device) => device.id === 'front_door');
  if (!front?.paired) throw fail(409, 'DEVICE_NOT_PAIRED', 'Pair the front door first');
  if (!phones?.hasAdmin()) throw fail(409, 'ADMIN_PHONE_REQUIRED', 'Pair an admin phone first; only it can approve');
  let r;
  try { r = doors.request({ kind, name }); } catch (error) { throw doorError(error); }
  if (r.existing && kind === 'ring') guardian?.noteDoorbellAgain();
  if (!r.existing) void attachDoorSnapshot(r.requestId, at);
  return { ...r, status: 'pending_approval', deviceId: 'front_door', action: 'unlock',
    message: 'Door unlock requested (SIMULATED). Nothing opens until the admin approves on the paired admin phone within 60 seconds.' };
}
// Ring doorbell -> door request (the admin phone still decides). Real presses come from the watcher below; the admin can also
// ring a simulated doorbell for a demo without a Ring token.
function doorbellPressed({ simulated, at, kind = 'ding' }) {
  const name = kind === 'person' ? 'Ring: person at the door' : simulated ? 'Ring doorbell (simulated)' : 'Ring doorbell';
  try { return requestDoorOpen('ring', name, { at }); }
  catch (error) {
    if (error.code === 'DOOR_REQUEST_PENDING') { console.log('ring doorbell pressed again while a door request is waiting'); guardian?.noteDoorbellAgain(); return null; }
    console.error(`ERROR ring doorbell press not turned into a door request: ${error.code ?? 'ERROR'}`);
    return null;
  }
}
// Ring webhook events pulled from the relay (HOME_MCP_RING_WEBHOOKS=on; Ring posts them to the relay's public /ring/webhook).
// A press or a person becomes a door request only while fresh (2 min); device_offline / device_online move the camera state at once.
function onRingWebhookEvent(e) {
  const type = String(e?.type ?? '');
  console.log(`ring webhook: ${type.replace(/[^a-z_]/gu, '?').slice(0, 32)}${e?.subType ? ` (${String(e.subType).replace(/[^a-z_.]/gu, '?').slice(0, 32)})` : ''}`);
  if (type === 'device_offline' || type === 'device_online') { guardian?.noteRingDevice({ online: type === 'device_online' }); return; }
  const person = type === 'person_detected' || (type === 'motion_detected' && e.subType === 'human');
  if (type !== 'button_press' && !person) return;
  if (!Number.isFinite(e.at) || Math.abs(Date.now() - e.at) > 120_000) { console.log('ring webhook: event older than 2 minutes, not turned into a door request'); return; }
  doorbellPressed({ simulated: false, at: e.at, kind: person ? 'person' : 'ding' });
}
// Ring live view on the admin phone's approval banner (WHEP): only while a door request waits; closed when it ends.
const ringLive = createRingLive({ origin: RING_API_ORIGIN, getToken: () => (ringNetworkOff ? null : ringProviderToken),
  log: (line) => (line.startsWith('ERROR') ? console.error(line) : console.log(line)) });
const ringDoorbell = createRingDoorbell({ origin: RING_API_ORIGIN, getToken: () => (ringNetworkOff ? null : ringProviderToken),
  onDing: ({ at, kind }) => { console.log(`ring doorbell: new ${kind === 'ding' ? 'doorbell press' : 'person at the door'} seen in Ring event history`); doorbellPressed({ simulated: false, at, kind }); },
  onStop: (reason) => { if (reason === 'token_expired') console.log('ring doorbell: Playground token expired; doorbell watching paused until a new token is loaded'); } });
function doorError(error) {
  if (error instanceof DoorRequestError) return fail(error.status, error.code, 'Door request denied');
  return error;
}
// The approval itself: the core's one-use confirmation is minted and spent here, server side, so it never reaches any client.
function performApprovedUnlock() {
  const c = simulator.beginConfirmation({ actor: 'owner', deviceId: 'front_door', action: 'unlock' });
  const r = simulator.perform({ actor: 'owner', deviceId: 'front_door', action: 'unlock', confirmationId: c.confirmationId,
    confirmationPhrase: c.phrase, origin: 'ui' });
  if (r?.status !== 'simulated_applied') { const error = new Error('not applied'); error.code = r?.code ?? 'NOT_APPLIED'; throw error; }
  return { receiptId: typeof r.commandId === 'string' ? r.commandId.slice(0, 12) : null, status: r.status, simulated: true };
}

const notifyEnv = { topicArn: process.env.HOME_MCP_NOTIFY_SNS_TOPIC_ARN, profile: process.env.HOME_MCP_NOTIFY_AWS_PROFILE,
  region: process.env.HOME_MCP_NOTIFY_REGION || 'ap-southeast-1' };
const notifier = createSnsNotifier({ ...notifyEnv, awsBin: resolveAwsCli(process.env.HOME_MCP_AWS_CLI),
  hubName: process.env.HOME_MCP_HUB_NAME || 'home', log: (line) => console.error(line) });
const voice = createVoiceNotice({ log: (line) => (line.startsWith('ERROR') ? console.error(line) : console.log(line)) });
const dayLog = createDayLog({ clock: guardianClock.now });
const careSummary = createCareSummary({ awsBin: resolveAwsCli(process.env.HOME_MCP_AWS_CLI), profile: notifyEnv.profile,
  region: process.env.HOME_MCP_BEDROCK_REGION || notifyEnv.region, modelId: process.env.HOME_MCP_BEDROCK_MODEL,
  log: (line) => console.error(line) });
const guardian = directEntry && demoMcpEnabled && simulator ? createGuardian({ onEvent: (e) => { voice.onGuardianEvent(e); dayLog.note(e); }, simulator, clock: guardianClock.now,
  ringStatus: process.env.HOME_MCP_RING_PROBE === 'off' ? null : ringCameraStatus, notifier, log: (line) => console.log(line),
  familyUrl: () => (remoteRelay && remoteRelay.status().phones.length > 0 ? `${process.env.HOME_MCP_RELAY_BASE.replace(/\/$/u, '')}/family` : null) }) : null;
// Daily care summary: written by Bedrock from today's facts (template if Bedrock is off or ungrounded), emailed through SNS.
const SUMMARY_AT = /^\d{2}:\d{2}$/u.test(process.env.HOME_MCP_SUMMARY_AT ?? '') ? process.env.HOME_MCP_SUMMARY_AT : '21:00';
// Started after today's summary time: wait for tomorrow (a restart never re-sends today's note).
let summarySentFor = (() => { const d = new Date(guardianClock.now());
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}` >= SUMMARY_AT ? d.toDateString() : null; })();
async function sendCareSummary(trigger) {
  const now = new Date(guardianClock.now());
  const date = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
  const facts = buildDayFacts(dayLog.today(), { date });
  const note = await careSummary.write(facts);
  const footer = note.source === 'bedrock' ? `Written by Amazon Bedrock (${careSummary.status().modelId}) from today's hub log only.`
    : `Plain summary (Bedrock not used: ${note.reason}).`;
  const mail = await notifier.publish({ subject: `Daily care summary ${date}`, message: `${note.text}\n\n${footer}\nSimulated devices / Ring Playground test environment.` });
  console.log(`care summary (${trigger}): ${note.source}${note.reason ? ` ${note.reason}` : ''}; email ${mail.sent ? 'sent' : `not sent (${mail.reason})`}`);
  return { date, text: note.text, source: note.source, reason: note.reason, emailed: mail.sent === true, facts };
}
function maybeDailySummary() {
  const now = new Date(guardianClock.now());
  const hhmm = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
  const date = now.toDateString();
  if (hhmm >= SUMMARY_AT && summarySentFor !== date && summarySentFor !== 'busy') {
    const prev = summarySentFor; summarySentFor = 'busy';
    sendCareSummary('daily').then((r) => { summarySentFor = date; return r; }).catch(() => { summarySentFor = prev; console.error('ERROR care summary failed'); });
  }
}

// Family remote approval through the AWS relay (AWS_REMOTE_APPROVAL_PLAN_zh.md). On only with HOME_MCP_RELAY_BASE (https).
let remoteRelay = null; let relayKeySpki = null;
if (directEntry && demoMcpEnabled && process.env.HOME_MCP_RELAY_BASE) {
  try {
    const relayKey = loadOrCreateRelayKey(process.env.HOME_MCP_RELAY_KEY || join(process.env.HOME || homedir(), '.home-mcp-console', 'relay.key'));
    relayKeySpki = relayPublicKeySpki(relayKey);
    remoteRelay = createRemoteRelay({ base: process.env.HOME_MCP_RELAY_BASE, privateKey: relayKey,
      storePath: process.env.HOME_MCP_RELAY_STORE || join(process.env.HOME || homedir(), '.home-mcp-console', 'relay_phones.json'),
      log: (line) => (line.startsWith('ERROR') ? console.error(line) : console.log(line)),
      onRingEvent: (e) => onRingWebhookEvent(e),
      onDecision: ({ requestId, decision, approver }) => {
        try { doors?.decide({ requestId, decision, approver, execute: performApprovedUnlock }); }
        catch (error) { console.error(`ERROR remote decision not applied: ${error.code ?? 'ERROR'}`); }
      } });
  } catch { console.error('ERROR remote approval relay not started (key or address); door approval stays local only'); }
}
const relayLabel = (r) => (r.requester.kind === 'mcp' ? 'AI agent (MCP)' : r.requester.kind === 'console' ? 'Home console'
  : String(r.requester.name).replace(/[^\p{L}\p{N} ().,:'-]/gu, ' ').trim().slice(0, 60) || 'Someone');
const doors = guardian ? createDoorRequests({ onEvent: (kind, request) => {
  guardian.noteDoor(kind, request);
  if (kind !== 'requested') void ringLive.stop({ why: `request ${kind}` });
  console.log(`door request ${kind}: by "${request.requester.name}"${request.approver ? ` decided by "${request.approver}"` : ''}${request.reason ? ` (${request.reason})` : ''} SIMULATED`);
  if (!remoteRelay) return;
  // text only: who asks and until when; never the snapshot, a face hint or a token
  const job = kind === 'requested'
    ? remoteRelay.publishRequest({ requestId: request.requestId, kind: request.requester.kind, label: relayLabel(request), hasSnapshot: true, expiresAtMs: Date.parse(request.expiresAt) })
    : remoteRelay.publishResult({ requestId: request.requestId, status: kind, receiptId: request.receipt?.receiptId ?? null });
  job.catch((error) => console.error(`ERROR remote approval relay ${kind}: ${error.code ?? 'unreachable'}`));
} }) : null;
let ringTokenGeneration = 0;
let ringOperationLease = null;
const wifiTrustService = createDisabledWifiTrustService();
let formalRuntime = createDisabledFormalRuntimeComposition({ configured: false });

function ownServerValue(value, name) {
  if (!value || types.isProxy(value)) throw fail(503, 'B02_FORMAL_PRODUCTION_ADAPTERS_REQUIRED', 'Formal adapters required');
  const descriptor = Object.getOwnPropertyDescriptor(value, name);
  if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
    throw fail(503, 'B02_FORMAL_PRODUCTION_ADAPTERS_REQUIRED', 'Formal adapters required');
  }
  return descriptor.value;
}

export function createProductionFormalAssemblyInput({ composition = null, formalAuthorizationPolicy = null } = {}) {
  if (!Object.isFrozen(composition) || ownServerValue(composition, 'enabled') !== true) {
    throw fail(503, 'B02_FORMAL_PRODUCTION_ADAPTERS_REQUIRED', 'Formal adapters required');
  }
  const assembly = ownServerValue(composition, 'assembly');
  const context = ownServerValue(composition, 'formalContextPort');
  const close = ownServerValue(composition, 'close');
  if (!Object.isFrozen(assembly) || !Object.isFrozen(context) || !Object.isFrozen(formalAuthorizationPolicy) ||
      ownServerValue(assembly, 'mode') !== 'FORMAL' ||
      ownServerValue(assembly, 'profile').profile !== 'FORMAL' ||
      typeof ownServerValue(context, 'resolve') !== 'function' ||
      ownServerValue(context, 'productionAdmitted') !== true || typeof close !== 'function' ||
      ownServerValue(formalAuthorizationPolicy, 'productionAdmitted') !== true ||
      typeof ownServerValue(formalAuthorizationPolicy, 'authorize') !== 'function' ||
      typeof ownServerValue(formalAuthorizationPolicy, 'protectedResourceMetadata') !== 'function') {
    throw fail(503, 'B02_FORMAL_PRODUCTION_ADAPTERS_REQUIRED', 'Formal adapters required');
  }
  return Object.freeze({ executableAssembly: assembly, formalContextPort: context,
    formalAuthorizationPolicy, composition, close: close.bind(composition) });
}

export function createServerOwnedMcpConsumer({ enabled = false, composition = null,
  formalAuthorizationPolicy = null, demoFactory = null, demoRequestRouter = null,
  readJsonFn = readJson, jsonFn = json } = {}) {
  if (typeof enabled !== 'boolean' || typeof readJsonFn !== 'function' || typeof jsonFn !== 'function') {
    throw fail(503, 'B02_SERVER_CONSUMER_INPUT_DENIED', 'Server consumer input denied');
  }
  let input;
  if (enabled) {
    if (demoFactory !== null || demoRequestRouter !== null) {
      throw fail(503, 'B02_SERVER_CONSUMER_INPUT_DENIED', 'Formal profile cannot retain demo authority');
    }
    input = createProductionFormalAssemblyInput({ composition, formalAuthorizationPolicy });
  } else {
    if (composition !== null || formalAuthorizationPolicy !== null ||
        ((demoFactory === null) !== (demoRequestRouter === null))) {
      throw fail(503, 'B02_SERVER_CONSUMER_INPUT_DENIED', 'Disabled profile input denied');
    }
    const assembly = demoFactory === null ? null : createExecutableServerAssembly({ mode: 'DEMO',
      demoFactory, formalFactory: null });
    input = { executableAssembly: assembly, formalContextPort: null, formalAuthorizationPolicy: null,
      composition: null, close: assembly === null ? async () => ({ resourceReleased: true }) : assembly.close.bind(assembly) };
  }
  let closed = false;
  let inFlight = 0;
  let released = false;
  let closing = null;
  const assertActive = () => {
    if (closed) throw fail(503, 'B02_SERVER_CONSUMER_CLOSED', 'Server consumer closed');
  };
  const router = input.executableAssembly === null
    ? async () => { assertActive(); throw fail(503, 'B02_FORMAL_RUNTIME_NOT_READY', 'Formal MCP runtime is not ready'); }
    : createHomeMcpRequestRouter({ executableAssembly: input.executableAssembly,
      formalContextPort: input.formalContextPort, formalAuthorizationPolicy: input.formalAuthorizationPolicy,
      demoRequestRouter: enabled ? async () => { throw fail(403, 'B02_FORMAL_ROUTE_DENIED', 'Formal route denied'); } : demoRequestRouter,
      readJsonFn, jsonFn, assertActive });
  return Object.freeze({ enabled, executableAssembly: input.executableAssembly,
    formalContextPort: input.formalContextPort, formalAuthorizationPolicy: input.formalAuthorizationPolicy,
    composition: input.composition,
    async router(req, res, url) {
      assertActive(); inFlight += 1;
      try { await router(req, res, url); assertActive(); }
      finally { inFlight -= 1; }
    },
    close() {
      if (closing) return closing;
      closed = true;
      closing = Promise.resolve().then(() => input.close()).then(result => {
        released = result?.resourceReleased === true || (!enabled && result?.closed === true);
        return Object.freeze({ closed: true, inFlight, resourceReleased: released && inFlight === 0 });
      });
      return closing;
    },
    resources() { return Object.freeze({ closed, inFlight, resourceReleased: closed && released && inFlight === 0 }); }
  });
}

export async function startServerOwnedMcpConsumer(options = {}) {
  const consumer = createServerOwnedMcpConsumer(options);
  if (!consumer.enabled) return consumer;
  try {
    const start = ownServerValue(consumer.composition, 'start');
    const status = ownServerValue(consumer.composition, 'status');
    if (typeof start !== 'function' || typeof status !== 'function') {
      throw fail(503, 'B02_FORMAL_PRODUCTION_ADAPTERS_REQUIRED', 'Formal startup required');
    }
    const result = await start.call(consumer.composition);
    if (result?.state !== 'READY' || status.call(consumer.composition).state !== 'READY' ||
        consumer.executableAssembly.profile.ready !== true) {
      throw fail(503, 'B02_FORMAL_RUNTIME_NOT_READY', 'Formal startup is not ready');
    }
    return consumer;
  } catch (error) {
    const released = await consumer.close();
    if (released.resourceReleased !== true) throw fail(503, 'B02_FORMAL_STARTUP_RELEASE_PENDING', 'Formal startup cleanup is incomplete');
    throw error;
  }
}

async function readWifiTrustConfig() {
  let value;
  try { value = JSON.parse(await readFile(wifiConfigPath, 'utf8')); }
  catch { throw new Error('Invalid Wi-Fi trust configuration'); }
  const keys = Object.keys(value).sort();
  const expected = ['enabled', 'interface', 'platform', 'schema', 'stateRoot'].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index]) ||
      value.schema !== 'ring-b02-wifi-trust-config-v1' || typeof value.enabled !== 'boolean' ||
      value.platform !== 'darwin' || value.interface !== 'en0' ||
      value.stateRoot !== 'var/private/wifi-trust') {
    throw new Error('Invalid Wi-Fi trust configuration');
  }
  return Object.freeze({ ...value });
}

async function readFormalRuntimeConfig() {
  let value;
  try { value = JSON.parse(await readFile(formalRuntimeConfigPath, 'utf8')); }
  catch (error) {
    if (error?.code === 'ENOENT') {
      return Object.freeze({
        schema: 'ring-b02-formal-runtime-config-v1',
        enabled: false,
        profile: 'FORMAL',
        stateRoot: 'var/private/formal-runtime',
        maximumGrantTtlMs: 300_000,
        providerCallsOnConstruction: false,
        externalWitnessRequired: true
      });
    }
    throw new Error('Invalid formal runtime configuration');
  }
  const keys = Object.keys(value).sort();
  const expected = ['enabled', 'externalWitnessRequired', 'maximumGrantTtlMs', 'profile',
    'providerCallsOnConstruction', 'schema', 'stateRoot'].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index]) ||
      value.schema !== 'ring-b02-formal-runtime-config-v1' || typeof value.enabled !== 'boolean' ||
      value.profile !== 'FORMAL' || value.externalWitnessRequired !== true ||
      value.stateRoot !== 'var/private/formal-runtime' || value.maximumGrantTtlMs !== 300_000 ||
      value.providerCallsOnConstruction !== false) {
    throw new Error('Invalid formal runtime configuration');
  }
  return Object.freeze({ ...value });
}

function acquireRingOperation(req, operation) {
  if (ringOperationLease !== null) throw fail(429, `${operation}_BUSY`, 'Ring operation already in progress');
  const entry = requireSessionEntry(req);
  if (entry.actor !== 'owner') throw fail(403, 'OWNER_REQUIRED', 'Owner session required');
  requireRingOperatorPasscode(req);
  const lease = Object.freeze({ entry, actor: entry.actor, generation: ringTokenGeneration });
  ringOperationLease = lease;
  return lease;
}

function assertRingOperationCurrent(lease, req) {
  if (localRing || ringOperationLease !== lease || ringTokenGeneration !== lease.generation
    || req.aborted || requireSessionEntry(req) !== lease.entry || lease.entry.actor !== lease.actor
    || lease.actor !== 'owner') throw fail(409, 'RING_AUTHORIZATION_CHANGED', 'Ring authorization changed');
  requireRingOperatorPasscode(req);
}

function releaseRingOperation(lease) {
  if (ringOperationLease === lease) ringOperationLease = null;
}

function sha256(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest();
}

function equalDigest(left, right) {
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function readRingTestConfig() {
  const names = [
    'HOME_MCP_RING_TEST_SECRET',
    'HOME_MCP_RING_ACCOUNT_ID',
    'HOME_MCP_RING_SOURCE_ID',
    'HOME_MCP_RING_SOURCE_TYPE',
    'HOME_MCP_RING_HOME_ID',
    'HOME_MCP_RING_GRANT_VERSION',
    'HOME_MCP_RING_GRANT_EXPIRES_AT_MS',
  ];
  const enabled = process.env.HOME_MCP_RING_TEST_ENABLED;
  const supplied = names.filter((name) => Object.hasOwn(process.env, name));
  if (enabled === undefined && supplied.length === 0) {
    return { enabled: false, secret: null, automation: { enabled: false } };
  }
  if (enabled === '0' && supplied.length === 0) {
    return { enabled: false, secret: null, automation: { enabled: false } };
  }
  if (enabled !== '1' || supplied.length !== names.length) {
    throw new Error('Ring test ingress configuration must be fully enabled or fully absent');
  }
  const required = (name) => {
    const value = process.env[name];
    if (typeof value !== 'string' || value.length === 0 || value !== value.trim()) {
      throw new Error(`Invalid Ring test ingress configuration field: ${name}`);
    }
    return value;
  };
  const secret = required('HOME_MCP_RING_TEST_SECRET');
  if (secret.length < 16) {
    throw new Error('HOME_MCP_RING_TEST_SECRET must have at least 16 characters');
  }
  const sourceType = required('HOME_MCP_RING_SOURCE_TYPE');
  if (sourceType !== 'devices') {
    throw new Error('HOME_MCP_RING_SOURCE_TYPE must be devices');
  }
  const expiresAtText = required('HOME_MCP_RING_GRANT_EXPIRES_AT_MS');
  if (!/^[1-9][0-9]*$/.test(expiresAtText)) {
    throw new Error('Invalid Ring test ingress expiration');
  }
  const expiresAtMs = Number(expiresAtText);
  if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= Date.now()) {
    throw new Error('Ring test ingress grant must expire in the future');
  }
  return {
    enabled: true,
    secret,
    automation: {
      enabled: true,
      accountId: required('HOME_MCP_RING_ACCOUNT_ID'),
      sourceId: required('HOME_MCP_RING_SOURCE_ID'),
      sourceType,
      homeId: required('HOME_MCP_RING_HOME_ID'),
      grantVersion: required('HOME_MCP_RING_GRANT_VERSION'),
      expiresAtMs,
    },
  };
}

function json(res, status, value, extraHeaders = {}) {
  const body = JSON.stringify(value);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'x-frame-options': 'DENY',
    ...extraHeaders,
  });
  res.end(body);
}

function empty(res, status, extraHeaders = {}) {
  res.writeHead(status, { 'cache-control': 'no-store', ...extraHeaders });
  res.end();
}

function fail(status, code, message) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  return error;
}

function requireLocalHost(req) {
  const host = req.headers.host;
  if (host !== `127.0.0.1:${activePort}` && host !== `localhost:${activePort}`) {
    throw fail(403, 'INVALID_HOST', 'Local host required');
  }
  const origin = req.headers.origin;
  if (origin && origin !== `http://127.0.0.1:${activePort}` && origin !== `http://localhost:${activePort}`) {
    throw fail(403, 'INVALID_ORIGIN', 'Local origin required');
  }
}

async function readJson(req, maxBytes = 16_384) {
  if (!String(req.headers['content-type'] || '').toLowerCase().startsWith('application/json')) {
    throw fail(415, 'JSON_REQUIRED', 'Content-Type application/json required');
  }
  let size = 0;
  const parts = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw fail(413, 'BODY_TOO_LARGE', 'Request body too large');
    parts.push(chunk);
  }
  let value;
  try {
    value = JSON.parse(Buffer.concat(parts).toString('utf8'));
  } catch {
    throw fail(400, 'INVALID_JSON', 'Invalid JSON body');
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw fail(400, 'OBJECT_REQUIRED', 'JSON object required');
  }
  return value;
}

async function readRingRawBody(req) {
  let size = 0;
  const parts = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 16_384) throw fail(413, 'RING_BODY_TOO_LARGE', 'Ring test event body too large');
    parts.push(chunk);
  }
  return Buffer.concat(parts, size);
}

function singleRingSignature(req) {
  const values = [];
  for (let index = 0; index < req.rawHeaders.length; index += 2) {
    if (req.rawHeaders[index].toLowerCase() === 'x-signature') {
      values.push(req.rawHeaders[index + 1]);
    }
  }
  if (values.length !== 1 || typeof values[0] !== 'string') {
    throw fail(401, 'RING_SIGNATURE_INVALID', 'One Ring signature required');
  }
  return values[0];
}

async function handleRingTestEvent(req, res) {
  if (req.method !== 'POST') {
    empty(res, 405, { allow: 'POST' });
    return;
  }
  if (!ringTest.enabled) {
    throw fail(503, 'RING_TEST_DISABLED', 'Local Ring test ingress is disabled');
  }
  const rawBody = await readRingRawBody(req);
  const normalized = Object.freeze(verifyAndNormalizeRingEvent({
    rawBody,
    signature: singleRingSignature(req),
    secret: ringTest.secret,
  }));
  if (!String(req.headers['content-type'] || '').toLowerCase().startsWith('application/json')) {
    throw fail(415, 'JSON_REQUIRED', 'Content-Type application/json required');
  }
  verifiedRingEvents.add(normalized);
  const envelope = {
    jsonrpc: '2.0',
    id: normalized.requestId,
    method: 'tools/call',
    params: { name: 'ring_motion_to_light', arguments: { event: normalized } },
  };
  const response = dispatchMcpToolCall(envelope, { verifiedRingEvent: normalized });
  if (!response.result || response.result.isError || !response.result.structuredContent) {
    throw fail(500, 'RING_MCP_BRIDGE_FAILED', 'Ring event dispatch failed');
  }
  json(res, 200, response.result.structuredContent);
}

function requireSessionEntry(req) {
  const header = req.headers.authorization;
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) {
    throw fail(401, 'AUTH_REQUIRED', 'Bearer token required');
  }
  const raw = header.slice(7);
  if (!/^[A-Za-z0-9_-]{40,120}$/.test(raw)) {
    throw fail(401, 'INVALID_TOKEN', 'Invalid bearer token');
  }
  const digest = sha256(raw);
  let matched = null;
  for (const entry of sessions.values()) {
    if (equalDigest(digest, entry.digest)) matched = entry;
  }
  if (!matched || Date.now() >= matched.expiresAt || (matched.via === 'phone' && !phones?.isActive(matched.deviceId))) {
    throw fail(401, 'SESSION_EXPIRED', 'Session expired or invalid');
  }
  return matched;
}

function requireSession(req) { return requireSessionEntry(req).actor; }

function requireRingOperatorPasscode(req) {
  // A Mac-approved admin phone stands in for the operator code (possession of the paired phone, approved on this terminal).
  let entry = null; try { entry = requireSessionEntry(req); } catch { entry = null; }
  if (entry?.via === 'phone' && entry.role === 'admin') return;
  if (!ringOperatorConfigured) {
    throw fail(503, 'RING_OPERATOR_UNAVAILABLE', 'Ring operator gate unavailable');
  }
  const now = Date.now();
  ringOperatorFailures = ringOperatorFailures.filter((time) => now - time < 60_000);
  if (ringOperatorFailures.length >= 5) {
    throw fail(429, 'RING_OPERATOR_RATE_LIMIT', 'Ring operator gate temporarily limited');
  }
  const values = [];
  for (let index = 0; index < req.rawHeaders.length; index += 2) {
    if (req.rawHeaders[index].toLowerCase() === 'x-ring-operator-passcode') {
      values.push(req.rawHeaders[index + 1]);
    }
  }
  const candidate = values.length === 1 && typeof values[0] === 'string' ? values[0] : '';
  const valid = candidate.length >= 24 && candidate.length <= 256
    && equalDigest(sha256(candidate), ringOperatorDigest);
  if (!valid) {
    ringOperatorFailures.push(now);
    throw fail(403, 'RING_OPERATOR_DENIED', 'Ring operator gate denied');
  }
  ringOperatorFailures = [];
}

function validRingProviderToken(token) {
  return typeof token === 'string'
    && token.length > 0
    && token.length <= 4096
    && /^[A-Za-z0-9._~+/-]+={0,2}$/.test(token);
}

function login(body) {
  const key = 'loopback';
  const now = Date.now();
  const attempts = (loginAttempts.get(key) || []).filter((time) => now - time < 60_000);
  if (attempts.length >= 5) throw fail(429, 'LOGIN_RATE_LIMIT', 'Try again in one minute');
  const candidate = typeof body.passcode === 'string' ? body.passcode : '';
  const valid = equalDigest(sha256(candidate), passcodeDigest);
  if (!valid) {
    attempts.push(now);
    loginAttempts.set(key, attempts);
    throw fail(401, 'INVALID_PASSCODE', 'Invalid passcode');
  }
  loginAttempts.delete(key);
  return issueSession({ role: 'admin', via: 'passcode' });
}

function issueSession({ role, via, deviceId = null, name = null }) {
  const now = Date.now();
  const token = crypto.randomBytes(32).toString('base64url');
  const digest = sha256(token);
  sessions.set(digest.toString('hex'), { digest, actor: 'owner', role, via, deviceId, name, expiresAt: now + 60 * 60_000 });
  return { token, expiresAt: new Date(now + 60 * 60_000).toISOString(), simulated: true };
}

async function handleApi(req, res, url) {
  if (url.pathname === '/api/login' && req.method === 'POST') {
    json(res, 200, login(await readJson(req)));
    return;
  }
  if (PHONE_PUBLIC_ROUTES.has(url.pathname)) {
    await handlePhonePublic(req, res, url);
    return;
  }
  const sessionEntry = requireSessionEntry(req);
  const actor = sessionEntry.actor;
  if (sessionEntry.role === 'member' && !MEMBER_ROUTES.has(`${req.method} ${url.pathname}`)) {
    throw fail(403, 'MEMBER_NOT_ALLOWED', 'Family phones can read state and run everyday actions only');
  }
  if (url.pathname.startsWith('/api/phones')) {
    await handlePhoneAdmin(req, res, url, sessionEntry);
    return;
  }
  if (url.pathname.startsWith('/api/guardian/')) {
    await handleGuardian(req, res, url, sessionEntry);
    return;
  }
  if (url.pathname.startsWith('/api/door/')) {
    await handleDoor(req, res, url, sessionEntry);
    return;
  }
  if (url.pathname.startsWith('/api/relay/')) {
    await handleRelay(req, res, url, sessionEntry);
    return;
  }
  if (url.pathname === '/api/faces' || url.pathname.startsWith('/api/faces/')) {
    await handleFaces(req, res, url, sessionEntry);
    return;
  }
  if (url.pathname.startsWith('/api/wifi-trust/')) {
    if (actor !== 'owner') throw fail(403, 'OWNER_REQUIRED', 'Owner session required');
    if (url.search) throw fail(400, 'QUERY_NOT_ALLOWED', 'No query parameters');
    if (url.pathname === '/api/wifi-trust/status') {
      if (req.method !== 'GET') throw fail(405, 'METHOD_NOT_ALLOWED', 'GET required');
      if (req.headers['transfer-encoding'] || Number(req.headers['content-length'] || 0) !== 0) {
        throw fail(400, 'BODY_NOT_ALLOWED', 'Status accepts no body');
      }
      json(res, 200, await wifiTrustService.sanitizedStatus());
      return;
    }
    const operations = new Map([
      ['/api/wifi-trust/consent', Object.freeze({
        action: 'authorize-household-wifi', run: () => wifiTrustService.consentCurrentWifi()
      })],
      ['/api/wifi-trust/revoke', Object.freeze({
        action: 'revoke-household-wifi', run: () => wifiTrustService.revokeCurrentWifi()
      })]
    ]);
    const operation = operations.get(url.pathname);
    if (!operation) throw fail(404, 'NOT_FOUND', 'Route not found');
    if (req.method !== 'POST') throw fail(405, 'METHOD_NOT_ALLOWED', 'POST required');
    const allowedOrigins = [`http://127.0.0.1:${activePort}`, `http://localhost:${activePort}`];
    if (!allowedOrigins.includes(req.headers.origin)) throw fail(403, 'INVALID_ORIGIN', 'Same origin required');
    const body = await readJson(req);
    if (Object.keys(body).length !== 1 || body.action !== operation.action) {
      throw fail(400, 'INVALID_ARGUMENT', 'Exact Wi-Fi permission action required');
    }
    json(res, 200, await operation.run());
    return;
  }
  if (url.pathname === '/api/logout' && req.method === 'POST') {
    const raw = req.headers.authorization.slice(7);
    try {
      if (localRing) await localRing.logout();
    } finally {
      sessions.delete(sha256(raw).toString('hex'));
    }
    json(res, 200, { revoked: true, simulated: true });
    return;
  }
  if (url.pathname.startsWith('/api/local-ring/')) {
    if (!localRing) throw fail(404, 'LOCAL_RING_DISABLED', 'Local Ring simulation is disabled');
    if (url.search) throw fail(400, 'QUERY_NOT_ALLOWED', 'No query parameters');
    if (url.pathname === '/api/local-ring/status' && req.method === 'GET') {
      json(res, 200, localRing.status());
      return;
    }
    const operations = new Map([
      ['/api/local-ring/link', () => localRing.link()],
      ['/api/local-ring/motion', () => localRing.motion()],
      ['/api/local-ring/worker', () => localRing.runWorker()],
      ['/api/local-ring/remove', () => localRing.remove()],
      ['/api/local-ring/logout', () => localRing.logout()],
    ]);
    const online = url.pathname === '/api/local-ring/online';
    if (!operations.has(url.pathname) && !online) throw fail(404, 'NOT_FOUND', 'Route not found');
    if (req.method !== 'POST') throw fail(405, 'METHOD_NOT_ALLOWED', 'POST required');
    const allowedOrigins = [`http://127.0.0.1:${activePort}`, `http://localhost:${activePort}`];
    if (!allowedOrigins.includes(req.headers.origin) || req.headers['x-local-ring-intent'] !== 'simulation') {
      throw fail(403, 'LOCAL_INTENT_REQUIRED', 'Same-origin simulation intent required');
    }
    const body = await readJson(req);
    const keys = Object.keys(body);
    if (online ? keys.length !== 1 || keys[0] !== 'online' || typeof body.online !== 'boolean' : keys.length !== 0) {
      throw fail(400, 'INVALID_ARGUMENT', 'Only the fixed simulation operation is accepted');
    }
    try {
      const result = online ? await localRing.setWorkerOnline(body.online) : await operations.get(url.pathname)();
      json(res, 200, result);
    } catch {
      throw fail(409, 'LOCAL_RING_DENIED', 'Local identity, binding or command guard denied this operation');
    }
    return;
  }
  if (url.pathname.startsWith('/api/cloud-mcp/')) {
    await handleCloudMcp(req, res, url, actor);
    return;
  }
  if (localRing && url.pathname.startsWith('/api/ring/')) {
    throw fail(503, 'PROVIDER_DISABLED_IN_LOCAL_MODE', 'Official provider calls are outside local simulation');
  }
  // Ring Playground token pasted into the console (masked field). Memory only: never echoed, logged or written to disk.
  if (url.pathname === '/api/ring/token' || url.pathname === '/api/ring/token-clear' || url.pathname === '/api/ring/token-status') {
    await handleRingToken(req, res, url, sessionEntry);
    return;
  }
  if (url.pathname === '/api/ring/import-clipboard') {
    if (req.method !== 'POST') {
      empty(res, 405, { allow: 'POST' });
      return;
    }
    if (url.search) throw fail(400, 'QUERY_NOT_ALLOWED', 'Ring import accepts no query parameters');
    if (req.headers['transfer-encoding'] || Number(req.headers['content-length'] || 0) > 0) {
      throw fail(400, 'BODY_NOT_ALLOWED', 'Ring import accepts no request body');
    }
    if (actor !== 'owner') throw fail(403, 'OWNER_REQUIRED', 'Owner session required');
    requireRingOperatorPasscode(req);
    const lease = acquireRingOperation(req, 'IMPORT');
    ringImportInFlight = true;
    try {
      let clipboardValue;
      try {
        const result = await execFileAsync('/usr/bin/pbpaste', [], {
          encoding: 'utf8',
          timeout: 2500,
          maxBuffer: 4096,
          shell: false,
          env: { PATH: '/usr/bin:/bin' },
        });
        clipboardValue = result.stdout;
      } catch {
        throw fail(503, 'CLIPBOARD_UNAVAILABLE', 'Local clipboard unavailable');
      }
      if (!validRingProviderToken(clipboardValue)) {
        throw fail(422, 'RING_TOKEN_INVALID', 'Clipboard does not contain a standalone Ring token');
      }
      assertRingOperationCurrent(lease, req);
      ringProviderToken = clipboardValue;
      ringTokenGeneration += 1;
      clipboardValue = undefined;
      json(res, 200, {
        ok: true,
        configured: true,
        source: 'local_clipboard',
        imported_at: new Date().toISOString(),
      });
    } finally {
      ringImportInFlight = false;
      releaseRingOperation(lease);
    }
    return;
  }
  if (url.pathname === '/api/ring/discovery-receipt') {
    if (req.method !== 'POST') throw fail(405, 'METHOD_NOT_ALLOWED', 'POST required');
    if (url.search) throw fail(400, 'QUERY_NOT_ALLOWED', 'No query parameters');
    const origins = [];
    for (let index = 0; index < req.rawHeaders.length; index += 2) {
      if (req.rawHeaders[index].toLowerCase() === 'origin') origins.push(req.rawHeaders[index + 1]);
    }
    if (origins.length !== 1 || origins[0] !== `http://${req.headers.host}`
      || req.headers['x-ring-capture-intent'] !== 'pending-receipt') {
      throw fail(403, 'RING_CAPTURE_INTENT_REQUIRED', 'Same-origin explicit capture required');
    }
    if (req.headers['transfer-encoding'] || (req.headers['content-length'] !== undefined && req.headers['content-length'] !== '0')) {
      throw fail(400, 'BODY_NOT_ALLOWED', 'No request body');
    }
    for await (const chunk of req) if (chunk.length !== 0) throw fail(400, 'BODY_NOT_ALLOWED', 'No request body');
    const lease = acquireRingOperation(req, 'CAPTURE');
    try {
      const capture = createLoopbackOfficialReceiptCapture({
        tokenProvider: () => { assertRingOperationCurrent(lease, req); return ringProviderToken; },
        assertCurrentAuthorization: () => assertRingOperationCurrent(lease, req),
      });
      const result = await capture.capture();
      json(res, 200, { receipt_id: result.receipt_id, device_count: result.device_count,
        captured_at: result.captured_at, classification: result.classification });
    } catch (error) {
      const code = error instanceof ReceiptCaptureError ? error.code : 'RECEIPT_CAPTURE_FAILED';
      json(res, code === 'SERVER_AUTHORIZATION_REVOKED' ? 409 : 503, { error: code });
    } finally { releaseRingOperation(lease); }
    return;
  }
  if (url.pathname === '/api/ring/discovery') {
    if (req.method !== 'GET') {
      empty(res, 405, { allow: 'GET' });
      return;
    }
    if (url.search) throw fail(400, 'QUERY_NOT_ALLOWED', 'Ring discovery accepts no query parameters');
    if (actor !== 'owner') throw fail(403, 'OWNER_REQUIRED', 'Owner session required');
    requireRingOperatorPasscode(req);
    const lease = acquireRingOperation(req, 'DISCOVERY');
    ringDiscoveryInFlight = true;
    try {
      const result = await ringOfficialClient.discoverDevices();
      assertRingOperationCurrent(lease, req);
      const payload = {
        ok: result.ok === true,
        configured: result.configured === true,
        source: 'official_playground_api',
        checked_at: result.checked_at,
        http_status: result.http_status,
        device_count: result.ok === true ? result.device_count : 0,
        display_aliases: result.ok === true ? result.display_aliases : [],
      };
      if (result.error_code) payload.error_code = result.error_code;
      const localTokenUnavailable = payload.error_code === 'TOKEN_UNAVAILABLE'
        || payload.error_code === 'TOKEN_INVALID';
      json(res, payload.ok ? 200 : localTokenUnavailable ? 503 : 502, payload);
    } catch {
      json(res, 502, {
        ok: false,
        configured: true,
        source: 'official_playground_api',
        checked_at: new Date().toISOString(),
        http_status: null,
        device_count: 0,
        display_aliases: [],
        error_code: 'DISCOVERY_INTERNAL',
      });
    } finally {
      ringDiscoveryInFlight = false;
      releaseRingOperation(lease);
    }
    return;
  }
  if (url.pathname === '/api/ring/history') {
    if (req.method !== 'GET') {
      empty(res, 405, { allow: 'GET' });
      return;
    }
    if (actor !== 'owner') throw fail(403, 'OWNER_REQUIRED', 'Owner session required');
    requireRingOperatorPasscode(req);
    if (url.searchParams.size !== 1 || !url.searchParams.has('ordinal')) {
      throw fail(400, 'INVALID_ORDINAL', 'One device ordinal required');
    }
    const ordinalText = url.searchParams.get('ordinal');
    if (!/^[1-9][0-9]{0,2}$/.test(ordinalText)) {
      throw fail(400, 'INVALID_ORDINAL', 'Device ordinal must be 1 to 256');
    }
    const deviceOrdinal = Number(ordinalText);
    if (deviceOrdinal > 256) throw fail(400, 'INVALID_ORDINAL', 'Device ordinal must be 1 to 256');
    const lease = acquireRingOperation(req, 'HISTORY');
    ringHistoryInFlight = true;
    try {
      const result = await ringHistoryClient.probeMotionHistory({ deviceOrdinal });
      assertRingOperationCurrent(lease, req);
      const localTokenUnavailable = result.error_code === 'TOKEN_UNAVAILABLE'
        || result.error_code === 'TOKEN_INVALID';
      json(res, result.ok === true ? 200 : localTokenUnavailable ? 503 : 502, result);
    } catch {
      json(res, 502, {
        ok: false,
        configured: true,
        source: 'official_event_history_api',
        checked_at: new Date().toISOString(),
        discovery_http_status: null,
        history_http_status: null,
        device_count: 0,
        device_ordinal: deviceOrdinal,
        motion_count: 0,
        latest_motion_at: null,
        error_code: 'HISTORY_INTERNAL',
      });
    } finally {
      ringHistoryInFlight = false;
      releaseRingOperation(lease);
    }
    return;
  }
  if (url.pathname === '/api/state' && req.method === 'GET') {
    json(res, 200, { ...simulator.getState(), localRing: localRing ? localRing.status() : { mode: 'disabled' } });
    return;
  }
  if (url.pathname === '/api/pair/start' && req.method === 'POST') {
    const body = await readJson(req);
    json(res, 200, simulator.beginPair({ actor, deviceId: body.deviceId }));
    return;
  }
  if (url.pathname === '/api/pair/confirm' && req.method === 'POST') {
    const body = await readJson(req);
    json(res, 200, simulator.completePair({ actor, deviceId: body.deviceId, code: body.code }));
    return;
  }
  if (url.pathname === '/api/confirm/start' && req.method === 'POST') {
    const body = await readJson(req);
    // The door's one-use phrase used to be handed to whoever held a session (so an agent could confirm itself). Not any more.
    if (isDoorUnlock(body.deviceId, body.action)) throw fail(403, 'DOOR_APPROVAL_REQUIRED', 'Request the door; the admin phone approves');
    json(res, 200, simulator.beginConfirmation({ actor, deviceId: body.deviceId, action: body.action }));
    return;
  }
  if (url.pathname === '/api/action' && req.method === 'POST') {
    const body = await readJson(req);
    if (isDoorUnlock(body.deviceId, body.action)) {
      json(res, 202, requestDoorOpen(sessionEntry.via === 'phone' ? 'phone' : 'console', sessionEntry.name ?? 'console'));
      return;
    }
    if (sessionEntry.role === 'member' && memberForbiddenAction(body.deviceId, body.action)) {
      throw fail(403, 'MEMBER_ACTION_FORBIDDEN', 'Camera disarm is admin-only');
    }
    if (sessionEntry.via === 'phone') console.log(`phone "${sessionEntry.name}" action ${String(body.deviceId).replace(/[^a-z_]/gu, '?').slice(0, 32)} ${String(body.action).replace(/[^a-z_]/gu, '?').slice(0, 32)}`);
    json(res, 200, simulator.perform({
      actor,
      deviceId: body.deviceId,
      action: body.action,
      parameters: body.parameters,
      confirmationId: body.confirmationId,
      confirmationPhrase: body.confirmationPhrase,
      origin: 'ui',
    }));
    return;
  }
  if (url.pathname === '/api/edge/online' && req.method === 'POST') {
    const body = await readJson(req);
    const result = simulator.setEdgeOnline({ actor, online: body.online });
    guardian?.noteGateway({ online: body.online === true });   // the gateway reports its reconnect immediately
    json(res, 200, result);
    return;
  }
  if (url.pathname === '/api/edge/heartbeat' && req.method === 'POST') {
    const body = await readJson(req);
    if (Object.keys(body).length !== 0) throw fail(400, 'INVALID_ARGUMENT', 'Heartbeat accepts an empty object');
    json(res, 200, simulator.heartbeat({ actor }));
    return;
  }
  if (url.pathname === '/api/edge/fault' && req.method === 'POST') {
    const body = await readJson(req);
    json(res, 200, simulator.setEdgeFault({ actor, deviceId: body.deviceId, mode: body.mode }));
    return;
  }
  if (url.pathname === '/api/schedules' && req.method === 'POST') {
    const body = await readJson(req);
    json(res, 201, simulator.addSchedule({
      actor,
      deviceId: body.deviceId,
      action: body.action,
      parameters: body.parameters,
      at: body.at,
    }));
    return;
  }
  const scheduleMatch = /^\/api\/schedules\/([A-Za-z0-9_-]+)$/.exec(url.pathname);
  if (scheduleMatch && req.method === 'DELETE') {
    json(res, 200, simulator.cancelSchedule({ actor, scheduleId: scheduleMatch[1] }));
    return;
  }
  throw fail(404, 'NOT_FOUND', 'Unknown API route');
}

// Guardian: everyone signed in can read it and make up a missed routine run; only admins flip the demo camera.
async function handleGuardian(req, res, url, entry) {
  if (!guardian) throw fail(404, 'GUARDIAN_DISABLED', 'Guardian is not available');
  if (url.search) throw fail(400, 'QUERY_NOT_ALLOWED', 'No query parameters');
  if (url.pathname === '/api/guardian/status' && req.method === 'GET') {
    json(res, 200, { ...guardian.status(), clock: { speed: guardianClock.speed, start: guardianClock.start }, simulated: true });
    return;
  }
  if (req.method !== 'POST') throw fail(405, 'METHOD_NOT_ALLOWED', 'POST required');
  if (![`http://127.0.0.1:${activePort}`, `http://localhost:${activePort}`].includes(req.headers.origin)) {
    throw fail(403, 'INVALID_ORIGIN', 'Same origin required');
  }
  const body = await readJson(req);
  if (url.pathname === '/api/guardian/retry') {
    if (Object.keys(body).join(',') !== 'runId' || typeof body.runId !== 'string' || body.runId.length > 64) throw fail(400, 'INVALID_ARGUMENT', 'Only runId is accepted');
    const r = guardian.retry({ runId: body.runId });
    if (!r.ok && r.code) throw fail(409, r.code, 'Routine run cannot be retried');
    console.log(`guardian retry ${body.runId.replace(/[^A-Za-z0-9:_-]/gu, '?')} -> ${r.run.result}${entry.via === 'phone' ? ` by phone "${entry.name}"` : ''}`);
    json(res, 200, r);
    return;
  }
  if (url.pathname === '/api/guardian/summary') {
    if (entry.role !== 'admin') throw fail(403, 'ADMIN_REQUIRED', 'Admin required');
    if (Object.keys(body).length !== 0) throw fail(400, 'INVALID_ARGUMENT', 'No fields are accepted');
    const r = await sendCareSummary('on request');
    json(res, 200, { ...r, simulated: true });
    return;
  }
  if (url.pathname === '/api/guardian/camera') {
    if (entry.role !== 'admin') throw fail(403, 'ADMIN_REQUIRED', 'Admin required');
    if (Object.keys(body).join(',') !== 'online' || typeof body.online !== 'boolean') throw fail(400, 'INVALID_ARGUMENT', 'Only online:boolean is accepted');
    json(res, 200, guardian.setSimulatedCamera({ online: body.online }));
    return;
  }
  throw fail(404, 'NOT_FOUND', 'Route not found');
}

// Door approval. Anyone signed in may request and follow their request; only the admin PHONE sees the pending request with its
// snapshot, and approving needs that phone's long-lived credential (kept in the phone's browser), not just a session token.
async function handleDoor(req, res, url, entry) {
  if (!doors) throw fail(404, 'DOOR_APPROVAL_DISABLED', 'Door approval is not available');
  if (url.search) throw fail(400, 'QUERY_NOT_ALLOWED', 'No query parameters');
  const adminPhone = entry.via === 'phone' && entry.role === 'admin';
  if (req.method === 'GET') {
    if (!adminPhone) throw fail(403, 'ADMIN_PHONE_REQUIRED', 'Only the admin phone sees door requests');
    if (url.pathname === '/api/door/pending') { json(res, 200, { pending: doors.pending(), simulated: true }); return; }
    if (url.pathname === '/api/door/snapshot') {
      let shot;
      try { shot = doors.snapshot(); } catch (error) { throw doorError(error); }
      res.writeHead(200, { 'content-type': shot.type, 'content-length': shot.bytes.length, 'cache-control': 'no-store',
        'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'",
        'x-snapshot-source': shot.source });
      res.end(shot.bytes);
      return;
    }
    throw fail(404, 'NOT_FOUND', 'Route not found');
  }
  if (req.method !== 'POST') throw fail(405, 'METHOD_NOT_ALLOWED', 'POST required');
  if (![`http://127.0.0.1:${activePort}`, `http://localhost:${activePort}`].includes(req.headers.origin)) {
    throw fail(403, 'INVALID_ORIGIN', 'Same origin required');
  }
  const body = await readJson(req, url.pathname === '/api/door/live' ? 40_000 : 16_384);
  const keys = Object.keys(body).sort().join(',');
  if (url.pathname === '/api/door/request') {
    if (keys !== '') throw fail(400, 'INVALID_ARGUMENT', 'No fields are accepted');
    json(res, 202, requestDoorOpen(entry.via === 'phone' ? 'phone' : 'console', entry.name ?? 'console'));
    return;
  }
  if (url.pathname === '/api/door/doorbell-demo') {
    if (!adminPhone) throw fail(403, 'ADMIN_PHONE_REQUIRED', 'Only the admin phone can ring the demo doorbell');
    if (keys !== '') throw fail(400, 'INVALID_ARGUMENT', 'No fields are accepted');
    let rang;
    try { rang = requestDoorOpen('ring', 'Ring doorbell (simulated)'); }
    catch (error) { if (error.code === 'DOOR_REQUEST_PENDING') guardian?.noteDoorbellAgain(); throw error; }
    json(res, 202, rang);
    return;
  }
  if (url.pathname === '/api/door/live' || url.pathname === '/api/door/live-stop') {
    if (!adminPhone) throw fail(403, 'ADMIN_PHONE_REQUIRED', 'Only the admin phone sees the live view');
    if (url.pathname === '/api/door/live-stop') {
      if (keys !== 'sessionId' || typeof body.sessionId !== 'string' || body.sessionId.length > 64) throw fail(400, 'INVALID_ARGUMENT', 'Only sessionId is accepted');
      json(res, 200, await ringLive.stop({ sessionId: body.sessionId }));
      return;
    }
    if (keys !== 'sdp') throw fail(400, 'INVALID_ARGUMENT', 'Only sdp is accepted');
    if (!doors.pending()) throw fail(409, 'DOOR_REQUEST_NONE', 'Live view opens only while someone is waiting at the door');
    try {
      json(res, 200, { ...(await ringLive.start({ sdp: body.sdp })), source: 'ring' });
      // Ring had no image yet (Playground: none until the camera streams). Once the live view runs, fetch the snapshot again.
      const waiting = doors.pending();
      if (waiting?.snapshot?.source === 'simulated') {
        const t = setTimeout(() => { if (doors.pending()?.requestId === waiting.requestId) void attachDoorSnapshot(waiting.requestId); }, 5000);
        t.unref?.();
      }
    }
    catch (error) {
      if (!(error instanceof RingLiveError)) throw error;
      if (error.detail) console.error(`ERROR ring live view: ${error.detail}`);
      throw fail(error.status, error.code, 'Ring live view not available');
    }
    return;
  }
  if (url.pathname === '/api/door/status') {
    if (keys !== 'requestId') throw fail(400, 'INVALID_ARGUMENT', 'Only requestId is accepted');
    try { json(res, 200, doors.status({ requestId: body.requestId })); } catch (error) { throw doorError(error); }
    return;
  }
  if (url.pathname === '/api/door/decide') {
    if (!adminPhone) throw fail(403, 'ADMIN_PHONE_REQUIRED', 'Only the admin phone can decide');
    if (keys !== 'decision,deviceToken,requestId') throw fail(400, 'INVALID_ARGUMENT', 'Only requestId, decision and deviceToken are accepted');
    if (!['approve', 'deny'].includes(body.decision)) throw fail(400, 'INVALID_DECISION', 'approve or deny');
    // Proof of the phone itself (rotated like every other use); it must be the same admin phone this session belongs to.
    let device;
    try { device = phoneCall(() => phones.exchange({ deviceToken: body.deviceToken, requireRole: 'admin', expectDeviceId: entry.deviceId })); }
    catch (error) { if (error.code === 'DEVICE_REVOKED') console.error('ERROR phone credential reuse or revoked phone refused (door decision)'); throw error; }
    let result;
    try { result = doors.decide({ requestId: body.requestId, decision: body.decision, approver: device.name, execute: performApprovedUnlock }); }
    catch (error) {
      const e = doorError(error);
      json(res, e.status ?? 500, { error: e.code ?? 'ERROR', message: 'Door decision refused', deviceToken: device.deviceToken });
      return;
    }
    if (result.status === 'failed') console.error(`ERROR door approved but not opened: ${result.reason}`);
    json(res, 200, { ...result, deviceToken: device.deviceToken });
    return;
  }
  throw fail(404, 'NOT_FOUND', 'Route not found');
}

// Face hint (src/face_hint.mjs): admin PHONE only. Enrol needs a separate consent; photos are analysed and dropped (only the
// encrypted feature is kept); delete one or everyone; "check" tries a photo against the enrolled people and keeps nothing.
const FACE_BODY_MAX = 2_100_000;
function faceError(error) { return error instanceof FaceHintError ? fail(error.status, error.code, 'Face hint request refused') : error; }
function imageFromBody(value) {
  if (typeof value !== 'string' || value.length > FACE_BODY_MAX || !/^[A-Za-z0-9+/]+={0,2}$/u.test(value)) throw fail(400, 'IMAGE_INVALID', 'Base64 JPEG or PNG required');
  return Buffer.from(value, 'base64');
}
async function handleFaces(req, res, url, entry) {
  if (!(entry.via === 'phone' && entry.role === 'admin')) throw fail(403, 'ADMIN_PHONE_REQUIRED', 'Only the admin phone manages face hints');
  if (url.search) throw fail(400, 'QUERY_NOT_ALLOWED', 'No query parameters');
  if (url.pathname === '/api/faces' && req.method === 'GET') {
    const status = faceHint.status();
    json(res, 200, { ...status, people: faceHint.enabled ? faceHint.list() : [], hintOnly: true });
    return;
  }
  if (req.method !== 'POST') throw fail(405, 'METHOD_NOT_ALLOWED', 'POST required');
  if (![`http://127.0.0.1:${activePort}`, `http://localhost:${activePort}`].includes(req.headers.origin)) {
    throw fail(403, 'INVALID_ORIGIN', 'Same origin required');
  }
  const body = await readJson(req, FACE_BODY_MAX + 4096);
  const keys = Object.keys(body).sort().join(',');
  try {
    if (url.pathname === '/api/faces/enroll') {
      if (keys !== 'consent,image,name') throw fail(400, 'INVALID_ARGUMENT', 'Only name, consent and image are accepted');
      const person = await faceHint.enroll({ name: body.name, consent: body.consent, image: imageFromBody(body.image) });
      console.log(`face hint: one person enrolled with consent (${faceHint.status().people} total)`);
      json(res, 201, person);
      return;
    }
    if (url.pathname === '/api/faces/delete') {
      if (keys === 'all' && body.all === true) { const r = faceHint.removeAll(); console.log(`face hint: all enrolled people deleted (${r.removed})`); json(res, 200, r); return; }
      if (keys !== 'id') throw fail(400, 'INVALID_ARGUMENT', 'id, or all:true');
      const r = faceHint.remove(body.id); console.log('face hint: one enrolled person deleted');
      json(res, 200, r);
      return;
    }
    if (url.pathname === '/api/faces/check') {
      if (keys !== 'image') throw fail(400, 'INVALID_ARGUMENT', 'Only image is accepted');
      json(res, 200, { hint: await faceHint.hint(imageFromBody(body.image)), hintOnly: true });
      return;
    }
  } catch (error) { throw faceError(error); }
  throw fail(404, 'NOT_FOUND', 'Route not found');
}

const RING_PLAYGROUND_TOKEN_MINUTES = 30;   // Ring release notes (Developers Playground, 2026-05-28)
function ringTokenView() {
  const guardianRing = guardian?.status().camera.ring ?? null;
  const bell = ringDoorbell.status().state;
  const state = !ringProviderToken ? 'none' : guardianRing === 'token_expired' || bell === 'token_expired' ? 'expired' : ringNetworkOff ? 'offline_mode' : 'live';
  return { state, loadedAt: ringTokenLoadedAt ? new Date(ringTokenLoadedAt).toISOString() : null,
    expiresAtEstimate: ringTokenLoadedAt ? new Date(ringTokenLoadedAt + RING_PLAYGROUND_TOKEN_MINUTES * 60_000).toISOString() : null,
    doorbell: bell, camera: guardianRing, playgroundUrl: 'https://developer.amazon.com/ring/console/playground' };
}
async function handleRingToken(req, res, url, entry) {
  if (entry.role !== 'admin') throw fail(403, 'ADMIN_REQUIRED', 'Admin required');
  if (url.search) throw fail(400, 'QUERY_NOT_ALLOWED', 'No query parameters');
  if (url.pathname === '/api/ring/token-status') {
    if (req.method !== 'GET') throw fail(405, 'METHOD_NOT_ALLOWED', 'GET required');
    json(res, 200, ringTokenView());
    return;
  }
  if (req.method !== 'POST') throw fail(405, 'METHOD_NOT_ALLOWED', 'POST required');
  if (![`http://127.0.0.1:${activePort}`, `http://localhost:${activePort}`].includes(req.headers.origin)) throw fail(403, 'INVALID_ORIGIN', 'Same origin required');
  requireRingOperatorPasscode(req);   // the admin phone passes; a desktop session needs the operator code
  const body = await readJson(req);
  if (url.pathname === '/api/ring/token-clear') {
    if (Object.keys(body).length !== 0) throw fail(400, 'INVALID_ARGUMENT', 'No fields are accepted');
    ringProviderToken = null; ringTokenLoadedAt = null; ringTokenGeneration += 1;
    console.log('ring token: removed from memory by the admin');
    json(res, 200, ringTokenView());
    return;
  }
  if (Object.keys(body).join(',') !== 'token') throw fail(400, 'INVALID_ARGUMENT', 'Only token is accepted');
  let value = typeof body.token === 'string' ? body.token.trim() : '';
  body.token = undefined;
  if (!validRingProviderToken(value)) throw fail(422, 'RING_TOKEN_INVALID', 'That does not look like a Ring access token');
  ringProviderToken = value; value = undefined;
  ringTokenLoadedAt = Date.now(); ringTokenGeneration += 1;
  console.log(`ring token: loaded into memory from the console${entry.via === 'phone' ? ` (phone "${entry.name}")` : ''}; real Ring calls on, about ${RING_PLAYGROUND_TOKEN_MINUTES} minutes`);
  guardian?.probeRingNow();
  void ringDoorbell.poll();
  json(res, 200, ringTokenView());
}

// Remote approval set-up (admin PHONE only): a one-time code that this same phone takes to the relay page.
async function handleRelay(req, res, url, entry) {
  if (!(entry.via === 'phone' && entry.role === 'admin')) throw fail(403, 'ADMIN_PHONE_REQUIRED', 'Only the admin phone sets up remote approval');
  if (!remoteRelay) { json(res, 200, { enabled: false, reason: 'HOME_MCP_RELAY_BASE not set' }); return; }
  if (url.pathname === '/api/relay/status' && req.method === 'GET') { json(res, 200, { enabled: true, ...remoteRelay.status() }); return; }
  if (req.method !== 'POST') throw fail(405, 'METHOD_NOT_ALLOWED', 'POST required');
  if (![`http://127.0.0.1:${activePort}`, `http://localhost:${activePort}`].includes(req.headers.origin)) throw fail(403, 'INVALID_ORIGIN', 'Same origin required');
  const body = await readJson(req);
  if (url.pathname === '/api/relay/enable') {
    if (Object.keys(body).length !== 0) throw fail(400, 'INVALID_ARGUMENT', 'No fields are accepted');
    try { json(res, 200, await remoteRelay.enable({ deviceId: entry.deviceId })); }
    catch (error) { throw fail(502, 'RELAY_UNREACHABLE', `Relay not reachable (${error.code ?? 'error'})`); }
    return;
  }
  if (url.pathname === '/api/relay/revoke') {
    if (Object.keys(body).join(',') !== 'keyId' || typeof body.keyId !== 'string' || !/^[0-9a-f]{64}$/u.test(body.keyId)) throw fail(400, 'INVALID_ARGUMENT', 'Only keyId is accepted');
    if (!remoteRelay.status().phones.some((p) => p.keyId === body.keyId)) throw fail(404, 'RELAY_PHONE_UNKNOWN', 'No such phone');
    // removed at home first; the cloud copy is told too, but even if that call fails the hub no longer trusts the key
    try { await remoteRelay.revoke(body.keyId); } catch (error) { console.error(`ERROR remote approval revoke not sent to relay: ${error.code ?? 'unreachable'}`); }
    console.log(`remote approval: phone removed by "${entry.name}"`);
    json(res, 200, { enabled: true, ...remoteRelay.status() });
    return;
  }
  throw fail(404, 'NOT_FOUND', 'Route not found');
}

const PHONE_PUBLIC_ROUTES = new Set(['/api/phones/pair-request', '/api/phones/pair-status', '/api/phones/session']);

function phoneCall(run) {
  try { return run(); } catch (error) {
    if (error instanceof PhonePairingError) throw fail(error.status, error.code, 'Phone pairing denied');
    throw error;
  }
}
// No console session yet: the phone proves itself with a pairing code, a pairing request id or its device credential.
async function handlePhonePublic(req, res, url) {
  if (!phones) throw fail(404, 'PHONES_DISABLED', 'Phone pairing is not available');
  if (req.method !== 'POST') throw fail(405, 'METHOD_NOT_ALLOWED', 'POST required');
  if (url.search) throw fail(400, 'QUERY_NOT_ALLOWED', 'No query parameters');
  if (![`http://127.0.0.1:${activePort}`, `http://localhost:${activePort}`].includes(req.headers.origin)) {
    throw fail(403, 'INVALID_ORIGIN', 'Same origin required');
  }
  const body = await readJson(req);
  const keys = Object.keys(body).sort().join(',');
  if (url.pathname === '/api/phones/pair-request') {
    if (keys !== 'code,name') throw fail(400, 'INVALID_ARGUMENT', 'Only code and name are accepted');
    const r = phoneCall(() => phones.requestPairing({ code: body.code, name: body.name }));
    console.log(`phone pairing requested "${r.name}" as ${r.role}; waiting for approval ${r.role === 'member' ? 'on the admin phone (or y on this terminal)' : macDialog ? 'in the Mac window (or y on this terminal)' : 'on this terminal'}`);
    json(res, 202, { requestId: r.requestId, name: r.name, role: r.role, status: 'pending', check: r.check, expiresAt: r.expiresAt,
      approver: r.role === 'admin' ? 'mac' : 'admin_phone' });
    return;
  }
  if (url.pathname === '/api/phones/pair-status') {
    if (keys !== 'requestId') throw fail(400, 'INVALID_ARGUMENT', 'Only requestId is accepted');
    const r = phoneCall(() => phones.pairStatus({ requestId: body.requestId }));
    if (r.status === 'approved') console.log(`phone paired "${r.name}" as ${r.role}`);
    json(res, 200, r);
    return;
  }
  if (keys !== 'deviceToken') throw fail(400, 'INVALID_ARGUMENT', 'Only deviceToken is accepted');
  let device;
  try { device = phoneCall(() => phones.exchange({ deviceToken: body.deviceToken })); }
  catch (error) { if (error.code === 'DEVICE_REVOKED') console.error('ERROR phone credential reuse or revoked phone refused'); throw error; }
  const session = issueSession({ role: device.role, via: 'phone', deviceId: device.deviceId, name: device.name });
  json(res, 200, { ...session, deviceToken: device.deviceToken, deviceExpiresAt: device.deviceExpiresAt, role: device.role, name: device.name });
}
// Admin only: issue a pairing code (admin or family member), list phones, revoke one.
async function handlePhoneAdmin(req, res, url, entry) {
  if (!phones) throw fail(404, 'PHONES_DISABLED', 'Phone pairing is not available');
  if (entry.role !== 'admin') throw fail(403, 'ADMIN_REQUIRED', 'Admin required');
  if (url.search) throw fail(400, 'QUERY_NOT_ALLOWED', 'No query parameters');
  if (url.pathname === '/api/phones' && req.method === 'GET') { json(res, 200, { phones: phones.list() }); return; }
  const adminPhone = entry.via === 'phone' && entry.role === 'admin';
  if (url.pathname === '/api/phones/pending' && req.method === 'GET') {
    if (!adminPhone) throw fail(403, 'ADMIN_PHONE_REQUIRED', 'Only the admin phone approves family phones');
    json(res, 200, { pending: phones.pendingMembers() });
    return;
  }
  if (req.method !== 'POST') throw fail(405, 'METHOD_NOT_ALLOWED', 'POST required');
  if (![`http://127.0.0.1:${activePort}`, `http://localhost:${activePort}`].includes(req.headers.origin)) {
    throw fail(403, 'INVALID_ORIGIN', 'Same origin required');
  }
  const body = await readJson(req);
  if (url.pathname === '/api/phones/pair-code') {
    if (Object.keys(body).join(',') !== 'role') throw fail(400, 'INVALID_ARGUMENT', 'Only role is accepted');
    json(res, 201, phoneCall(() => phones.createPairCode({ role: body.role })));
    return;
  }
  // Family phone approval on the admin phone: needs that phone's own long-lived credential (rotated), like door approval.
  if (url.pathname === '/api/phones/decide') {
    if (!adminPhone) throw fail(403, 'ADMIN_PHONE_REQUIRED', 'Only the admin phone approves family phones');
    if (Object.keys(body).sort().join(',') !== 'approvalId,decision,deviceToken') throw fail(400, 'INVALID_ARGUMENT', 'Only approvalId, decision and deviceToken are accepted');
    let device;
    try { device = phoneCall(() => phones.exchange({ deviceToken: body.deviceToken, requireRole: 'admin', expectDeviceId: entry.deviceId })); }
    catch (error) { if (error.code === 'DEVICE_REVOKED') console.error('ERROR phone credential reuse or revoked phone refused (family approval)'); throw error; }
    let result;
    try { result = phoneCall(() => phones.decideMember({ approvalId: body.approvalId, decision: body.decision })); }
    catch (error) { json(res, error.status ?? 500, { error: error.code ?? 'ERROR', message: 'Family approval refused', deviceToken: device.deviceToken }); return; }
    console.log(`phone pairing "${result.name}": ${result.decided === 'approve' ? 'APPROVED' : 'refused'} on admin phone "${device.name}"`);
    json(res, 200, { ...result, deviceToken: device.deviceToken });
    return;
  }
  if (url.pathname === '/api/phones/revoke') {
    if (Object.keys(body).join(',') !== 'deviceId' || typeof body.deviceId !== 'string') throw fail(400, 'INVALID_ARGUMENT', 'Only deviceId is accepted');
    json(res, 200, phoneCall(() => phones.revoke({ deviceId: body.deviceId })));
    return;
  }
  throw fail(404, 'NOT_FOUND', 'Route not found');
}

const CLOUD_MCP_ACTIONS = new Map([
  ['/api/cloud-mcp/login-url', 'login-url'],
  ['/api/cloud-mcp/callback', 'callback'],
  ['/api/cloud-mcp/callback-clipboard', 'callback-clipboard'],
  ['/api/cloud-mcp/switch', 'switch'],
  ['/api/cloud-mcp/device', 'device'],
  ['/api/cloud-mcp/listen', 'listen'],
]);

function noRequestBody(req) {
  if (req.headers['transfer-encoding'] || (req.headers['content-length'] !== undefined && req.headers['content-length'] !== '0')) {
    throw fail(400, 'BODY_NOT_ALLOWED', 'No request body');
  }
}

// Owner session (checked by handleApi) + owner actor + same-origin intent for every cloud action. The existing local operator
// gate (shared failure counter / rate limit with Ring import and discovery) is asked once per cloud login, at login-url:
// callbacks only complete a login the operator started, and later actions reuse that login until its token expires.
async function handleCloudMcp(req, res, url, actor) {
  if (!cloudPanel.enabled) throw fail(404, 'CLOUD_PANEL_DISABLED', 'Cloud MCP panel is disabled');
  if (url.search) throw fail(400, 'QUERY_NOT_ALLOWED', 'No query parameters');
  if (actor !== 'owner') throw fail(403, 'OWNER_REQUIRED', 'Owner session required');
  try {
    if (url.pathname === '/api/cloud-mcp/status') {
      if (req.method !== 'GET') throw fail(405, 'METHOD_NOT_ALLOWED', 'GET required');
      noRequestBody(req);
      json(res, 200, await cloudPanel.status());
      return;
    }
    const action = CLOUD_MCP_ACTIONS.get(url.pathname);
    if (!action) throw fail(404, 'NOT_FOUND', 'Route not found');
    if (req.method !== 'POST') throw fail(405, 'METHOD_NOT_ALLOWED', 'POST required');
    const origins = [];
    for (let index = 0; index < req.rawHeaders.length; index += 2) {
      if (req.rawHeaders[index].toLowerCase() === 'origin') origins.push(req.rawHeaders[index + 1]);
    }
    if (origins.length !== 1 || ![`http://127.0.0.1:${activePort}`, `http://localhost:${activePort}`].includes(origins[0])
      || req.headers['x-cloud-mcp-intent'] !== action) {
      throw fail(403, 'CLOUD_INTENT_REQUIRED', 'Same-origin explicit cloud action required');
    }
    const entry = requireSessionEntry(req);
    if (action === 'login-url') requireRingOperatorPasscode(req);
    if (action === 'login-url') {
      noRequestBody(req);
      const result = await cloudPanel.loginUrl();
      console.log('cloud-mcp login-url issued (open manually in a new tab)');
      json(res, 200, result);
      return;
    }
    if (action === 'callback') {
      const body = await readJson(req);
      if (Object.keys(body).length !== 1 || typeof body.callbackUrl !== 'string') {
        throw fail(400, 'INVALID_ARGUMENT', 'Only callbackUrl is accepted');
      }
      const result = await cloudPanel.stageCallback(body.callbackUrl, 'paste');
      console.log('cloud-mcp callback staged (source=paste)');
      json(res, 200, result);
      return;
    }
    if (action === 'callback-clipboard') {
      noRequestBody(req);
      let clipboardValue;
      try {
        const result = await execFileAsync('/usr/bin/pbpaste', [], {
          encoding: 'utf8',
          timeout: 2500,
          maxBuffer: 4096,
          shell: false,
          env: { PATH: '/usr/bin:/bin' },
        });
        clipboardValue = result.stdout;
      } catch {
        throw fail(503, 'CLIPBOARD_UNAVAILABLE', 'Local clipboard unavailable');
      }
      if (typeof clipboardValue === 'string' && clipboardValue.endsWith('\n')) {
        clipboardValue = clipboardValue.slice(0, clipboardValue.endsWith('\r\n') ? -2 : -1);
      }
      const result = await cloudPanel.stageCallback(clipboardValue, 'clipboard');
      clipboardValue = undefined;
      console.log('cloud-mcp callback staged (source=clipboard)');
      json(res, 200, result);
      return;
    }
    const body = await readJson(req);
    const isDevice = action === 'device';
    const isListen = action === 'listen';
    if (isListen ? Object.keys(body).length !== 0
      : isDevice ? Object.keys(body).length !== 2 || typeof body.deviceId !== 'string' || typeof body.action !== 'string'
        : Object.keys(body).length !== 1 || typeof body.enabled !== 'boolean') {
      throw fail(400, 'INVALID_ARGUMENT', isListen ? 'An empty object is required'
        : isDevice ? 'Only deviceId and action strings are accepted' : 'Only enabled:boolean is accepted');
    }
    const safeWord = value => String(value).replace(/[^a-z_]/gu, '?').slice(0, 32);
    const label = isListen ? 'listen' : isDevice ? `device ${safeWord(body.deviceId)} ${safeWord(body.action)}` : `switch enabled=${body.enabled}`;
    if (req.aborted || requireSessionEntry(req) !== entry) throw fail(409, 'CLOUD_AUTHORIZATION_CHANGED', 'Authorization changed');
    const lines = [];
    let streamOpen = false;
    const emit = value => { if (streamOpen && !res.writableEnded) res.write(JSON.stringify(value) + '\n'); else lines.push(value); };
    const onStep = step => emit({ type: 'step', ...step });
    const job = isListen ? await cloudPanel.prepareListen(onStep)
      : isDevice ? await cloudPanel.prepareDevice(body.deviceId, body.action, onStep) : await cloudPanel.prepareSwitch(body.enabled, onStep);
    let started = false;
    try {
      // The job holds the busy flag and a passphrase copy; if anything below throws before start(), abort() releases both.
      if (req.aborted || res.destroyed) throw fail(409, 'CLOUD_CLIENT_GONE', 'Client went away');
      res.writeHead(200, {
        'content-type': 'application/x-ndjson; charset=utf-8',
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        'x-frame-options': 'DENY',
      });
      streamOpen = true;
      for (const value of lines.splice(0)) res.write(JSON.stringify(value) + '\n');
      started = true;
      try {
        const result = await job.start();
        console.log(`cloud-mcp ${label} ok=${result.ok} executed=${result.result.executed} mode=${result.mode}`);
        emit({ type: 'result', at: new Date().toISOString(), ...result });
      } catch (error) {
        const code = error instanceof CloudPanelError ? error.code : 'CLOUD_STEP_FAILED';
        console.error(`ERROR cloud-mcp ${label} code=${code}`);
        emit({ type: 'error', at: new Date().toISOString(), code });
      }
      res.end();
    } finally {
      if (!started && job.abort()) console.error(`ERROR cloud-mcp ${label} code=CLOUD_ABORTED_BEFORE_START`);
    }
  } catch (error) {
    if (error instanceof CloudPanelError) {
      console.error(`ERROR cloud-mcp ${url.pathname.slice(15)} code=${error.code}`);
      throw fail(error.status, error.code, 'Cloud MCP action denied');
    }
    throw error;
  }
}

function mcpTools() {
  const devices = simulator.getState().devices;
  const deviceTools = devices.map((device) => ({
    name: `device_${device.id}`,
    title: device.label,
    description: `SIMULATED ${device.label} control. Requires a paired virtual device; high-risk actions require a confirmation created in the owner UI.`,
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: device.actions },
        parameters: { type: 'object' },
        confirmationId: { type: 'string' },
        confirmationPhrase: { type: 'string' },
      },
      required: ['action'],
      additionalProperties: false,
    },
  }));
  return [...deviceTools, {
    name: 'device_batch',
    title: '一對多虛擬設備控制',
    description: 'SIMULATED one-to-many control. Each paired device has an independent receipt or fallback result. Unlock and camera disarm are forbidden in a batch.',
    inputSchema: {
      type: 'object',
      properties: {
        commands: {
          type: 'array',
          minItems: 1,
          maxItems: 7,
          items: {
            type: 'object',
            properties: {
              deviceId: { type: 'string', enum: devices.map((device) => device.id) },
              action: { type: 'string' },
              parameters: { type: 'object' },
              commandId: { type: 'string' },
            },
            required: ['deviceId', 'action'],
            additionalProperties: false,
          },
        },
      },
      required: ['commands'],
      additionalProperties: false,
    },
  }];
}

function rpcResult(id, result) {
  return { jsonrpc: '2.0', id, result };
}

function rpcError(id, code, message) {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

function rpcToolResult(id, result) {
  return rpcResult(id, {
    content: [{ type: 'text', text: JSON.stringify(result) }],
    structuredContent: result,
    isError: false,
  });
}

function dispatchMcpToolCall(body, { actor = null, verifiedRingEvent = null } = {}) {
  const name = body.params?.name;
  const args = body.params?.arguments;
  if (name === 'ring_motion_to_light') {
    if (!verifiedRingEvent || !verifiedRingEvents.has(verifiedRingEvent)
      || !args || typeof args !== 'object' || Array.isArray(args)
      || Object.keys(args).length !== 1 || args.event !== verifiedRingEvent) {
      return rpcError(body.id, -32602, 'Unknown tool or invalid arguments');
    }
    return rpcToolResult(body.id, simulator.performRingMotion(verifiedRingEvent));
  }
  const tool = mcpTools().find((item) => item.name === name);
  if (!tool || !args || typeof args !== 'object' || Array.isArray(args)) {
    return rpcError(body.id, -32602, 'Unknown tool or invalid arguments');
  }
  if (name !== 'device_batch' && !tool.inputSchema.properties.action.enum.includes(args.action)) {
    return rpcError(body.id, -32602, 'Unsupported device action');
  }
  try {
    const result = name === 'device_batch'
      ? simulator.performBatch({ actor, commands: args.commands, origin: 'mcp' })
      : simulator.perform({
        actor,
        deviceId: name.slice('device_'.length),
        action: args.action,
        parameters: args.parameters,
        confirmationId: args.confirmationId,
        confirmationPhrase: args.confirmationPhrase,
        origin: 'mcp',
      });
    return rpcToolResult(body.id, result);
  } catch (error) {
    return rpcResult(body.id, {
      content: [{ type: 'text', text: `${error.code || 'DENIED'}: ${error.message}` }],
      isError: true,
    });
  }
}

async function handleMcp(req, res) {
  if (req.method === 'GET' || req.method === 'DELETE') {
    empty(res, 405, { allow: 'POST' });
    return;
  }
  if (req.method !== 'POST') throw fail(405, 'METHOD_NOT_ALLOWED', 'POST required');
  const sessionEntry = requireSessionEntry(req);
  const actor = sessionEntry.actor;
  const accept = String(req.headers.accept || '');
  if (!accept.includes('application/json') || !accept.includes('text/event-stream')) {
    throw fail(406, 'INVALID_ACCEPT', 'MCP requires JSON and event-stream Accept types');
  }
  const body = await readJson(req);
  if (body.jsonrpc !== '2.0' || typeof body.method !== 'string' || Array.isArray(body.params)) {
    json(res, 400, rpcError(body.id ?? null, -32600, 'Invalid JSON-RPC request'));
    return;
  }
  const isNotification = !Object.hasOwn(body, 'id');
  if (isNotification) {
    if (body.method === 'notifications/initialized' || body.method === 'notifications/cancelled') {
      empty(res, 202);
    } else {
      empty(res, 400);
    }
    return;
  }
  const version = req.headers['mcp-protocol-version'];
  if (body.method !== 'initialize' && version !== protocolVersion) {
    throw fail(400, 'UNSUPPORTED_MCP_VERSION', `MCP-Protocol-Version ${protocolVersion} required`);
  }
  if (body.method === 'initialize') {
    if (body.params?.protocolVersion !== protocolVersion) {
      json(res, 200, rpcError(body.id, -32602, `Only MCP ${protocolVersion} is supported`));
      return;
    }
    json(res, 200, rpcResult(body.id, {
      protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: 'ring-home-mcp-hub', version: '0.1.0' },
      instructions: 'SIMULATED devices only. Pair in the owner UI first. Door unlock requires a fresh owner UI confirmation.',
    }));
    return;
  }
  if (body.method === 'ping') {
    json(res, 200, rpcResult(body.id, {}));
    return;
  }
  if (body.method === 'tools/list') {
    if (!mcpProfile) {
      json(res, 200, rpcError(body.id, -32003, 'Formal MCP runtime is not ready'));
      return;
    }
    json(res, 200, rpcResult(body.id, await mcpProfile.list()));
    return;
  }
  if (body.method === 'tools/call') {
    if (!mcpProfile || mcpProfile.profile !== 'DEMO') {
      json(res, 200, rpcError(body.id, -32003, 'Formal MCP runtime is not ready'));
      return;
    }
    const toolName = body.params?.name; const toolAction = body.params?.arguments?.action;
    if (toolName === 'device_front_door' && toolAction === 'unlock') {
      // An AI agent may ASK; the admin phone decides. The answer is a normal tool result saying "pending approval".
      try {
        json(res, 200, rpcToolResult(body.id, requestDoorOpen('mcp', sessionEntry.via === 'phone' ? sessionEntry.name : 'AI agent (MCP)')));
      } catch (error) {
        json(res, 200, rpcError(body.id, -32003, `Door request refused: ${error.code ?? 'ERROR'}`));
      }
      return;
    }
    if (sessionEntry.role === 'member' && typeof toolName === 'string' && toolName.startsWith('device_') &&
        memberForbiddenAction(toolName.slice(7), toolAction)) {
      json(res, 200, rpcError(body.id, -32003, 'Camera disarm is admin-only'));
      return;
    }
    if (sessionEntry.via === 'phone') console.log(`phone "${sessionEntry.name}" mcp ${String(toolName).replace(/[^a-z_]/gu, '?').slice(0, 40)} ${String(toolAction).replace(/[^a-z_]/gu, '?').slice(0, 32)}`);
    json(res, 200, await mcpProfile.call(body, { actor }));
    return;
  }
  json(res, 200, rpcError(body.id, -32601, 'Method not found'));
}

const acceptedFormalEnvelopes = new WeakMap();

export async function resolveServerOwnedFormalContext({ formalContextPort, req, actor, validatedWire, effectiveEnvelope }) {
  const accepted = validatedWire && acceptedFormalEnvelopes.get(validatedWire);
  if (!accepted || accepted.effectiveEnvelope !== effectiveEnvelope || accepted.request !== req || accepted.actor !== actor) {
    throw fail(403, 'B02_FORMAL_CONTEXT_DENIED', 'Formal context denied');
  }
  if (!formalContextPort || formalContextPort.productionAdmitted !== true ||
      typeof formalContextPort.resolve !== 'function') throw fail(503, 'B02_FORMAL_CONTEXT_UNAVAILABLE', 'Formal context unavailable');
  const resolved = await formalContextPort.resolve(Object.freeze({ request: accepted.contextRequest, actor, validatedWire, effectiveEnvelope }));
  if (!resolved || !['local', 'remote'].includes(resolved.source) ||
      resolved.serverContext === null || typeof resolved.serverContext !== 'object' ||
      Array.isArray(resolved.serverContext)) {
    throw fail(403, 'B02_FORMAL_CONTEXT_DENIED', 'Formal context denied');
  }
  return Object.freeze({ source: resolved.source, serverContext: resolved.serverContext });
}

export { createFormalRequestAuthorizationPolicy } from './formal-runtime/request-authorization-policy.mjs';

export async function handleExecutableFormalToolsCall({ executableAssembly: assembly, validatedWire, effectiveEnvelope, req,
  actor, formalContextPort, assertActive = () => {} }) {
  assertActive();
  if (!assembly?.profile || assembly.mode !== 'FORMAL' || assembly.profile.ready !== true) {
    throw fail(503, 'B02_FORMAL_RUNTIME_NOT_READY', 'Formal MCP runtime is not ready');
  }
  const context = await resolveServerOwnedFormalContext({ formalContextPort, req, actor, validatedWire, effectiveEnvelope });
  assertActive();
  return dispatchExecutableFormalRequest({ profile: assembly.profile, envelope: effectiveEnvelope,
    source: context.source, serverContext: context.serverContext });
}

export function createHomeMcpRequestRouter({ executableAssembly: assembly, formalContextPort = null,
  formalAuthorizationPolicy = null, demoRequestRouter, readJsonFn = readJson, jsonFn = json, assertActive = () => {} }) {
  if (!assembly || !['DEMO', 'FORMAL'].includes(assembly.mode) || typeof demoRequestRouter !== 'function' ||
      typeof readJsonFn !== 'function' || typeof jsonFn !== 'function' || typeof assertActive !== 'function' ||
      (assembly.mode === 'FORMAL' && (!formalAuthorizationPolicy ||
        formalAuthorizationPolicy.productionAdmitted !== true ||
        typeof formalAuthorizationPolicy.authorize !== 'function' ||
        typeof formalAuthorizationPolicy.protectedResourceMetadata !== 'function'))) {
    throw new Error('B02_SERVER_ROUTER_INPUT_DENIED');
  }
  return async function homeMcpRequestRouter(req, res, url) {
    assertActive();
    if (assembly.mode === 'DEMO') return demoRequestRouter(req, res, url);
    let body = null;
    if (url.pathname === '/mcp' && req.method === 'POST') body = await readJsonFn(req);
    let wire = null;
    try {
      if (body !== null) wire = validateFormalMcpWireRequest({ headers: req.headers, envelope: body });
    } catch (error) {
      const response = formalWireErrorResponse(error, body?.id ?? null);
      if (response !== null) {
        jsonFn(res, error.status, response);
        return;
      }
      throw error;
    }
    const routeId = routeIdForRequest({ method: req.method, pathname: url.pathname,
      mcpMethod: wire?.routeId ?? body?.method ?? null });
    assertAssemblyRouteAllowed(assembly, routeId);
    if (routeId === 'health') {
      jsonFn(res, 200, { ok: true, profile: 'FORMAL' });
      return;
    }
    if (routeId === 'oauth/protected-resource') {
      jsonFn(res, 200, await formalAuthorizationPolicy.protectedResourceMetadata({ request: req }));
      return;
    }
    const authorization = await formalAuthorizationPolicy.authorize({ request: req, routeId });
    assertActive();
    if (!authorization || !authorization.actor) {
      throw fail(401, 'B02_FORMAL_ACCESS_TOKEN_DENIED', 'Access token denied');
    }
    const actor = authorization.actor;
    const effectiveEnvelope = routeId === 'tools/call'
      ? (wire.era === 'MODERN_STATELESS' ? modernDispatchEnvelope(wire) : wire.request) : null;
    if (effectiveEnvelope !== null) acceptedFormalEnvelopes.set(wire, Object.freeze({
      effectiveEnvelope, request: req, actor, contextRequest: Object.freeze({ httpRequest: req }) }));
    if (wire.era === 'MODERN_STATELESS') {
      if (routeId === 'server/discover') {
        jsonFn(res, 200, modernDiscoverResponse(body.id));
        return;
      }
      if (routeId === 'tools/list') {
        if (assembly.profile.ready !== true) throw fail(503, 'B02_FORMAL_RUNTIME_NOT_READY', 'Formal MCP runtime is not ready');
        const listOptions = Object.hasOwn(body.params, 'cursor')
          ? Object.freeze({ cursor: body.params.cursor }) : Object.freeze({});
        jsonFn(res, 200, modernListResponse({ id: body.id, result: await assembly.profile.list(listOptions) }));
        return;
      }
      const result = await handleExecutableFormalToolsCall({ executableAssembly: assembly,
        validatedWire: wire, effectiveEnvelope, req, actor, formalContextPort, assertActive });
      jsonFn(res, 200, modernResultResponse({ id: body.id, result: result.result }));
      return;
    }
    if (routeId === 'initialize') {
      if (body.params?.protocolVersion !== protocolVersion) {
        jsonFn(res, 200, rpcError(body.id, -32602, `Only MCP ${protocolVersion} is supported`));
        return;
      }
      jsonFn(res, 200, rpcResult(body.id, { protocolVersion, capabilities: { tools: {} },
        serverInfo: { name: 'ring-home-mcp-hub', version: '0.1.0' },
        instructions: 'Formal MCP admission is required for every tools/call.' }));
      return;
    }
    if (routeId === 'tools/list') {
      if (assembly.profile.ready !== true) throw fail(503, 'B02_FORMAL_RUNTIME_NOT_READY', 'Formal MCP runtime is not ready');
      jsonFn(res, 200, rpcResult(body.id, await assembly.profile.list()));
      return;
    }
    const result = await handleExecutableFormalToolsCall({ executableAssembly: assembly, validatedWire: wire, effectiveEnvelope,
      req, actor, formalContextPort, assertActive });
    jsonFn(res, 200, result);
  };
}

async function handleDemoHttpRequest(req, res, url) {
  if ((url.pathname === '/' || url.pathname === '/index.html') && req.method === 'GET') {
    const html = await readFile(htmlPath);
    res.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'content-length': html.length,
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'x-frame-options': 'DENY'
    });
    res.end(html);
    return;
  }
  if (staticAssets.has(url.pathname) && req.method === 'GET') {
    const asset = staticAssets.get(url.pathname);
    const body = await readFile(asset.path);
    res.writeHead(200, {
      'content-type': asset.type,
      'content-length': body.length,
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'x-frame-options': 'DENY'
    });
    res.end(body);
    return;
  }
  if (url.pathname === '/api/ring-test-event') return handleRingTestEvent(req, res);
  if (url.pathname.startsWith('/api/')) return handleApi(req, res, url);
  if (url.pathname === '/mcp') return handleMcp(req, res);
  throw fail(404, 'NOT_FOUND', 'Route not found');
}

export async function startHomeMcpServer({ enabled = false, composition = null, formalAuthorizationPolicy = null,
  demoFactory = null, demoRequestRouter = null, readJsonFn = readJson, jsonFn = json, port = 0 } = {}) {
  if (!Number.isSafeInteger(port) || port < 0 || port > 65535) throw fail(503, 'B02_SERVER_STARTUP_INPUT_DENIED', 'Invalid local port');
  const consumer = await startServerOwnedMcpConsumer({ enabled, composition, formalAuthorizationPolicy,
    demoFactory, demoRequestRouter, readJsonFn, jsonFn });
  let closed = false;
  let listening = false;
  let starting = false;
  let localPort = port;
  let server;
  try { server = http.createServer(async (req, res) => {
    try {
      if (closed) throw fail(503, 'B02_SERVER_CONSUMER_CLOSED', 'Server closed');
      requireLocalHost(req);
      await consumer.router(req, res, new URL(req.url || '/', `http://127.0.0.1:${localPort}`));
    } catch (error) {
      if (res.headersSent) { res.destroy(); return; }
      const status = Number.isSafeInteger(error.status) && error.status >= 400 && error.status < 600 ? error.status : 500;
      jsonFn(res, status, { error: error.code || 'INTERNAL_ERROR', message: status === 500 ? 'Internal error' : error.message });
    }
  }); } catch (error) { await consumer.close(); throw error; }
  const close = async () => {
    closed = true;
    const released = await consumer.close();
    if (server.listening) await new Promise((accept, reject) => server.close(error => error ? reject(error) : accept()));
    listening = false;
    return Object.freeze({ closed, listening, inFlight: released.inFlight, resourceReleased: released.resourceReleased && !server.listening });
  };
  return Object.freeze({ consumer, router: consumer.router,
    async listen() {
      if (closed || listening || starting) throw fail(503, 'B02_SERVER_STARTUP_INPUT_DENIED', 'Server already started or closed');
      starting = true;
      try {
        await new Promise((accept, reject) => {
          const failed = error => { server.removeListener('listening', ready); reject(error); };
          const ready = () => { server.removeListener('error', failed); accept(); };
          server.once('error', failed); server.once('listening', ready);
          try { server.listen(port, '127.0.0.1'); }
          catch (error) { server.removeListener('error', failed); server.removeListener('listening', ready); reject(error); }
        });
        if (closed) throw fail(503, 'B02_SERVER_CONSUMER_CLOSED', 'Server closed during startup');
        listening = true; localPort = server.address().port; return Object.freeze({ listening, port: localPort });
      } catch (error) {
        const released = await close();
        if (released.resourceReleased !== true) throw fail(503, 'B02_FORMAL_STARTUP_RELEASE_PENDING', 'Listener startup cleanup is incomplete');
        throw error;
      } finally { starting = false; }
    },
    close,
    resources() { return Object.freeze({ ...consumer.resources(), listening }); }
  });
}

if (directEntry) {
  const started = await startHomeMcpServer({ enabled: formalRuntimeConfig.enabled, port: portValue,
    ...(formalRuntimeConfig.enabled ? {} : { demoFactory: () => ({ listTools: () => ({ tools: mcpTools() }), dispatchMcpToolCall }),
      demoRequestRouter: handleDemoHttpRequest }) });
  serverMcpConsumer = started.consumer; executableAssembly = serverMcpConsumer.executableAssembly;
  mcpProfile = executableAssembly.profile; formalRuntime = serverMcpConsumer.composition ?? formalRuntime;
  const interval = demoMcpEnabled && listenEnabled ? setInterval(() => {
    try { simulator.tick(); const now = Date.now();
      for (const [key, entry] of sessions) if (now >= entry.expiresAt) sessions.delete(key);
    } catch { console.error('ERROR schedule_tick'); }
  }, 500) : null;
  interval?.unref();
  // Guardian ticks often enough that one tick never spans more than 30 virtual seconds, even on a fast demo clock;
  // otherwise a short gateway blip could be sampled as a 5-minute outage.
  // Ring doorbell watching: every 10 s, real time, only while a Playground token is loaded (idle otherwise; nothing is sent).
  const doorbellTick = doors && listenEnabled && !ringNetworkOff
    ? setInterval(async () => {
      const before = ringDoorbell.status().lastDetail;
      const r = await ringDoorbell.poll();
      const after = ringDoorbell.status().lastDetail;
      if (r.state === 'error' && after && after !== before) console.log(`ring doorbell: Ring event history not available (${after}); will keep trying`);
    }, 10_000) : null;   // idle (no request) until a token is loaded
  doorbellTick?.unref();
  if (doorbellTick && ringProviderToken) void ringDoorbell.poll();
  // Remote approval: poll the relay every 3 s while something is pending (a code or a door request); idle otherwise.
  let relayBusy = false;
  const relayTick = remoteRelay && listenEnabled ? setInterval(async () => {
    if (relayBusy) return; relayBusy = true;
    try { await remoteRelay.tick(); } catch (error) { console.error(`ERROR remote approval relay poll: ${error.code ?? 'unreachable'}`); }
    finally { relayBusy = false; }
  }, 3000) : null;
  relayTick?.unref();
  // Ring webhooks: pull what Ring delivered to the relay every 10 s (opt-in; each pull is one signed call).
  let ringHookBusy = false;
  const ringHookTick = remoteRelay && listenEnabled && process.env.HOME_MCP_RING_WEBHOOKS === 'on' ? setInterval(async () => {
    if (ringHookBusy) return; ringHookBusy = true;
    try { await remoteRelay.pullRingEvents(); } catch (error) { console.error(`ERROR ring webhook pull: ${error.code ?? 'unreachable'}`); }
    finally { ringHookBusy = false; }
  }, 10_000) : null;
  ringHookTick?.unref();
  const guardianTick = guardian && listenEnabled ? setInterval(() => {
    try { guardian.tick(); doors?.sweep(); maybeDailySummary(); } catch { console.error('ERROR guardian_tick'); }
  }, Math.max(20, Math.min(500, Math.floor(30_000 / guardianClock.speed)))) : null;
  guardianTick?.unref();
  // Hub heartbeat for the CloudWatch dead-man alarm: real time, every 5 minutes, only when email alerts are configured.
  const hubBeat = notifier.enabled && listenEnabled ? setInterval(() => { void notifier.heartbeat(); }, 5 * 60_000) : null;
  hubBeat?.unref();
  if (notifier.enabled && listenEnabled) void notifier.heartbeat();
  if (listenEnabled) {
    const address = await started.listen(); activePort = address.port;
    console.log(`Home MCP simulator: http://127.0.0.1:${activePort}`);
    if (generatedPasscode) console.log(`One-time local demo passcode: ${passcode}`);
    else console.log('Using HOME_MCP_DEMO_PASS from environment');
    if (phones && !phones.hasAdmin()) {
      const c = phones.createPairCode({ role: 'admin' });
      console.log(`ADMIN phone pairing code: ${c.code.slice(0, 4)} ${c.code.slice(4)} (10 minutes, single use). On the phone open http://127.0.0.1:${activePort}/ and choose "Pair this phone", then ${macDialog ? 'press Allow in the window that pops up on this Mac (or type y here)' : 'type y here'}.`);
    } else if (phones) {
      console.log(`Paired phones: ${phones.list().filter((d) => d.active).length} active (admin present). Add family phones from the console.`);
    }
    if (guardian) console.log(`Care summary: daily at ${SUMMARY_AT} (guardian clock), ${careSummary.status().bedrock === 'configured' ? `Bedrock ${careSummary.status().modelId}` : 'template only (HOME_MCP_BEDROCK_MODEL not set)'}.`);
    if (guardian) console.log(`Voice notice for the person at home: ${voice.status().enabled ? `on (${voice.status().lang}, Mac speaker)` : 'off (HOME_MCP_VOICE=on to enable)'}.`);
    if (remoteRelay) console.log(`Remote approval: via ${new URL(process.env.HOME_MCP_RELAY_BASE).host} (relay public key, pin as FamilyRelayMacKeySpki: ${relayKeySpki}).`);
    if (remoteRelay) console.log(`Ring webhooks: ${process.env.HOME_MCP_RING_WEBHOOKS === 'on' ? 'pulled from the relay every 10 s (Ring posts to /ring/webhook)' : 'off (HOME_MCP_RING_WEBHOOKS=on to pull them from the relay)'}.`);
    if (doors) console.log(`Ring doorbell: ${ringProviderToken && !ringNetworkOff ? 'watching Ring event history every 10 s for doorbell presses and a person at the door (it asks the admin phone; it never opens the door)' : ringNetworkOff ? 'off (HOME_MCP_RING_PROBE=off)' : 'waiting for a Playground token (paste it in the console: Ring connection)'}; the admin can also ring a simulated doorbell.`);
    { const f = faceHint.status(); console.log(f.enabled ? `Face hint: ON (local OpenCV YuNet + SFace; ${f.people} enrolled with consent; hint only, never opens the door).` : `Face hint: OFF (${f.reason}).`); }
    if (guardian) console.log(`Guardian: ON (gateway heartbeat 60 s, camera check 5 min, daily routine 8 items; clock x${guardianClock.speed}${guardianClock.start ? ' from ' + guardianClock.start : ''}). Ring camera: ${ringProviderToken ? 'Playground token loaded (real status checks)' : 'simulated (no token)'}. Email alerts: ${notifier.status().email}.`);
    console.log(`Local Ring composition: ${localRing ? 'enabled' : 'disabled'} (generated identity, RAM state, simulated worker)`);
    console.log(`Ring test ingress: ${ringTest.enabled ? 'enabled' : 'disabled'} (loopback synthetic only)`);
    console.log(`Household Wi-Fi trust: ${wifiTrustConfig.enabled ? 'disabled (formal binding ports absent)' : 'disabled by config'}`);
    console.log(`Formal MCP runtime: ${formalRuntimeConfig.enabled ? 'ready' : 'disabled by config'}`);
    if (cloudPanel.enabled) {
      console.log(`Cloud MCP (AWS) panel: ENABLED. Real AWS calls happen only on explicit owner + operator action. Mac key: ${await cloudPanel.keyStatus()} (passphrase source: ${cloudPanel.passphraseSource()}); Mac mode: software-direct (reduced assurance); Ring side: Playground sandbox.`);
      console.log('Seven devices are SIMULATED; Ring discovery requires a manual owner and independent local operator gate. No Wi-Fi or physical device connection.');
    } else {
      console.log('Seven devices are SIMULATED; Ring discovery requires a manual owner and independent local operator gate. No Wi-Fi, physical device, or cloud connection.');
    }
  }
  const shutdown = () => { if (interval !== null) clearInterval(interval); if (hubBeat !== null) clearInterval(hubBeat); if (guardianTick !== null) clearInterval(guardianTick); if (doorbellTick !== null) clearInterval(doorbellTick); if (relayTick !== null) clearInterval(relayTick); phonePromptReader?.close(); faceWorker?.close(); void started.close(); };
  process.on('SIGINT', shutdown); process.on('SIGTERM', shutdown);
}
