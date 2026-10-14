import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { createSimulator } from '../core.mjs';
import { verifyAndNormalizeRingEvent } from '../ring_event.mjs';
import { createLocalIdentityBinding } from './identity-binding.mjs';

const EVENT_MAX_AGE_MS = 300_000;
const EVENT_FUTURE_MS = 60_000;
const COMMAND_MAX_AGE_MS = 120_000;
const TERMINAL = new Set(['executed_in_simulator', 'execution_unconfirmed', 'denied', 'expired']);

function fail(code, status = 403) {
  const error = new Error(code);
  error.code = code;
  error.status = status;
  throw error;
}

function safeCode(error) {
  return typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,79}$/u.test(error.code)
    ? error.code : 'LOCAL_AUTHORITY_DENIED';
}

function isExpiry(error) {
  return error?.status === 410 || safeCode(error).endsWith('_EXPIRED');
}

function text(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 256;
}

export function createLocalRingRuntime({
  now = Date.now,
  binding = createLocalIdentityBinding({ now }),
  beforeExecute = async () => {},
  loseAck = false,
  maxCommands = 128,
} = {}) {
  if (typeof now !== 'function' || typeof beforeExecute !== 'function'
    || typeof loseAck !== 'boolean' || !Number.isSafeInteger(maxCommands)
    || maxCommands < 1 || maxCommands > 128) fail('LOCAL_RUNTIME_CONFIG_INVALID', 400);
  if (!binding || !['link', 'authorize', 'remove', 'logout', 'status'].every(
    (method) => typeof binding[method] === 'function',
  )) fail('LOCAL_BINDING_INVALID', 400);
  const config = Object.freeze({ ...binding.ringConfig });
  if (config.enabled !== true || config.sourceType !== 'devices'
    || !['accountId', 'sourceId', 'homeId', 'grantVersion'].every((key) => text(config[key]))
    || !Number.isSafeInteger(config.expiresAtMs) || config.expiresAtMs <= 0) {
    fail('LOCAL_BINDING_INVALID', 400);
  }
  const secret = randomBytes(32).toString('hex');
  const commands = new Map();
  const edgeFaults = new Map();
  let workerOnline = true;
  let workerPromise = null;
  let highWaterMs = 0;
  let activeExecutionDeadline = null;

  function clock() {
    const value = now();
    if (!Number.isSafeInteger(value) || value <= 0 || value < highWaterMs) {
      fail('LOCAL_CLOCK_INVALID', 503);
    }
    highWaterMs = value;
    if (activeExecutionDeadline !== null && value >= activeExecutionDeadline) {
      fail('LOCAL_COMMAND_EXPIRED', 410);
    }
    return value;
  }

  const core = createSimulator({ now: clock, ringAutomation: config });
  const simulator = Object.freeze({
    ...core,
    performRingMotion() { fail('LOCAL_RUNTIME_INGRESS_REQUIRED'); },
    setEdgeFault(input) {
      const result = core.setEdgeFault(input);
      edgeFaults.set(result.deviceId, result.mode);
      return result;
    },
  });

  function snapshot(row, replayed = false) {
    return {
      commandId: row.commandId,
      requestId: row.event.requestId,
      deviceId: 'living_light',
      action: 'on',
      status: row.state === 'admitting' ? 'accepted' : row.state,
      version: row.version,
      acceptedAt: new Date(row.acceptedAtMs).toISOString(),
      ...(row.expiresAtMs ? { expiresAt: new Date(row.expiresAtMs).toISOString() } : {}),
      ...(row.code ? { code: row.code } : {}),
      receipt: row.receipt ? structuredClone(row.receipt) : null,
      replayed,
      simulated: true,
      deviceObserved: false,
    };
  }

  function status() {
    return {
      mode: 'local_simulation',
      workerOnline,
      binding: structuredClone(binding.status()),
      commands: [...commands.values()].map((row) => snapshot(row)),
      capacity: maxCommands,
      durable: false,
      simulated: true,
      deviceObserved: false,
    };
  }

  function validateAuthority(authority, current) {
    if (!authority || authority.actorId !== 'owner'
      || authority.accountId !== config.accountId || authority.sourceId !== config.sourceId
      || authority.homeId !== config.homeId || authority.grantVersion !== config.grantVersion
      || !Number.isSafeInteger(authority.accountEpoch) || authority.accountEpoch < 1
      || !Number.isSafeInteger(authority.expiresAtMs)
      || authority.expiresAtMs <= current || config.expiresAtMs <= current) {
      fail('LOCAL_AUTHORITY_DENIED');
    }
    return Object.freeze({ ...authority });
  }

  function validateEvent(event, current) {
    if (event.accountId !== config.accountId || event.sourceId !== config.sourceId
      || event.sourceType !== 'devices' || event.eventType !== 'motion_detected') {
      fail('LOCAL_EVENT_NOT_ALLOWED');
    }
    if (event.requestId.length > 128 || event.eventId.length > 128) {
      fail('LOCAL_EVENT_INVALID', 400);
    }
    if (event.eventAtMs + EVENT_MAX_AGE_MS <= current
      || event.eventAtMs > current + EVENT_FUTURE_MS
      || event.sentAtMs > current + EVENT_FUTURE_MS) fail('LOCAL_EVENT_STALE', 410);
  }

  function finish(row, state, code = null) {
    if (TERMINAL.has(row.state)) return;
    row.state = state;
    row.version += 1;
    row.code = code;
  }

  async function admit(row) {
    try {
      const authority = await binding.authorize();
      const current = clock();
      validateEvent(row.event, current);
      row.authority = validateAuthority(authority, current);
      row.expiresAtMs = Math.min(
        row.acceptedAtMs + COMMAND_MAX_AGE_MS,
        row.event.eventAtMs + EVENT_MAX_AGE_MS,
        authority.expiresAtMs,
        config.expiresAtMs,
      );
      if (row.expiresAtMs <= current) fail('LOCAL_COMMAND_EXPIRED', 410);
      row.state = 'queued';
      row.version += 1;
    } catch (error) {
      finish(row, isExpiry(error) ? 'expired' : 'denied', safeCode(error));
    }
    return snapshot(row);
  }

  async function receive({ rawBody, signature } = {}) {
    const event = Object.freeze(verifyAndNormalizeRingEvent({ rawBody, signature, secret }));
    const previous = commands.get(event.requestId);
    if (previous) {
      if (previous.event.bodyDigest !== event.bodyDigest) fail('LOCAL_REQUEST_BODY_CONFLICT', 409);
      await previous.admission;
      return snapshot(previous, true);
    }
    const acceptedAtMs = clock();
    validateEvent(event, acceptedAtMs);
    if (commands.size >= maxCommands) fail('LOCAL_COMMAND_CAPACITY', 503);
    const row = {
      commandId: randomUUID(), event, acceptedAtMs, expiresAtMs: null,
      state: 'admitting', version: 1, authority: null, code: null, receipt: null,
      coreResult: null, admission: null,
    };
    commands.set(event.requestId, row);
    row.admission = admit(row);
    return row.admission;
  }

  function buildSyntheticEvent(overrides = {}) {
    if (!overrides || typeof overrides !== 'object' || Array.isArray(overrides)) {
      fail('LOCAL_EVENT_FACTORY_INVALID', 400);
    }
    const allowed = new Set(['requestId', 'eventId', 'accountId', 'sourceId', 'sourceType',
      'eventType', 'eventAtMs', 'sentAtMs', 'targetDeviceId', 'action']);
    if (Object.keys(overrides).some((key) => !allowed.has(key))) fail('LOCAL_EVENT_FACTORY_INVALID', 400);
    const current = clock();
    const rawBody = Buffer.from(JSON.stringify({
      meta: {
        version: '1.1',
        time: new Date(overrides.sentAtMs ?? current).toISOString(),
        request_id: overrides.requestId ?? randomUUID(),
        account_id: overrides.accountId ?? config.accountId,
      },
      data: {
        id: overrides.eventId ?? randomUUID(),
        type: overrides.eventType ?? 'motion_detected',
        attributes: {
          source: overrides.sourceId ?? config.sourceId,
          source_type: overrides.sourceType ?? 'devices',
          timestamp: overrides.eventAtMs ?? current,
          ...(overrides.targetDeviceId === undefined ? {} : { target: overrides.targetDeviceId }),
          ...(overrides.action === undefined ? {} : { action: overrides.action }),
        },
      },
    }), 'utf8');
    return Object.freeze({ rawBody, signature: `sha256=${createHmac('sha256', secret).update(rawBody).digest('hex')}` });
  }

  async function link() {
    await binding.link();
    validateAuthority(await binding.authorize(), clock());
    const pairing = core.beginPair({ actor: 'owner', deviceId: 'living_light' });
    core.completePair({ actor: 'owner', deviceId: 'living_light', code: pairing.code });
    return status();
  }

  async function motion() {
    return receive(buildSyntheticEvent());
  }

  function unchangedAuthority(row, currentAuthority, current) {
    validateAuthority(currentAuthority, current);
    const captured = row.authority;
    if (!captured || ['actorId', 'accountId', 'sourceId', 'homeId', 'grantVersion', 'accountEpoch']
      .some((key) => captured[key] !== currentAuthority[key])) fail('LOCAL_AUTHORITY_CHANGED');
    if (current >= row.expiresAtMs || current >= captured.expiresAtMs) fail('LOCAL_COMMAND_EXPIRED', 410);
  }

  function executionReady() {
    if (!workerOnline || !core.getState().edge.online) fail('LOCAL_WORKER_OFFLINE', 503);
    if (!['none', undefined].includes(edgeFaults.get('living_light'))) fail('LOCAL_EDGE_NOT_READY', 503);
  }

  async function processQueue() {
    for (const row of commands.values()) {
      if (row.state !== 'queued') continue;
      if (!workerOnline || !core.getState().edge.online) continue;
      row.state = 'applying';
      row.version += 1;
      let dispatched = false;
      try {
        unchangedAuthority(row, await binding.authorize(), clock());
        await beforeExecute(Object.freeze(snapshot(row)));
        const finalAuthority = await binding.authorize();
        const current = clock();
        unchangedAuthority(row, finalAuthority, current);
        validateEvent(row.event, current);
        executionReady();
        activeExecutionDeadline = Math.min(row.expiresAtMs, finalAuthority.expiresAtMs);
        core.heartbeat({ actor: 'owner' });
        dispatched = true;
        const result = core.performRingMotion(row.event);
        row.coreResult = result;
        const receipt = result.receipt;
        if (result.status !== 'executed_in_simulator' || !receipt
          || result.requestId !== row.event.requestId || receipt.requestId !== row.event.requestId
          || receipt.commandId !== result.commandId || !text(receipt.auditId)
          || receipt.gatewayAck !== true || receipt.deviceObserved !== false || receipt.simulated !== true) {
          fail('LOCAL_EXECUTION_UNCONFIRMED', 503);
        }
        if (loseAck) {
          finish(row, 'execution_unconfirmed', 'LOCAL_ACK_MISSING');
        } else {
          row.receipt = Object.freeze({
            commandId: row.commandId,
            edgeCommandId: receipt.commandId,
            requestId: row.event.requestId,
            auditId: receipt.auditId,
            status: 'executed_in_simulator',
            at: receipt.at,
            state: structuredClone(receipt.state),
            gatewayAck: true,
            deviceObserved: false,
            simulated: true,
          });
          finish(row, 'executed_in_simulator');
        }
      } catch (error) {
        const state = dispatched ? 'execution_unconfirmed' : isExpiry(error) ? 'expired' : 'denied';
        finish(row, state, safeCode(error));
      } finally {
        activeExecutionDeadline = null;
      }
    }
    return status();
  }

  function runWorker() {
    if (workerPromise) return workerPromise;
    workerPromise = processQueue().finally(() => { workerPromise = null; });
    return workerPromise;
  }

  async function remove() {
    await binding.remove();
    return status();
  }

  async function logout() {
    await binding.logout();
    return status();
  }

  function setWorkerOnline(online) {
    if (typeof online !== 'boolean') fail('LOCAL_WORKER_CONFIG_INVALID', 400);
    workerOnline = online;
    return status();
  }

  return Object.freeze({ simulator, status, link, motion, receive, runWorker,
    remove, logout, setWorkerOnline, buildSyntheticEvent });
}
