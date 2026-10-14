import {
  createHmac,
  randomBytes,
  randomInt,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';

const PAIR_TTL_MS = 2 * 60 * 1000;
const CONFIRM_TTL_MS = 90 * 1000;
const MAX_SCHEDULE_AHEAD_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_SCHEDULES = 50;
const MAX_AUDIT = 200;
const MAX_ATTEMPTS = 3;
const MAX_RING_REQUESTS = 1024;
const RING_EVENT_MAX_AGE_MS = 5 * 60 * 1000;
const RING_EVENT_FUTURE_MS = 60 * 1000;
const EDGE_QUEUE_TTL_MS = 2 * 60 * 1000;
const MAX_EDGE_QUEUE = 32;
const MAX_EDGE_COMMANDS = MAX_RING_REQUESTS + 1024;
const MAX_EDGE_RECEIPTS = 100;
const EDGE_GATEWAY_ID = 'virtual_esp32c3';
const EDGE_HEARTBEAT_INTERVAL_MS = 5 * 1000;
const EDGE_HEARTBEAT_STALE_MS = 15 * 1000;

const DEVICE_DEFINITIONS = [
  {
    id: 'robot_vacuum',
    label: '掃地機器人',
    actions: ['start', 'pause', 'dock'],
    state: { mode: 'docked' },
  },
  {
    id: 'air_conditioner',
    label: '冷氣',
    actions: ['on', 'off', 'set_temperature'],
    state: { power: false, temperature: 24 },
  },
  {
    id: 'front_door',
    label: '門鎖',
    actions: ['lock', 'unlock'],
    state: { locked: true },
  },
  {
    id: 'alarm_clock',
    label: '電子鬧鐘',
    actions: ['set_alarm', 'clear_alarm'],
    state: { time: null },
  },
  {
    id: 'living_light',
    label: '客廳燈',
    actions: ['on', 'off'],
    state: { power: false },
  },
  {
    id: 'camera',
    label: '監視器（狀態模擬）',
    actions: ['arm', 'disarm'],
    state: { armed: false },
  },
  {
    id: 'dehumidifier',
    label: '除濕機',
    actions: ['on', 'off', 'set_target_humidity'],
    state: { power: false, targetHumidity: 55 },
  },
];

function fail(code, status, message) {
  const error = new Error(message);
  error.code = code;
  error.status = status;
  throw error;
}

function requireOwner(actor) {
  if (actor !== 'owner') {
    fail('FORBIDDEN', 403, 'Only the demo owner may use this simulator.');
  }
}

function requireObject(value, name) {
  if (value === undefined) return {};
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail('INVALID_ARGUMENT', 400, `${name} must be an object.`);
  }
  return value;
}

function validateParameters(deviceId, action, input) {
  const parameters = requireObject(input, 'parameters');
  const keys = Object.keys(parameters);
  const keyed = {
    'air_conditioner:set_temperature': 'temperature',
    'alarm_clock:set_alarm': 'time',
    'dehumidifier:set_target_humidity': 'humidity',
  };
  const expected = keyed[`${deviceId}:${action}`];
  if (!expected) {
    if (keys.length !== 0) {
      fail('INVALID_ARGUMENT', 400, 'This action does not accept parameters.');
    }
    return {};
  }
  if (keys.length !== 1 || keys[0] !== expected) {
    fail('INVALID_ARGUMENT', 400, `This action requires only parameters.${expected}.`);
  }
  const value = parameters[expected];
  if (expected === 'temperature') {
    if (!Number.isInteger(value) || value < 16 || value > 30) {
      fail('INVALID_ARGUMENT', 400, 'Temperature must be an integer from 16 to 30.');
    }
  } else if (expected === 'humidity') {
    if (!Number.isInteger(value) || value < 30 || value > 80) {
      fail('INVALID_ARGUMENT', 400, 'Humidity must be an integer from 30 to 80.');
    }
  } else if (typeof value !== 'string' || !/^([01]\d|2[0-3]):[0-5]\d$/.test(value)) {
    fail('INVALID_ARGUMENT', 400, 'Alarm time must use 24-hour HH:MM format.');
  }
  return { [expected]: value };
}

function isHighRisk(deviceId, action) {
  return deviceId === 'front_door' && action === 'unlock';
}

function isScheduleForbidden(deviceId, action) {
  return isHighRisk(deviceId, action)
    || (deviceId === 'camera' && action === 'disarm');
}

function clone(value) {
  return structuredClone(value);
}

function validBoundedText(value, maxLength = 256) {
  return typeof value === 'string' && value.length > 0 && value.length <= maxLength;
}

function validateRingAutomation(input) {
  if (input === undefined || input === null) return null;
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    fail('INVALID_RING_AUTOMATION', 400, 'Ring automation must be an object.');
  }
  const allowedKeys = ['enabled', 'accountId', 'sourceId', 'sourceType', 'homeId', 'grantVersion', 'expiresAtMs'];
  if (Object.keys(input).some((key) => !allowedKeys.includes(key)) || typeof input.enabled !== 'boolean') {
    fail('INVALID_RING_AUTOMATION', 400, 'Ring automation configuration is invalid.');
  }
  if (!input.enabled) {
    if (Object.keys(input).length !== 1) {
      fail('INVALID_RING_AUTOMATION', 400, 'Disabled Ring automation cannot contain a partial grant.');
    }
    return null;
  }
  if (
    Object.keys(input).length !== allowedKeys.length
    || !validBoundedText(input.accountId)
    || !validBoundedText(input.sourceId)
    || !validBoundedText(input.sourceType)
    || !validBoundedText(input.homeId)
    || !validBoundedText(input.grantVersion)
    || !Number.isSafeInteger(input.expiresAtMs)
    || input.expiresAtMs <= 0
  ) {
    fail('INVALID_RING_AUTOMATION', 400, 'Ring automation grant is incomplete or invalid.');
  }
  return Object.freeze({ ...input });
}

export function createSimulator({ now = Date.now, ringAutomation } = {}) {
  if (typeof now !== 'function') {
    fail('INVALID_ARGUMENT', 400, 'now must be a function.');
  }
  const ringGrant = validateRingAutomation(ringAutomation);

  const devices = new Map(DEVICE_DEFINITIONS.map((definition) => [
    definition.id,
    { ...definition, actions: [...definition.actions], state: clone(definition.state) },
  ]));
  const paired = new Map();
  const pairClaims = new Map();
  const confirmations = new Map();
  const schedules = new Map();
  const audit = [];
  const ringRequests = new Map();
  const digestKey = randomBytes(32);
  const edgeKeys = new Map(DEVICE_DEFINITIONS.map(({ id }) => [id, randomBytes(32)]));
  const edgeQueue = new Map();
  const edgeCommands = new Map();
  const edgeReceipts = [];
  const edgeFaults = new Map();
  let edgeOnline = true;
  let lastHeartbeatMs = clock();
  let lastHeartbeatAt = iso(lastHeartbeatMs);

  function clock() {
    const raw = now();
    const milliseconds = raw instanceof Date ? raw.getTime() : Number(raw);
    if (!Number.isFinite(milliseconds)) {
      fail('INVALID_CLOCK', 500, 'Simulator clock returned an invalid time.');
    }
    return milliseconds;
  }

  function iso(milliseconds) {
    return new Date(milliseconds).toISOString();
  }

  function digest(purpose, actor, deviceId, secret) {
    return createHmac('sha256', digestKey)
      .update(`${purpose}\0${actor}\0${deviceId}\0${secret}`)
      .digest();
  }

  function matches(left, right) {
    return Buffer.isBuffer(left)
      && Buffer.isBuffer(right)
      && left.length === right.length
      && timingSafeEqual(left, right);
  }

  function getDevice(deviceId) {
    const device = devices.get(deviceId);
    if (!device) fail('DEVICE_NOT_FOUND', 404, 'Unknown simulated device.');
    return device;
  }

  function getAction(deviceId, action) {
    const device = getDevice(deviceId);
    if (!device.actions.includes(action)) {
      fail('ACTION_NOT_SUPPORTED', 400, 'Action is not supported by this simulated device.');
    }
    return device;
  }

  function requirePaired(actor, deviceId) {
    if (paired.get(deviceId) !== actor) {
      fail('DEVICE_NOT_PAIRED', 403, 'Pair this simulated device before using it.');
    }
  }

  function record({ actor, deviceId = null, action, origin = 'simulator', outcome, commandId, requestId, atMs }) {
    const entry = {
      id: randomUUID(),
      at: iso(atMs === undefined ? clock() : atMs),
      actor,
      deviceId,
      action,
      origin,
      outcome,
      simulated: true,
    };
    if (commandId !== undefined) entry.commandId = commandId;
    if (requestId !== undefined) entry.requestId = requestId;
    audit.push(entry);
    if (audit.length > MAX_AUDIT) audit.splice(0, audit.length - MAX_AUDIT);
    return clone(entry);
  }

  function pruneExpired(current = clock()) {
    for (const [deviceId, claim] of pairClaims) {
      if (claim.expiresAt <= current) pairClaims.delete(deviceId);
    }
    for (const [id, claim] of confirmations) {
      if (claim.expiresAt <= current) confirmations.delete(id);
    }
    for (const [commandId, command] of edgeQueue) {
      if (command.expiresAtMs <= current) {
        edgeQueue.delete(commandId);
        finishExpiredEdgeCommand(command, current, 'fallback_queue');
      }
    }
  }

  function getState() {
    pruneExpired();
    return {
      simulated: true,
      devices: [...devices.values()].map((device) => ({
        id: device.id,
        label: device.label,
        paired: paired.get(device.id) === 'owner',
        actions: [...device.actions],
        state: clone(device.state),
      })),
      schedules: [...schedules.values()]
        .sort((a, b) => a.atMs - b.atMs)
        .map(({ atMs, actor, ...schedule }) => clone(schedule)),
      audit: clone(audit),
      edge: {
        gatewayId: EDGE_GATEWAY_ID,
        online: edgeOnline,
        lastHeartbeatAt,
        heartbeatFresh: edgeOnline && clock() - lastHeartbeatMs <= EDGE_HEARTBEAT_STALE_MS,
        pendingCount: edgeQueue.size,
        receipts: clone(edgeReceipts),
        queue: [...edgeQueue.values()].map(({ commandId, deviceId, action, expiresAtMs }) => ({
          commandId, deviceId, action, expiresAt: iso(expiresAtMs),
        })),
        simulated: true,
      },
    };
  }

  function beginPair({ actor, deviceId } = {}) {
    requireOwner(actor);
    getDevice(deviceId);
    pruneExpired();
    const code = randomInt(0, 1_000_000).toString().padStart(6, '0');
    const expiresAt = clock() + PAIR_TTL_MS;
    pairClaims.set(deviceId, {
      actor,
      digest: digest('pair', actor, deviceId, code),
      expiresAt,
      attempts: 0,
    });
    record({ actor, deviceId, action: 'pair_start', outcome: 'issued' });
    return { code, expiresAt: iso(expiresAt), simulated: true };
  }

  function completePair({ actor, deviceId, code } = {}) {
    requireOwner(actor);
    getDevice(deviceId);
    pruneExpired();
    const claim = pairClaims.get(deviceId);
    if (!claim || claim.actor !== actor) {
      fail('PAIR_EXPIRED', 410, 'No active pairing claim for this device.');
    }
    if (typeof code !== 'string' || !/^\d{6}$/.test(code)) {
      fail('INVALID_ARGUMENT', 400, 'Pairing code must contain six digits.');
    }
    claim.attempts += 1;
    if (!matches(claim.digest, digest('pair', actor, deviceId, code))) {
      if (claim.attempts >= MAX_ATTEMPTS) pairClaims.delete(deviceId);
      record({ actor, deviceId, action: 'pair_complete', outcome: 'denied' });
      fail('PAIR_DENIED', claim.attempts >= MAX_ATTEMPTS ? 429 : 403, 'Pairing code was rejected.');
    }
    pairClaims.delete(deviceId);
    paired.set(deviceId, actor);
    record({ actor, deviceId, action: 'pair_complete', outcome: 'paired' });
    return { deviceId, paired: true, simulated: true };
  }

  function beginConfirmation({ actor, deviceId, action } = {}) {
    requireOwner(actor);
    getAction(deviceId, action);
    requirePaired(actor, deviceId);
    if (!isHighRisk(deviceId, action)) {
      fail('CONFIRMATION_NOT_REQUIRED', 400, 'This action does not require confirmation.');
    }
    pruneExpired();
    const confirmationId = randomUUID();
    const phrase = randomInt(0, 1_000_000).toString().padStart(6, '0');
    const expiresAt = clock() + CONFIRM_TTL_MS;
    confirmations.set(confirmationId, {
      actor,
      deviceId,
      action,
      digest: digest('confirm', actor, deviceId, `${confirmationId}:${phrase}`),
      expiresAt,
      attempts: 0,
    });
    record({ actor, deviceId, action: 'confirmation_start', outcome: 'issued' });
    return { confirmationId, phrase, expiresAt: iso(expiresAt), simulated: true };
  }

  function consumeConfirmation({ actor, deviceId, action, confirmationId, confirmationPhrase }) {
    pruneExpired();
    if (typeof confirmationId !== 'string' || typeof confirmationPhrase !== 'string') {
      fail('CONFIRMATION_REQUIRED', 403, 'A valid one-use confirmation is required.');
    }
    const claim = confirmations.get(confirmationId);
    if (!claim || claim.actor !== actor || claim.deviceId !== deviceId || claim.action !== action) {
      fail('CONFIRMATION_DENIED', 403, 'Confirmation is invalid or expired.');
    }
    claim.attempts += 1;
    const correct = matches(
      claim.digest,
      digest('confirm', actor, deviceId, `${confirmationId}:${confirmationPhrase}`),
    );
    if (!correct) {
      if (claim.attempts >= MAX_ATTEMPTS) confirmations.delete(confirmationId);
      fail('CONFIRMATION_DENIED', claim.attempts >= MAX_ATTEMPTS ? 429 : 403, 'Confirmation was rejected.');
    }
    confirmations.delete(confirmationId);
  }

  function applyAction(device, action, parameters) {
    switch (device.id) {
      case 'robot_vacuum':
        device.state.mode = { start: 'cleaning', pause: 'paused', dock: 'docked' }[action];
        break;
      case 'air_conditioner':
        if (action === 'set_temperature') device.state.temperature = parameters.temperature;
        else device.state.power = action === 'on';
        break;
      case 'front_door':
        device.state.locked = action === 'lock';
        break;
      case 'alarm_clock':
        device.state.time = action === 'set_alarm' ? parameters.time : null;
        break;
      case 'living_light':
        device.state.power = action === 'on';
        break;
      case 'camera':
        device.state.armed = action === 'arm';
        break;
      case 'dehumidifier':
        if (action === 'set_target_humidity') device.state.targetHumidity = parameters.humidity;
        else device.state.power = action === 'on';
        break;
      default:
        fail('DEVICE_NOT_FOUND', 404, 'Unknown simulated device.');
    }
  }

  function commandFingerprint(command) {
    return JSON.stringify([
      command.actor, command.deviceId, command.action, command.parameters,
      command.origin, command.requestId, command.homeId, command.grantVersion,
    ]);
  }

  function edgeProof(command) {
    const payload = JSON.stringify([
      command.commandId, command.nonce, command.actor, command.deviceId,
      command.action, command.parameters, command.expiresAtMs,
      command.origin, command.requestId, command.homeId, command.grantVersion,
    ]);
    return createHmac('sha256', edgeKeys.get(command.deviceId)).update(payload).digest();
  }

  function rememberReceipt(receipt) {
    edgeReceipts.push(receipt);
    if (edgeReceipts.length > MAX_EDGE_RECEIPTS) {
      edgeReceipts.splice(0, edgeReceipts.length - MAX_EDGE_RECEIPTS);
    }
  }

  function makeEdgeResult(command, status, delivery, receipt, atMs) {
    return {
      deviceId: command.deviceId,
      action: command.action,
      commandId: command.commandId,
      status,
      delivery,
      state: clone(devices.get(command.deviceId).state),
      receipt: receipt ? clone(receipt) : null,
      ...(status === 'queued' ? { expiresAt: iso(command.expiresAtMs) } : {}),
      ...(status === 'expired' ? { expiredAt: iso(atMs) } : {}),
      simulated: true,
    };
  }

  function finishExpiredEdgeCommand(command, current, delivery) {
    const result = makeEdgeResult(command, 'expired', delivery, null, current);
    edgeCommands.set(command.commandId, {
      fingerprint: commandFingerprint(command), result: clone(result),
    });
    rememberReceipt({ commandId: command.commandId, requestId: command.requestId,
      deviceId: command.deviceId, action: command.action, status: 'expired',
      gatewayAck: false, deviceObserved: false, at: iso(current), simulated: true });
    record({ actor: command.actor, deviceId: command.deviceId, action: command.action,
      origin: command.origin, outcome: 'expired', commandId: command.commandId,
      requestId: command.requestId, atMs: current });
    return result;
  }

  function queueEdgeCommand(command, current) {
    if (edgeQueue.size >= MAX_EDGE_QUEUE) {
      fail('EDGE_QUEUE_FULL', 503, 'Simulated fallback queue is full.');
    }
    edgeQueue.set(command.commandId, command);
    const result = makeEdgeResult(command, 'queued', 'fallback_queue', null, current);
    edgeCommands.set(command.commandId, {
      fingerprint: commandFingerprint(command), result: clone(result),
    });
    record({ actor: command.actor, deviceId: command.deviceId, action: command.action,
      origin: command.origin, outcome: 'queued', commandId: command.commandId,
      requestId: command.requestId, atMs: current });
    return result;
  }

  function dispatchEdgeCommand(command, current) {
    if (command.expiresAtMs <= current) {
      return finishExpiredEdgeCommand(command, current, 'simulated_wifi');
    }
    const proof = edgeFaults.get(command.deviceId) === 'bad_hmac'
      ? Buffer.alloc(32)
      : command.proof;
    if (!matches(proof, edgeProof(command))) {
      fail('EDGE_AUTH_DENIED', 403, 'Simulated device command authentication failed.');
    }
    // immediateOnly (cloud-origin): the caller IS the live gateway for this one command, so heartbeat staleness does not
    // apply, but a gateway set offline or a device without acknowledgement fails here and is never queued for later.
    if (command.immediateOnly && (!edgeOnline || edgeFaults.get(command.deviceId) === 'no_ack')) {
      fail('EDGE_NOT_IMMEDIATE', 503, 'Cloud command needs an online simulated gateway and an acknowledging device.');
    }
    if (!command.immediateOnly && (!edgeOnline || current - lastHeartbeatMs > EDGE_HEARTBEAT_STALE_MS
      || edgeFaults.get(command.deviceId) === 'no_ack')) {
      if (isScheduleForbidden(command.deviceId, command.action)) {
        fail('EDGE_OFFLINE_UNSAFE', 503, 'Unsafe action requires a live simulated gateway receipt.');
      }
      return queueEdgeCommand(command, current);
    }
    const device = devices.get(command.deviceId);
    applyAction(device, command.action, command.parameters);
    command.applied = true;
    const auditEntry = record({ actor: command.actor, deviceId: command.deviceId,
      action: command.action, origin: command.origin, outcome: 'applied',
      commandId: command.commandId, requestId: command.requestId, atMs: current });
    const receipt = {
      commandId: command.commandId,
      ...(command.requestId ? { requestId: command.requestId, auditId: auditEntry.id } : {}),
      deviceId: command.deviceId,
      action: command.action,
      status: 'simulated_applied',
      signalSent: true,
      gatewayAck: true,
      deviceObserved: false,
      at: iso(current),
      simulated: true,
    };
    rememberReceipt(receipt);
    const result = makeEdgeResult(command, 'simulated_applied', 'simulated_wifi', receipt, current);
    edgeCommands.set(command.commandId, {
      fingerprint: commandFingerprint(command), result: clone(result),
    });
    return result;
  }

  function flushEdgeQueue(current = clock()) {
    pruneExpired(current);
    if (!edgeOnline || current - lastHeartbeatMs > EDGE_HEARTBEAT_STALE_MS) {
      return { applied: [], pendingCount: edgeQueue.size, simulated: true };
    }
    const applied = [];
    for (const [commandId, command] of [...edgeQueue]) {
      if (edgeFaults.get(command.deviceId) === 'no_ack') continue;
      edgeQueue.delete(commandId);
      try {
        const result = dispatchEdgeCommand(command, current);
        edgeCommands.get(commandId).result = clone(result);
        applied.push(result);
      } catch (error) {
        const result = makeEdgeResult(command, 'denied', 'simulated_wifi', null, current);
        edgeCommands.get(commandId).result = clone(result);
        rememberReceipt({ commandId, deviceId: command.deviceId, action: command.action,
          requestId: command.requestId,
          status: 'denied', gatewayAck: false, deviceObserved: false,
          at: iso(current), simulated: true });
        record({ actor: command.actor, deviceId: command.deviceId, action: command.action,
          origin: command.origin, outcome: 'denied', commandId,
          requestId: command.requestId, atMs: current });
      }
    }
    return { applied, pendingCount: edgeQueue.size, simulated: true };
  }

  function setEdgeOnline({ actor, online } = {}) {
    requireOwner(actor);
    if (typeof online !== 'boolean') fail('INVALID_ARGUMENT', 400, 'online must be a boolean.');
    edgeOnline = online;
    const current = clock();
    if (online) {
      lastHeartbeatMs = current;
      lastHeartbeatAt = iso(current);
    }
    record({ actor, action: 'edge_connectivity', outcome: online ? 'online' : 'offline', atMs: current });
    const flushed = online ? flushEdgeQueue(current) : { applied: [], pendingCount: edgeQueue.size };
    return { gatewayId: EDGE_GATEWAY_ID, online, lastHeartbeatAt, ...flushed, simulated: true };
  }

  function setEdgeFault({ actor, deviceId, mode } = {}) {
    requireOwner(actor);
    getDevice(deviceId);
    if (!['none', 'no_ack', 'bad_hmac'].includes(mode)) {
      fail('INVALID_ARGUMENT', 400, 'Unknown simulated edge fault.');
    }
    if (mode === 'none') edgeFaults.delete(deviceId);
    else edgeFaults.set(deviceId, mode);
    record({ actor, deviceId, action: 'edge_fault', outcome: mode });
    return { deviceId, mode, simulated: true };
  }

  function heartbeat({ actor } = {}) {
    requireOwner(actor);
    const current = clock();
    if (!edgeOnline) fail('EDGE_OFFLINE', 503, 'Simulated edge gateway is offline.');
    lastHeartbeatMs = current;
    lastHeartbeatAt = iso(current);
    record({ actor, action: 'edge_heartbeat', outcome: 'received', atMs: current });
    const flushed = flushEdgeQueue(current);
    return { gatewayId: EDGE_GATEWAY_ID, online: true, lastHeartbeatAt, ...flushed, simulated: true };
  }

  function perform({
    actor,
    deviceId,
    action,
    parameters,
    confirmationId,
    confirmationPhrase,
    origin = 'ui',
    commandId,
    immediateOnly = false,
  } = {}) {
    requireOwner(actor);
    if (typeof immediateOnly !== 'boolean') fail('INVALID_ARGUMENT', 400, 'immediateOnly must be boolean.');
    const device = getAction(deviceId, action);
    requirePaired(actor, deviceId);
    const validatedParameters = validateParameters(deviceId, action, parameters);
    if (commandId !== undefined && (typeof commandId !== 'string'
      || !/^[A-Za-z0-9_-]{8,128}$/.test(commandId))) {
      fail('INVALID_ARGUMENT', 400, 'commandId must be 8 to 128 safe characters.');
    }
    const id = commandId || randomUUID();
    const fingerprint = commandFingerprint({ actor, deviceId, action,
      parameters: validatedParameters, origin });
    const prior = edgeCommands.get(id);
    if (prior) {
      if (prior.fingerprint !== fingerprint || isScheduleForbidden(deviceId, action)) {
        fail('COMMAND_REPLAY', 409, 'Command ID has already been used.');
      }
      return { ...clone(prior.result), replayed: true };
    }
    if (edgeCommands.size >= MAX_EDGE_COMMANDS) {
      fail('EDGE_LEDGER_FULL', 503, 'Simulated command ledger is full.');
    }
    if ((!edgeOnline || clock() - lastHeartbeatMs > EDGE_HEARTBEAT_STALE_MS
      || edgeFaults.get(deviceId) === 'no_ack')
      && isScheduleForbidden(deviceId, action)) {
      record({ actor, deviceId, action, origin, outcome: 'denied', commandId: id });
      fail('EDGE_OFFLINE_UNSAFE', 503, 'Unsafe action requires a live simulated gateway receipt.');
    }
    if (isHighRisk(deviceId, action)) {
      try {
        consumeConfirmation({ actor, deviceId, action, confirmationId, confirmationPhrase });
      } catch (error) {
        record({ actor, deviceId, action, origin, outcome: 'denied' });
        throw error;
      }
    }
    const current = clock();
    const command = {
      actor, deviceId, action, parameters: validatedParameters, origin,
      commandId: id, nonce: randomBytes(16).toString('hex'),
      expiresAtMs: current + EDGE_QUEUE_TTL_MS, immediateOnly,
    };
    command.proof = edgeProof(command);
    try {
      return dispatchEdgeCommand(command, current);
    } catch (error) {
      rememberReceipt({ commandId: id, deviceId, action,
        status: 'denied', gatewayAck: false, deviceObserved: false,
        at: iso(current), simulated: true });
      record({ actor, deviceId, action, origin, outcome: 'denied', commandId: id, atMs: current });
      throw error;
    }
  }

  function performBatch({ actor, commands, origin = 'ui' } = {}) {
    requireOwner(actor);
    if (!Array.isArray(commands) || commands.length < 1 || commands.length > 7) {
      fail('INVALID_BATCH', 400, 'Batch requires 1 to 7 device commands.');
    }
    const seen = new Set();
    for (const command of commands) {
      if (!command || typeof command !== 'object' || Array.isArray(command)
        || typeof command.deviceId !== 'string' || seen.has(command.deviceId)) {
        fail('INVALID_BATCH', 400, 'Batch device IDs must be distinct.');
      }
      seen.add(command.deviceId);
    }
    const results = commands.map((command) => {
      const { deviceId, action } = command;
      try {
        if (isScheduleForbidden(deviceId, action)) {
          fail('BATCH_UNSAFE', 403, 'Unsafe action cannot be batched.');
        }
        return perform({ ...command, actor, origin });
      } catch (error) {
        return { deviceId, action, status: 'denied', code: error.code || 'EXECUTION_FAILED',
          simulated: true };
      }
    });
    return { results, simulated: true };
  }

  function ringResultFromEdge(command, edgeResult) {
    const common = {
      commandId: command.commandId,
      requestId: command.requestId,
      homeId: command.homeId,
      grantVersion: command.grantVersion,
      actor: command.actor,
      deviceId: command.deviceId,
      action: command.action,
      simulated: true,
    };
    if (edgeResult.status === 'simulated_applied') {
      const { receipt } = edgeResult;
      if (!receipt || !receipt.gatewayAck || !receipt.auditId
        || receipt.commandId !== command.commandId
        || receipt.requestId !== command.requestId) {
        fail('RING_EXECUTION_UNCONFIRMED', 503, 'Ring command lacks a matching simulated receipt.');
      }
      return {
        status: 'executed_in_simulator',
        ...common,
        receipt: {
          commandId: command.commandId,
          requestId: command.requestId,
          auditId: receipt.auditId,
          status: 'executed_in_simulator',
          at: receipt.at,
          state: clone(edgeResult.state),
          gatewayAck: true,
          deviceObserved: false,
          simulated: true,
        },
      };
    }
    return {
      status: edgeResult.status,
      ...common,
      delivery: edgeResult.delivery,
      receipt: null,
      ...(edgeResult.expiresAt ? { expiresAt: edgeResult.expiresAt } : {}),
      ...(edgeResult.expiredAt ? { expiredAt: edgeResult.expiredAt } : {}),
      ...(edgeResult.reason ? { reason: edgeResult.reason } : {}),
    };
  }

  function performRingMotion(normalized) {
    if (!normalized || typeof normalized !== 'object' || Array.isArray(normalized)) {
      fail('INVALID_RING_EVENT', 400, 'Verified Ring event tuple required.');
    }
    const {
      version, sentAtMs, requestId, accountId, eventId, eventType,
      sourceId, sourceType, eventAtMs, bodyDigest,
    } = normalized;
    if (
      version !== '1.1'
      || !validBoundedText(requestId, 128)
      || !validBoundedText(accountId)
      || !validBoundedText(eventId, 128)
      || !validBoundedText(eventType, 64)
      || !validBoundedText(sourceId)
      || !validBoundedText(sourceType, 64)
      || !Number.isSafeInteger(sentAtMs)
      || !Number.isSafeInteger(eventAtMs)
      || typeof bodyDigest !== 'string'
      || !/^[a-f0-9]{64}$/.test(bodyDigest)
    ) {
      fail('INVALID_RING_EVENT', 400, 'Verified Ring event tuple is invalid.');
    }
    const previous = ringRequests.get(requestId);
    if (previous) {
      if (previous.bodyDigest !== bodyDigest) {
        return { status: 'ignored_conflict', reason: 'REQUEST_ID_BODY_CONFLICT', requestId, simulated: true };
      }
      if (previous.errorCode) {
        fail(previous.errorCode,
          previous.errorCode === 'EDGE_AUTH_DENIED' ? 403 : 503,
          'Ring motion execution has no confirmed receipt.');
      }
      pruneExpired(clock());
      const edgeResult = edgeCommands.get(previous.commandId)?.result;
      if (!edgeResult) {
        fail('RING_EXECUTION_UNCONFIRMED', 503, 'Ring command result is unavailable.');
      }
      return ringResultFromEdge(previous.command, edgeResult);
    }
    const current = clock();
    const ignored = (reason) => ({ status: 'ignored', reason, requestId, simulated: true });
    if (!ringGrant) return ignored('AUTOMATION_DISABLED');
    if (
      accountId !== ringGrant.accountId
      || sourceId !== ringGrant.sourceId
      || sourceType !== ringGrant.sourceType
      || eventType !== 'motion_detected'
    ) return ignored('EVENT_NOT_ALLOWED');
    if (current >= ringGrant.expiresAtMs) return ignored('GRANT_EXPIRED');
    if (
      eventAtMs < current - RING_EVENT_MAX_AGE_MS
      || eventAtMs > current + RING_EVENT_FUTURE_MS
      || sentAtMs > current + RING_EVENT_FUTURE_MS
    ) return ignored('EVENT_OUTSIDE_FRESHNESS_WINDOW');
    const device = getAction('living_light', 'on');
    if (paired.get(device.id) !== 'owner') return ignored('LIGHT_NOT_PAIRED');
    if (ringRequests.size >= MAX_RING_REQUESTS) {
      fail('RING_LEDGER_FULL', 503, 'Ring motion request capacity is full.');
    }
    if (edgeCommands.size >= MAX_EDGE_COMMANDS) {
      fail('EDGE_LEDGER_FULL', 503, 'Simulated command ledger is full.');
    }
    const expiresAtMs = Math.min(
      current + EDGE_QUEUE_TTL_MS,
      ringGrant.expiresAtMs,
      eventAtMs + RING_EVENT_MAX_AGE_MS,
    );
    if (expiresAtMs <= current) return ignored('EVENT_OUTSIDE_FRESHNESS_WINDOW');
    const mustQueue = !edgeOnline || current - lastHeartbeatMs > EDGE_HEARTBEAT_STALE_MS
      || edgeFaults.get(device.id) === 'no_ack';
    if (mustQueue && edgeQueue.size >= MAX_EDGE_QUEUE) {
      fail('EDGE_QUEUE_FULL', 503, 'Simulated fallback queue is full.');
    }

    const commandId = randomUUID();
    const actor = `ring_automation:${ringGrant.homeId}`;
    const command = {
      actor,
      deviceId: device.id,
      action: 'on',
      parameters: {},
      origin: 'ring',
      commandId,
      nonce: randomBytes(16).toString('hex'),
      requestId,
      homeId: ringGrant.homeId,
      grantVersion: ringGrant.grantVersion,
      expiresAtMs,
      applied: false,
    };
    command.proof = edgeProof(command);
    const reserved = { bodyDigest, commandId, command, errorCode: 'RING_EXECUTION_PENDING' };
    ringRequests.set(requestId, reserved);
    try {
      const edgeResult = dispatchEdgeCommand(command, current);
      const result = ringResultFromEdge(command, edgeResult);
      reserved.errorCode = null;
      return result;
    } catch (error) {
      if (error.code === 'EDGE_AUTH_DENIED' && !command.applied) {
        const denied = makeEdgeResult(command, 'denied', 'simulated_wifi', null, current);
        denied.reason = 'EDGE_AUTH_DENIED';
        edgeCommands.set(commandId, {
          fingerprint: commandFingerprint(command), result: clone(denied),
        });
        rememberReceipt({ commandId, requestId, deviceId: device.id,
          action: 'on', status: 'denied', gatewayAck: false,
          deviceObserved: false, at: iso(current), simulated: true });
        record({ actor, deviceId: device.id, action: 'on', origin: 'ring',
          outcome: 'denied', commandId, requestId, atMs: current });
        reserved.errorCode = 'EDGE_AUTH_DENIED';
        fail('EDGE_AUTH_DENIED', 403, 'Simulated device command authentication failed.');
      }
      if (!command.applied) {
        ringRequests.delete(requestId);
        fail('RING_EXECUTION_FAILED', 503, 'Ring motion was not applied.');
      }
      reserved.errorCode = 'RING_EXECUTION_UNCONFIRMED';
      fail('RING_EXECUTION_UNCONFIRMED', 503, 'Ring motion was applied without a confirmed receipt.');
    }
  }

  function addSchedule({ actor, deviceId, action, parameters, at } = {}) {
    requireOwner(actor);
    getAction(deviceId, action);
    requirePaired(actor, deviceId);
    if (isScheduleForbidden(deviceId, action)) {
      fail('SCHEDULE_FORBIDDEN', 403, 'This action cannot be scheduled.');
    }
    const validatedParameters = validateParameters(deviceId, action, parameters);
    if (schedules.size >= MAX_SCHEDULES) {
      fail('SCHEDULE_LIMIT', 429, 'Simulator schedule limit reached.');
    }
    const atMs = typeof at === 'string' ? Date.parse(at) : NaN;
    const current = clock();
    if (!Number.isFinite(atMs) || atMs <= current || atMs > current + MAX_SCHEDULE_AHEAD_MS) {
      fail('INVALID_SCHEDULE', 400, 'Schedule must be an ISO date within the next 30 days.');
    }
    const schedule = {
      id: randomUUID(),
      actor,
      deviceId,
      action,
      parameters: validatedParameters,
      at: iso(atMs),
      atMs,
      simulated: true,
    };
    schedules.set(schedule.id, schedule);
    record({ actor, deviceId, action: 'schedule_add', origin: 'ui', outcome: 'scheduled' });
    const { actor: hiddenActor, atMs: hiddenAtMs, ...visible } = schedule;
    return clone(visible);
  }

  function cancelSchedule({ actor, scheduleId } = {}) {
    requireOwner(actor);
    const schedule = schedules.get(scheduleId);
    if (!schedule || schedule.actor !== actor) {
      fail('SCHEDULE_NOT_FOUND', 404, 'Schedule does not exist.');
    }
    schedules.delete(scheduleId);
    record({ actor, deviceId: schedule.deviceId, action: 'schedule_cancel', outcome: 'cancelled' });
    return { scheduleId, cancelled: true, simulated: true };
  }

  function tick() {
    const current = clock();
    if (edgeOnline && current - lastHeartbeatMs >= EDGE_HEARTBEAT_INTERVAL_MS) {
      lastHeartbeatMs = current;
      lastHeartbeatAt = iso(current);
      flushEdgeQueue(current);
    }
    const due = [...schedules.values()]
      .filter((schedule) => schedule.atMs <= current)
      .sort((a, b) => a.atMs - b.atMs);
    const executed = [];
    const queued = [];
    const failed = [];
    for (const schedule of due) {
      schedules.delete(schedule.id);
      try {
        const result = perform({
          actor: schedule.actor,
          deviceId: schedule.deviceId,
          action: schedule.action,
          parameters: schedule.parameters,
          origin: 'schedule',
        });
        if (result.status === 'queued') queued.push({ scheduleId: schedule.id, ...result });
        else if (result.status === 'simulated_applied') executed.push({ scheduleId: schedule.id, ...result });
        else failed.push({ scheduleId: schedule.id, code: 'EDGE_COMMAND_EXPIRED' });
      } catch (error) {
        record({
          actor: schedule.actor,
          deviceId: schedule.deviceId,
          action: 'schedule_execute',
          origin: 'schedule',
          outcome: 'failed',
        });
        failed.push({ scheduleId: schedule.id, code: error.code || 'EXECUTION_FAILED' });
      }
    }
    return { executed, queued, failed, simulated: true };
  }

  return {
    getState,
    beginPair,
    completePair,
    beginConfirmation,
    perform,
    performBatch,
    setEdgeOnline,
    setEdgeFault,
    heartbeat,
    performRingMotion,
    addSchedule,
    cancelSchedule,
    tick,
  };
}
