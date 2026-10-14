import { types } from 'node:util';
import { createTelegramAdmissionClient, validateTelegramMe, validateTelegramUpdates,
  telegramUpdateProvenanceConstants } from './telegram-client.mjs';
import { validateDurableBindingV2 } from '../wifi/durable-binding-v2.mjs';
import { exactObject, deepFreeze, denyFormalRuntime, safeRevision, zeroBinary } from './protocol.mjs';

function data(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value)) {
    denyFormalRuntime('B02_TRANSPORT_RESPONSE_DENIED');
  }
  const field = Object.getOwnPropertyDescriptor(value, name);
  if (!field || !Object.hasOwn(field, 'value')) denyFormalRuntime('B02_TRANSPORT_RESPONSE_DENIED');
  return field.value;
}
function numericId(value) {
  if (typeof value === 'number' && Number.isSafeInteger(value)) value = String(value);
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,19}$/.test(value)) denyFormalRuntime('B02_TRANSPORT_ID_DENIED');
  return value;
}

export function createTelegramTransportPort({ request, identityProjectorPort, currentBindingPort,
  timeoutMs = 10_000, maxCapacity = 8 }) {
  if (typeof request !== 'function' || !identityProjectorPort ||
      typeof identityProjectorPort.projectTelegramIdentity !== 'function' || !currentBindingPort ||
      typeof currentBindingPort.readCurrent !== 'function' || !Number.isSafeInteger(timeoutMs) ||
      timeoutMs < 100 || timeoutMs > 30_000 || !Number.isSafeInteger(maxCapacity) || maxCapacity < 1 || maxCapacity > 64) {
    denyFormalRuntime('B02_TRANSPORT_CONFIG_DENIED');
  }
  let closed = false;
  const jobs = new Set();
  const work = new Set();
  let associatedBots = new WeakMap();
  const track = promise => {
    const actual = Promise.resolve(promise);
    work.add(actual);
    actual.then(() => work.delete(actual), () => work.delete(actual));
    return actual;
  };
  function release(job) {
    if (job.finished && job.dependencies === 0) jobs.delete(job);
  }
  function dependency(job, action) {
    job.dependencies += 1;
    return track(Promise.resolve().then(action).finally(() => {
      job.dependencies -= 1;
      release(job);
    }));
  }
  function alive(job) {
    if (closed || job.cancelled) denyFormalRuntime('B02_TRANSPORT_CLOSED');
  }
  async function snapshot(job) {
    alive(job);
    const value = exactObject(await dependency(job, () => currentBindingPort.readCurrent()), ['binding', 'credentialRevision'], 'B02_TRANSPORT_BINDING_DENIED');
    alive(job);
    if (!Number.isSafeInteger(value.credentialRevision) || value.credentialRevision < 1) denyFormalRuntime('B02_TRANSPORT_BINDING_DENIED');
    return Object.freeze({ binding: validateDurableBindingV2(value.binding, { allowRevoked: false }),
      credentialRevision: value.credentialRevision });
  }
  async function project(job, kind, rawId, binding) {
    const result = await dependency(job, () => identityProjectorPort.projectTelegramIdentity(Object.freeze({ kind,
      rawId: numericId(rawId), botRawId: kind === 'bot' ? numericId(rawId) : job.botRawId, binding })));
    alive(job);
    const values = exactObject(result, ['kind', 'rawId', 'identity', 'bindingGeneration'], 'B02_TRANSPORT_PROJECTION_DENIED');
    const expected = kind === 'bot' ? binding.botId : binding.ownerId;
    if (values.kind !== kind || values.rawId !== numericId(rawId) || values.identity !== expected ||
        values.bindingGeneration !== binding.generation) denyFormalRuntime('B02_TRANSPORT_PROJECTION_DENIED');
    return expected;
  }
  async function sanitize(job, method, raw, binding) {
    if (data(raw, 'ok') !== true) denyFormalRuntime('B02_TRANSPORT_RESPONSE_DENIED');
    const result = data(raw, 'result');
    if (method === 'getMe') {
      if (data(result, 'is_bot') !== true) denyFormalRuntime('B02_TRANSPORT_RESPONSE_DENIED');
      const id = await project(job, 'bot', data(result, 'id'), binding);
      job.botRawId = numericId(data(result, 'id'));
      const username = data(result, 'username');
      const response = deepFreeze({ ok: true, result: { id, isBot: true, username } });
      validateTelegramMe(response);
      return response;
    }
    if (!Array.isArray(result) || types.isProxy(result) || result.length > 100) denyFormalRuntime('B02_TRANSPORT_RESPONSE_DENIED');
    const normalized = [];
    for (let index = 0; index < result.length; index += 1) {
      const item = Object.getOwnPropertyDescriptor(result, String(index));
      if (!item || !Object.hasOwn(item, 'value')) denyFormalRuntime('B02_TRANSPORT_RESPONSE_DENIED');
      const update = item.value;
      data(update, 'update_id');
      if (Object.hasOwn(update, 'edited_message')) denyFormalRuntime('B02_TRANSPORT_PROVENANCE_DENIED');
      const message = data(update, 'message');
      const from = data(message, 'from');
      if (telegramUpdateProvenanceConstants.forbiddenMessageFields.some(key => Object.hasOwn(message, key))) {
        denyFormalRuntime('B02_TRANSPORT_PROVENANCE_DENIED');
      }
      const chat = data(message, 'chat');
      if (data(from, 'is_bot') !== false || data(chat, 'type') !== 'private' ||
          numericId(data(from, 'id')) !== numericId(data(chat, 'id'))) denyFormalRuntime('B02_TRANSPORT_PROVENANCE_DENIED');
      const id = await project(job, 'owner', data(from, 'id'), binding);
      const text = data(message, 'text');
      const date = data(message, 'date');
      if (typeof text !== 'string' || text.length > 4096 || !Number.isSafeInteger(date) || date < 1) {
        denyFormalRuntime('B02_TRANSPORT_RESPONSE_DENIED');
      }
      normalized.push({ update_id: safeRevision(data(update, 'update_id')),
        message: { from: { id, is_bot: false }, chat: { id, type: 'private' }, text, date } });
    }
    const response = deepFreeze({ ok: true, result: normalized });
    validateTelegramUpdates(response);
    return response;
  }
  async function invoke(method, input) {
    const fields = exactObject(input, method === 'getMe' ? ['lease'] : ['lease', 'offset', 'limit'], 'B02_TRANSPORT_INPUT_DENIED');
    const lease = fields.lease;
    if (closed || !lease || lease.productionAdmitted !== true || lease.secretBufferBoundary !== 'mutable-buffer-v1' ||
        typeof lease.withToken !== 'function' || typeof lease.close !== 'function') denyFormalRuntime('B02_TRANSPORT_LEASE_DENIED');
    if (method === 'getUpdates' && (!Number.isSafeInteger(fields.limit) || fields.limit < 1 || fields.limit > 100)) {
      denyFormalRuntime('B02_TRANSPORT_INPUT_DENIED');
    }
    if (method === 'getUpdates') safeRevision(fields.offset);
    if (jobs.size >= maxCapacity) denyFormalRuntime('B02_TRANSPORT_CAPACITY_DENIED');
    const job = { cancelled: false, buffers: new Set(), client: null, closing: null, clean: null,
      dependencies: 0, finished: false };
    jobs.add(job);
    const clean = () => {
      job.cancelled = true;
      for (const buffer of job.buffers) zeroBinary(buffer);
      job.client?.close();
      if (!job.closing) job.closing = track(Promise.resolve().then(() => lease.close()));
      job.closing.catch(() => {});
    };
    job.clean = clean;
    const actual = track(Promise.resolve().then(async () => {
      try {
        const before = await snapshot(job);
        if (typeof lease.status !== 'function') denyFormalRuntime('B02_TRANSPORT_LEASE_DENIED');
        const leaseState = lease.status();
        if (leaseState.closed !== false || leaseState.zeroized !== false || leaseState.tokenResident !== true ||
            leaseState.revision !== before.credentialRevision || leaseState.bindingGeneration !== before.binding.generation) {
          denyFormalRuntime('B02_TRANSPORT_LEASE_DENIED');
        }
        if (method === 'getUpdates') {
          const association = associatedBots.get(lease);
          if (!association || association.snapshot !== JSON.stringify(before)) denyFormalRuntime('B02_TRANSPORT_BOT_ASSOCIATION_DENIED');
          job.botRawId = association.botRawId;
        }
        let captured;
        job.client = createTelegramAdmissionClient({ timeoutMs, request: async values => {
          alive(job);
          job.buffers.add(values.token);
          try { const raw = await dependency(job, () => request(values)); alive(job); return raw; }
          finally { zeroBinary(values.token); job.buffers.delete(values.token); }
        } });
        const consumed = await lease.withToken(async token => {
          const raw = method === 'getMe' ? await job.client.getMe({ token }) :
            await job.client.getUpdates({ token, offset: fields.offset, limit: fields.limit });
          alive(job);
          captured = await sanitize(job, method, raw, before.binding);
          const after = await snapshot(job);
          if (JSON.stringify(before) !== JSON.stringify(after)) denyFormalRuntime('B02_TRANSPORT_BINDING_DRIFT');
          return 'CONSUMED';
        });
        alive(job);
        if (consumed !== 'CONSUMED' || !captured) denyFormalRuntime('B02_TRANSPORT_RESULT_DENIED');
        if (method === 'getMe') {
          const prior = associatedBots.get(lease);
          if (prior && (prior.botRawId !== job.botRawId || prior.snapshot !== JSON.stringify(before))) {
            denyFormalRuntime('B02_TRANSPORT_BOT_ASSOCIATION_DENIED');
          }
          associatedBots.set(lease, Object.freeze({ botRawId: job.botRawId, snapshot: JSON.stringify(before) }));
        }
        return captured;
      } catch {
        associatedBots.delete(lease);
        clean();
        denyFormalRuntime('B02_TRANSPORT_PROVIDER_DENIED');
      } finally {
        job.client?.close();
        for (const buffer of job.buffers) zeroBinary(buffer);
        if (job.closing) await job.closing;
        job.finished = true;
        release(job);
      }
    }));
    let timer;
    try {
      return await Promise.race([actual, new Promise((_, reject) => {
        timer = setTimeout(() => { clean(); reject(new Error('B02_TRANSPORT_TIMEOUT')); }, timeoutMs);
      })]);
    } catch { denyFormalRuntime('B02_TRANSPORT_PROVIDER_DENIED'); }
    finally { clearTimeout(timer); }
  }
  return Object.freeze({ productionAdmitted: true, secretBufferBoundary: 'mutable-buffer-v1',
    getMeWithLease: input => invoke('getMe', input), getUpdatesWithLease: input => invoke('getUpdates', input),
    async close() {
      closed = true;
      associatedBots = new WeakMap();
      for (const job of jobs) {
        job.clean();
      }
      let timer;
      await Promise.race([Promise.allSettled([...work]), new Promise(resolve => { timer = setTimeout(resolve, timeoutMs); })]);
      clearTimeout(timer);
      return Object.freeze({ closed: true, inFlight: work.size, capacityHeld: jobs.size,
        resourceReleased: work.size === 0 && jobs.size === 0 });
    },
    status() { return Object.freeze({ closed, inFlight: work.size, capacityHeld: jobs.size }); }
  });
}
