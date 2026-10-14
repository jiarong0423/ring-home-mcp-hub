import { createFormalRuntimeComposition } from './runtime-assembly.mjs';
import { dispatchFormalMcpToolCall } from './server-composition.mjs';
import { createMacRequestBindingPort } from './mac-request-binding-port.mjs';
import { createMacRemoteEntryPorts } from './remote-entry-port.mjs';
import { createMacCommandWorker } from './mac-command-worker.mjs';
import { createSoftwareTestSwitchPort } from './software-test-switch-port.mjs';
import { SOFTWARE_SWITCH_CAPABILITY, record, port, deny, freeze } from './mac-command-contract.mjs';

// All external runtime ports and the admitted session are existing runtime-owned resources.
// Construction does not open a listener, fetch a token, create a session, or contact a provider.
export function createMacCommandRuntime({ runtimeOptions, sessionAssociationServices, currentBindingPort, sessionLogin,
  transport, journal, runTimeoutMs = 10000, limits = { maxHandles: 8, ttlMs: 30000, operationTimeoutMs: 3000, closeTimeoutMs: 3000 } } = {}) {
  if (!Number.isSafeInteger(runTimeoutMs) || runTimeoutMs < 100 || runTimeoutMs > 10000) deny('MAC_COMMAND_RUNTIME_TIMEOUT_CONFIG');
  limits = record(limits, ['maxHandles', 'ttlMs', 'operationTimeoutMs', 'closeTimeoutMs']);
  const login = record(sessionLogin, ['actor', 'sessionHandle', 'csrf']);
  if (!login.actor || !Object.isFrozen(login.actor) || !login.sessionHandle || typeof login.sessionHandle !== 'object' || typeof login.csrf !== 'string') deny('MAC_COMMAND_SESSION_REQUIRED');
  const sessions = port(sessionAssociationServices, ['bindVerifiedRequest', 'lookupRequest']);
  const config = record(runtimeOptions, ['config', 'statePathMetadata', 'productionPorts', 'wifiTrustService', 'wifiTrustStore', 'ringReferencePort', 'authorityClock', 'bootEpoch']);
  const clock = config.authorityClock; const bootEpoch = config.bootEpoch;
  const bridge = createMacRequestBindingPort({ identityAuthority: sessionAssociationServices.identityAuthority,
    sessionAssociationServices: Object.freeze({ lookupRequest: sessions.lookupRequest }), currentBindingPort, authorityClock: clock, bootEpoch,
    limits: { maxCapacity: limits.maxHandles, operationTimeoutMs: limits.operationTimeoutMs, closeTimeoutMs: limits.closeTimeoutMs } });
  const remote = createMacRemoteEntryPorts({ identityAuthority: sessionAssociationServices.identityAuthority,
    requestBindingPort: bridge, clock, bootEpoch, limits });
  const receipts = new WeakMap(), commands = new WeakMap(), grants = new WeakMap();
  let closed = false, ready = false, active = null, activeEnvelope = null, permit = null;
  function assertActive() { if (closed || !ready || !permit || permit.cancelled) deny('MAC_COMMAND_RUNTIME_NOT_READY'); }
  const adapter = createSoftwareTestSwitchPort({ clock: () => clock.wallNowMs(), verifyAdmission(input) {
    const proof = receipts.get(input.admission); receipts.delete(input.admission);
    return proof !== undefined && proof === input.envelope && input.envelope === activeEnvelope &&
      input.capability === SOFTWARE_SWITCH_CAPABILITY && input.arguments === input.envelope.params.arguments;
  } });
  const formalCapabilityPort = Object.freeze({ productionAdmitted: true,
    async list() { return freeze({ tools: [{ name: SOFTWARE_SWITCH_CAPABILITY, description: 'Software-only test switch; no physical device',
      inputSchema: { type: 'object', properties: { enabled: { type: 'boolean' } }, required: ['enabled'], additionalProperties: false } }] }); },
    execute(input) { assertActive(); if (!activeEnvelope) deny('MAC_COMMAND_RUNTIME_NOT_READY'); return adapter.execute(input); },
    async close() { return freeze({ closed: true, resourceReleased: true }); }
  });
  const ports = Object.freeze({ ...config.productionPorts, remoteEntryPort: remote.remoteEntryPort, formalCapabilityPort });
  const core = createFormalRuntimeComposition({ ...config, productionPorts: ports });
  const runtime = Object.freeze({
    async issueMcpEntry(input) {
      assertActive(); if (!activeEnvelope) deny('MAC_COMMAND_RUNTIME_CONTEXT');
      const grant = await core.issueMcpEntry(input); assertActive(); grants.set(grant, { envelope: activeEnvelope, transport: input.transport }); return grant;
    },
    async consumeMcpEntry(input) {
      assertActive(); const issued = grants.get(input.grant); grants.delete(input.grant);
      if (!issued || issued.envelope !== activeEnvelope || issued.transport !== input.transport) deny('MAC_COMMAND_RUNTIME_GRANT');
      const admission = await core.consumeMcpEntry(input); assertActive();
      if (!admission || typeof admission !== 'object' || !Object.isFrozen(admission) || admission.accepted !== true) deny('MAC_COMMAND_RUNTIME_GRANT');
      receipts.set(admission, issued.envelope); return admission;
    }
  });
  const worker = createMacCommandWorker({ transport, journal, clock: () => clock.wallNowMs(),
    async authorizeCommand(c) {
      assertActive();
      const httpRequest = Object.freeze(Object.create(null));
      await sessions.bindVerifiedRequest({ httpRequest, actor: login.actor, sessionHandle: login.sessionHandle, csrf: login.csrf });
      const bound = await sessions.lookupRequest({ httpRequest, actor: login.actor }); assertActive();
      if (bound.association.ownerRef !== c.ownerRef || bound.association.revision !== c.associationRevision ||
          bound.sessionHandle !== login.sessionHandle || bound.actor !== login.actor) deny('MAC_COMMAND_SESSION_OWNER');
      const input = freeze({ request: { httpRequest }, actor: login.actor, validatedWire: { request: c.envelope }, effectiveEnvelope: c.envelope });
      const context = await remote.formalContextPort.resolve(input); assertActive();
      commands.set(c, context);
      return Object.freeze({ ownerRef: bound.association.ownerRef, associationRevision: bound.association.revision,
        assertCurrent() {
          assertActive(); if (clock.wallNowMs() >= c.expiresAt) deny('MAC_COMMAND_RUNTIME_NOT_READY');
          return bound.sessionAuthority.assertCurrentSession() === true;
        }
      });
    },
    async dispatchFormal({ command, envelope }) {
      assertActive(); const context = commands.get(command); commands.delete(command);
      if (!context || activeEnvelope || envelope !== command.envelope || context.source !== 'remote') deny('MAC_COMMAND_RUNTIME_CONTEXT');
      activeEnvelope = envelope;
      try {
        return await dispatchFormalMcpToolCall({ envelope, context: { path: 'remote-encrypted', handle: context.serverContext },
          runtime, ports, bootEpoch, clock });
      } finally { activeEnvelope = null; }
    }
  });
  function run(operation) {
    if (closed || !ready || active) return Promise.reject(Object.assign(new Error('MAC_COMMAND_RUNTIME_NOT_READY'), { code: 'MAC_COMMAND_RUNTIME_NOT_READY' }));
    const lease = { cancelled: false }; permit = lease;
    const task = Promise.resolve().then(operation); active = task;
    const finished = () => { if (active === task) active = null; if (permit === lease) permit = null; };
    task.then(finished, finished);
    let timer;
    const timeout = new Promise((resolve, reject) => { timer = setTimeout(() => { lease.cancelled = true;
      reject(Object.assign(new Error('MAC_COMMAND_RUNTIME_TIMEOUT'), { code: 'MAC_COMMAND_RUNTIME_TIMEOUT' })); }, runTimeoutMs); });
    return Promise.race([task, timeout]).finally(() => clearTimeout(timer));
  }
  return Object.freeze({
    async start() {
      if (closed || ready || active) deny('MAC_COMMAND_RUNTIME_START');
      const pending = core.start(); active = pending;
      try { const result = await pending; if (closed) deny('MAC_COMMAND_RUNTIME_NOT_READY'); ready = core.status().state === 'READY';
        if (!ready) deny('MAC_COMMAND_RUNTIME_NOT_READY'); return result;
      } finally { if (active === pending) active = null; }
    },
    runOnce() { return run(() => worker.runOnce()); },
    retryReceipt(commandId) { return run(() => worker.retryReceipt(commandId)); },
    status() { return freeze({ state: closed ? 'CLOSED' : ready ? 'READY' : 'CONSTRUCTED', inFlight: active ? 1 : 0,
      softwareOnly: true, listening: false, core: core.status() }); },
    async close() {
      closed = true; ready = false; if (permit) permit.cancelled = true;
      if (active) { let timer; await Promise.race([active.catch(() => {}), new Promise(resolve => { timer = setTimeout(resolve, limits.closeTimeoutMs); })]); clearTimeout(timer); }
      const results = await Promise.allSettled([core.close(), bridge.close()]);
      const r = remote.status();
      return freeze({ closed: true, inFlight: active ? 1 : 0, resourceReleased: false, ownedGlueReleased: !active && results.every(x => x.status === 'fulfilled') &&
        r.closed && r.pendingOperations === 0 && r.pendingDependencies === 0 && r.activeHandles === 0,
        externalRuntimeLeafClosure: 'UNKNOWN', callerOwnedSessionServices: true, callerOwnedTransport: true, callerOwnedJournal: true });
    }
  });
}

// Production composition: the enrolled key signs the exact worker payload after real grant consumption.
export async function createSignedMacCommandRuntime({ signingKey, https, ...options } = {}) {
  const { openMacCommandSigningKey } = await import('./mac-command-signing-key.mjs');
  const { createMacCommandHttpsClient } = await import('./mac-command-https-client.mjs');
  if (options.transport !== undefined || https?.proofSigner !== undefined || https?.request !== undefined) deny('MAC_SIGNED_RUNTIME_CONFIG');
  const signer = await openMacCommandSigningKey(signingKey);
  let runtime;
  try {
    const client = createMacCommandHttpsClient({ ...https, proofSigner: signer });
    const transport = Object.freeze({ async fetch() {
      const value = await client.fetch();
      if (value.status === 'CLAIMED' && (value.command?.ownerRef !== signer.ownerRef || value.command?.associationRevision !== signer.associationRevision)) deny('MAC_COMMAND_SESSION_OWNER');
      return value;
    }, receipt: client.receipt });
    runtime = createMacCommandRuntime({ ...options, transport });
    return Object.freeze({ start: runtime.start, runOnce: runtime.runOnce, retryReceipt: runtime.retryReceipt, status: runtime.status,
      async close() { const result = await runtime.close(); if (result.inFlight === 0) signer.close(); return result; } });
  } catch (error) { signer.close(); await runtime?.close(); throw error; }
}
