import { dirname, basename } from 'node:path';
import { types } from 'node:util';
import { createFormalRuntimeComposition, createDisabledFormalRuntimeComposition } from './runtime-assembly.mjs';
import { createExecutableServerAssembly } from './server-composition.mjs';
import { validateProductionPortSet } from './production-ports.mjs';
import { createFormalRuntimeStatePathContract } from './state-path-contract.mjs';
import { createMacRemoteEntryPorts } from './remote-entry-port.mjs';
import { createCredentialOperatorPort } from './credential-operator-port.mjs';
import { createTelegramTransportPort } from './telegram-transport-port.mjs';
import { createTelegramIdentityProjector } from './telegram-identity-projector.mjs';
import { createBinaryCredentialFileDriver } from './binary-credential-file-driver.mjs';
import { createTelegramTlsRequest } from './telegram-tls-request.mjs';
import { createNativeStatePorts } from './native-state-io.mjs';
import { exactObject, denyFormalRuntime, zeroBinary } from './protocol.mjs';

const CODE = 'B02_MAC_COMPOSITION_INPUT_DENIED';
const REQUIRED = Object.freeze({
  antiRollbackWitnessPort: ['readCurrent', 'compareAndAdvance', 'confirm', 'close'],
  localSessionPort: ['resolve', 'close'],
  formalCapabilityPort: ['list', 'execute', 'close'],
  currentBindingPort: ['readCurrent'],
  requestBindingPort: ['resolve', 'recheck'],
  identityAuthority: ['resolveMatchedRingAccount', 'recheck'],
  operatorPort: ['requestPassphrase'],
  credentialRevisionFloorPort: ['read'],
  wifiTrustService: ['recognizeForMcpEntry'],
  wifiTrustStore: ['readCurrent'],
  ringReferencePort: ['current'],
  authorityClock: ['monotonicNowMs', 'wallNowMs'],
  bootEpoch: ['derive', 'status', 'close']
});
const ADMITTED = new Set(['antiRollbackWitnessPort', 'localSessionPort', 'formalCapabilityPort', 'ringReferencePort',
  'authorityClock', 'bootEpoch']);

function record(value, required, optional = []) {
  if (!value || types.isProxy(value)) denyFormalRuntime(CODE);
  const keys = Reflect.ownKeys(value);
  if (required.some(key => !keys.includes(key)) || keys.some(key => ![...required, ...optional].includes(key))) {
    denyFormalRuntime(CODE);
  }
  return exactObject(value, keys, CODE);
}
function captureService(value, methods, admitted) {
  if (!value || types.isProxy(value)) denyFormalRuntime(CODE);
  const captured = {};
  for (const name of methods) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function') {
      denyFormalRuntime(CODE);
    }
    captured[name] = descriptor.value.bind(value);
  }
  if (admitted) {
    const descriptor = Object.getOwnPropertyDescriptor(value, 'productionAdmitted');
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.value !== true) denyFormalRuntime(CODE);
    captured.productionAdmitted = true;
  }
  return Object.freeze(captured);
}
function limits(value) {
  if (value === undefined) return Object.freeze({ operationTimeoutMs: 10_000, closeTimeoutMs: 10_000, maxCapacity: 8 });
  const fields = record(value, ['operationTimeoutMs', 'closeTimeoutMs', 'maxCapacity']);
  if (!Number.isSafeInteger(fields.operationTimeoutMs) || fields.operationTimeoutMs < 100 || fields.operationTimeoutMs > 30_000 ||
      !Number.isSafeInteger(fields.closeTimeoutMs) || fields.closeTimeoutMs < 100 || fields.closeTimeoutMs > 30_000 ||
      !Number.isSafeInteger(fields.maxCapacity) || fields.maxCapacity < 1 || fields.maxCapacity > 64) denyFormalRuntime(CODE);
  return Object.freeze({ ...fields });
}

export function createMacRuntimeComposition(input = { enabled: false }) {
  if (!input || types.isProxy(input)) denyFormalRuntime(CODE);
  const descriptor = Object.getOwnPropertyDescriptor(input, 'enabled');
  if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'boolean') denyFormalRuntime(CODE);
  if (!descriptor.value) {
    const runtime = createDisabledFormalRuntimeComposition();
    let closed = false;
    return Object.freeze({ enabled: false, assembly: null, productionPorts: null, formalContextPort: null,
      start: runtime.start, readCurrentBinding: runtime.readCurrentBinding,
      async close() { closed = true; await runtime.close(); return Object.freeze({ closed, inFlight: 0, resourceReleased: true }); },
      status() { return Object.freeze({ ...runtime.status(), inFlight: 0, resourceReleased: closed }); },
      resources() { return Object.freeze({ ownedLeaves: 0, nativeHelperRunning: false, inFlight: 0, resourceReleased: closed }); }
    });
  }
  const fields = record(input, ['enabled', 'baseDirectory', 'services'], ['pythonBin', 'limits']);
  const supplied = record(fields.services, Object.keys(REQUIRED));
  const services = Object.fromEntries(Object.entries(REQUIRED).map(([name, methods]) =>
    [name, captureService(supplied[name], methods, ADMITTED.has(name))]));
  const localContextDescriptor = Object.getOwnPropertyDescriptor(supplied.localSessionPort, 'resolveRequestContext');
  let resolveLocalContext = null;
  if (localContextDescriptor !== undefined) {
    if (!Object.hasOwn(localContextDescriptor, 'value') || typeof localContextDescriptor.value !== 'function') denyFormalRuntime(CODE);
    resolveLocalContext = localContextDescriptor.value.bind(supplied.localSessionPort);
  }
  const authorizedRequestDescriptor = Object.getOwnPropertyDescriptor(supplied.localSessionPort, 'bindAuthorizedRequest');
  let bindAuthorizedRequest = null;
  if (authorizedRequestDescriptor !== undefined) {
    if (!Object.hasOwn(authorizedRequestDescriptor, 'value') || typeof authorizedRequestDescriptor.value !== 'function') denyFormalRuntime(CODE);
    bindAuthorizedRequest = authorizedRequestDescriptor.value.bind(supplied.localSessionPort);
  }
  const epochDescriptor = Object.getOwnPropertyDescriptor(supplied.bootEpoch, 'digest');
  if (!epochDescriptor || !Object.hasOwn(epochDescriptor, 'value') || typeof epochDescriptor.value !== 'string' ||
      !/^[a-f0-9]{64}$/.test(epochDescriptor.value)) denyFormalRuntime(CODE);
  services.bootEpoch = Object.freeze({ ...services.bootEpoch, digest: epochDescriptor.value });
  const bound = limits(fields.limits);
  const paths = createFormalRuntimeStatePathContract({ projectRoot: fields.baseDirectory });
  const native = createNativeStatePorts({ baseDirectory: fields.baseDirectory,
    ...(Object.hasOwn(fields, 'pythonBin') ? { pythonBin: fields.pythonBin } : {}) });
  const driver = createBinaryCredentialFileDriver({ rootPath: dirname(paths.absolute.custody), fileName: basename(paths.absolute.custody) });
  const tls = createTelegramTlsRequest({ maxCapacity: bound.maxCapacity });
  const projector = createTelegramIdentityProjector({ currentBindingPort: services.currentBindingPort });
  const clock = services.authorityClock;
  const bootEpoch = services.bootEpoch;
  let closed = false;
  const work = new Set();
  const closeResults = new Map();
  const closePromises = new Map();
  let core;
  let closing = false;
  function track(value) {
    const actual = Promise.resolve(value);
    work.add(actual);
    actual.then(() => work.delete(actual), () => work.delete(actual));
    return actual;
  }
  function closeOnce(name, action) {
    if (!closePromises.has(name)) {
      closePromises.set(name, track(Promise.resolve().then(action).then(result => {
        closeResults.set(name, result?.resourceReleased === true);
        return result;
      }, () => { closeResults.set(name, false); return null; })));
    }
    return closePromises.get(name);
  }
  function managed(name, port) {
    return Object.freeze({ ...port, close: () => closeOnce(name, port.close) });
  }
  const remote = createMacRemoteEntryPorts({ identityAuthority: services.identityAuthority,
    requestBindingPort: services.requestBindingPort, clock, bootEpoch,
    limits: { maxHandles: bound.maxCapacity, ttlMs: 30_000,
      operationTimeoutMs: bound.operationTimeoutMs, closeTimeoutMs: bound.closeTimeoutMs } });
  const formalContextPort = Object.freeze({ productionAdmitted: true,
    async resolve(input) {
      if (closed) denyFormalRuntime('B02_MAC_COMPOSITION_CLOSED');
      if (bindAuthorizedRequest !== null) {
        await track(Promise.resolve().then(() => bindAuthorizedRequest(input)));
        if (closed) denyFormalRuntime('B02_MAC_COMPOSITION_CLOSED');
      }
      if (resolveLocalContext !== null) {
        const local = await track(Promise.resolve().then(() => resolveLocalContext(input)));
        if (closed) denyFormalRuntime('B02_MAC_COMPOSITION_CLOSED');
        if (local !== null) {
          const handles = record(local, ['socketHandle', 'sessionHandle']);
          if (![handles.socketHandle, handles.sessionHandle].every(value => value && typeof value === 'object' && !types.isProxy(value))) denyFormalRuntime(CODE);
          return Object.freeze({ source: 'local', serverContext: Object.freeze(handles) });
        }
      }
      return await remote.formalContextPort.resolve(input);
    }
  });
  const credentialOperator = createCredentialOperatorPort({ currentBindingPort: services.currentBindingPort, bootEpoch,
    timeoutMs: bound.operationTimeoutMs, maxCapacity: bound.maxCapacity,
    leaseInputPort: Object.freeze({ async requestLeaseInputs(request) {
      const passphrase = await track(Promise.resolve().then(() => services.operatorPort.requestPassphrase(request)));
      if (closed || !Buffer.isBuffer(passphrase)) { zeroBinary(passphrase); denyFormalRuntime('B02_MAC_OPERATOR_DENIED'); }
      return Object.freeze({ encryptedDriver: driver, passphrase, revisionFloor: services.credentialRevisionFloorPort,
        expectedRevision: request.expectedRevision, binding: request.binding });
    } }) });
  const telegram = createTelegramTransportPort({ request: tls.request,
    identityProjectorPort: projector, currentBindingPort: services.currentBindingPort,
    timeoutMs: bound.operationTimeoutMs, maxCapacity: bound.maxCapacity });
  const ports = validateProductionPortSet({
    antiRollbackWitnessPort: managed('witness', services.antiRollbackWitnessPort),
    descriptorStateIoPort: native.descriptorStateIoPort,
    stateTransactionLockPort: native.stateTransactionLockPort,
    credentialOperatorPort: credentialOperator,
    telegramTransportPort: telegram,
    localSessionPort: managed('localSession', services.localSessionPort),
    remoteEntryPort: remote.remoteEntryPort,
    formalCapabilityPort: managed('capability', services.formalCapabilityPort)
  });
  core = createFormalRuntimeComposition({ config: {
    schema: 'ring-b02-formal-runtime-config-v1', enabled: true, profile: 'FORMAL',
    stateRoot: paths.relative.root, maximumGrantTtlMs: 300_000,
    providerCallsOnConstruction: false, externalWitnessRequired: true
  }, statePathMetadata: { stateRoot: paths.relative.root }, productionPorts: ports,
  wifiTrustService: services.wifiTrustService, wifiTrustStore: services.wifiTrustStore,
  ringReferencePort: services.ringReferencePort, authorityClock: clock, bootEpoch });

  function resources() {
    const n = native.status(), c = credentialOperator.status(), t = telegram.status(),
      p = projector.status(), b = driver.status(), s = tls.status(), r = remote.status();
    const released = closed && work.size === 0 && n.resourceReleased === true &&
      c.closed && c.inFlight === 0 && c.capacityHeld === 0 && t.closed && t.inFlight === 0 && t.capacityHeld === 0 &&
      p.closed && p.inFlight === 0 && b.closed && b.sessions === 0 && b.openDescriptors === 0 &&
      s.closed && s.inFlight === 0 && r.closed && r.activeHandles === 0 &&
      r.pendingOperations === 0 && r.pendingDependencies === 0 && r.reservations === 0 &&
      bootEpoch.status().closed && ['witness', 'localSession', 'capability'].every(name => closeResults.get(name) === true);
    return Object.freeze({ ownedLeaves: 7, nativeHelperRunning: n.helperRunning,
      inFlight: work.size, resourceReleased: released,
      native: n, credential: c, telegram: t, projector: p, custody: b, tls: s, remote: r,
      externalCloseConfirmed: ['witness', 'localSession', 'capability'].filter(name => closeResults.get(name) === true).length });
  }
  async function close() {
    closed = true;
    if (!closing) {
      closing = true;
      closeOnce('core', () => core.close());
      closeOnce('credential', () => credentialOperator.close());
      closeOnce('telegram', () => telegram.close());
      closeOnce('remote', () => remote.close());
      closeOnce('projector', () => projector.close());
      closeOnce('driver', () => driver.close());
      closeOnce('tls', () => tls.close());
      closeOnce('native', () => native.close());
      ports.antiRollbackWitnessPort.close(); ports.localSessionPort.close(); ports.formalCapabilityPort.close();
      bootEpoch.close();
    }
    let timer;
    await Promise.race([Promise.allSettled([...work]), new Promise(resolve => { timer = setTimeout(resolve, bound.closeTimeoutMs); })]);
    clearTimeout(timer);
    const result = resources();
    return Object.freeze({ closed: true, inFlight: result.inFlight, resourceReleased: result.resourceReleased });
  }
  function operation(method, input) {
    if (closed) return Promise.reject(new Error('B02_MAC_COMPOSITION_CLOSED'));
    return track(Promise.resolve().then(() => {
      if (closed) denyFormalRuntime('B02_MAC_COMPOSITION_CLOSED');
      return core[method](input);
    }).then(async result => {
      if (closed) { await core.close(); denyFormalRuntime('B02_MAC_COMPOSITION_CLOSED'); }
      return result;
    }));
  }
  const runtime = Object.freeze({
    start: () => operation('start'), readCurrentBinding: () => operation('readCurrentBinding'), issueMcpEntry: input => operation('issueMcpEntry', input),
    consumeMcpEntry: input => operation('consumeMcpEntry', input),
    close, status() { return Object.freeze({ ...core.status(), ready: !closed && core.status().ready }); }
  });
  const assembly = createExecutableServerAssembly({ mode: 'FORMAL', demoFactory: null,
    formalFactory: () => ({ runtime, ports, bootEpoch, clock }) });
  return Object.freeze({ enabled: true, assembly, productionPorts: ports,
    formalContextPort, start: runtime.start, readCurrentBinding: runtime.readCurrentBinding, close,
    status() { return Object.freeze({ ...runtime.status(), inFlight: work.size,
      resourceReleased: resources().resourceReleased }); }, resources });
}

export const macRuntimeCompositionContract = Object.freeze({
  schema: 'ring-b02-mac-runtime-composition-v1', residency: 'MAC_ONLY',
  requiredServices: Object.freeze(Object.keys(REQUIRED)), constructorIo: false,
  cloudIngressAuthority: false, maximumGrantTtlMs: 300_000,
  custodyFormat: 'ring-b02-binary-credential-file-v2',
  suppliedLifetimePortsRequireReleasedReceipt: true,
  authoritativeBootAndClockRequired: true,
  suppliedBootLifetimeTransferred: true,
  suppliedSharedAuthorityServicesOwnedByCaller: true
});
