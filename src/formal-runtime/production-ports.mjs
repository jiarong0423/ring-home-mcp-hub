import { deepFreeze, denyFormalRuntime, exactObject, safeLabel, safeTime } from './protocol.mjs';

function exactProductionPort(port, methods, code, extra = () => true) {
  if (!port || port.productionAdmitted !== true || methods.some((name) => typeof port[name] !== 'function') || !extra(port)) {
    denyFormalRuntime(code);
  }
  return port;
}

export function validateProductionPortSet(ports) {
  const fields = exactObject(ports, [
    'antiRollbackWitnessPort', 'descriptorStateIoPort', 'stateTransactionLockPort', 'credentialOperatorPort',
    'telegramTransportPort', 'localSessionPort', 'remoteEntryPort', 'formalCapabilityPort'
  ], 'B02_FORMAL_PRODUCTION_PORTS_DENIED');
  exactProductionPort(fields.antiRollbackWitnessPort, ['readCurrent', 'compareAndAdvance', 'confirm', 'close'], 'B02_FORMAL_WITNESS_PORT_DENIED');
  exactProductionPort(fields.descriptorStateIoPort, ['openRootNoFollow', 'readAt', 'createTempAt', 'renameAt', 'unlinkAt', 'statAt', 'fsyncFile', 'fsyncDirectory', 'close'], 'B02_FORMAL_DESCRIPTOR_IO_DENIED', (p) => p.descriptorRelative === true);
  exactProductionPort(fields.stateTransactionLockPort, ['acquireExclusive', 'releaseOwned'], 'B02_FORMAL_LOCK_PORT_DENIED');
  exactProductionPort(fields.credentialOperatorPort, ['openLease', 'close'], 'B02_FORMAL_CREDENTIAL_OPERATOR_DENIED');
  exactProductionPort(fields.telegramTransportPort, ['getMeWithLease', 'getUpdatesWithLease', 'close'], 'B02_FORMAL_TELEGRAM_TRANSPORT_DENIED', (p) => p.secretBufferBoundary === 'mutable-buffer-v1');
  exactProductionPort(fields.localSessionPort, ['resolve', 'close'], 'B02_FORMAL_LOCAL_SESSION_DENIED');
  exactProductionPort(fields.remoteEntryPort, ['consumeSealedIntent', 'consumeSessionReceipt', 'recheckSessionReceipt', 'validateClaimedSessionReceipt', 'finishSessionReceipt', 'close'], 'B02_FORMAL_REMOTE_ENTRY_DENIED');
  exactProductionPort(fields.formalCapabilityPort, ['list', 'execute', 'close'], 'B02_FORMAL_CAPABILITY_DENIED');
  return Object.freeze(fields);
}

export async function deriveFormalEntryTransport({ path, handle, ports, bootEpoch, scope, capability, purpose, clock, envelope }) {
  if (!bootEpoch || typeof bootEpoch.digest !== 'string' || !clock || typeof clock.monotonicNowMs !== 'function') {
    denyFormalRuntime('B02_FORMAL_TRANSPORT_INPUT_DENIED');
  }
  const common = { bootEpoch: bootEpoch.digest, scope: safeLabel(scope), capability: safeLabel(capability), purpose: safeLabel(purpose) };
  let receipt;
  if (path === 'local-encrypted') {
    const values = exactObject(handle, ['socketHandle', 'sessionHandle'], 'B02_FORMAL_LOCAL_HANDLE_DENIED');
    receipt = await ports.localSessionPort.resolve(values);
    const fields = exactObject(receipt, ['productionAdmitted', 'singleUse', 'loopback', 'path', 'purpose', 'bootEpoch', 'entryId'], 'B02_FORMAL_LOCAL_RECEIPT_DENIED');
    if (fields.productionAdmitted !== true || fields.singleUse !== true || fields.loopback !== true || fields.path !== path ||
        fields.purpose !== common.purpose || fields.bootEpoch !== common.bootEpoch) denyFormalRuntime('B02_FORMAL_LOCAL_RECEIPT_DENIED');
    return deepFreeze({ path, entryId: safeLabel(fields.entryId), wifiTrust: 'required' });
  }
  if (path !== 'remote-encrypted') denyFormalRuntime('B02_FORMAL_TRANSPORT_PATH_DENIED');
  const values = exactObject(handle, ['intentHandle'], 'B02_FORMAL_REMOTE_HANDLE_DENIED');
  receipt = await ports.remoteEntryPort.consumeSealedIntent({ ...values, envelope });
  const fields = exactObject(receipt, ['productionAdmitted', 'singleUse', 'path', 'purpose', 'bootEpoch', 'scope', 'capability', 'entryId', 'issuedMonotonicMs', 'wifiTrust', 'sessionReceipt'], 'B02_FORMAL_REMOTE_RECEIPT_DENIED');
  const age = clock.monotonicNowMs() - fields.issuedMonotonicMs;
  if (fields.productionAdmitted !== true || fields.singleUse !== true || fields.path !== path || fields.purpose !== common.purpose ||
      fields.bootEpoch !== common.bootEpoch || fields.scope !== common.scope || fields.capability !== common.capability ||
      fields.wifiTrust !== null || !fields.sessionReceipt || typeof fields.sessionReceipt !== 'object' || !Object.isFrozen(fields.sessionReceipt) || !Number.isSafeInteger(fields.issuedMonotonicMs) || age < 0 || age > 30_000) {
    denyFormalRuntime('B02_FORMAL_REMOTE_RECEIPT_DENIED');
  }
  return deepFreeze({ path, entryId: safeLabel(fields.entryId), wifiTrust: null, sessionReceipt: fields.sessionReceipt });
}

export function createProductionTelegramTransport(port) {
  exactProductionPort(port, ['getMeWithLease', 'getUpdatesWithLease', 'close'], 'B02_FORMAL_TELEGRAM_TRANSPORT_DENIED',
    (p) => p.secretBufferBoundary === 'mutable-buffer-v1');
  return Object.freeze({ productionAdmitted: true, secretBufferBoundary: 'mutable-buffer-v1',
    getMeWithLease: port.getMeWithLease.bind(port), getUpdatesWithLease: port.getUpdatesWithLease.bind(port), close: port.close.bind(port) });
}
