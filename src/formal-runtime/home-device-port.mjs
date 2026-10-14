import { HOME_DEVICE_CAPABILITY, COMMAND_ID, envelope as normalizeEnvelope, record, deviceResult, homeDeviceAllowed, time, deny } from './mac-command-contract.mjs';

// Mac-side port for home_device.command. `apply` is injected by the local owner console and must change exactly one
// paired SIMULATED device immediately (no queueing); it returns { status } and is called at most once per admission.
export function createHomeDevicePort({ verifyAdmission, apply, clock = Date.now } = {}) {
  if (typeof verifyAdmission !== 'function' || typeof clock !== 'function') deny('HOME_DEVICE_CONFIG');
  let revision = 0; const consumed = new WeakSet();
  return Object.freeze({
    async execute(input) {
      const call = record(input, ['capability', 'arguments', 'admission', 'envelope', 'commandId']);
      const e = normalizeEnvelope(call.envelope); const args = record(call.arguments, ['deviceId', 'action']);
      if (!call.admission || typeof call.admission !== 'object' || consumed.has(call.admission) || call.capability !== HOME_DEVICE_CAPABILITY ||
          typeof call.commandId !== 'string' || !COMMAND_ID.test(call.commandId) ||
          e.params.name !== HOME_DEVICE_CAPABILITY || !homeDeviceAllowed(args.deviceId, args.action) ||
          args.deviceId !== e.params.arguments.deviceId || args.action !== e.params.arguments.action ||
          verifyAdmission({ admission: call.admission, envelope: call.envelope, capability: call.capability, arguments: call.arguments }) !== true) deny('HOME_DEVICE_ADMISSION');
      if (typeof apply !== 'function') deny('HOME_DEVICE_UNAVAILABLE');
      if (revision >= Number.MAX_SAFE_INTEGER) deny('HOME_DEVICE_REVISION');
      consumed.add(call.admission);
      const applied = await apply({ deviceId: args.deviceId, action: args.action, commandId: call.commandId });
      if (!applied || applied.status !== 'simulated_applied') deny('HOME_DEVICE_NOT_APPLIED');
      return deviceResult({ kind: 'home-device', deviceId: args.deviceId, action: args.action, status: 'simulated_applied',
        revision: ++revision, observedAt: time(clock()) });
    }
  });
}
