// Minimal Mac-side adapters for the library worker. REDUCED ASSURANCE (see BLOCKERS.md): this does NOT run the
// formal grant issue/consume dispatcher; the cloud has already verified bearer + enrolled-key proof + session.
import { createSoftwareTestSwitchPort } from '../vendor/software-test-switch-port.mjs';
import { createHomeDevicePort } from '../vendor/home-device-port.mjs';
import { SOFTWARE_SWITCH_CAPABILITY, HOME_DEVICE_CAPABILITY, deny } from '../vendor/mac-command-contract.mjs';

// applyHomeDevice is optional: only the local owner console provides it (CLI runs refuse home_device.command).
export function createDirectExecutor({ identity, clock = Date.now, applyHomeDevice }) {
  const admissions = new WeakMap(); let activeEnvelope = null;
  const verifyAdmission = capability => input => {
    const bound = admissions.get(input.admission); admissions.delete(input.admission);
    return bound !== undefined && bound === input.envelope && input.envelope === activeEnvelope &&
      input.capability === capability && input.arguments === input.envelope.params.arguments;
  };
  const switchPort = createSoftwareTestSwitchPort({ clock, verifyAdmission: verifyAdmission(SOFTWARE_SWITCH_CAPABILITY) });
  const devicePort = createHomeDevicePort({ clock, apply: applyHomeDevice, verifyAdmission: verifyAdmission(HOME_DEVICE_CAPABILITY) });
  return Object.freeze({
    async authorizeCommand(c) {
      if (c.ownerRef !== identity.ownerRef || c.associationRevision !== identity.associationRevision) deny('MAC_COMMAND_SESSION_OWNER');
      return Object.freeze({ ownerRef: c.ownerRef, associationRevision: c.associationRevision,
        assertCurrent() { const n = clock(); return n < c.expiresAt && n < c.sessionExpiresAt; } });
    },
    async dispatchFormal({ command, envelope }) {
      if (activeEnvelope || envelope !== command.envelope) deny('MAC_COMMAND_RUNTIME_CONTEXT');
      activeEnvelope = envelope; const admission = Object.freeze({ selfIssued: true }); admissions.set(admission, envelope);
      try {
        const name = envelope.params.name;
        const result = name === SOFTWARE_SWITCH_CAPABILITY
          ? switchPort.execute({ capability: name, arguments: envelope.params.arguments, admission, envelope })
          : name === HOME_DEVICE_CAPABILITY
            ? await devicePort.execute({ capability: name, arguments: envelope.params.arguments, admission, envelope, commandId: command.commandId })
            : deny('MAC_COMMAND_CAPABILITY');
        return { jsonrpc: '2.0', id: envelope.id, result };
      } finally { activeEnvelope = null; }
    }
  });
}
