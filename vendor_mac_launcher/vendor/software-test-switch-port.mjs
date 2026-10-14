import { SOFTWARE_SWITCH_CAPABILITY, envelope as normalizeEnvelope, record, switchResult, time, deny } from './mac-command-contract.mjs';

export function createSoftwareTestSwitchPort({ verifyAdmission, clock = Date.now } = {}) {
  if (typeof verifyAdmission !== 'function' || typeof clock !== 'function') deny('SOFTWARE_SWITCH_CONFIG');
  let revision = 0; let enabled = false; const consumed = new WeakSet();
  return Object.freeze({
    execute(input) {
      const call = record(input, ['capability', 'arguments', 'admission', 'envelope']);
      const e = normalizeEnvelope(call.envelope); const args = record(call.arguments, ['enabled']);
      if (!call.admission || typeof call.admission !== 'object' || consumed.has(call.admission) || call.capability !== SOFTWARE_SWITCH_CAPABILITY || typeof args.enabled !== 'boolean' || args.enabled !== e.params.arguments.enabled ||
          verifyAdmission({ admission: call.admission, envelope: call.envelope, capability: call.capability, arguments: call.arguments }) !== true) deny('SOFTWARE_SWITCH_ADMISSION');
      if (revision >= Number.MAX_SAFE_INTEGER) deny('SOFTWARE_SWITCH_REVISION');
      const observedAt = time(clock()); consumed.add(call.admission); enabled = args.enabled;
      return switchResult({ kind: 'software-test-switch', enabled, revision: ++revision, observedAt });
    }
  });
}
