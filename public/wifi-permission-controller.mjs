import { t } from './i18n-map.mjs';

const PHASES = Object.freeze(['disabled', 'idle', 'pending', 'active', 'revoked', 'denied', 'adapter-error']);

// Phase -> mapping-table key (public/i18n-map.mjs); the message text is looked up when a view is built.
const COPY = Object.freeze(Object.fromEntries(PHASES.map(phase => [phase, 'wifi.phase.' + phase])));

export class WifiPermissionControllerError extends Error {
  constructor(code) {
    super(code);
    this.name = 'WifiPermissionControllerError';
    this.code = code;
  }
}

function deny(code) {
  throw new WifiPermissionControllerError(code);
}

function exact(value, keys, code) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny(code);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some(key => typeof key !== 'string' || !keys.includes(key)) ||
      keys.some(key => !Object.hasOwn(descriptors, key)) ||
      Object.values(descriptors).some(item => !item.enumerable || !Object.hasOwn(item, 'value'))) deny(code);
  return value;
}

function validatePort(port, name) {
  if (typeof port !== 'function') deny(`B02_WIFI_UI_${name}_PORT_DENIED`);
  return port;
}

function validateResult(value, allowed) {
  const fields = exact(value, ['state'], 'B02_WIFI_UI_RESULT_DENIED');
  if (!allowed.includes(fields.state)) deny('B02_WIFI_UI_RESULT_DENIED');
  return fields.state;
}

function viewFor(phase) {
  if (!PHASES.includes(phase)) deny('B02_WIFI_UI_PHASE_DENIED');
  return Object.freeze({
    phase,
    message: t(COPY[phase]),
    busy: phase === 'pending',
    authorizeDisabled: phase === 'disabled' || phase === 'pending' || phase === 'active',
    revokeDisabled: phase === 'pending' || phase !== 'active'
  });
}

export function createWifiPermissionController({ statusPort, consentPort, revokePort, render }) {
  const readStatus = validatePort(statusPort, 'STATUS');
  const requestConsent = validatePort(consentPort, 'CONSENT');
  const requestRevoke = validatePort(revokePort, 'REVOKE');
  if (typeof render !== 'function') deny('B02_WIFI_UI_RENDER_DENIED');

  let view = viewFor('idle');
  let operation = 0;
  let pendingAction = null;

  function publish(next) {
    view = viewFor(next);
    render(view);
    return view;
  }

  function current() {
    return view;
  }

  async function execute(action, port, allowed) {
    if (pendingAction !== null) {
      return Object.freeze({ outcome: 'IGNORED', code: 'B02_WIFI_UI_DUPLICATE_CLICK' });
    }
    if (view.phase === 'disabled' ||
        (action === 'authorize-household-wifi' && view.phase === 'active') ||
        (action === 'revoke-household-wifi' && view.phase === 'revoked')) {
      return Object.freeze({ outcome: 'IGNORED', code: 'B02_WIFI_UI_ACTION_NOT_ALLOWED' });
    }
    const marker = ++operation;
    pendingAction = action;
    publish('pending');
    try {
      const phase = validateResult(await port(Object.freeze({ action })), allowed);
      if (marker !== operation) return Object.freeze({ outcome: 'IGNORED', code: 'B02_WIFI_UI_STALE_RESULT' });
      publish(phase);
      return Object.freeze({ outcome: 'APPLIED', state: phase });
    } catch {
      if (marker !== operation) return Object.freeze({ outcome: 'IGNORED', code: 'B02_WIFI_UI_STALE_RESULT' });
      publish('adapter-error');
      return Object.freeze({ outcome: 'DENIED', code: 'B02_WIFI_UI_ADAPTER_ERROR' });
    } finally {
      if (marker === operation) pendingAction = null;
    }
  }

  async function reload() {
    const marker = ++operation;
    pendingAction = 'read-status';
    publish('pending');
    try {
      const phase = validateResult(await readStatus(Object.freeze({ action: 'read-status' })),
        ['disabled', 'idle', 'active', 'revoked', 'denied']);
      if (marker !== operation) return Object.freeze({ outcome: 'IGNORED', code: 'B02_WIFI_UI_STALE_RESULT' });
      publish(phase);
      return Object.freeze({ outcome: 'APPLIED', state: phase });
    } catch {
      if (marker !== operation) return Object.freeze({ outcome: 'IGNORED', code: 'B02_WIFI_UI_STALE_RESULT' });
      publish('adapter-error');
      return Object.freeze({ outcome: 'DENIED', code: 'B02_WIFI_UI_ADAPTER_ERROR' });
    } finally {
      if (marker === operation) pendingAction = null;
    }
  }

  function supersedeAndReload() {
    pendingAction = null;
    return reload();
  }

  publish('idle');
  return Object.freeze({
    current,
    reload: supersedeAndReload,
    authorize() { return execute('authorize-household-wifi', requestConsent, ['active', 'denied']); },
    revoke() { return execute('revoke-household-wifi', requestRevoke, ['revoked', 'denied']); }
  });
}

export const wifiPermissionUiConstants = Object.freeze({ phases: PHASES, copy: COPY });
