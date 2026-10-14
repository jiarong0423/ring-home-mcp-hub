import { createWifiPermissionController } from './wifi-permission-controller.mjs';

function requiredElement(root, selector) {
  const element = root.querySelector(selector);
  if (!element) throw new Error('B02_WIFI_UI_ELEMENT_MISSING');
  return element;
}

export function mountWifiPermissionUi({ root, ports }) {
  if (!root || typeof root.querySelector !== 'function') throw new Error('B02_WIFI_UI_ROOT_DENIED');
  if (ports === null || typeof ports !== 'object') throw new Error('B02_WIFI_UI_PORTS_DENIED');
  const status = requiredElement(root, '[data-wifi-permission-status]');
  const authorize = requiredElement(root, '[data-wifi-authorize]');
  const revoke = requiredElement(root, '[data-wifi-revoke]');

  function render(view) {
    status.textContent = view.message;
    status.dataset.state = view.phase;
    status.setAttribute('aria-busy', String(view.busy));
    authorize.disabled = view.authorizeDisabled;
    revoke.disabled = view.revokeDisabled;
  }

  const controller = createWifiPermissionController({
    statusPort: ports.status,
    consentPort: ports.consent,
    revokePort: ports.revoke,
    render
  });

  authorize.addEventListener('click', () => { void controller.authorize(); });
  revoke.addEventListener('click', () => { void controller.revoke(); });
  globalThis.addEventListener?.('wifi-permission-session-refresh', () => { void controller.reload(); });
  void controller.reload();
  return controller;
}

function unavailablePort() {
  return Promise.reject(new Error('B02_WIFI_UI_ADAPTER_UNAVAILABLE'));
}

const root = typeof document === 'undefined' ? null : document.querySelector('[data-wifi-permission-root]');
if (root) {
  const injected = globalThis.householdWifiPermissionPorts;
  const ports = injected && typeof injected === 'object' ? injected : Object.freeze({
    status: unavailablePort,
    consent: unavailablePort,
    revoke: unavailablePort
  });
  mountWifiPermissionUi({ root, ports });
}
