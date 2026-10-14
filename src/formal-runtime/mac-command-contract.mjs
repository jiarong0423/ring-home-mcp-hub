import { createHash } from 'node:crypto';
import { types } from 'node:util';

export const SOFTWARE_SWITCH_CAPABILITY = 'software_test_switch.set';
export const HOME_DEVICE_CAPABILITY = 'home_device.command';
// Cloud-controllable simulated devices and parameter-free actions. Deliberately excluded: front_door unlock (local
// one-use confirmation), camera disarm (live gateway receipt), and every action that needs a value parameter.
export const HOME_DEVICE_ACTIONS = Object.freeze({
  living_light: Object.freeze(['on', 'off']), air_conditioner: Object.freeze(['on', 'off']), dehumidifier: Object.freeze(['on', 'off']),
  robot_vacuum: Object.freeze(['start', 'pause', 'dock']), camera: Object.freeze(['arm']), front_door: Object.freeze(['lock'])
});
export function homeDeviceAllowed(deviceId, action) {
  return typeof deviceId === 'string' && typeof action === 'string' && Object.hasOwn(HOME_DEVICE_ACTIONS, deviceId) &&
    HOME_DEVICE_ACTIONS[deviceId].includes(action);
}
export const COMMAND_TABLE = 'ring-home-mcp-private-event';
export const COMMAND_TTL_MS = 30_000;
export const TOMBSTONE_MS = 86_400_000;
export const COMMAND_ID = /^cmd_[a-f0-9]{64}$/u;
export const OPAQUE = /^[A-Za-z0-9._:@/-]{1,256}$/u;
export const HASH = /^[a-f0-9]{64}$/u;
export function deny(code) { const error = new Error(code); error.name = 'MacCommandError'; error.code = code; throw error; }
export function record(value, keys, code = 'MAC_COMMAND_INPUT') {
  if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny(code);
  const fields = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(fields).length !== keys.length || keys.some(key => !Object.hasOwn(fields, key)) ||
      Reflect.ownKeys(fields).some(key => typeof key !== 'string' || !keys.includes(key) ||
        !Object.hasOwn(fields[key], 'value'))) deny(code);
  return Object.fromEntries(keys.map(key => [key, fields[key].value]));
}
export function port(value, names) {
  if (!value || types.isProxy(value)) deny('MAC_COMMAND_PORT');
  return Object.fromEntries(names.map(name => {
    const field = Object.getOwnPropertyDescriptor(value, name);
    if (!field || !Object.hasOwn(field, 'value') || typeof field.value !== 'function' || types.isProxy(field.value)) deny('MAC_COMMAND_PORT');
    return [name, field.value.bind(value)];
  }));
}
export function time(value) { if (!Number.isSafeInteger(value) || value < 0) deny('MAC_COMMAND_CLOCK'); return value; }
export function text(value) { if (typeof value !== 'string' || !OPAQUE.test(value)) deny('MAC_COMMAND_IDENTITY'); return value; }
export function hash(value) { return createHash('sha256').update(value).digest('hex'); }
export function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
  return value;
}
export function envelope(value) {
  const e = record(value, ['jsonrpc', 'id', 'method', 'params']);
  if (e.jsonrpc !== '2.0' || e.method !== 'tools/call' || !(typeof e.id === 'string' && /^[A-Za-z0-9._:-]{1,128}$/u.test(e.id) || Number.isSafeInteger(e.id))) deny('MAC_COMMAND_ENVELOPE');
  const p = record(e.params, ['name', 'arguments']);
  if (p.name === SOFTWARE_SWITCH_CAPABILITY) {
    const a = record(p.arguments, ['enabled']);
    if (typeof a.enabled !== 'boolean') deny('MAC_COMMAND_CAPABILITY');
    return freeze({ jsonrpc: '2.0', id: e.id, method: 'tools/call', params: { name: p.name, arguments: { enabled: a.enabled } } });
  }
  if (p.name === HOME_DEVICE_CAPABILITY) {
    const a = record(p.arguments, ['deviceId', 'action']);
    if (!homeDeviceAllowed(a.deviceId, a.action)) deny('MAC_COMMAND_CAPABILITY');
    return freeze({ jsonrpc: '2.0', id: e.id, method: 'tools/call', params: { name: p.name, arguments: { deviceId: a.deviceId, action: a.action } } });
  }
  deny('MAC_COMMAND_CAPABILITY');
}
export function command(value) {
  const c = record(value, ['schema', 'commandId', 'ownerRef', 'associationRevision', 'sessionRef', 'sessionExpiresAt', 'issuedAt', 'expiresAt', 'envelope', 'envelopeSha256']);
  if (c.schema !== 'ring-mac-command-v1' || (typeof c.commandId !== 'string' || !COMMAND_ID.test(c.commandId)) || !Number.isSafeInteger(c.associationRevision) || c.associationRevision < 1) deny('MAC_COMMAND_SCHEMA');
  text(c.ownerRef); text(c.sessionRef); time(c.issuedAt); time(c.expiresAt); time(c.sessionExpiresAt);
  const e = envelope(c.envelope);
  if (c.expiresAt <= c.issuedAt || c.expiresAt > c.issuedAt + COMMAND_TTL_MS || c.expiresAt > c.sessionExpiresAt || c.sessionExpiresAt > c.issuedAt + 300_000 ||
      c.envelopeSha256 !== hash(JSON.stringify(e)) || c.commandId !== commandId(c.ownerRef, c.sessionRef, e.id)) deny('MAC_COMMAND_SCHEMA');
  return freeze({ ...c, envelope: e });
}
export function commandId(ownerRef, sessionRef, id) { return 'cmd_' + hash(JSON.stringify([text(ownerRef), text(sessionRef), typeof id, id])); }
export function switchResult(value) {
  const r = record(value, ['kind', 'enabled', 'revision', 'observedAt']);
  if (r.kind !== 'software-test-switch' || typeof r.enabled !== 'boolean' || !Number.isSafeInteger(r.revision) || r.revision < 1) deny('MAC_COMMAND_RESULT');
  time(r.observedAt); return freeze(r);
}
export function deviceResult(value) {
  const r = record(value, ['kind', 'deviceId', 'action', 'status', 'revision', 'observedAt']);
  if (r.kind !== 'home-device' || !homeDeviceAllowed(r.deviceId, r.action) || r.status !== 'simulated_applied' ||
      !Number.isSafeInteger(r.revision) || r.revision < 1) deny('MAC_COMMAND_RESULT');
  time(r.observedAt); return freeze(r);
}
// Result of either capability, chosen by its own kind; resultMatches() binds it to the command's envelope.
export function commandResult(value) {
  const kind = value && typeof value === 'object' && !types.isProxy(value) ? Object.getOwnPropertyDescriptor(value, 'kind')?.value : undefined;
  return kind === 'home-device' ? deviceResult(value) : switchResult(value);
}
export function resultMatches(result, e) {
  const a = e.params.arguments;
  if (e.params.name === SOFTWARE_SWITCH_CAPABILITY) return result.kind === 'software-test-switch' && result.enabled === a.enabled;
  if (e.params.name === HOME_DEVICE_CAPABILITY) return result.kind === 'home-device' && result.deviceId === a.deviceId && result.action === a.action;
  return false;
}
export function receipt(value) {
  const r = record(value, ['schema', 'commandId', 'envelopeSha256', 'claimToken', 'status', 'result']);
  if (r.schema !== 'ring-mac-receipt-v1' || typeof r.commandId !== 'string' || !COMMAND_ID.test(r.commandId) || typeof r.envelopeSha256 !== 'string' || !HASH.test(r.envelopeSha256) ||
      typeof r.claimToken !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(r.claimToken) || Buffer.from(r.claimToken, 'base64url').length !== 32 ||
      Buffer.from(r.claimToken, 'base64url').toString('base64url') !== r.claimToken || r.status !== 'SUCCEEDED') deny('MAC_COMMAND_RECEIPT');
  return freeze({ ...r, result: commandResult(r.result) });
}
