import { types } from 'node:util';
import { validateDurableBindingV2 } from '../wifi/durable-binding-v2.mjs';
import { exactObject, denyFormalRuntime } from './protocol.mjs';

const SCHEMA = 'ring-telegram-durable-identity-label-v1';
const DECIMAL = /^[1-9][0-9]{0,19}$/;
const PREFIXES = Object.freeze({ owner: 'uid:', bot: 'bot:' });

function exact(value, fields, code) {
  if (types.isProxy(value)) denyFormalRuntime(code);
  return exactObject(value, fields, code);
}
function kind(value) {
  if (typeof value !== 'string' || !Object.hasOwn(PREFIXES, value)) {
    denyFormalRuntime('B02_TELEGRAM_LABEL_KIND_DENIED');
  }
  return value;
}
function decimal(value) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) denyFormalRuntime('B02_TELEGRAM_LABEL_ID_DENIED');
  return value;
}
function revision(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value >= Number.MAX_SAFE_INTEGER) {
    denyFormalRuntime('B02_TELEGRAM_PROJECTION_REVISION_DENIED');
  }
  return value;
}
function validatedBinding(value) {
  if (types.isProxy(value)) denyFormalRuntime('B02_TELEGRAM_PROJECTION_BINDING_DENIED');
  return validateDurableBindingV2(value, { allowRevoked: false });
}

// Versioned codec only. Encoding a label is not identity or migration evidence.
export function encodeTelegramIdentityLabel(input) {
  const fields = exact(input, ['kind', 'rawId'], 'B02_TELEGRAM_LABEL_INPUT_DENIED');
  return PREFIXES[kind(fields.kind)] + decimal(fields.rawId);
}

export function decodeTelegramIdentityLabel(input) {
  const fields = exact(input, ['kind', 'label'], 'B02_TELEGRAM_LABEL_INPUT_DENIED');
  const prefix = PREFIXES[kind(fields.kind)];
  if (typeof fields.label !== 'string' || !fields.label.startsWith(prefix)) {
    denyFormalRuntime('B02_TELEGRAM_LABEL_ID_DENIED');
  }
  const rawId = decimal(fields.label.slice(prefix.length));
  if (prefix + rawId !== fields.label) denyFormalRuntime('B02_TELEGRAM_LABEL_ID_DENIED');
  return rawId;
}

export const telegramIdentityCodec = Object.freeze({ schema: SCHEMA, version: 1,
  ownerPrefix: PREFIXES.owner, botPrefix: PREFIXES.bot,
  encode: encodeTelegramIdentityLabel, decode: decodeTelegramIdentityLabel,
  authenticationProof: false, actualMigration: false });

export function createTelegramIdentityProjector(options) {
  const fields = exact(options, ['currentBindingPort'], 'B02_TELEGRAM_PROJECTOR_CONFIG_DENIED');
  const reader = fields.currentBindingPort;
  if (!reader || typeof reader !== 'object' || types.isProxy(reader)) denyFormalRuntime('B02_TELEGRAM_PROJECTOR_CONFIG_DENIED');
  const readMethod = Object.getOwnPropertyDescriptor(reader, 'readCurrent');
  if (!readMethod || !Object.hasOwn(readMethod, 'value') || typeof readMethod.value !== 'function' || types.isProxy(readMethod.value)) {
    denyFormalRuntime('B02_TELEGRAM_PROJECTOR_CONFIG_DENIED');
  }
  const readCurrent = readMethod.value;
  let closed = false;
  let inFlight = 0;
  function alive() {
    if (closed) denyFormalRuntime('B02_TELEGRAM_PROJECTOR_CLOSED');
  }
  async function current() {
    alive();
    const snapshot = exact(await readCurrent.call(reader), ['binding', 'credentialRevision'],
      'B02_TELEGRAM_PROJECTION_CURRENT_DENIED');
    alive();
    return Object.freeze({ binding: validatedBinding(snapshot.binding),
      credentialRevision: revision(snapshot.credentialRevision) });
  }
  return Object.freeze({
    async projectTelegramIdentity(input) {
      alive();
      const submitted = exact(input, ['kind', 'rawId', 'botRawId', 'binding'], 'B02_TELEGRAM_PROJECTION_INPUT_DENIED');
      const acceptedKind = kind(submitted.kind);
      const rawId = decimal(submitted.rawId);
      const botRawId = decimal(submitted.botRawId);
      const binding = validatedBinding(submitted.binding);
      const identity = encodeTelegramIdentityLabel({ kind: acceptedKind, rawId });
      const botIdentity = encodeTelegramIdentityLabel({ kind: 'bot', rawId: botRawId });
      if (binding.botId !== botIdentity || (acceptedKind === 'bot' ? rawId !== botRawId || binding.botId !== identity :
        binding.ownerId !== identity)) denyFormalRuntime('B02_TELEGRAM_PROJECTION_IDENTITY_DENIED');
      inFlight += 1;
      try {
        const before = await current();
        if (JSON.stringify(before.binding) !== JSON.stringify(binding)) {
          denyFormalRuntime('B02_TELEGRAM_PROJECTION_BINDING_DRIFT');
        }
        const after = await current();
        if (JSON.stringify(after) !== JSON.stringify(before)) denyFormalRuntime('B02_TELEGRAM_PROJECTION_BINDING_DRIFT');
        alive();
        return Object.freeze({ kind: acceptedKind, rawId, identity, bindingGeneration: binding.generation });
      } catch (error) {
        if (error && typeof error === 'object' && !types.isProxy(error)) {
          const code = Object.getOwnPropertyDescriptor(error, 'code');
          if (code && Object.hasOwn(code, 'value') && typeof code.value === 'string' &&
              ['B02_TELEGRAM_PROJECTOR_CLOSED', 'B02_TELEGRAM_PROJECTION_BINDING_DRIFT'].includes(code.value)) {
            denyFormalRuntime(code.value);
          }
        }
        denyFormalRuntime('B02_TELEGRAM_PROJECTION_CURRENT_DENIED');
      } finally {
        inFlight -= 1;
      }
    },
    close() { closed = true; return Object.freeze({ closed: true, inFlight, resourceReleased: inFlight === 0 }); },
    status() { return Object.freeze({ closed, inFlight, resourceReleased: closed && inFlight === 0 }); }
  });
}
