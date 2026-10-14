import { types } from 'node:util';

const LAYER_MODULE = 'file:///opt/ring-b02/session-port.mjs';

function fail() {
  throw new TypeError('b02_session_seam_unavailable');
}

function ownMethod(value, name) {
  try {
    if (value === null || typeof value !== 'object' || types.isProxy(value)) fail();
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function' ||
        types.isProxy(descriptor.value)) fail();
    return descriptor.value.bind(value);
  } catch {
    fail();
  }
}

export function validateB02SessionSeam(value) {
  const resolveLinkSession = ownMethod(value, 'resolveLinkSession');
  let identityAuthority;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, 'identityAuthority');
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) fail();
    identityAuthority = descriptor.value;
  } catch {
    fail();
  }
  const resolveMatchedRingAccount = ownMethod(identityAuthority, 'resolveMatchedRingAccount');
  const recheck = ownMethod(identityAuthority, 'recheck');
  return Object.freeze({
    resolveLinkSession,
    identityAuthority: Object.freeze({ resolveMatchedRingAccount, recheck })
  });
}

export async function loadB02SessionSeam({ importer = value => import(value) } = {}) {
  if (typeof importer !== 'function' || types.isProxy(importer)) fail();
  let module;
  try {
    module = await importer(LAYER_MODULE);
  } catch {
    fail();
  }
  let createRingB02SessionSeam;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(module, 'createRingB02SessionSeam');
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function' ||
        types.isProxy(descriptor.value)) fail();
    createRingB02SessionSeam = descriptor.value;
  } catch {
    fail();
  }
  let seam;
  try {
    seam = await createRingB02SessionSeam();
  } catch {
    fail();
  }
  return validateB02SessionSeam(seam);
}

export const B02_SESSION_LAYER_MODULE = LAYER_MODULE;
