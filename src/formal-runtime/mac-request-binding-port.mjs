import { types } from 'node:util';
import { exactAssociation, associationMethods, createAssociationWork, isAssociationWork, associationHash, failAssociation } from './mac-session-association-store.mjs';

function commandInput(value) {
  const x = exactAssociation(value, ['request', 'actor', 'validatedWire', 'effectiveEnvelope']);
  if (!Object.isFrozen(value) || !Object.isFrozen(x.request) || !Object.isFrozen(x.actor) || !Object.isFrozen(x.validatedWire)) failAssociation('MAC_REQUEST_CONTEXT_DENIED');
  const wrapper = exactAssociation(x.request, ['httpRequest']);
  if (!wrapper.httpRequest || types.isProxy(wrapper.httpRequest)) failAssociation('MAC_REQUEST_CONTEXT_DENIED');
  const e = exactAssociation(x.effectiveEnvelope, ['jsonrpc', 'id', 'method', 'params']);
  const p = exactAssociation(e.params, ['name', 'arguments']);
  function immutable(v, seen = new WeakSet(), depth = 0) {
    if (v === null || ['string', 'boolean'].includes(typeof v) || typeof v === 'number' && Number.isFinite(v)) return;
    if (!v || typeof v !== 'object' || types.isProxy(v) || !Object.isFrozen(v) || depth > 16 || seen.has(v)) failAssociation('MAC_REQUEST_COMMAND_DENIED');
    seen.add(v);
    const d = Object.getOwnPropertyDescriptors(v);
    for (const k of Reflect.ownKeys(d)) {
      if (k === 'length' && Array.isArray(v)) continue;
      if (typeof k !== 'string' || !Object.hasOwn(d[k], 'value')) failAssociation('MAC_REQUEST_COMMAND_DENIED');
      immutable(d[k].value, seen, depth + 1);
    }
    seen.delete(v);
  }
  immutable(x.effectiveEnvelope);
  if (e.jsonrpc !== '2.0' || e.method !== 'tools/call' || !['string', 'number'].includes(typeof e.id) ||
      typeof e.id === 'number' && !Number.isSafeInteger(e.id) || typeof p.name !== 'string' || !/^[A-Za-z][A-Za-z0-9:._-]{2,127}$/.test(p.name)) failAssociation('MAC_REQUEST_COMMAND_DENIED');
  return x;
}

export function createMacRequestBindingPort(input) {
  const c = exactAssociation(input, ['identityAuthority', 'sessionAssociationServices', 'currentBindingPort', 'authorityClock', 'bootEpoch', 'limits']);
  const identity = associationMethods(c.identityAuthority, ['resolveMatchedRingAccount', 'recheck']);
  const sessions = associationMethods(c.sessionAssociationServices, ['lookupRequest']);
  const current = associationMethods(c.currentBindingPort, ['readCurrent']);
  const descriptor = Object.getOwnPropertyDescriptor(c.sessionAssociationServices, 'operationController');
  const work = descriptor && Object.hasOwn(descriptor, 'value') && isAssociationWork(descriptor.value) ? descriptor.value : createAssociationWork(c);
  const proofs = new WeakMap(), live = new Set();
  async function snapshot(input, baseline) {
    const x = commandInput(input);
    const bound = await sessions.lookupRequest({ httpRequest: x.request.httpRequest, actor: x.actor }); work.now();
    const binding = exactAssociation(await current.readCurrent(), ['binding', 'credentialRevision']); work.now();
    const a = bound.association;
    if (binding.binding.revoked || !binding.binding.active || binding.binding.ownerId !== a.ownerId || binding.binding.botId !== a.botId || binding.binding.generation !== a.bindingGeneration) failAssociation('MAC_REQUEST_BINDING_DRIFT');
    if (baseline && (bound !== baseline.bound || input !== baseline.input || x.effectiveEnvelope !== baseline.input.effectiveEnvelope ||
        associationHash(binding) !== baseline.bindingHash)) failAssociation('MAC_REQUEST_SUBSTITUTION_DENIED');
    const lease = baseline ? await identity.recheck(baseline.identityProof) : await identity.resolveMatchedRingAccount(bound.identityInput);
    work.now();
    if (lease.actorRef !== a.actorRef || lease.ownerRef !== a.ownerRef || lease.householdRef !== a.householdRef || lease.epoch !== a.ownerEpoch ||
        lease.scopeRefs.length !== a.scopeRefs.length || lease.scopeRefs.some((s, i) => s !== a.scopeRefs[i]) ||
        lease.accountIdentifier !== bound.identityInput.accountId || lease.expiresAt <= work.now().wall) failAssociation('MAC_REQUEST_IDENTITY_DENIED');
    return { bound, bindingHash: associationHash(binding), lease };
  }
  return Object.freeze({ productionAdmitted: true,
    resolve(input) { return work.run(async () => {
      const result = await snapshot(input), proof = Object.freeze(Object.create(null)), lease = result.lease;
      for (const item of live) if (!item.ref.deref() || item.expiresAt <= work.now().wall) live.delete(item);
      if (live.size >= 128) failAssociation('MAC_REQUEST_PROOF_CAPACITY_DENIED');
      const value = Object.freeze({ proof, identityInput: result.bound.identityInput, contextInput: input,
        actorRef: lease.actorRef, ownerRef: lease.ownerRef, householdRef: lease.householdRef,
        scopeRefs: lease.scopeRefs, epoch: lease.epoch, expiresAt: lease.expiresAt,
        capability: input.effectiveEnvelope.params.name, ...result.bound.sessionAuthority });
      proofs.set(proof, { input, bound: result.bound, bindingHash: result.bindingHash, identityProof: lease.proof, value });
      live.add({ ref: new WeakRef(proof), expiresAt: lease.expiresAt });
      return value;
    }); },
    recheck(input) { return work.run(async () => {
      const x = exactAssociation(input, ['proof', 'contextInput']);
      const capture = proofs.get(x.proof); if (!capture) failAssociation('MAC_REQUEST_PROOF_DENIED');
      try {
        if (x.contextInput !== capture.input) failAssociation('MAC_REQUEST_SUBSTITUTION_DENIED');
        const result = await snapshot(x.contextInput, capture);
        if (result.lease.expiresAt !== capture.value.expiresAt) failAssociation('MAC_REQUEST_IDENTITY_CHANGED');
        return capture.value;
      } catch (error) { proofs.delete(x.proof); throw error; }
    }); },
    async close() { live.clear(); return await work.close(); },
    status: work.status
  });
}
