// Door unlock by approval. Anyone may ASK to open the (simulated) front door: an AI agent over local MCP, a family phone, the
// admin. Asking never opens it. Only the admin phone decides (the server checks that before calling decide()). One request at a
// time, 60 s, single use; a Ring door snapshot may ride along in memory only and is dropped the moment the request ends.
//
// Pure logic: the caller supplies the clock, the id source, the executor (which performs the simulated unlock) and an event sink.
import { randomBytes } from 'node:crypto';

export class DoorRequestError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}
const deny = (status, code) => { throw new DoorRequestError(status, code); };
const ID = /^[A-Za-z0-9_-]{22}$/u;
const KINDS = new Set(['mcp', 'phone', 'console', 'ring']);   // ring = the Ring doorbell was pressed
const cleanName = (name) => String(name ?? '').replace(/[\u0000-\u001f\u007f<>]/gu, '').trim().slice(0, 40);

export function createDoorRequests({ clock = Date.now, ttlMs = 60_000, newId = () => randomBytes(16).toString('base64url'),
  onEvent = () => {}, keepFinished = 20 } = {}) {
  let current = null;            // the one pending request, or null
  const finished = new Map();    // requestId -> ended request (status only; never a snapshot)

  function view(r, { forAdmin = false } = {}) {
    const out = { requestId: r.requestId, status: r.status, requester: { kind: r.requester.kind, name: r.requester.name },
      createdAt: new Date(r.createdAt).toISOString(), expiresAt: new Date(r.expiresAt).toISOString(), simulated: true };
    if (r.status === 'pending') out.secondsLeft = Math.max(0, Math.ceil((r.expiresAt - clock()) / 1000));
    if (r.approver) out.approver = r.approver;
    if (r.decidedAt) out.decidedAt = new Date(r.decidedAt).toISOString();
    if (r.receipt) out.receipt = r.receipt;
    if (r.reason) out.reason = r.reason;
    if (forAdmin && r.status === 'pending') {
      out.snapshot = r.snapshot ? { ready: true, source: r.snapshot.source, reason: r.snapshot.reason ?? null } : { ready: false };
      out.faceHint = r.faceHint ?? { state: 'pending' };   // a hint only; never part of any decision
    }
    return out;
  }
  function end(r, status, extra = {}) {
    Object.assign(r, { status, decidedAt: clock(), ...extra });
    r.snapshot = null; r.faceHint = null;
    if (current === r) current = null;
    finished.set(r.requestId, r);
    while (finished.size > keepFinished) finished.delete(finished.keys().next().value);
    onEvent(status, view(r));
  }
  // Expire the pending request once its 60 s are over (also called on every read, so nothing outlives its time).
  function sweep() {
    if (current && clock() >= current.expiresAt) end(current, 'expired');
  }

  function request({ kind, name }) {
    if (!KINDS.has(kind)) deny(400, 'INVALID_REQUESTER');
    sweep();
    const who = cleanName(name) || kind;
    if (current) {
      // The same asker gets the same request back (an agent may simply ask again); anyone else waits for it to end.
      if (current.requester.kind === kind && current.requester.name === who) return { ...view(current), existing: true };
      deny(409, 'DOOR_REQUEST_PENDING');
    }
    const now = clock();
    current = { requestId: newId(), status: 'pending', requester: { kind, name: who }, createdAt: now, expiresAt: now + ttlMs,
      snapshot: null, faceHint: null, approver: null, receipt: null, reason: null, decidedAt: null };
    onEvent('requested', view(current));
    return view(current);
  }

  function find(requestId) {
    if (typeof requestId !== 'string' || !ID.test(requestId)) deny(400, 'INVALID_REQUEST_ID');
    sweep();
    if (current?.requestId === requestId) return current;
    return finished.get(requestId) ?? deny(404, 'DOOR_REQUEST_UNKNOWN');
  }
  function status({ requestId }) { return view(find(requestId)); }
  function pending() { sweep(); return current ? view(current, { forAdmin: true }) : null; }

  // execute() performs the simulated unlock and returns a receipt; it throws when the gateway cannot do it right now.
  function decide({ requestId, decision, approver, execute }) {
    if (decision !== 'approve' && decision !== 'deny') deny(400, 'INVALID_DECISION');
    const r = find(requestId);
    if (r.status !== 'pending') deny(409, r.status === 'expired' ? 'DOOR_REQUEST_EXPIRED' : 'DOOR_REQUEST_ALREADY_DECIDED');
    const who = cleanName(approver) || 'admin';
    if (decision === 'deny') { end(r, 'denied', { approver: who }); return view(r); }
    // Close the request before running anything, so a second approve (or a deny) racing this one finds it already decided.
    current = null;
    try {
      const receipt = execute();
      end(r, 'approved', { approver: who, receipt });
    } catch (error) {
      end(r, 'failed', { approver: who, reason: typeof error?.code === 'string' ? error.code : 'EXECUTION_FAILED' });
    }
    return view(r);
  }

  // Snapshot for the admin's approval screen: memory only, attached to the pending request, gone when it ends.
  function attachSnapshot(requestId, snapshot) {
    if (current?.requestId !== requestId || current.status !== 'pending') return false;
    current.snapshot = snapshot;
    return true;
  }
  function attachFaceHint(requestId, hint) {
    if (current?.requestId !== requestId || current.status !== 'pending') return false;
    current.faceHint = hint;
    return true;
  }
  function snapshot() {
    sweep();
    if (!current?.snapshot) deny(404, 'DOOR_SNAPSHOT_NONE');
    return current.snapshot;
  }

  return Object.freeze({ request, status, pending, decide, attachSnapshot, attachFaceHint, snapshot, sweep });
}
