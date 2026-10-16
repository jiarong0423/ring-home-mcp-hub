// Ring live view for the admin's approval screen (Ring API "Live Video Streaming", WebRTC WHEP), same flow as Ring's official
// hello-world sample: the phone's browser makes the SDP offer, the hub forwards it with the Ring token, the browser gets the
// SDP answer and plays the stream. The token and Ring's session URL stay on the hub; the phone only gets an opaque session id.
// One session at a time, closed after maxMs (Ring ends battery streams at ~30 s, line-powered at ~60 s) or when the request ends.
import { randomBytes } from 'node:crypto';

const DEVICE_ID = /^[A-Za-z0-9._:-]{1,128}$/u;
export const SDP_MAX_BYTES = 32 * 1024;
const looksLikeSdp = (s) => typeof s === 'string' && s.startsWith('v=0') && Buffer.byteLength(s) <= SDP_MAX_BYTES && !/[\u0000\u0007]/u.test(s);

export class RingLiveError extends Error {
  constructor(status, code, detail = null) { super(code); this.status = status; this.code = code; this.detail = detail; }
}

export function createRingLive({ origin = 'https://api.amazonvision.com', getToken, fetchImpl = fetch, clock = Date.now, maxMs = 60_000,
  setTimer = setTimeout, clearTimer = clearTimeout, log = () => {} }) {
  let session = null;   // { id, url, timer, startedAt }

  async function closeRing(s, why) {
    clearTimer(s.timer);
    const token = getToken();
    if (!token) return;
    try {
      const r = await fetchImpl(s.url, { method: 'DELETE', headers: { Authorization: 'Bearer ' + token }, redirect: 'error', signal: AbortSignal.timeout(5000) });
      log(`ring live view closed (${why}) HTTP ${r.status}`);
    } catch (error) { log(`ERROR ring live view close (${why}): network ${error?.name ?? 'error'}`); }
  }

  async function start({ sdp }) {
    if (!looksLikeSdp(sdp)) throw new RingLiveError(400, 'SDP_INVALID');
    const token = getToken();
    if (!token) throw new RingLiveError(409, 'RING_NOT_CONNECTED');
    if (session) { const old = session; session = null; await closeRing(old, 'replaced'); }
    const headers = { Authorization: 'Bearer ' + token, Accept: 'application/vnd.api+json, application/json' };
    let list;
    try { list = await fetchImpl(origin + '/v1/devices', { headers, redirect: 'error', signal: AbortSignal.timeout(5000) }); }
    catch (error) { throw new RingLiveError(502, 'RING_UNREACHABLE', `devices network ${error?.name ?? 'error'}`); }
    if (list.status === 401) throw new RingLiveError(409, 'RING_TOKEN_EXPIRED');
    if (!list.ok) throw new RingLiveError(502, 'RING_ERROR', `devices HTTP ${list.status}`);
    const first = (await list.json().catch(() => null))?.data?.[0];
    if (typeof first?.id !== 'string' || !DEVICE_ID.test(first.id)) throw new RingLiveError(502, 'RING_ERROR', 'devices: no usable device id');
    let r;
    try {
      r = await fetchImpl(origin + '/v1/devices/' + encodeURIComponent(first.id) + '/media/streaming/whep/sessions', { method: 'POST',
        headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/sdp' }, body: sdp, redirect: 'error', signal: AbortSignal.timeout(10_000) });
    } catch (error) { throw new RingLiveError(502, 'RING_UNREACHABLE', `whep network ${error?.name ?? 'error'}`); }
    if (r.status === 401) throw new RingLiveError(409, 'RING_TOKEN_EXPIRED');
    if (r.status !== 201 && r.status !== 200) throw new RingLiveError(502, 'RING_LIVE_REFUSED', `whep HTTP ${r.status}`);
    const answer = await r.text();
    if (!looksLikeSdp(answer)) throw new RingLiveError(502, 'RING_ERROR', 'whep: answer is not SDP');
    // Ring's session URL (for DELETE) must be on the Ring API origin; anything else is not followed.
    let url = null;
    try { const u = new URL(r.headers.get('location') ?? '', origin); if (u.origin === new URL(origin).origin) url = u.href; } catch { url = null; }
    const id = randomBytes(16).toString('base64url');
    if (url) {
      const s = { id, url, startedAt: clock() };
      s.timer = setTimer(() => { if (session?.id === id) { session = null; void closeRing(s, 'time limit'); } }, maxMs);
      s.timer?.unref?.();
      session = s;
    } else log('ring live view: no session URL from Ring; it will end on its own');
    log('ring live view started');
    return { sessionId: id, sdp: answer, maxSeconds: Math.round(maxMs / 1000) };
  }

  async function stop({ sessionId, why = 'closed on the phone' } = {}) {
    if (!session || (sessionId !== undefined && session.id !== sessionId)) return { stopped: false };
    const s = session; session = null;
    await closeRing(s, why);
    return { stopped: true };
  }

  return Object.freeze({ start, stop, active: () => Boolean(session) });
}
