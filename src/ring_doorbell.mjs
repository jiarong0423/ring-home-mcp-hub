// Ring doorbell watcher: while a Playground token is loaded, ask Ring's Event History for doorbell presses ("ding") and a person
// detected at the door ("motion.human", which the Ring Developer Playground can simulate) every 10 s
// (real time). Ring also offers a button_press webhook, but that needs a public HTTPS endpoint; the hub lives at home, so it polls.
//   GET /v1/history/devices/{id}/events?event_types=ding,motion.human   -> newest first; data[].id, data[].attributes.{event_type,start}
// The first poll only remembers what is already there (an old press never opens anything). A new press calls onDing once.
// A ding never opens the door: the caller turns it into a door request that the admin phone must approve.
const DEVICE_ID = /^[A-Za-z0-9._:-]{1,128}$/u;
const EVENT_ID = /^[A-Za-z0-9._:-]{1,256}$/u;

export function createRingDoorbell({ origin = 'https://api.amazonvision.com', getToken, fetchImpl = fetch, onDing, onStop = () => {},
  now = Date.now, maxSeen = 200 }) {
  let deviceId = null;
  let baselineReady = false;
  let startedAt = now();
  const seen = new Set();
  let state = 'idle';                 // idle | watching | token_missing | token_expired | error
  let inFlight = false;
  let lastDetail = null;                // last Ring error (step + HTTP status), never the token

  const remember = (id) => { seen.add(id); while (seen.size > maxSeen) seen.delete(seen.values().next().value); };
  async function get(path, token) {
    return fetchImpl(origin + path, { headers: { Authorization: 'Bearer ' + token, Accept: 'application/vnd.api+json, application/json' },
      redirect: 'error', signal: AbortSignal.timeout(5000) });
  }
  function stop(reason) {
    if (state === reason) return;
    state = reason; baselineReady = false; seen.clear();
    onStop(reason);
  }

  async function poll() {
    if (inFlight) return { state };
    const token = getToken();
    if (!token) { if (state !== 'token_missing') { state = 'token_missing'; baselineReady = false; } return { state }; }
    inFlight = true;
    try {
      if (!deviceId) {
        const list = await get('/v1/devices', token);
        if (list.status === 401) { stop('token_expired'); return { state }; }
        if (!list.ok) { state = 'error'; lastDetail = `devices HTTP ${list.status}`; return { state }; }
        const first = (await list.json())?.data?.[0];
        if (typeof first?.id !== 'string' || !DEVICE_ID.test(first.id)) { state = 'error'; return { state }; }
        deviceId = first.id;
      }
      const r = await get('/v1/history/devices/' + encodeURIComponent(deviceId) + '/events?event_types=ding,motion.human', token);
      if (r.status === 401) { stop('token_expired'); return { state }; }
      if (!r.ok) { state = 'error'; lastDetail = `history HTTP ${r.status}`; return { state }; }
      const events = ((await r.json())?.data ?? [])
        .filter((e) => typeof e?.id === 'string' && EVENT_ID.test(e.id) && ['ding', 'motion', 'motion.human'].includes(e?.attributes?.event_type) && Number.isFinite(e?.attributes?.start));
      if (!baselineReady) {                       // first look: remember, never trigger
        for (const e of events) remember(e.id);
        baselineReady = true; startedAt = now(); state = 'watching';
        return { state, fired: 0 };
      }
      state = 'watching';
      const fresh = events.filter((e) => !seen.has(e.id) && e.attributes.start >= startedAt - 60_000).sort((a, b) => a.attributes.start - b.attributes.start);
      for (const e of events) remember(e.id);
      // The filter asked for human motion only, so "motion" here means a person at the door.
      for (const e of fresh) onDing({ eventId: e.id, at: e.attributes.start, deviceId, kind: e.attributes.event_type === 'ding' ? 'ding' : 'person' });
      return { state, fired: fresh.length };
    } catch (error) { state = 'error'; lastDetail = `network ${error?.name ?? 'error'}`; return { state }; }
    finally { inFlight = false; }
  }
  return Object.freeze({ poll, status: () => ({ state, deviceKnown: Boolean(deviceId), lastDetail }) });
}
