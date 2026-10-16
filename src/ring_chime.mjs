// Ring Chime announcements and device capabilities (Ring API reference: Devices, Chimes; WEBHOOK_CHIME_DESIGN_zh.md).
// When the hub has something to tell the person at home (the same moments as the Mac voice notice), a Ring Chime in the home
// sounds first, so the notice is heard anywhere in the house; the Mac speaker then says the words. No Chime, a snoozed or
// offline Chime, or any Ring error simply leaves the Mac voice on its own. Off unless HOME_MCP_CHIME=on, and only while a
// Ring token is loaded. Never plays more than once a minute.
//   GET  /v1/devices                                 -> device ids
//   GET  /v1/devices/{id}/capabilities               -> a Chime reports audio.customizable_slots (a count); cameras report video
//   GET  /v1/devices/{id}/status                     -> online, audio.snooze.active
//   GET  /v1/devices/{id}/configurations             -> audio.customizable_slots[] { event, disabled, audio_ref, audio_name }
//   POST /v1/devices/{id}/media/audio/playback        { data: { type: "audio", attributes: { audio_ref } } } -> status "completed"
const DEVICE_ID = /^[A-Za-z0-9._:-]{1,128}$/u;
const AUDIO_REF = /^[A-Za-z0-9._:/-]{1,256}$/u;
const MAX_DEVICES = 10;
const REDISCOVER_MS = 10 * 60_000;

export function createRingChime({ origin = 'https://api.amazonvision.com', getToken, fetchImpl = fetch, clock = Date.now,
  enabled = process.env.HOME_MCP_CHIME === 'on', minGapMs = 60_000, log = () => {} }) {
  let devices = null;            // { at, chime: { id, slots } | null, cameras: [{ id, video, motion }] }
  let lastPlayAt = -Infinity;
  let last = { outcome: 'idle', detail: null };
  const note = (outcome, detail = null) => { last = { outcome, detail }; return { played: outcome === 'played', outcome, detail }; };

  async function api(path, token, init = {}) {
    const r = await fetchImpl(origin + path, { ...init, headers: { Authorization: 'Bearer ' + token, Accept: 'application/vnd.api+json, application/json',
      ...(init.body ? { 'Content-Type': 'application/json' } : {}) }, redirect: 'error', signal: AbortSignal.timeout(5000) });
    const body = await r.json().catch(() => null);
    return { status: r.status, ok: r.ok, body };
  }

  // Which device is a Chime, and what the cameras can do: decided from the documented capabilities, never from a name.
  async function discover(token) {
    const list = await api('/v1/devices', token);
    if (!list.ok) return { error: `devices HTTP ${list.status}` };
    const ids = (list.body?.data ?? []).map((d) => d?.id).filter((id) => typeof id === 'string' && DEVICE_ID.test(id)).slice(0, MAX_DEVICES);
    const found = { at: clock(), chime: null, cameras: [] };
    for (const id of ids) {
      const caps = await api('/v1/devices/' + encodeURIComponent(id) + '/capabilities', token);
      if (!caps.ok) continue;
      const a = caps.body?.data?.attributes ?? caps.body?.data ?? {};
      const slots = a?.audio?.customizable_slots;
      if (!found.chime && Number.isInteger(slots) && slots > 0 && !a.video) found.chime = { id, slots };
      else if (a.video) found.cameras.push({ id, video: true, motion: Boolean(a.motion_detection) });
    }
    devices = found;
    log(`ring devices: ${ids.length} found; chime ${found.chime ? 'yes' : 'none'}; cameras with live video ${found.cameras.length}`);
    return { ok: true };
  }

  async function play(reason = 'notice') {
    if (!enabled) return note('off');
    const token = getToken();
    if (!token) return note('no_token');
    const now = clock();
    if (now - lastPlayAt < minGapMs) return note('too_soon');
    try {
      if (!devices || now - devices.at > REDISCOVER_MS) { const d = await discover(token); if (d.error) return note('error', d.error); }
      const chime = devices.chime;
      if (!chime) return note('no_chime');
      const base = '/v1/devices/' + encodeURIComponent(chime.id);
      const st = await api(base + '/status', token);
      if (!st.ok) return note('error', `status HTTP ${st.status}`);
      const s = st.body?.data?.attributes ?? st.body?.data ?? {};
      if (s.online !== true) return note('chime_offline');
      if (s.audio?.snooze?.active === true) return note('chime_snoozed');   // the person asked for quiet; respect it
      const cfg = await api(base + '/configurations', token);
      if (!cfg.ok) return note('error', `configurations HTTP ${cfg.status}`);
      const c = cfg.body?.data?.attributes ?? cfg.body?.data ?? {};
      const slot = (c?.audio?.customizable_slots ?? []).find((x) => x && x.disabled !== true && typeof x.audio_ref === 'string' && AUDIO_REF.test(x.audio_ref));
      if (!slot) return note('no_audio_slot');
      lastPlayAt = now;
      const r = await api(base + '/media/audio/playback', token, { method: 'POST', body: JSON.stringify({ data: { type: 'audio', attributes: { audio_ref: slot.audio_ref } } }) });
      if (!r.ok) return note('error', `playback HTTP ${r.status}`);
      if (r.body?.data?.attributes?.status !== 'completed') return note('error', 'playback not completed');
      log(`ring chime: played "${String(slot.audio_name ?? slot.event ?? 'slot').replace(/[^\p{L}\p{N} ._-]/gu, '?').slice(0, 40)}" (${reason})`);
      return note('played');
    } catch (error) { return note('error', `network ${error?.name ?? 'error'}`); }
  }

  return Object.freeze({
    play,
    status: () => ({ enabled, ...last, chime: Boolean(devices?.chime), cameras: devices?.cameras.length ?? null }),
    forget: () => { devices = null; }   // a new token may belong to another account
  });
}
