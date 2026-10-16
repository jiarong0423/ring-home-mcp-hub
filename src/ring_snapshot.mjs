// Ring door snapshot for the admin's approval screen (Ring API "Image Snapshots"):
//   POST /v1/devices/{id}/media/image/download {type:"latest_in_range"} -> 303 Location: short-lived pre-signed URL -> GET image.
// 416 = no image in range, 425 = not ready yet (retried), 5xx retried with backoff. The Ring token goes to the Ring API only,
// never to the pre-signed URL. The image is returned in memory; nothing here writes it anywhere.
export const SNAPSHOT_MAX_BYTES = 3 * 1024 * 1024;
const DEVICE_ID = /^[A-Za-z0-9._:-]{1,128}$/u;

export function createRingSnapshot({ origin = 'https://api.amazonvision.com', getToken, fetchImpl = fetch,
  sleep = (ms) => new Promise((done) => setTimeout(done, ms)), now = Date.now, attempts = 3 }) {
  // at: epoch ms of a doorbell press -> the frame at that moment (type at_timestamp); otherwise the latest image of the last 10 min.
  return async function ringDoorSnapshot({ at } = {}) {
    const token = getToken();
    if (!token) return { reason: 'token_missing' };
    const headers = { Authorization: 'Bearer ' + token, Accept: 'application/vnd.api+json, application/json' };
    try {
      const list = await fetchImpl(origin + '/v1/devices', { headers, redirect: 'error', signal: AbortSignal.timeout(5000) });
      if (list.status === 401) return { reason: 'token_expired' };
      if (!list.ok) return { reason: 'ring_error', detail: `devices HTTP ${list.status}` };
      const first = (await list.json())?.data?.[0];
      if (typeof first?.id !== 'string' || !DEVICE_ID.test(first.id)) return { reason: 'ring_error', detail: 'devices: no usable device id' };
      const body = JSON.stringify(Number.isSafeInteger(at) && at > 0 && at <= now()
        ? { type: 'at_timestamp', timestamp: at, image_options: { format: 'jpeg' } }
        : { type: 'latest_in_range', start_timestamp: now() - 10 * 60_000, image_options: { format: 'jpeg' } });
      for (let attempt = 0; attempt < attempts; attempt += 1) {
        const r = await fetchImpl(origin + '/v1/devices/' + encodeURIComponent(first.id) + '/media/image/download', { method: 'POST',
          headers: { ...headers, 'Content-Type': 'application/json' }, body, redirect: 'manual', signal: AbortSignal.timeout(8000) });
        if (r.status === 401) return { reason: 'token_expired' };
        if (r.status === 416) return { reason: 'no_recent_image' };
        if (r.status === 425 || r.status >= 500) { await sleep(1500 * (attempt + 1)); continue; }
        if (r.status !== 303) return { reason: 'ring_error', detail: `image/download HTTP ${r.status}` };
        let target;
        try { target = new URL(r.headers.get('location') ?? ''); } catch { return { reason: 'ring_error', detail: 'image/download: no Location' }; }
        if (target.protocol !== 'https:') return { reason: 'ring_error', detail: 'image/download: Location not https' };
        const img = await fetchImpl(target.href, { redirect: 'error', signal: AbortSignal.timeout(8000) });   // no Ring token here
        // Seen with a real Playground token: the image GET itself answers 416 until the camera has produced an image
        // (it had one right after a live view). Same meaning as 416 on the request: no image in range yet.
        if (img.status === 416) return { reason: 'no_recent_image', detail: 'image GET HTTP 416' };
        if (img.status === 425) { await sleep(1500 * (attempt + 1)); continue; }
        const type = (img.headers.get('content-type') ?? '').split(';')[0].trim().toLowerCase();
        if (!img.ok || !['image/jpeg', 'image/png'].includes(type)) return { reason: 'ring_error', detail: `image GET HTTP ${img.status} ${type || 'no type'}` };
        const declared = Number(img.headers.get('content-length') ?? 0);
        if (declared > SNAPSHOT_MAX_BYTES) return { reason: 'ring_error' };
        const bytes = Buffer.from(await img.arrayBuffer());
        if (bytes.length === 0 || bytes.length > SNAPSHOT_MAX_BYTES) return { reason: 'ring_error' };
        return { bytes, type, source: 'ring' };
      }
      return { reason: 'ring_not_ready' };
    } catch (error) { return { reason: 'ring_error', detail: `network ${error?.name ?? 'error'}` }; }
  };
}

// Without a usable Ring image the approval screen shows a clearly labelled stand-in (and why); approval still works.
const REASONS = new Set(['token_missing', 'token_expired', 'no_recent_image', 'ring_not_ready', 'ring_error']);
export function simulatedDoorSnapshot(reason) {
  const why = REASONS.has(reason) ? reason : 'ring_error';
  const svg = '<svg xmlns="http://www.w3.org/2000/svg" width="480" height="270" viewBox="0 0 480 270"><rect width="480" height="270" fill="#26313a"/>'
    + '<rect x="190" y="60" width="100" height="170" rx="6" fill="#55636e"/><circle cx="272" cy="150" r="6" fill="#c9d3da"/>'
    + '<text x="240" y="36" fill="#f2c94c" font-family="sans-serif" font-size="22" font-weight="700" text-anchor="middle">SIMULATED</text>'
    + `<text x="240" y="256" fill="#c9d3da" font-family="sans-serif" font-size="14" text-anchor="middle">no Ring image: ${why}</text></svg>`;
  return { bytes: Buffer.from(svg), type: 'image/svg+xml', source: 'simulated', reason: why };
}
