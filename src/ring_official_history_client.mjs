const ORIGIN = "https://api.amazonvision.com";
const DEVICES_URL = `${ORIGIN}/v1/devices`;
const SOURCE = "official_event_history_api";
const MAX_ITEMS = 256;

function validToken(token) {
  return typeof token === "string"
    && token.length > 0
    && token.length <= 4096
    && /^[A-Za-z0-9._~+/-]+={0,2}$/.test(token);
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function result(state, checkedAt, { ok = false, errorCode = null } = {}) {
  return {
    ok,
    configured: state.configured,
    source: SOURCE,
    checked_at: checkedAt,
    discovery_http_status: state.discoveryStatus,
    history_http_status: state.historyStatus,
    device_count: state.deviceCount,
    device_ordinal: state.deviceOrdinal,
    motion_count: state.motionCount,
    latest_motion_at: state.latestMotionAt,
    error_code: errorCode,
  };
}

async function readJson(response, budget) {
  const contentType = response.headers?.get?.("content-type") ?? "";
  if (!/\bjson\b|\+json\b/i.test(contentType)) return { errorCode: "INVALID_CONTENT_TYPE" };
  const contentLength = response.headers?.get?.("content-length");
  if (contentLength !== null && contentLength !== undefined) {
    const length = Number(contentLength);
    if (!Number.isSafeInteger(length) || length < 0 || length > budget.remaining) {
      return { errorCode: "RESPONSE_TOO_LARGE" };
    }
  }
  if (typeof response.body?.getReader !== "function") return { errorCode: "UNREADABLE_RESPONSE" };

  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) return { errorCode: "UNREADABLE_RESPONSE" };
      bytes += value.byteLength;
      if (bytes > budget.remaining) return { errorCode: "RESPONSE_TOO_LARGE" };
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }

  budget.remaining -= bytes;
  const raw = new Uint8Array(bytes);
  let offset = 0;
  for (const chunk of chunks) {
    raw.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return { json: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw)) };
  } catch {
    return { errorCode: "INVALID_JSON" };
  }
}

function validDevices(body) {
  if (!plainObject(body) || Object.hasOwn(body, "errors")
    || !Array.isArray(body.data) || body.data.length > MAX_ITEMS) return false;
  const ids = new Set();
  for (const device of body.data) {
    if (!plainObject(device) || device.type !== "devices"
      || typeof device.id !== "string" || device.id.length === 0 || device.id.length > 4096
      || device.id === "." || device.id === ".."
      || ids.has(device.id)) return false;
    ids.add(device.id);
  }
  return true;
}

function validateEvents(body, selectedDeviceId) {
  if (!plainObject(body) || Object.hasOwn(body, "errors")
    || !Array.isArray(body.data) || body.data.length > MAX_ITEMS) return null;
  let latest = null;
  const eventIds = new Set();
  for (const event of body.data) {
    const attributes = event?.attributes;
    const source = event?.relationships?.source?.data;
    if (!plainObject(event) || event.type !== "history-events"
      || typeof event.id !== "string" || event.id.length === 0 || event.id.length > 4096
      || eventIds.has(event.id)
      || !plainObject(attributes) || attributes.event_type !== "motion"
      || typeof attributes.is_third_party_reviewed !== "boolean"
      || !Number.isSafeInteger(attributes.start) || !Number.isSafeInteger(attributes.end)
      || attributes.start < 0 || attributes.end < attributes.start
      || !Number.isFinite(new Date(attributes.start).getTime())
      || !Number.isFinite(new Date(attributes.end).getTime())
      || !plainObject(source) || source.type !== "devices" || source.id !== selectedDeviceId) {
      return null;
    }
    eventIds.add(event.id);
    latest = latest === null ? attributes.start : Math.max(latest, attributes.start);
  }
  return { count: body.data.length, latestAt: latest === null ? null : new Date(latest).toISOString() };
}

export function createRingHistoryClient({
  tokenProvider,
  fetchImpl = globalThis.fetch,
  timeoutMs = 5000,
  maxResponseBytes = 262144,
  now = () => new Date(),
} = {}) {
  if (typeof tokenProvider !== "function") throw new TypeError("tokenProvider is required");
  if (typeof fetchImpl !== "function") throw new TypeError("fetchImpl is required");
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10000) {
    throw new RangeError("timeoutMs must be between 1 and 10000");
  }
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1024 || maxResponseBytes > 262144) {
    throw new RangeError("maxResponseBytes must be between 1024 and 262144");
  }
  if (typeof now !== "function") throw new TypeError("now must be a function");

  async function probeMotionHistory({ deviceOrdinal = 1 } = {}) {
    const checkedAt = new Date(now()).toISOString();
    const state = {
      configured: false,
      discoveryStatus: null,
      historyStatus: null,
      deviceCount: 0,
      deviceOrdinal,
      motionCount: 0,
      latestMotionAt: null,
    };
    if (!Number.isSafeInteger(deviceOrdinal) || deviceOrdinal < 1 || deviceOrdinal > MAX_ITEMS) {
      return result(state, checkedAt, { errorCode: "INVALID_DEVICE_ORDINAL" });
    }

    const controller = new AbortController();
    const budget = { remaining: maxResponseBytes };
    let timer;
    const operation = async () => {
      let token;
      try {
        token = await tokenProvider();
      } catch {
        return result(state, checkedAt, { errorCode: "TOKEN_UNAVAILABLE" });
      }
      if (controller.signal.aborted) return result(state, checkedAt, { errorCode: "TIMEOUT" });
      state.configured = typeof token === "string" && token.length > 0;
      if (!state.configured) return result(state, checkedAt, { errorCode: "TOKEN_UNAVAILABLE" });
      if (!validToken(token)) return result(state, checkedAt, { errorCode: "TOKEN_INVALID" });

      const headers = {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.api+json, application/json",
      };
      const request = async (url, stage) => {
        let response;
        try {
          response = await fetchImpl(url, {
            method: "GET",
            headers,
            signal: controller.signal,
            redirect: "error",
            credentials: "omit",
            cache: "no-store",
          });
        } catch {
          return { errorCode: controller.signal.aborted ? "TIMEOUT" : "NETWORK_ERROR" };
        }
        if (controller.signal.aborted) return { errorCode: "TIMEOUT" };
        if (!Number.isInteger(response?.status) || response.status < 100 || response.status > 599
          || response.redirected === true) return { errorCode: "INVALID_HTTP_RESPONSE" };
        if (stage === "discovery") state.discoveryStatus = response.status;
        else state.historyStatus = response.status;
        if (response.status !== 200) {
          const suffix = [401, 403, 404].includes(response.status) ? response.status : "ERROR";
          return { errorCode: `${stage.toUpperCase()}_HTTP_${suffix}` };
        }
        try {
          const parsed = await readJson(response, budget);
          if (controller.signal.aborted) return { errorCode: "TIMEOUT" };
          return parsed;
        } catch {
          return { errorCode: controller.signal.aborted ? "TIMEOUT" : "UNREADABLE_RESPONSE" };
        }
      };

      const discovery = await request(DEVICES_URL, "discovery");
      if (discovery.errorCode) return result(state, checkedAt, { errorCode: discovery.errorCode });
      if (!validDevices(discovery.json)) return result(state, checkedAt, { errorCode: "INVALID_SCHEMA" });
      state.deviceCount = discovery.json.data.length;
      if (deviceOrdinal > state.deviceCount) {
        return result(state, checkedAt, { errorCode: "DEVICE_NOT_FOUND" });
      }

      const selectedDeviceId = discovery.json.data[deviceOrdinal - 1].id;
      let encodedDeviceId;
      try {
        encodedDeviceId = encodeURIComponent(selectedDeviceId);
      } catch {
        return result(state, checkedAt, { errorCode: "INVALID_SCHEMA" });
      }
      const historyUrl = `${ORIGIN}/v1/history/devices/${encodedDeviceId}/events?event_types=motion`;
      if (new URL(historyUrl).pathname !== `/v1/history/devices/${encodedDeviceId}/events`) {
        return result(state, checkedAt, { errorCode: "INVALID_SCHEMA" });
      }
      const history = await request(historyUrl, "history");
      if (history.errorCode) return result(state, checkedAt, { errorCode: history.errorCode });
      const events = validateEvents(history.json, selectedDeviceId);
      if (events === null) return result(state, checkedAt, { errorCode: "INVALID_SCHEMA" });
      state.motionCount = events.count;
      state.latestMotionAt = events.latestAt;
      return result(state, checkedAt, { ok: true });
    };

    const timeout = new Promise((resolve) => {
      timer = setTimeout(() => {
        controller.abort();
        resolve(result(state, checkedAt, { errorCode: "TIMEOUT" }));
      }, timeoutMs);
    });
    try {
      return await Promise.race([operation(), timeout]);
    } finally {
      clearTimeout(timer);
    }
  }

  return Object.freeze({ probeMotionHistory });
}
