const RING_DEVICES_URL = "https://api.amazonvision.com/v1/devices";
const SOURCE = "official_playground_api";
const MAX_DEVICES = 256;

function outcome({ ok, configured, httpStatus = null, checkedAt, deviceCount = 0, errorCode = null }) {
  const result = {
    ok,
    configured,
    source: SOURCE,
    checked_at: checkedAt,
    http_status: httpStatus,
    device_count: deviceCount,
    display_aliases: ok
      ? Array.from({ length: deviceCount }, (_, index) => `Ring device ${index + 1}`)
      : [],
  };
  if (errorCode !== null) result.error_code = errorCode;
  return result;
}

function validToken(token) {
  return typeof token === "string"
    && token.length > 0
    && token.length <= 4096
    && /^[A-Za-z0-9._~+/-]+={0,2}$/.test(token);
}

async function readBoundedJson(response, maxResponseBytes) {
  const contentType = response.headers?.get?.("content-type") ?? "";
  if (!/\bjson\b/i.test(contentType) && !/\+json\b/i.test(contentType)) {
    return { errorCode: "INVALID_CONTENT_TYPE" };
  }

  const contentLength = response.headers?.get?.("content-length");
  if (contentLength !== null && contentLength !== undefined) {
    const length = Number(contentLength);
    if (!Number.isSafeInteger(length) || length < 0 || length > maxResponseBytes) {
      return { errorCode: "RESPONSE_TOO_LARGE" };
    }
  }

  if (typeof response.body?.getReader !== "function") {
    return { errorCode: "UNREADABLE_RESPONSE" };
  }

  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) return { errorCode: "UNREADABLE_RESPONSE" };
      bytes += value.byteLength;
      if (bytes > maxResponseBytes) return { errorCode: "RESPONSE_TOO_LARGE" };
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }

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

export function createRingOfficialClient({
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

  async function discoverDevices() {
    const checkedAt = () => new Date(now()).toISOString();
    const controller = new AbortController();
    let timer;
    let configured = false;
    let httpStatus = null;

    const operation = async () => {
      let token;
      try {
        token = await tokenProvider();
      } catch {
        return outcome({ ok: false, configured, checkedAt: checkedAt(), errorCode: "TOKEN_UNAVAILABLE" });
      }
      if (controller.signal.aborted) {
        return outcome({ ok: false, configured, checkedAt: checkedAt(), errorCode: "TIMEOUT" });
      }
      configured = typeof token === "string" && token.length > 0;
      if (!configured) {
        return outcome({ ok: false, configured: false, checkedAt: checkedAt(), errorCode: "TOKEN_UNAVAILABLE" });
      }
      if (!validToken(token)) {
        return outcome({ ok: false, configured: true, checkedAt: checkedAt(), errorCode: "TOKEN_INVALID" });
      }

      let response;
      try {
        response = await fetchImpl(RING_DEVICES_URL, {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
            Accept: "application/vnd.api+json, application/json",
          },
          signal: controller.signal,
          redirect: "error",
          credentials: "omit",
          cache: "no-store",
        });
      } catch {
        return outcome({ ok: false, configured, checkedAt: checkedAt(), errorCode: "NETWORK_ERROR" });
      } finally {
        token = undefined;
      }
      if (controller.signal.aborted) {
        return outcome({ ok: false, configured, httpStatus, checkedAt: checkedAt(), errorCode: "TIMEOUT" });
      }

      if (!Number.isInteger(response?.status) || response.status < 100 || response.status > 599 || response.redirected === true) {
        return outcome({ ok: false, configured, checkedAt: checkedAt(), errorCode: "INVALID_HTTP_RESPONSE" });
      }
      httpStatus = response.status;
      if (httpStatus !== 200) {
        return outcome({ ok: false, configured, httpStatus, checkedAt: checkedAt(), errorCode: "HTTP_ERROR" });
      }

      let parsed;
      try {
        parsed = await readBoundedJson(response, maxResponseBytes);
      } catch {
        return outcome({ ok: false, configured, httpStatus, checkedAt: checkedAt(), errorCode: "UNREADABLE_RESPONSE" });
      }
      if (parsed.errorCode) {
        return outcome({ ok: false, configured, httpStatus, checkedAt: checkedAt(), errorCode: parsed.errorCode });
      }
      const body = parsed.json;
      if (!body || typeof body !== "object" || Array.isArray(body) || !Array.isArray(body.data)
        || body.data.length > MAX_DEVICES
        || body.data.some((device) => !device || typeof device !== "object" || Array.isArray(device)
          || typeof device.id !== "string" || device.id.length === 0
          || device.type !== "devices")) {
        return outcome({ ok: false, configured, httpStatus, checkedAt: checkedAt(), errorCode: "INVALID_SCHEMA" });
      }
      return outcome({ ok: true, configured, httpStatus, checkedAt: checkedAt(), deviceCount: body.data.length });
    };

    const timeout = new Promise((resolve) => {
      timer = setTimeout(() => {
        controller.abort();
        resolve(outcome({ ok: false, configured, httpStatus, checkedAt: checkedAt(), errorCode: "TIMEOUT" }));
      }, timeoutMs);
    });
    try {
      return await Promise.race([operation(), timeout]);
    } finally {
      clearTimeout(timer);
    }
  }

  return Object.freeze({ discoverDevices });
}
