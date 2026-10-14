import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import { createRingHistoryClient } from "../src/ring_official_history_client.mjs";

const checkedAt = "2026-09-29T09:30:00.000Z";
const now = () => new Date(checkedAt);
const token = randomBytes(24).toString("base64url");
const deviceId = randomBytes(12).toString("hex");
const eventId = randomBytes(12).toString("hex");
const deviceUrl = "https://api.amazonvision.com/v1/devices";
const historyUrl = `https://api.amazonvision.com/v1/history/devices/${encodeURIComponent(deviceId)}/events?event_types=motion`;

function clientWith(fetchImpl, overrides = {}) {
  return createRingHistoryClient({ tokenProvider: () => token, fetchImpl, now, ...overrides });
}

function jsonResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/vnd.api+json", ...headers },
  });
}

function deviceResponse(ids = [deviceId]) {
  return jsonResponse({ data: ids.map((id) => ({ type: "devices", id })) });
}

function motionEvent({ id = eventId, sourceId = deviceId, start = 1699457200000, end = 1699457225000, eventType = "motion" } = {}) {
  return {
    type: "history-events",
    id,
    attributes: { event_type: eventType, is_third_party_reviewed: false, start, end },
    relationships: { source: { data: { type: "devices", id: sourceId } } },
  };
}

function assertNoPrivateValue(result, values = [token, deviceId, eventId]) {
  const serialized = JSON.stringify(result);
  for (const value of values) assert.equal(serialized.includes(value), false);
}

function assertFailed(result, errorCode) {
  assert.equal(result.ok, false);
  assert.equal(result.source, "official_event_history_api");
  assert.equal(result.checked_at, checkedAt);
  assert.equal(result.error_code, errorCode);
  assert.equal(result.motion_count, 0);
  assert.equal(result.latest_motion_at, null);
  assertNoPrivateValue(result);
}

test("one explicit probe performs exactly two fixed-host GETs and returns only redacted motion facts", async () => {
  const calls = [];
  const fetchImpl = (url, options) => {
    calls.push({ url, options });
    assert.equal(options.method, "GET");
    assert.equal(options.headers.Authorization, `Bearer ${token}`);
    assert.equal(options.headers.Accept, "application/vnd.api+json, application/json");
    assert.equal(options.redirect, "error");
    assert.equal(options.credentials, "omit");
    assert.equal(options.cache, "no-store");
    assert.equal(options.body, undefined);
    assert.equal(options.signal.aborted, false);
    if (calls.length === 1) return deviceResponse();
    if (calls.length === 2) return jsonResponse({
      data: [
        motionEvent({ start: 1699457200000, end: 1699457225000 }),
        motionEvent({ id: randomBytes(12).toString("hex"), start: 1699457300000, end: 1699457310000 }),
      ],
      links: { next: "/v1/history/devices/should-never-be-fetched/events?page[key]=cursor" },
    });
    throw new Error("unexpected third request");
  };
  const result = await clientWith(fetchImpl).probeMotionHistory({ deviceOrdinal: 1 });
  assert.deepEqual(calls.map(({ url }) => url), [deviceUrl, historyUrl]);
  assert.equal(result.ok, true);
  assert.equal(result.configured, true);
  assert.equal(result.source, "official_event_history_api");
  assert.equal(result.checked_at, checkedAt);
  assert.equal(result.discovery_http_status, 200);
  assert.equal(result.history_http_status, 200);
  assert.equal(result.device_count, 1);
  assert.equal(result.device_ordinal, 1);
  assert.equal(result.motion_count, 2);
  assert.equal(result.latest_motion_at, new Date(1699457300000).toISOString());
  assert.equal(result.error_code ?? null, null);
  assertNoPrivateValue(result);
});

test("empty 200 history is a successful empty result, distinct from denied access", async () => {
  let calls = 0;
  const empty = await clientWith(() => {
    calls += 1;
    return calls === 1 ? deviceResponse() : jsonResponse({ data: [] });
  }).probeMotionHistory({ deviceOrdinal: 1 });
  assert.equal(calls, 2);
  assert.equal(empty.ok, true);
  assert.equal(empty.history_http_status, 200);
  assert.equal(empty.motion_count, 0);
  assert.equal(empty.latest_motion_at, null);
  assert.equal(empty.error_code ?? null, null);

  calls = 0;
  const denied = await clientWith(() => {
    calls += 1;
    return calls === 1 ? deviceResponse() : jsonResponse({ errors: [{ detail: "private upstream detail" }] }, 403);
  }).probeMotionHistory({ deviceOrdinal: 1 });
  assert.equal(calls, 2);
  assertFailed(denied, "HISTORY_HTTP_403");
  assert.equal(denied.history_http_status, 403);
  assert.equal(JSON.stringify(denied).includes("private upstream detail"), false);
});

test("missing, invalid token and invalid ordinal make zero upstream requests", async (context) => {
  const cases = [
    ["missing token", { tokenProvider: () => undefined }, "TOKEN_UNAVAILABLE", 1],
    ["invalid token", { tokenProvider: () => "Bearer invalid token" }, "TOKEN_INVALID", 1],
    ["zero ordinal", {}, "INVALID_DEVICE_ORDINAL", 0],
    ["noninteger ordinal", {}, "INVALID_DEVICE_ORDINAL", 1.2],
    ["ordinal past maximum", {}, "INVALID_DEVICE_ORDINAL", 257],
    ["string ordinal", {}, "INVALID_DEVICE_ORDINAL", "1"],
  ];
  for (const [name, overrides, expectedCode, deviceOrdinal] of cases) {
    await context.test(name, async () => {
      let calls = 0;
      const result = await clientWith(() => {
        calls += 1;
        throw new Error("unexpected network request");
      }, overrides).probeMotionHistory({ deviceOrdinal });
      assertFailed(result, expectedCode);
      assert.equal(calls, 0);
    });
  }
});

test("missing selected device after one bounded discovery GET never starts history GET", async () => {
  let calls = 0;
  const result = await clientWith(() => {
    calls += 1;
    return deviceResponse();
  }).probeMotionHistory({ deviceOrdinal: 2 });
  assertFailed(result, "DEVICE_NOT_FOUND");
  assert.equal(result.discovery_http_status, 200);
  assert.equal(result.history_http_status, null);
  assert.equal(calls, 1);
});

test("device list schema and count fail closed before selected-device request", async (context) => {
  const cases = [
    ["missing data", { meta: {} }],
    ["wrong data container", { data: {} }],
    ["missing ID", { data: [{ type: "devices" }] }],
    ["wrong resource type", { data: [{ type: "accounts", id: deviceId }] }],
    ["dot segment device ID", { data: [{ type: "devices", id: "." }] }],
    ["parent segment device ID", { data: [{ type: "devices", id: ".." }] }],
    ["invalid Unicode device ID", { data: [{ type: "devices", id: "\ud800" }] }],
    ["success and error together", { data: [{ type: "devices", id: deviceId }], errors: [{ detail: "conflicting" }] }],
    ["too many devices", { data: Array.from({ length: 257 }, (_, index) => ({ type: "devices", id: `device-${index}` })) }],
  ];
  for (const [name, body] of cases) {
    await context.test(name, async () => {
      let calls = 0;
      const result = await clientWith(() => {
        calls += 1;
        return jsonResponse(body);
      }).probeMotionHistory({ deviceOrdinal: 1 });
      assertFailed(result, "INVALID_SCHEMA");
      assert.deepEqual(Object.keys(result).sort(), [
        "checked_at", "configured", "device_count", "device_ordinal", "discovery_http_status",
        "error_code", "history_http_status", "latest_motion_at", "motion_count", "ok", "source",
      ]);
      assert.equal(result.history_http_status, null);
      assert.equal(calls, 1);
    });
  }
});

test("history schema validates resource type, motion type, source, time and bound", async (context) => {
  const cases = [
    ["missing data", { meta: {} }],
    ["wrong data container", { data: {} }],
    ["wrong resource type", { data: [{ ...motionEvent(), type: "devices" }] }],
    ["missing event ID", { data: [{ ...motionEvent(), id: undefined }] }],
    ["wrong event type", { data: [motionEvent({ eventType: "ding" })] }],
    ["missing reviewed flag", { data: [{ ...motionEvent(), attributes: { event_type: "motion", start: 1699457200000, end: 1699457225000 } }] }],
    ["success and error together", { data: [motionEvent()], errors: [{ detail: "conflicting" }] }],
    ["wrong source device", { data: [motionEvent({ sourceId: "other-device" })] }],
    ["missing source", { data: [{ ...motionEvent(), relationships: undefined }] }],
    ["invalid start", { data: [motionEvent({ start: "1699457200000" })] }],
    ["end before start", { data: [motionEvent({ end: 1699457100000 })] }],
    ["safe-integer end outside JS Date range", { data: [motionEvent({ end: 8640000000000001 })] }],
    ["too many events", { data: Array.from({ length: 257 }, (_, index) => motionEvent({ id: `event-${index}` })) }],
  ];
  for (const [name, body] of cases) {
    await context.test(name, async () => {
      let calls = 0;
      const result = await clientWith(() => {
        calls += 1;
        return calls === 1 ? deviceResponse() : jsonResponse(body);
      }).probeMotionHistory({ deviceOrdinal: 1 });
      assertFailed(result, "INVALID_SCHEMA");
      assert.equal(calls, 2);
    });
  }
});

test("discovery and history preserve 401, 403 and 404 without retry", async (context) => {
  for (const stage of ["DISCOVERY", "HISTORY"]) {
    for (const status of [401, 403, 404]) {
      await context.test(`${stage} ${status}`, async () => {
        let calls = 0;
        const result = await clientWith(() => {
          calls += 1;
          if (stage === "HISTORY" && calls === 1) return deviceResponse();
          return jsonResponse({ errors: [{ detail: "provider private detail" }] }, status);
        }).probeMotionHistory({ deviceOrdinal: 1 });
        assertFailed(result, `${stage}_HTTP_${status}`);
        assert.equal(result[stage === "DISCOVERY" ? "discovery_http_status" : "history_http_status"], status);
        assert.equal(calls, stage === "DISCOVERY" ? 1 : 2);
        assert.equal(JSON.stringify(result).includes("provider private detail"), false);
      });
    }
  }
});

test("redirect and wrong MIME fail closed at both request stages", async (context) => {
  for (const stage of ["DISCOVERY", "HISTORY"]) {
    for (const kind of ["redirect", "wrong MIME"]) {
      await context.test(`${stage} ${kind}`, async () => {
        let calls = 0;
        const result = await clientWith(() => {
          calls += 1;
          if (stage === "HISTORY" && calls === 1) return deviceResponse();
          if (kind === "redirect") {
            const response = jsonResponse({ data: [] });
            Object.defineProperty(response, "redirected", { value: true });
            return response;
          }
          return jsonResponse({ data: [] }, 200, { "content-type": "text/plain" });
        }).probeMotionHistory({ deviceOrdinal: 1 });
        assertFailed(result, kind === "redirect" ? "INVALID_HTTP_RESPONSE" : "INVALID_CONTENT_TYPE");
        assert.equal(calls, stage === "DISCOVERY" ? 1 : 2);
      });
    }
  }
});

test("declared and streamed oversized bodies fail closed at both stages", async (context) => {
  for (const stage of ["DISCOVERY", "HISTORY"]) {
    for (const kind of ["declared", "streamed"]) {
      await context.test(`${stage} ${kind}`, async () => {
        let calls = 0;
        const result = await clientWith(() => {
          calls += 1;
          if (stage === "HISTORY" && calls === 1) return deviceResponse();
          if (kind === "declared") return jsonResponse({ data: [] }, 200, { "content-length": "1025" });
          return new Response("x".repeat(1025), { status: 200, headers: { "content-type": "application/json" } });
        }, { maxResponseBytes: 1024 }).probeMotionHistory({ deviceOrdinal: 1 });
        assertFailed(result, "RESPONSE_TOO_LARGE");
        assert.equal(calls, stage === "DISCOVERY" ? 1 : 2);
      });
    }
  }
});

test("both response bodies share one total byte budget", async () => {
  let calls = 0;
  const result = await clientWith(() => {
    calls += 1;
    if (calls === 1) {
      return jsonResponse({ data: [{ type: "devices", id: deviceId }], padding: "x".repeat(510) });
    }
    return jsonResponse({ data: [], padding: "y".repeat(510) });
  }, { maxResponseBytes: 1024 }).probeMotionHistory({ deviceOrdinal: 1 });
  assertFailed(result, "RESPONSE_TOO_LARGE");
  assert.equal(calls, 2);
});

test("malformed JSON is rejected at either stage without exposing upstream bytes", async (context) => {
  for (const stage of ["DISCOVERY", "HISTORY"]) {
    await context.test(stage, async () => {
      let calls = 0;
      const result = await clientWith(() => {
        calls += 1;
        if (stage === "HISTORY" && calls === 1) return deviceResponse();
        return new Response("{private-invalid-json", {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }).probeMotionHistory({ deviceOrdinal: 1 });
      assertFailed(result, "INVALID_JSON");
      assert.equal(JSON.stringify(result).includes("private-invalid-json"), false);
      assert.equal(calls, stage === "DISCOVERY" ? 1 : 2);
    });
  }
});

test("token provider resolving after timeout cannot start a late official request", async () => {
  let resolveToken;
  let calls = 0;
  const pendingToken = new Promise((resolve) => { resolveToken = resolve; });
  const result = await clientWith(() => {
    calls += 1;
    throw new Error("late fetch");
  }, { tokenProvider: () => pendingToken, timeoutMs: 10 }).probeMotionHistory({ deviceOrdinal: 1 });
  assertFailed(result, "TIMEOUT");
  resolveToken(token);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(calls, 0);
});

test("network failure and deadline abort do not retry or begin later stages", async (context) => {
  for (const stage of ["DISCOVERY", "HISTORY"]) {
    await context.test(`${stage} network failure`, async () => {
      let calls = 0;
      const result = await clientWith(() => {
        calls += 1;
        if (stage === "HISTORY" && calls === 1) return deviceResponse();
        throw new Error("private transport detail");
      }).probeMotionHistory({ deviceOrdinal: 1 });
      assertFailed(result, "NETWORK_ERROR");
      assert.equal(JSON.stringify(result).includes("private transport detail"), false);
      assert.equal(calls, stage === "DISCOVERY" ? 1 : 2);
    });

    await context.test(`${stage} timeout`, async () => {
      let calls = 0;
      let aborted = false;
      const result = await clientWith((_url, options) => {
        calls += 1;
        if (stage === "HISTORY" && calls === 1) return deviceResponse();
        return new Promise((_resolve, reject) => {
          options.signal.addEventListener("abort", () => {
            aborted = true;
            reject(new Error("aborted"));
          }, { once: true });
        });
      }, { timeoutMs: 10 }).probeMotionHistory({ deviceOrdinal: 1 });
      assertFailed(result, "TIMEOUT");
      assert.equal(aborted, true);
      assert.equal(calls, stage === "DISCOVERY" ? 1 : 2);
    });
  }
});
