import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createRingOfficialClient } from "../src/ring_official_client.mjs";

const checkedAt = "2026-09-29T00:00:00.000Z";
const now = () => new Date(checkedAt);
const token = randomBytes(24).toString("base64url");

function clientWith(fetchImpl, overrides = {}) {
  return createRingOfficialClient({
    tokenProvider: () => token,
    fetchImpl,
    now,
    ...overrides,
  });
}

function jsonResponse(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/vnd.api+json", ...headers },
  });
}

function assertFailure(result, errorCode, httpStatus = null) {
  assert.equal(result.ok, false);
  assert.equal(result.source, "official_playground_api");
  assert.equal(result.checked_at, checkedAt);
  assert.equal(result.http_status, httpStatus);
  assert.equal(result.device_count, 0);
  assert.deepEqual(result.display_aliases, []);
  assert.equal(result.error_code, errorCode);
}

test("missing or invalid token causes zero API calls", async () => {
  let calls = 0;
  const fetchImpl = () => { calls += 1; throw new Error("unexpected fetch"); };
  const missing = await clientWith(fetchImpl, { tokenProvider: () => undefined }).discoverDevices();
  assertFailure(missing, "TOKEN_UNAVAILABLE");
  assert.equal(missing.configured, false);
  const invalid = await clientWith(fetchImpl, { tokenProvider: () => "Bearer invalid token" }).discoverDevices();
  assertFailure(invalid, "TOKEN_INVALID");
  assert.equal(invalid.configured, true);
  assert.equal(calls, 0);
});

test("200 JSON:API response uses fixed GET and emits counts and generated aliases only", async () => {
  let calls = 0;
  const upstreamId = randomBytes(12).toString("hex");
  const upstreamName = randomBytes(12).toString("hex");
  const fetchImpl = (url, options) => {
    calls += 1;
    assert.equal(url, "https://api.amazonvision.com/v1/devices");
    assert.equal(options.method, "GET");
    assert.equal(options.headers.Authorization, `Bearer ${token}`);
    assert.equal(options.headers.Accept, "application/vnd.api+json, application/json");
    assert.equal(options.redirect, "error");
    assert.equal(options.credentials, "omit");
    assert.equal(options.cache, "no-store");
    assert.equal(options.signal.aborted, false);
    return jsonResponse({ data: [{ id: upstreamId, type: "devices", attributes: { name: upstreamName } }] });
  };
  const result = await clientWith(fetchImpl).discoverDevices();
  assert.equal(calls, 1);
  assert.deepEqual(result, {
    ok: true,
    configured: true,
    source: "official_playground_api",
    checked_at: checkedAt,
    http_status: 200,
    device_count: 1,
    display_aliases: ["Ring device 1"],
  });
  const serialized = JSON.stringify(result);
  for (const privateValue of [token, upstreamId, upstreamName]) {
    assert.equal(serialized.includes(privateValue), false);
  }
});

test("schema and body parser reject malformed or missing JSON:API data", async (context) => {
  const cases = [
    ["missing data", jsonResponse({ meta: {} }), "INVALID_SCHEMA"],
    ["wrong data type", jsonResponse({ data: {} }), "INVALID_SCHEMA"],
    ["missing device id", jsonResponse({ data: [{ type: "devices" }] }), "INVALID_SCHEMA"],
    ["missing device type", jsonResponse({ data: [{ id: "device" }] }), "INVALID_SCHEMA"],
    ["invalid JSON", new Response("{", { status: 200, headers: { "content-type": "application/json" } }), "INVALID_JSON"],
    ["invalid content type", new Response("{}", { status: 200, headers: { "content-type": "text/plain" } }), "INVALID_CONTENT_TYPE"],
  ];
  for (const [name, response, errorCode] of cases) {
    await context.test(name, async () => {
      const result = await clientWith(() => response).discoverDevices();
      assertFailure(result, errorCode, 200);
    });
  }
});

test("200 JSON:API rejects a non-devices type without count or identifier disclosure", async () => {
  const upstreamId = randomBytes(12).toString("hex");
  const result = await clientWith(() => jsonResponse({
    data: [{ id: upstreamId, type: "accounts" }],
  })).discoverDevices();
  assertFailure(result, "INVALID_SCHEMA", 200);
  assert.equal(JSON.stringify(result).includes(upstreamId), false);
  assert.equal(JSON.stringify(result).includes(token), false);
});

test("206, 401 and 503 return fixed errors without upstream body disclosure", async (context) => {
  for (const status of [206, 401, 503]) {
    await context.test(String(status), async () => {
      const upstreamText = randomBytes(18).toString("hex");
      const response = new Response(upstreamText, { status, headers: { "content-type": "text/plain" } });
      const result = await clientWith(() => response).discoverDevices();
      assertFailure(result, "HTTP_ERROR", status);
      assert.equal(JSON.stringify(result).includes(upstreamText), false);
      assert.equal(JSON.stringify(result).includes(token), false);
    });
  }
});

test("content-length and streamed response limits both reject oversized bodies", async () => {
  const declared = new Response("{}", {
    status: 200,
    headers: { "content-type": "application/json", "content-length": "1025" },
  });
  assertFailure(await clientWith(() => declared, { maxResponseBytes: 1024 }).discoverDevices(), "RESPONSE_TOO_LARGE", 200);
  const streamed = new Response("x".repeat(1025), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
  assertFailure(await clientWith(() => streamed, { maxResponseBytes: 1024 }).discoverDevices(), "RESPONSE_TOO_LARGE", 200);
});

test("fetch timeout aborts and returns TIMEOUT", async () => {
  let aborted = false;
  const fetchImpl = (_url, options) => new Promise((_resolve, reject) => {
    options.signal.addEventListener("abort", () => {
      aborted = true;
      reject(new Error("aborted"));
    }, { once: true });
  });
  const result = await clientWith(fetchImpl, { timeoutMs: 10 }).discoverDevices();
  assertFailure(result, "TIMEOUT");
  assert.equal(aborted, true);
});

test("token provider resolving after timeout never starts an API request", async () => {
  let resolveToken;
  let calls = 0;
  const delayedToken = new Promise((resolve) => { resolveToken = resolve; });
  const fetchImpl = () => { calls += 1; throw new Error("late fetch"); };
  const result = await clientWith(fetchImpl, {
    tokenProvider: () => delayedToken,
    timeoutMs: 10,
  }).discoverDevices();
  assertFailure(result, "TIMEOUT");
  resolveToken(token);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(calls, 0);
});

test("operator CLI with missing token rejects safely and accepts no arguments", () => {
  const script = fileURLToPath(new URL("../scripts/ring_official_probe.mjs", import.meta.url));
  const environment = { ...process.env };
  delete environment.RING_PLAYGROUND_ACCESS_TOKEN;
  const missing = spawnSync(process.execPath, [script], {
    env: environment,
    encoding: "utf8",
    timeout: 2000,
  });
  assert.equal(missing.status, 2);
  assert.equal(missing.stderr, "");
  const missingResult = JSON.parse(missing.stdout);
  assert.equal(missingResult.ok, false);
  assert.equal(missingResult.configured, false);
  assert.equal(missingResult.source, "official_playground_api");
  assert.equal(missingResult.http_status, null);
  assert.equal(missingResult.device_count, 0);
  assert.deepEqual(missingResult.display_aliases, []);
  assert.equal(missingResult.error_code, "TOKEN_UNAVAILABLE");
  assert.equal(Number.isNaN(Date.parse(missingResult.checked_at)), false);
  const rejectedArgs = spawnSync(process.execPath, [script, "unexpected"], {
    env: environment,
    encoding: "utf8",
    timeout: 2000,
  });
  assert.equal(rejectedArgs.status, 2);
  assert.equal(rejectedArgs.stdout, "");
  assert.match(rejectedArgs.stderr, /accepts no command-line arguments/);
});
