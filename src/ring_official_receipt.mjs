import { createHash, randomBytes } from "node:crypto";
import { closeSync, constants, fstatSync, linkSync, lstatSync, openSync, readSync } from "node:fs";
import {
  chmod,
  link,
  lstat,
  mkdir,
  open,
  readFile,
  realpath,
  rename,
  unlink,
} from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { createRingOfficialClient } from "./ring_official_client.mjs";

const MODULE_PATH = fileURLToPath(import.meta.url);
const PROJECT_ROOT = dirname(dirname(MODULE_PATH));
const RECEIPT_DIRECTORY = join(
  PROJECT_ROOT,
  "output",
  "isolation",
  "current_runs",
  "20260929_ring_private_linking",
  "b01_demo_receipt",
  "runtime",
);
const CLIENT_PATH = join(PROJECT_ROOT, "src", "ring_official_client.mjs");
const CAPTURE_SCRIPT_PATH = join(PROJECT_ROOT, "scripts", "capture_ring_official_receipt.mjs");
const SERVER_PATH = join(PROJECT_ROOT, "src", "server.mjs");
const EXPECTED_SERVER_SHA256 = "9ee7c69b62c561f55a4fa896eb5aa59153e827a70014c1273071f0bcfa2207ee";
const SERVER_CREDENTIAL_HANDLING = "server_memory_input; never_accepted_via_argv; omitted_from_receipt_and_cli_output; no_child_process_propagation_by_capture_cli";
const UNVERIFIED_TEST_DIRECTORY = join(
  PROJECT_ROOT,
  ".test-runtime",
  `receipt-${process.pid}-${randomBytes(12).toString("hex")}`,
);
const EXPECTED_CLIENT_SHA256 = "2403b4084ed88d6954850afae2ae05474c1c583bca188ca6bbbb4f876f895bc2";
const MAX_RECEIPT_BYTES = 16 * 1024;
const MAX_DEVICES = 256;

const INJECTION_ENVIRONMENT_NAMES = new Set([
  "NODE_OPTIONS",
  "NODE_PATH",
  "NODE_V8_COVERAGE",
  "NODE_DEBUG",
  "NODE_DEBUG_NATIVE",
  "NODE_EXTRA_CA_CERTS",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
  "http_proxy",
  "https_proxy",
  "all_proxy",
  "GLOBAL_AGENT_HTTP_PROXY",
  "AWS_LAMBDA_EXEC_WRAPPER",
  "LD_PRELOAD",
  "DYLD_INSERT_LIBRARIES",
  "DYLD_LIBRARY_PATH",
  "DYLD_FRAMEWORK_PATH",
]);
const INJECTION_ENVIRONMENT_PREFIXES = [
  "OTEL_",
  "NYC_",
  "JEST_",
  "VITEST_",
  "MOCHA_",
  "NODE_TEST_",
];

export const LIVE_RECEIPT_DIRECTORY = RECEIPT_DIRECTORY;
export const UNVERIFIED_TEST_RECEIPT_DIRECTORY = UNVERIFIED_TEST_DIRECTORY;

export class ReceiptCaptureError extends Error {
  constructor(code) {
    super(code);
    this.name = "ReceiptCaptureError";
    this.code = code;
  }
}

function fail(code) {
  throw new ReceiptCaptureError(code);
}

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("RECEIPT_NONFINITE_NUMBER");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  fail("RECEIPT_UNSUPPORTED_VALUE");
}

function sha256(data) {
  return createHash("sha256").update(data).digest("hex");
}

function lockIdentity(status) {
  return Object.freeze({
    dev: status.dev,
    ino: status.ino,
    uid: status.uid,
  });
}

function sameLockIdentity(expected, status) {
  return status.isFile()
    && !status.isSymbolicLink()
    && status.dev === expected.dev
    && status.ino === expected.ino
    && status.uid === expected.uid
    && status.nlink >= 1;
}

async function lockPathMatches(lockPath, expected) {
  const status = await lstat(lockPath).catch((error) => {
    if (error?.code === "ENOENT") return null;
    throw error;
  });
  return status !== null && sameLockIdentity(expected, status);
}

async function assertOwnedLockFrame(lockHandle, lockPath, expected) {
  const handleStatus = await lockHandle.stat();
  if (!sameLockIdentity(expected, handleStatus)
    || !(await lockPathMatches(lockPath, expected))) {
    fail("RECEIPT_LOCK_OWNERSHIP_LOST");
  }
}

async function releaseOwnedLock(lockHandle, lockPath, expected) {
  const pathMatches = await lockPathMatches(lockPath, expected).catch(() => false);
  await lockHandle.close().catch(() => {
    fail("RECEIPT_LOCK_OWNERSHIP_LOST");
  });
  if (!pathMatches) fail("RECEIPT_LOCK_OWNERSHIP_LOST");

  const releasePath = `${lockPath}.release-${process.pid}-${randomBytes(12).toString("hex")}`;
  try {
    await rename(lockPath, releasePath);
  } catch {
    fail("RECEIPT_LOCK_OWNERSHIP_LOST");
  }
  const movedStatus = await lstat(releasePath).catch(() => null);
  if (movedStatus !== null && sameLockIdentity(expected, movedStatus)) {
    await unlink(releasePath).catch(() => {
      fail("RECEIPT_LOCK_OWNERSHIP_LOST");
    });
    return;
  }

  if (movedStatus !== null) {
    try {
      await link(releasePath, lockPath);
      await unlink(releasePath);
    } catch {
      // Preserve the moved foreign frame at releasePath if its original pathname is occupied.
    }
  }
  fail("RECEIPT_LOCK_OWNERSHIP_LOST");
}

function isInside(base, candidate) {
  const path = relative(resolve(base), resolve(candidate));
  return path === "" || (!path.startsWith(`..${sep}`) && path !== ".." && !isAbsolute(path));
}

async function assertNoSymlinkPath(base, directory) {
  const resolvedBase = resolve(base);
  const resolvedDirectory = resolve(directory);
  if (!isInside(resolvedBase, resolvedDirectory)) fail("RECEIPT_PATH_OUTSIDE_PROJECT");
  const suffix = relative(resolvedBase, resolvedDirectory);
  let cursor = resolvedBase;
  const parts = suffix === "" ? [] : suffix.split(sep);
  for (const part of parts) {
    cursor = join(cursor, part);
    const status = await lstat(cursor).catch((error) => {
      if (error?.code === "ENOENT") return null;
      throw error;
    });
    if (status === null) continue;
    if (status.isSymbolicLink() || !status.isDirectory()) fail("RECEIPT_DIRECTORY_UNSAFE");
  }
}

async function prepareDirectory(directory) {
  if (!isInside(PROJECT_ROOT, directory)) fail("RECEIPT_PATH_OUTSIDE_PROJECT");
  await assertNoSymlinkPath(PROJECT_ROOT, dirname(directory));
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await assertNoSymlinkPath(PROJECT_ROOT, directory);
  await chmod(directory, 0o700);
  const status = await lstat(directory);
  if (!status.isDirectory() || status.isSymbolicLink() || (status.mode & 0o777) !== 0o700) {
    fail("RECEIPT_DIRECTORY_UNSAFE");
  }
}

async function readRegularFileNoFollow(path, maximumBytes = MAX_RECEIPT_BYTES) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
  try {
    const status = await handle.stat();
    if (!status.isFile() || status.size > maximumBytes) fail("RECEIPT_FILE_UNSAFE");
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}

async function hashSource(path) {
  const body = await readRegularFileNoFollow(path, 512 * 1024);
  if (body === null) fail("RECEIPT_SOURCE_MISSING");
  return sha256(body);
}

function validateDiscovery(result) {
  if (!result || typeof result !== "object" || Array.isArray(result)) fail("DISCOVERY_RESULT_INVALID");
  if (result.ok !== true || result.configured !== true) {
    if (result.ok === false && result.configured === true && result.source === "official_playground_api") {
      if (result.error_code === "HTTP_ERROR" && result.http_status === 401) fail("DISCOVERY_HTTP_401");
      if (result.error_code === "HTTP_ERROR" && result.http_status === 403) fail("DISCOVERY_HTTP_403");
      if (result.error_code === "TIMEOUT") fail("DISCOVERY_TIMEOUT");
      if (result.error_code === "NETWORK_ERROR") fail("DISCOVERY_NETWORK_ERROR");
    }
    fail("DISCOVERY_NOT_SUCCESSFUL");
  }
  if (result.source !== "official_playground_api") fail("DISCOVERY_SOURCE_INVALID");
  if (result.http_status !== 200) fail("DISCOVERY_HTTP_INVALID");
  if (!Number.isSafeInteger(result.device_count)
    || result.device_count < 0
    || result.device_count > MAX_DEVICES) {
    fail("DISCOVERY_COUNT_INVALID");
  }
  if (typeof result.checked_at !== "string" || Number.isNaN(Date.parse(result.checked_at))) {
    fail("DISCOVERY_TIME_INVALID");
  }
  return result.device_count;
}

export function findRuntimeInjectionIndicators({ execArgv, env }) {
  const indicators = [];
  if (!Array.isArray(execArgv)) fail("RUNTIME_ATTESTATION_INVALID");
  for (const argument of execArgv) {
    if (typeof argument !== "string") fail("RUNTIME_ATTESTATION_INVALID");
    indicators.push(`execArgv:${argument.split("=")[0]}`);
  }
  if (!env || typeof env !== "object" || Array.isArray(env)) fail("RUNTIME_ATTESTATION_INVALID");
  for (const name of Object.keys(env).sort()) {
    if (INJECTION_ENVIRONMENT_NAMES.has(name)
      || INJECTION_ENVIRONMENT_PREFIXES.some((prefix) => name.startsWith(prefix))) {
      indicators.push(`env:${name}`);
    }
  }
  return indicators;
}

function buildReceipt({ result, capturedAt, captureMode, sourceHashes, runtime, credentialHandling }) {
  const deviceCount = validateDiscovery(result);
  if (typeof capturedAt !== "string" || Number.isNaN(Date.parse(capturedAt))) {
    fail("CAPTURE_TIME_INVALID");
  }
  const draft = {
    schema: "ring-official-discovery-receipt-v1",
    captured_at: capturedAt,
    operation: "discover_devices",
    endpoint_origin: "https://api.amazonvision.com",
    endpoint_path: "/v1/devices",
    http_status: 200,
    device_count: deviceCount,
    provider_source: "official_playground_api",
    capture_mode: captureMode,
    credential_handling: credentialHandling ?? "environment_input; never_accepted_via_argv; omitted_from_receipt_and_cli_output; no_child_process_propagation_by_capture_cli",
    source_hashes: sourceHashes,
    runtime,
  };
  const receiptId = `sha256:${sha256(Buffer.from(canonicalJson(draft), "utf8"))}`;
  return Object.freeze({
    schema: draft.schema,
    receipt_id: receiptId,
    captured_at: draft.captured_at,
    operation: draft.operation,
    endpoint_origin: draft.endpoint_origin,
    endpoint_path: draft.endpoint_path,
    http_status: draft.http_status,
    device_count: draft.device_count,
    provider_source: draft.provider_source,
    capture_mode: draft.capture_mode,
    credential_handling: draft.credential_handling,
    source_hashes: Object.freeze({ ...draft.source_hashes }),
    runtime: Object.freeze({ ...draft.runtime }),
  });
}

function receiptFileName(receipt, unverified) {
  const digest = receipt.receipt_id.slice("sha256:".length);
  if (!/^[a-f0-9]{64}$/.test(digest)) fail("RECEIPT_ID_INVALID");
  return `${digest}${unverified ? ".unverified" : ""}.json`;
}

async function writeAtomicReceipt(directory, receipt, { unverified, assertCommitAuthorization }) {
  await prepareDirectory(directory);
  const path = join(directory, receiptFileName(receipt, unverified));
  const lockPath = join(directory, ".ring-official-discovery-receipt.lock");
  const temporaryPath = join(directory, `.${receiptFileName(receipt, unverified)}.${process.pid}.${randomBytes(12).toString("hex")}.tmp`);
  let lockHandle;
  let lockOwned = false;
  let acquiredLockIdentity;
  let directoryHandle;
  let temporaryHandle;
  let published = false;
  let primaryError;
  let successResult;
  const bytes = Buffer.from(`${JSON.stringify(receipt)}\n`, "utf8");
  if (bytes.byteLength > MAX_RECEIPT_BYTES) fail("RECEIPT_TOO_LARGE");
  try {
    try {
      lockHandle = await open(
        lockPath,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      );
      lockOwned = true;
    } catch (error) {
      if (error?.code === "EEXIST") fail("RECEIPT_BUSY");
      throw error;
    }
    acquiredLockIdentity = lockIdentity(await lockHandle.stat());
    await lockHandle.writeFile(`${process.pid}\n`, "utf8");
    await lockHandle.sync();
    await assertOwnedLockFrame(lockHandle, lockPath, acquiredLockIdentity);
    directoryHandle = await open(
      directory,
      constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_DIRECTORY ?? 0),
    );
    temporaryHandle = await open(
      temporaryPath,
      constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    await temporaryHandle.writeFile(bytes);
    await temporaryHandle.sync();
    await temporaryHandle.close();
    temporaryHandle = undefined;
    await chmod(temporaryPath, 0o600);
    const temporaryStatus = await lstat(temporaryPath);
    if (!temporaryStatus.isFile() || temporaryStatus.isSymbolicLink()
      || (temporaryStatus.mode & 0o777) !== 0o600) {
      fail("RECEIPT_TEMP_UNSAFE");
    }
    const readback = await readRegularFileNoFollow(temporaryPath);
    if (readback === null || !readback.equals(bytes)) fail("RECEIPT_READBACK_MISMATCH");
    await assertOwnedLockFrame(lockHandle, lockPath, acquiredLockIdentity);
    await directoryHandle.sync();
    if (assertCommitAuthorization !== undefined) assertCommitAuthorization();
    try {
      if (assertCommitAuthorization === undefined) {
        await link(temporaryPath, path);
      } else {
        linkSync(temporaryPath, path);
      }
      published = true;
    } catch (error) {
      if (error?.code === "EEXIST") fail("RECEIPT_ALREADY_EXISTS");
      const current = await readRegularFileNoFollow(path).catch(() => null);
      if (current !== null && current.equals(bytes)) published = true;
      fail("RECEIPT_PUBLISH_OUTCOME_UNKNOWN");
    }
    await assertOwnedLockFrame(lockHandle, lockPath, acquiredLockIdentity);
    await directoryHandle.sync();
    successResult = { receipt, path, published: true };
  } catch (error) {
    primaryError = error instanceof ReceiptCaptureError
      ? error
      : new ReceiptCaptureError(published
        ? "RECEIPT_PUBLISH_OUTCOME_UNKNOWN"
        : "RECEIPT_WRITE_FAILED");
  }

  const cleanupFailures = [];
  async function cleanupStep(operation) {
    try {
      await operation();
    } catch {
      cleanupFailures.push("CLEANUP_STEP_FAILED");
    }
  }

  if (temporaryHandle !== undefined) {
    await cleanupStep(async () => temporaryHandle.close());
  }
  await cleanupStep(async () => {
    await unlink(temporaryPath).catch((error) => {
      if (error?.code !== "ENOENT") throw error;
    });
  });
  if (directoryHandle !== undefined) {
    await cleanupStep(async () => directoryHandle.sync());
    await cleanupStep(async () => directoryHandle.close());
  }
  if (lockOwned && lockHandle !== undefined && acquiredLockIdentity !== undefined) {
    await cleanupStep(async () => releaseOwnedLock(lockHandle, lockPath, acquiredLockIdentity));
  } else if (lockHandle !== undefined) {
    await cleanupStep(async () => lockHandle.close());
  }

  if (cleanupFailures.length !== 0) {
    const cleanupCode = published
      ? "RECEIPT_PUBLISH_OUTCOME_UNKNOWN"
      : "RECEIPT_CLEANUP_FAILED";
    if (primaryError === undefined) {
      primaryError = new ReceiptCaptureError(cleanupCode);
    } else {
      primaryError.cleanup_code = cleanupCode;
      primaryError.cleanup_failure_count = Math.min(cleanupFailures.length, 8);
    }
  }
  if (primaryError !== undefined) throw primaryError;
  return successResult;
}

async function currentSourceHashes() {
  const clientSha256 = await hashSource(CLIENT_PATH);
  if (clientSha256 !== EXPECTED_CLIENT_SHA256) fail("CLIENT_SOURCE_HASH_MISMATCH");
  return {
    client_sha256: clientSha256,
    capture_script_sha256: await hashSource(CAPTURE_SCRIPT_PATH),
    receipt_writer_sha256: await hashSource(MODULE_PATH),
  };
}

async function assertOfficialCliEntrypoint() {
  if (process.argv.length !== 2 || typeof process.argv[1] !== "string") {
    fail("CAPTURE_ENTRYPOINT_INVALID");
  }
  let actual;
  let expected;
  try {
    [actual, expected] = await Promise.all([
      realpath(process.argv[1]),
      realpath(CAPTURE_SCRIPT_PATH),
    ]);
  } catch {
    fail("CAPTURE_ENTRYPOINT_INVALID");
  }
  if (actual !== expected) fail("CAPTURE_ENTRYPOINT_INVALID");
}

export async function captureLiveOfficialReceipt() {
  await assertOfficialCliEntrypoint();
  const indicators = findRuntimeInjectionIndicators({ execArgv: process.execArgv, env: process.env });
  if (indicators.length !== 0) fail("RUNTIME_INJECTION_DETECTED");
  const sourceHashes = await currentSourceHashes();
  const client = createRingOfficialClient({
    tokenProvider: () => process.env.RING_PLAYGROUND_ACCESS_TOKEN,
  });
  const result = await client.discoverDevices();
  const receipt = buildReceipt({
    result,
    capturedAt: new Date().toISOString(),
    captureMode: "operator_provider_observation_candidate",
    sourceHashes,
    runtime: {
      node_version: process.versions.node,
      platform: process.platform,
      arch: process.arch,
      injection_check: "CLEAR",
      evidence_classification: "CANDIDATE_REQUIRES_VIDEO_AND_OPERATOR_ACCEPTANCE",
      provenance_qualification: "source_hashes_do_not_prove_live_provider_transport",
    },
  });
  return writeAtomicReceipt(RECEIPT_DIRECTORY, receipt, { unverified: false });
}

export async function persistUnverifiedTestObservation({ result, capturedAt }) {
  const sourceHashes = await currentSourceHashes();
  const receipt = buildReceipt({
    result,
    capturedAt,
    captureMode: "test_mock_unverified",
    sourceHashes,
    runtime: {
      node_version: process.versions.node,
      platform: process.platform,
      arch: process.arch,
      injection_check: "TEST_HARNESS",
      evidence_classification: "UNVERIFIED_TEST_ONLY",
      provenance_qualification: "source_hashes_do_not_prove_live_provider_transport",
    },
  });
  return writeAtomicReceipt(UNVERIFIED_TEST_DIRECTORY, receipt, { unverified: true });
}

function hashSourceSynchronously(path) {
  let fd;
  try {
    const before = lstatSync(path, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink() || before.size > 512n * 1024n) fail("SERVER_SOURCE_INVALID");
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const opened = fstatSync(fd, { bigint: true });
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino
      || opened.size !== before.size) fail("SERVER_SOURCE_INVALID");
    const buffer = Buffer.alloc(512 * 1024 + 1);
    let size = 0;
    for (;;) {
      const count = readSync(fd, buffer, size, buffer.length - size, size);
      if (count === 0) break;
      size += count;
      if (size > 512 * 1024) fail("SERVER_SOURCE_INVALID");
    }
    const after = fstatSync(fd, { bigint: true });
    const current = lstatSync(path, { bigint: true });
    if (after.size !== BigInt(size) || after.dev !== before.dev || after.ino !== before.ino
      || after.mtimeNs !== before.mtimeNs || after.ctimeNs !== before.ctimeNs
      || current.dev !== before.dev || current.ino !== before.ino
      || current.mtimeNs !== before.mtimeNs || current.ctimeNs !== before.ctimeNs) fail("SERVER_SOURCE_INVALID");
    return sha256(buffer.subarray(0, size));
  } finally { if (fd !== undefined) closeSync(fd); }
}

async function assertOfficialLoopbackServerEntrypoint() {
  if (process.argv.length !== 2 || typeof process.argv[1] !== "string") fail("SERVER_ENTRYPOINT_INVALID");
  const [actual, expected] = await Promise.all([realpath(process.argv[1]), realpath(SERVER_PATH)]);
  if (actual !== expected) fail("SERVER_ENTRYPOINT_INVALID");
  if (findRuntimeInjectionIndicators({ execArgv: process.execArgv, env: process.env }).length !== 0) {
    fail("RUNTIME_INJECTION_DETECTED");
  }
}

export function createLoopbackOfficialReceiptCapture(ports) {
  if (arguments.length !== 1 || !ports || Object.keys(ports).sort().join(",") !== "assertCurrentAuthorization,tokenProvider"
    || typeof ports.tokenProvider !== "function" || typeof ports.assertCurrentAuthorization !== "function") {
    fail("SERVER_PORTS_REQUIRED");
  }
  const tokenProvider = ports.tokenProvider;
  const assertCurrentAuthorization = ports.assertCurrentAuthorization;
  function assertAuthority() {
    try {
      if (assertCurrentAuthorization() !== undefined) fail("SERVER_AUTHORIZATION_REVOKED");
    } catch { fail("SERVER_AUTHORIZATION_REVOKED"); }
  }
  return Object.freeze({
    async capture() {
      if (arguments.length !== 0) fail("CAPTURE_ARGUMENTS_FORBIDDEN");
      assertAuthority();
      await assertOfficialLoopbackServerEntrypoint();
      const sourceHashes = { ...await currentSourceHashes(), server_sha256: await hashSource(SERVER_PATH) };
      if (sourceHashes.server_sha256 !== EXPECTED_SERVER_SHA256) fail("SERVER_SOURCE_HASH_MISMATCH");
      assertAuthority();
      const client = createRingOfficialClient({ tokenProvider });
      const result = await client.discoverDevices();
      assertAuthority();
      const receipt = buildReceipt({ result, capturedAt: new Date().toISOString(),
        captureMode: "operator_provider_observation_candidate", sourceHashes,
        credentialHandling: SERVER_CREDENTIAL_HANDLING,
        runtime: { node_version: process.versions.node, platform: process.platform, arch: process.arch,
          injection_check: "CLEAR", evidence_classification: "CANDIDATE_REQUIRES_VIDEO_AND_OPERATOR_ACCEPTANCE",
          provenance_qualification: "source_hashes_do_not_prove_live_provider_transport" } });
      const assertCommitAuthorization = () => {
        const expected = [[CLIENT_PATH, sourceHashes.client_sha256], [CAPTURE_SCRIPT_PATH, sourceHashes.capture_script_sha256],
          [MODULE_PATH, sourceHashes.receipt_writer_sha256], [SERVER_PATH, sourceHashes.server_sha256]];
        for (const [path, digest] of expected) {
          if (hashSourceSynchronously(path) !== digest) fail("SERVER_SOURCE_CHANGED");
        }
        assertAuthority();
      };
      const published = await writeAtomicReceipt(RECEIPT_DIRECTORY, receipt,
        { unverified: false, assertCommitAuthorization });
      return Object.freeze({ receipt_id: published.receipt.receipt_id,
        device_count: published.receipt.device_count, captured_at: published.receipt.captured_at,
        classification: "CANDIDATE_REQUIRES_VIDEO_AND_OPERATOR_ACCEPTANCE" });
    },
  });
}
