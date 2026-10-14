import { createHash } from "node:crypto";
import {
  closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readSync, realpathSync,
} from "node:fs";
import { lstat, open, readdir, realpath } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const WORK_ORDER = "20260929_ring_private_linking";
const MODULE_PATH = fileURLToPath(import.meta.url);
const CANDIDATE_SUFFIX = join("output", "isolation", "current_runs", WORK_ORDER,
  "b01_demo_acceptance", "candidate", "src", "ring_receipt_acceptance.mjs");
const PROJECT_ROOT = MODULE_PATH.endsWith(`${sep}${CANDIDATE_SUFFIX}`)
  ? MODULE_PATH.slice(0, -(CANDIDATE_SUFFIX.length + 1))
  : dirname(dirname(MODULE_PATH));
const DIRECTORY_SUFFIX = join("output", "isolation", "current_runs", WORK_ORDER,
  "b01_demo_receipt", "runtime");
const RECEIPT_DIRECTORY = join(PROJECT_ROOT, DIRECTORY_SUFFIX);
const MAX_BYTES = 16 * 1024;
const MAX_SOURCE_BYTES = 512 * 1024;
const CLASSIFICATION = "CANDIDATE_REQUIRES_VIDEO_AND_OPERATOR_ACCEPTANCE";
const QUALIFICATION = "source_hashes_do_not_prove_live_provider_transport";
const CREDENTIAL_HANDLING = "environment_input; never_accepted_via_argv; omitted_from_receipt_and_cli_output; no_child_process_propagation_by_capture_cli";
const INPUT_PINS = Object.freeze({
  "src/ring_official_client.mjs": "2403b4084ed88d6954850afae2ae05474c1c583bca188ca6bbbb4f876f895bc2",
  "src/ring_official_receipt.mjs": "c15ef42ed1525540e47854e1abbda4ca1a8acec82fb55350e19560a689740138",
  "scripts/capture_ring_official_receipt.mjs": "0ad2cac044ba00d5a7b06fe683b076b7271825a5b4d2cb6d3871e0073ae5e181",
  "tests/ring_official_receipt.mjs": "499dd098c39e8ff2cb92219cc505f9f08981028ba703e65277e88023fff9df79",
  "package.json": "b78806f3d17c318356481eacddf09aeb3339ae21d62772e8579e293e19303aa8",
  "src/server.mjs": "9ee7c69b62c561f55a4fa896eb5aa59153e827a70014c1273071f0bcfa2207ee",
});
const RECEIPT_SOURCE_PINS = Object.freeze({
  client_sha256: INPUT_PINS["src/ring_official_client.mjs"],
  capture_script_sha256: INPUT_PINS["scripts/capture_ring_official_receipt.mjs"],
  receipt_writer_sha256: INPUT_PINS["src/ring_official_receipt.mjs"],
});
const READBACKS = new WeakMap();
const SNAPSHOTS = new WeakMap();
const PACKET_SNAPSHOTS = new WeakMap();
const SNAPSHOT_QUALIFICATION = "synchronous_joint_point_in_time_check; no_external_writer_atomicity_or_lease";

export class RingReceiptReadbackError extends Error {
  constructor(code) {
    super(code);
    this.name = "RingReceiptReadbackError";
    this.code = code;
  }
}

function fail(code) { throw new RingReceiptReadbackError(code); }
function hash(bytes) { return createHash("sha256").update(bytes).digest("hex"); }
function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}
function freeze(value) {
  if (value !== null && typeof value === "object") {
    for (const item of Object.values(value)) freeze(item);
    Object.freeze(value);
  }
  return value;
}

// Parse JSON without permitting duplicate keys or unbounded nesting/collections.
function parseStrict(text) {
  if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > MAX_BYTES) {
    fail("JSON_SIZE_INVALID");
  }
  let cursor = 0;
  let nodes = 0;
  const whitespace = () => {
    while (cursor < text.length && /[\x20\t\r\n]/.test(text[cursor])) cursor += 1;
  };
  function string() {
    const start = cursor;
    cursor += 1;
    while (cursor < text.length) {
      const character = text[cursor++];
      if (character === "\\") {
        cursor += 1;
      } else if (character === '"') {
        try {
          const value = JSON.parse(text.slice(start, cursor));
          if (value.length > 1024) fail("JSON_STRING_TOO_LONG");
          return value;
        } catch (error) {
          if (error instanceof RingReceiptReadbackError) throw error;
          fail("JSON_INVALID");
        }
      }
    }
    fail("JSON_INVALID");
  }
  function value(depth) {
    if (depth > 12 || ++nodes > 256) fail("JSON_COMPLEXITY_INVALID");
    whitespace();
    const character = text[cursor];
    if (character === '"') return string();
    if (character === "{") {
      cursor += 1;
      const object = Object.create(null);
      const keys = new Set();
      whitespace();
      if (text[cursor] === "}") { cursor += 1; return object; }
      for (;;) {
        whitespace();
        if (text[cursor] !== '"') fail("JSON_INVALID");
        const key = string();
        if (keys.has(key)) fail("JSON_DUPLICATE_KEY");
        keys.add(key);
        if (keys.size > 32) fail("JSON_COMPLEXITY_INVALID");
        whitespace();
        if (text[cursor++] !== ":") fail("JSON_INVALID");
        object[key] = value(depth + 1);
        whitespace();
        const delimiter = text[cursor++];
        if (delimiter === "}") return object;
        if (delimiter !== ",") fail("JSON_INVALID");
      }
    }
    if (character === "[") {
      cursor += 1;
      const array = [];
      whitespace();
      if (text[cursor] === "]") { cursor += 1; return array; }
      for (;;) {
        if (array.length >= 32) fail("JSON_COMPLEXITY_INVALID");
        array.push(value(depth + 1));
        whitespace();
        const delimiter = text[cursor++];
        if (delimiter === "]") return array;
        if (delimiter !== ",") fail("JSON_INVALID");
      }
    }
    for (const [literal, result] of [["true", true], ["false", false], ["null", null]]) {
      if (text.startsWith(literal, cursor)) { cursor += literal.length; return result; }
    }
    const number = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(cursor));
    if (number === null) fail("JSON_INVALID");
    cursor += number[0].length;
    const result = Number(number[0]);
    if (!Number.isFinite(result)) fail("JSON_INVALID");
    return result;
  }
  const result = value(0);
  whitespace();
  if (cursor !== text.length) fail("JSON_INVALID");
  return result;
}

function keysExactly(object, keys, code) {
  if (object === null || typeof object !== "object" || Array.isArray(object)
    || Object.keys(object).sort().join("\n") !== [...keys].sort().join("\n")) fail(code);
}
function identity(status) {
  return [status.dev, status.ino, status.uid, status.gid, status.mode, status.nlink,
    status.size, status.mtimeNs, status.ctimeNs].map(String).join(":");
}
function noArguments(count) { if (count !== 0) fail("CALLER_ARGUMENTS_FORBIDDEN"); }
function requireReadback(readback) {
  const privateState = readback && READBACKS.get(readback);
  if (privateState === undefined) fail("READBACK_NOT_BRANDED");
  return privateState;
}

async function directoryFrame(target, { leafMode = false } = {}) {
  const suffix = relative(PROJECT_ROOT, target);
  if (suffix === ".." || suffix.startsWith(`..${sep}`) || resolve(PROJECT_ROOT, suffix) !== target) {
    fail("PATH_INVALID");
  }
  let cursor = PROJECT_ROOT;
  const paths = [cursor];
  for (const part of suffix.split(sep).filter(Boolean)) { cursor = join(cursor, part); paths.push(cursor); }
  const frames = [];
  for (const path of paths) {
    const status = await lstat(path, { bigint: true });
    if (!status.isDirectory() || status.isSymbolicLink() || (status.mode & 0o022n) !== 0n
      || (leafMode && path === target && (status.mode & 0o7777n) !== 0o700n)) {
      fail("DIRECTORY_UNSAFE");
    }
    if (path === target && typeof process.getuid === "function" && status.uid !== BigInt(process.getuid())) {
      fail("DIRECTORY_OWNER_INVALID");
    }
    frames.push([path, identity(status)]);
  }
  if (await realpath(target) !== target) fail("PATH_INVALID");
  return frames;
}

async function assertFrames(frames) {
  for (const [path, expected] of frames) {
    const actual = await lstat(path, { bigint: true });
    if (identity(actual) !== expected || !actual.isDirectory() || actual.isSymbolicLink()) {
      fail("FILESYSTEM_CHANGED");
    }
  }
}

async function readStableFile(path, maximum, exactMode) {
  const frames = await directoryFrame(dirname(path));
  const before = await lstat(path, { bigint: true });
  function safe(status) {
    return status.isFile() && !status.isSymbolicLink() && status.nlink === 1n
      && status.size > 0n && status.size <= BigInt(maximum)
      && (status.mode & 0o022n) === 0n
      && (exactMode === undefined || (status.mode & 0o7777n) === BigInt(exactMode))
      && (typeof process.getuid !== "function" || status.uid === BigInt(process.getuid()));
  }
  if (!safe(before)) fail("FILE_UNSAFE");
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const opened = await handle.stat({ bigint: true });
    if (!safe(opened) || identity(opened) !== identity(before)) fail("FILESYSTEM_CHANGED");
    const buffer = Buffer.alloc(maximum + 1);
    let bytesRead = 0;
    for (;;) {
      const result = await handle.read(buffer, bytesRead, buffer.length - bytesRead, bytesRead);
      if (result.bytesRead === 0) break;
      bytesRead += result.bytesRead;
      if (bytesRead > maximum) fail("FILE_UNSAFE");
    }
    if (BigInt(bytesRead) !== opened.size) fail("FILESYSTEM_CHANGED");
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(path, { bigint: true });
    if (!safe(after) || identity(after) !== identity(before) || identity(pathAfter) !== identity(before)) {
      fail("FILESYSTEM_CHANGED");
    }
    await assertFrames(frames);
    return { bytes: buffer.subarray(0, bytesRead), identity: identity(before), frames };
  } finally {
    if (handle !== undefined) await handle.close();
  }
}

async function verifyCurrentSources() {
  const frames = [];
  for (const [suffix, expected] of Object.entries(INPUT_PINS)) {
    const path = join(PROJECT_ROOT, suffix);
    const current = await readStableFile(path, MAX_SOURCE_BYTES);
    if (hash(current.bytes) !== expected) fail("CURRENT_SOURCE_MISMATCH");
    frames.push([path, current.identity, current.frames]);
  }
  return frames;
}

async function scanDirectory() {
  const frames = await directoryFrame(RECEIPT_DIRECTORY, { leafMode: true });
  const entries = (await readdir(RECEIPT_DIRECTORY)).sort();
  if (entries.length > 256) fail("RECEIPT_DIRECTORY_AMBIGUOUS");
  if (entries.some((name) => !/^[a-f0-9]{64}\.json$/.test(name))) {
    fail("RECEIPT_DIRECTORY_AMBIGUOUS");
  }
  await assertFrames(frames);
  if (entries.length === 0) fail("NO_ELIGIBLE_RECEIPT");
  if (entries.length !== 1) fail("MULTIPLE_ELIGIBLE_RECEIPTS");
  return { frames, entries, path: join(RECEIPT_DIRECTORY, entries[0]) };
}

function validateReceipt(receipt, filename) {
  keysExactly(receipt, ["schema", "receipt_id", "captured_at", "operation", "endpoint_origin",
    "endpoint_path", "http_status", "device_count", "provider_source", "capture_mode",
    "credential_handling", "source_hashes", "runtime"], "RECEIPT_KEYS_INVALID");
  if (receipt.schema !== "ring-official-discovery-receipt-v1") fail("RECEIPT_SCHEMA_INVALID");
  if (receipt.operation !== "discover_devices" || receipt.endpoint_origin !== "https://api.amazonvision.com"
    || receipt.endpoint_path !== "/v1/devices" || receipt.http_status !== 200
    || receipt.provider_source !== "official_playground_api") fail("RECEIPT_PROVIDER_FIELDS_INVALID");
  if (receipt.capture_mode !== "operator_provider_observation_candidate") fail("RECEIPT_CAPTURE_MODE_INVALID");
  const serverMemory = receipt.credential_handling === CREDENTIAL_HANDLING.replace("environment_input", "server_memory_input");
  if (!serverMemory && receipt.credential_handling !== CREDENTIAL_HANDLING) fail("RECEIPT_CREDENTIAL_FIELDS_INVALID");
  if (!Number.isSafeInteger(receipt.device_count) || receipt.device_count < 0 || receipt.device_count > 256) {
    fail("RECEIPT_COUNT_INVALID");
  }
  if (typeof receipt.captured_at !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(receipt.captured_at)
    || !Number.isFinite(Date.parse(receipt.captured_at))
    || new Date(receipt.captured_at).toISOString() !== receipt.captured_at) fail("RECEIPT_TIME_INVALID");
  const expectedSourcePins = serverMemory
    ? { ...RECEIPT_SOURCE_PINS, server_sha256: INPUT_PINS["src/server.mjs"] } : RECEIPT_SOURCE_PINS;
  keysExactly(receipt.source_hashes, Object.keys(expectedSourcePins), "RECEIPT_SOURCE_KEYS_INVALID");
  if (canonical(receipt.source_hashes) !== canonical(expectedSourcePins)) fail("RECEIPT_SOURCE_MISMATCH");
  keysExactly(receipt.runtime, ["node_version", "platform", "arch", "injection_check",
    "evidence_classification", "provenance_qualification"], "RECEIPT_RUNTIME_KEYS_INVALID");
  if (receipt.runtime.injection_check !== "CLEAR" || receipt.runtime.evidence_classification !== CLASSIFICATION
    || receipt.runtime.provenance_qualification !== QUALIFICATION) fail("RECEIPT_CLASSIFICATION_INVALID");
  if (typeof receipt.runtime.node_version !== "string" || !/^\d{2,3}\.\d{1,3}\.\d{1,3}$/.test(receipt.runtime.node_version)
    || !["aix", "android", "darwin", "freebsd", "linux", "openbsd", "sunos", "win32", "netbsd"].includes(receipt.runtime.platform)
    || !["arm", "arm64", "ia32", "mips", "mipsel", "mips64el", "ppc", "ppc64", "riscv64", "s390", "s390x", "x64", "loong64"].includes(receipt.runtime.arch)) {
    fail("RECEIPT_RUNTIME_INVALID");
  }
  const [major, minor] = receipt.runtime.node_version.split(".").map(Number);
  if (major < 20 || (major === 20 && minor < 11)) fail("RECEIPT_RUNTIME_INVALID");
  if (typeof receipt.receipt_id !== "string" || !/^sha256:[a-f0-9]{64}$/.test(receipt.receipt_id)) {
    fail("RECEIPT_ID_INVALID");
  }
  const { receipt_id, ...draft } = receipt;
  if (`sha256:${hash(canonical(draft))}` !== receipt_id) fail("RECEIPT_DIGEST_MISMATCH");
  if (filename !== `${receipt_id.slice(7)}.json`) fail("RECEIPT_FILENAME_MISMATCH");
}

function normalizedFailure(error) {
  return error instanceof RingReceiptReadbackError ? error : new RingReceiptReadbackError(
    error?.code === "ENOENT" ? "REQUIRED_PATH_MISSING" : "READBACK_FAILED");
}

// The barrier prevents target await/microtask interleaving. It does not lock external writers.
function assertJointSnapshotBarrier(snapshot) {
  const handles = [];
  let closeFailed = false;
  try {
    const allFrames = [...snapshot.frame.frames,
      ...snapshot.sources.flatMap(([, , frames]) => frames)];
    function checkFrames() {
      for (const [path, expected] of allFrames) {
        const current = lstatSync(path, { bigint: true });
        if (!current.isDirectory() || current.isSymbolicLink() || identity(current) !== expected) {
          fail("FILESYSTEM_CHANGED");
        }
      }
      if (realpathSync(RECEIPT_DIRECTORY) !== RECEIPT_DIRECTORY) fail("PATH_INVALID");
    }
    checkFrames();
    const directoryFd = openSync(RECEIPT_DIRECTORY,
      constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_DIRECTORY ?? 0));
    handles.push(directoryFd);
    const directoryIdentity = snapshot.frame.frames.at(-1)[1];
    if (identity(fstatSync(directoryFd, { bigint: true })) !== directoryIdentity) fail("FILESYSTEM_CHANGED");
    const targets = snapshot.sources.map(([path, expected]) => ({
      path, expected, maximum: MAX_SOURCE_BYTES,
      expectedHash: INPUT_PINS[relative(PROJECT_ROOT, path)], code: "CURRENT_SOURCE_CHANGED",
    }));
    targets.push({ path: snapshot.frame.path, expected: snapshot.file.identity,
      maximum: MAX_BYTES, exactMode: 0o600, expectedBytes: snapshot.file.bytes,
      code: "FILESYSTEM_CHANGED" });
    function checkFile(status, target) {
      if (!status.isFile() || status.isSymbolicLink() || status.nlink !== 1n
        || status.size <= 0n || status.size > BigInt(target.maximum)
        || (status.mode & 0o022n) !== 0n
        || (target.exactMode !== undefined && (status.mode & 0o7777n) !== BigInt(target.exactMode))
        || (typeof process.getuid === "function" && status.uid !== BigInt(process.getuid()))
        || identity(status) !== target.expected) fail(target.code);
    }
    for (const target of targets) {
      if (realpathSync(dirname(target.path)) !== dirname(target.path)) fail("PATH_INVALID");
      checkFile(lstatSync(target.path, { bigint: true }), target);
      target.fd = openSync(target.path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      handles.push(target.fd);
      checkFile(fstatSync(target.fd, { bigint: true }), target);
    }
    for (const target of targets) {
      const buffer = Buffer.alloc(target.maximum + 1);
      let bytesRead = 0;
      for (;;) {
        const count = readSync(target.fd, buffer, bytesRead, buffer.length - bytesRead, bytesRead);
        if (count === 0) break;
        bytesRead += count;
        if (bytesRead > target.maximum) fail(target.code);
      }
      const bytes = buffer.subarray(0, bytesRead);
      if (target.expectedBytes !== undefined ? !bytes.equals(target.expectedBytes)
        : hash(bytes) !== target.expectedHash) fail(target.code);
      checkFile(fstatSync(target.fd, { bigint: true }), target);
    }
    for (const target of targets) {
      checkFile(fstatSync(target.fd, { bigint: true }), target);
      checkFile(lstatSync(target.path, { bigint: true }), target);
    }
    checkFrames();
    if (canonical(readdirSync(RECEIPT_DIRECTORY).sort()) !== canonical(snapshot.frame.entries)
      || identity(fstatSync(directoryFd, { bigint: true })) !== directoryIdentity
      || identity(lstatSync(RECEIPT_DIRECTORY, { bigint: true })) !== directoryIdentity) {
      fail("FILESYSTEM_CHANGED");
    }
  } catch (error) { throw normalizedFailure(error); }
  finally {
    for (const fd of handles.reverse()) {
      try { closeSync(fd); } catch { closeFailed = true; }
    }
    if (closeFailed) fail("SYNC_BARRIER_CLOSE_FAILED");
  }
}

export async function readCanonicalRingReceipt() {
  noArguments(arguments.length);
  try {
    const sources = await verifyCurrentSources();
    const frame = await scanDirectory();
    const file = await readStableFile(frame.path, MAX_BYTES, 0o600);
    let text;
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(file.bytes); }
    catch { fail("JSON_ENCODING_INVALID"); }
    const receipt = parseStrict(text);
    validateReceipt(receipt, frame.entries[0]);
    await assertFrames(frame.frames);
    const after = await scanDirectory();
    if (canonical(after.entries) !== canonical(frame.entries)) fail("FILESYSTEM_CHANGED");
    for (const [path, expected] of sources) {
      const sourceAfter = await readStableFile(path, MAX_SOURCE_BYTES);
      if (sourceAfter.identity !== expected || hash(sourceAfter.bytes) !== INPUT_PINS[relative(PROJECT_ROOT, path)]) {
        fail("CURRENT_SOURCE_CHANGED");
      }
    }
    const finalFile = await readStableFile(frame.path, MAX_BYTES, 0o600);
    if (finalFile.identity !== file.identity || !finalFile.bytes.equals(file.bytes)) fail("FILESYSTEM_CHANGED");
    await assertFrames(frame.frames);
    if (canonical((await readdir(RECEIPT_DIRECTORY)).sort()) !== canonical(frame.entries)) fail("FILESYSTEM_CHANGED");
    const snapshot = { sources, frame, file };
    assertJointSnapshotBarrier(snapshot);
    const summary = freeze({
      receipt_id: receipt.receipt_id,
      captured_at: receipt.captured_at,
      device_count: receipt.device_count,
      receipt_file_sha256: hash(file.bytes),
      source_hashes: { ...receipt.source_hashes },
      status: "STRUCTURE_AND_CURRENT_SOURCE_VALIDATED",
      evidence_classification: CLASSIFICATION,
      provenance_qualification: QUALIFICATION,
      snapshot_qualification: SNAPSHOT_QUALIFICATION,
      live_evidence_accepted: false,
      productionAdmitted: false,
    });
    READBACKS.set(summary, summary);
    SNAPSHOTS.set(summary, snapshot);
    return summary;
  } catch (error) { throw normalizedFailure(error); }
}

export async function createPendingRingAcceptancePacket(readback) {
  if (arguments.length !== 1) fail("PACKET_ARGUMENTS_INVALID");
  const verified = requireReadback(readback);
  const current = await readCanonicalRingReceipt();
  if (canonical(current) !== canonical(verified)) fail("READBACK_STALE");
  const snapshot = SNAPSHOTS.get(current);
  assertJointSnapshotBarrier(snapshot);
  const draft = {
    schema: "ring-demo-acceptance-packet-v1",
    work_order_id: WORK_ORDER,
    gap_id: "RPL-008",
    receipt: {
      receipt_id: verified.receipt_id,
      captured_at: verified.captured_at,
      device_count: verified.device_count,
      receipt_file_sha256: verified.receipt_file_sha256,
      source_hashes: { ...verified.source_hashes },
    },
    receipt_validation: {
      status: verified.status,
      evidence_classification: CLASSIFICATION,
      provenance_qualification: QUALIFICATION,
      temporal_qualification: "capture_time_preserved; no_official_receipt_ttl_established",
      snapshot_qualification: SNAPSHOT_QUALIFICATION,
    },
    video: { status: "MISSING", receipt_id: verified.receipt_id, evidence_sha256: null },
    operator: { status: "NOT_ACCEPTED", receipt_id: verified.receipt_id, evidence_sha256: null },
    decision: {
      live_evidence_accepted: false,
      productionAdmitted: false,
      gap_status: "OPEN",
      missing: ["VIDEO_EVIDENCE", "OPERATOR_ACCEPTANCE", "INDEPENDENT_LIVE_TRANSPORT_REVIEW"],
    },
  };
  const packet = freeze({ ...draft, packet_id: `sha256:${hash(canonical(draft))}` });
  PACKET_SNAPSHOTS.set(packet, snapshot);
  return packet;
}

export async function verifyPendingRingAcceptancePacket(serializedPacket, readback) {
  if (arguments.length !== 2) fail("PACKET_ARGUMENTS_INVALID");
  requireReadback(readback);
  const actual = parseStrict(serializedPacket);
  const expected = await createPendingRingAcceptancePacket(readback);
  assertJointSnapshotBarrier(PACKET_SNAPSHOTS.get(expected));
  if (canonical(actual) !== canonical(expected)) fail("PENDING_PACKET_MISMATCH");
  return freeze({ valid_pending_packet: true, live_evidence_accepted: false,
    productionAdmitted: false, gap_status: "OPEN", packet_id: expected.packet_id });
}
