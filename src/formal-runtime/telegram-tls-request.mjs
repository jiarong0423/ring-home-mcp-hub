import tls from 'node:tls';
import { types, TextDecoder } from 'node:util';
import { exactObject, denyFormalRuntime, zeroBinary, FormalRuntimeError } from './protocol.mjs';

const HOST = 'api.telegram.org';
const MAX_HEADER = 16_384;
const MAX_BODY = 1_048_576;
const MAX_WIRE = 2_097_152;
const TLS_OPTIONS = Object.freeze({ host: HOST, port: 443, servername: HOST,
  rejectUnauthorized: true, minVersion: 'TLSv1.2', ALPNProtocols: Object.freeze(['http/1.1']) });
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function exact(value, fields) {
  if (types.isProxy(value)) denyFormalRuntime('B02_TELEGRAM_TLS_INPUT_DENIED');
  return exactObject(value, fields, 'B02_TELEGRAM_TLS_INPUT_DENIED');
}
function options(value, testOnly) {
  if (!value || typeof value !== 'object' || types.isProxy(value)) denyFormalRuntime('B02_TELEGRAM_TLS_CONFIG_DENIED');
  const keys = Reflect.ownKeys(value);
  if (keys.some(key => !['maxCapacity', ...(testOnly ? ['connect'] : [])].includes(key))) {
    denyFormalRuntime('B02_TELEGRAM_TLS_CONFIG_DENIED');
  }
  exact(value, keys);
  const maxCapacity = Object.hasOwn(value, 'maxCapacity') ? value.maxCapacity : 8;
  if (!Number.isSafeInteger(maxCapacity) || maxCapacity < 1 || maxCapacity > 64 ||
      (testOnly && (typeof value.connect !== 'function' || types.isProxy(value.connect)))) {
    denyFormalRuntime('B02_TELEGRAM_TLS_CONFIG_DENIED');
  }
  return { maxCapacity, connect: testOnly ? value.connect : nativeConnect };
}
function nativeConnect() { return tls.connect(TLS_OPTIONS); }

function requestWire(input) {
  const fields = exact(input, ['method', 'params', 'token', 'timeoutMs']);
  if (!['getMe', 'getUpdates'].includes(fields.method) || !Number.isSafeInteger(fields.timeoutMs) ||
      fields.timeoutMs < 100 || fields.timeoutMs > 30_000 || types.isProxy(fields.token) ||
      !Buffer.isBuffer(fields.token) || fields.token.length < 8 || fields.token.length > 4096) {
    denyFormalRuntime('B02_TELEGRAM_TLS_INPUT_DENIED');
  }
  let colon = -1;
  for (let n = 0; n < fields.token.length; n += 1) {
    const byte = fields.token[n];
    if (byte === 58) {
      if (colon !== -1) denyFormalRuntime('B02_TELEGRAM_TLS_TOKEN_DENIED');
      colon = n;
    } else if (!((byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90) ||
                 (byte >= 97 && byte <= 122) || byte === 95 || byte === 45)) {
      denyFormalRuntime('B02_TELEGRAM_TLS_TOKEN_DENIED');
    }
  }
  if (colon < 1 || colon > 20 || colon === fields.token.length - 1 || fields.token[0] === 48 ||
      fields.token.subarray(0, colon).some(byte => byte < 48 || byte > 57)) {
    denyFormalRuntime('B02_TELEGRAM_TLS_TOKEN_DENIED');
  }
  const params = exact(fields.params, fields.method === 'getMe' ? [] : ['offset', 'limit']);
  if (fields.method === 'getUpdates' && (!Number.isSafeInteger(params.offset) || params.offset < 0 ||
      params.offset >= Number.MAX_SAFE_INTEGER || !Number.isSafeInteger(params.limit) || params.limit < 1 || params.limit > 100)) {
    denyFormalRuntime('B02_TELEGRAM_TLS_PARAMS_DENIED');
  }
  const body = Buffer.from(JSON.stringify(params), 'utf8');
  const prefix = Buffer.from('POST /bot', 'ascii');
  const suffix = Buffer.from(`/${fields.method} HTTP/1.1\r\nHost: ${HOST}\r\nConnection: close\r\n` +
    'Accept: application/json\r\nAccept-Encoding: identity\r\nContent-Type: application/json\r\n' +
    `Content-Length: ${body.length}\r\n\r\n`, 'ascii');
  const wire = Buffer.alloc(prefix.length + fields.token.length + suffix.length + body.length);
  let at = prefix.copy(wire);
  at += fields.token.copy(wire, at);
  at += suffix.copy(wire, at);
  body.copy(wire, at);
  return { wire, method: fields.method, timeoutMs: fields.timeoutMs };
}

function headerLines(buffer) {
  if (buffer.length > MAX_HEADER || buffer.some(byte => byte > 126 ||
      (byte < 32 && ![9, 10, 13].includes(byte)))) denyFormalRuntime('B02_TELEGRAM_TLS_RESPONSE_DENIED');
  const lines = buffer.toString('ascii').split('\r\n');
  const headers = new Map();
  for (const line of lines) {
    const match = /^([!#$%&'*+.^_`|~0-9A-Za-z-]+):[ \t]*([^\r\n]*)$/.exec(line);
    if (!match) denyFormalRuntime('B02_TELEGRAM_TLS_RESPONSE_DENIED');
    const name = match[1].toLowerCase();
    if (headers.has(name)) denyFormalRuntime('B02_TELEGRAM_TLS_RESPONSE_DENIED');
    headers.set(name, match[2].trim());
  }
  return headers;
}
function chunkedBody(raw) {
  let at = 0;
  let size = 0;
  let count = 0;
  const parts = [];
  while (at < raw.length) {
    if (++count > 65_536) denyFormalRuntime('B02_TELEGRAM_TLS_RESPONSE_DENIED');
    const end = raw.indexOf('\r\n', at, 'ascii');
    if (end < at || end - at > 8) denyFormalRuntime('B02_TELEGRAM_TLS_RESPONSE_DENIED');
    const labelBytes = raw.subarray(at, end);
    if (labelBytes.some(byte => byte > 127)) denyFormalRuntime('B02_TELEGRAM_TLS_RESPONSE_DENIED');
    const label = labelBytes.toString('ascii');
    if (!/^[0-9A-Fa-f]{1,8}$/.test(label)) denyFormalRuntime('B02_TELEGRAM_TLS_RESPONSE_DENIED');
    const length = Number.parseInt(label, 16);
    at = end + 2;
    if (length === 0) {
      if (raw[at] === 13 && raw[at + 1] === 10) {
        if (at + 2 !== raw.length) denyFormalRuntime('B02_TELEGRAM_TLS_RESPONSE_DENIED');
      } else {
        const trailerEnd = raw.indexOf('\r\n\r\n', at, 'ascii');
        if (trailerEnd < at || trailerEnd + 4 !== raw.length) denyFormalRuntime('B02_TELEGRAM_TLS_RESPONSE_DENIED');
        const trailers = headerLines(raw.subarray(at, trailerEnd));
        if (['content-length', 'transfer-encoding', 'content-type', 'content-encoding'].some(name => trailers.has(name))) {
          denyFormalRuntime('B02_TELEGRAM_TLS_RESPONSE_DENIED');
        }
      }
      return Buffer.concat(parts, size);
    }
    size += length;
    if (size > MAX_BODY || at + length + 2 > raw.length || raw[at + length] !== 13 || raw[at + length + 1] !== 10) {
      denyFormalRuntime('B02_TELEGRAM_TLS_RESPONSE_DENIED');
    }
    parts.push(raw.subarray(at, at + length));
    at += length + 2;
  }
  denyFormalRuntime('B02_TELEGRAM_TLS_RESPONSE_DENIED');
}
function strictJson(body) {
  if (body.length === 0 || body.length > MAX_BODY ||
      (body[0] === 239 && body[1] === 187 && body[2] === 191)) denyFormalRuntime('B02_TELEGRAM_TLS_RESPONSE_DENIED');
  const text = utf8.decode(body);
  const value = JSON.parse(text);
  const stack = [];
  for (let at = 0; at < text.length; at += 1) {
    const char = text[at];
    if (char === '{' || char === '[') {
      if (stack.length >= 64) denyFormalRuntime('B02_TELEGRAM_TLS_RESPONSE_DENIED');
      stack.push(char === '{' ? new Set() : null);
    } else if (char === '}' || char === ']') stack.pop();
    else if (char === '"') {
      const start = at;
      for (at += 1; at < text.length; at += 1) {
        if (text[at] === '\\') at += 1;
        else if (text[at] === '"') break;
      }
      let next = at + 1;
      while (/\s/.test(text[next] ?? '') && next < text.length) next += 1;
      if (text[next] === ':') {
        const keys = stack[stack.length - 1];
        const key = JSON.parse(text.slice(start, at + 1));
        if (!keys || keys.has(key)) denyFormalRuntime('B02_TELEGRAM_TLS_RESPONSE_DENIED');
        keys.add(key);
      }
    }
  }
  return value;
}
function response(chunks, method) {
  const raw = Buffer.concat(chunks);
  let body;
  try {
    const boundary = raw.indexOf('\r\n\r\n', 0, 'ascii');
    const first = raw.indexOf('\r\n', 0, 'ascii');
    if (boundary < 0 || boundary > MAX_HEADER || first < 0 || first >= boundary ||
        raw.subarray(0, first).some(byte => byte < 32 || byte > 126) ||
        !/^HTTP\/1\.1 200(?: [\x20-\x7e]*)?$/.test(raw.subarray(0, first).toString('ascii'))) {
      denyFormalRuntime('B02_TELEGRAM_TLS_RESPONSE_DENIED');
    }
    const headers = headerLines(raw.subarray(first + 2, boundary));
    if (!/^application\/json(?:;\s*charset=utf-8)?$/i.test(headers.get('content-type') ?? '') ||
        (headers.has('content-encoding') && headers.get('content-encoding').toLowerCase() !== 'identity')) {
      denyFormalRuntime('B02_TELEGRAM_TLS_RESPONSE_DENIED');
    }
    const payload = raw.subarray(boundary + 4);
    const length = headers.get('content-length');
    const transfer = headers.get('transfer-encoding');
    if (length !== undefined && transfer !== undefined) denyFormalRuntime('B02_TELEGRAM_TLS_RESPONSE_DENIED');
    if (transfer !== undefined) {
      if (transfer.toLowerCase() !== 'chunked') denyFormalRuntime('B02_TELEGRAM_TLS_RESPONSE_DENIED');
      body = chunkedBody(payload);
    } else {
      if (length === undefined || !/^(?:0|[1-9][0-9]{0,6})$/.test(length) ||
          Number(length) > MAX_BODY || Number(length) !== payload.length) denyFormalRuntime('B02_TELEGRAM_TLS_RESPONSE_DENIED');
      body = Buffer.from(payload);
    }
    const value = strictJson(body);
    if (!value || typeof value !== 'object' || Array.isArray(value) || value.ok !== true ||
        !Object.hasOwn(value, 'result') || (method === 'getUpdates' ? !Array.isArray(value.result) :
          !value.result || typeof value.result !== 'object' || Array.isArray(value.result))) {
      denyFormalRuntime('B02_TELEGRAM_TLS_RESPONSE_DENIED');
    }
    return value;
  } finally { zeroBinary(body); zeroBinary(raw); }
}

function createPort(config, testOnly) {
  let closed = false;
  const jobs = new Set();
  return Object.freeze({
    testOnly,
    async request(input) {
      if (closed) denyFormalRuntime('B02_TELEGRAM_TLS_CLOSED');
      if (jobs.size >= config.maxCapacity) denyFormalRuntime('B02_TELEGRAM_TLS_CAPACITY_DENIED');
      const encoded = requestWire(input);
      return new Promise((resolve, reject) => {
        const job = { socket: null, wire: encoded.wire, chunks: [], bytes: 0, settled: false, secured: false, timer: null };
        jobs.add(job);
        function zeroOwned() { zeroBinary(job.wire); for (const chunk of job.chunks) zeroBinary(chunk); job.chunks.length = 0; }
        function settle(code, value) {
          if (job.settled) return;
          job.settled = true;
          clearTimeout(job.timer);
          zeroOwned();
          if (code) reject(new FormalRuntimeError(code)); else resolve(value);
        }
        function destroy() { try { job.socket?.destroy(); } catch {} }
        job.abort = () => { settle('B02_TELEGRAM_TLS_CLOSED'); destroy(); };
        job.timer = setTimeout(() => { settle('B02_TELEGRAM_TLS_TIMEOUT'); destroy(); }, encoded.timeoutMs);
        try {
          job.socket = config.connect(TLS_OPTIONS);
          if (!job.socket || typeof job.socket.on !== 'function' || typeof job.socket.write !== 'function' ||
              typeof job.socket.destroy !== 'function') throw new Error('invalid-socket');
          const socket = job.socket;
          socket.on('error', () => { settle('B02_TELEGRAM_TLS_TRANSPORT_DENIED'); destroy(); });
          socket.on('close', () => {
            settle('B02_TELEGRAM_TLS_TRANSPORT_DENIED');
            zeroOwned();
            jobs.delete(job);
          });
          socket.on('secureConnect', () => {
            if (job.secured || job.settled || closed) { job.abort(); return; }
            if (socket.authorized !== true || (socket.alpnProtocol && socket.alpnProtocol !== 'http/1.1')) {
              settle('B02_TELEGRAM_TLS_TRANSPORT_DENIED'); destroy(); return;
            }
            job.secured = true;
            try {
              socket.write(job.wire, error => {
                zeroBinary(job.wire);
                if (error) { settle('B02_TELEGRAM_TLS_TRANSPORT_DENIED'); destroy(); }
              });
            } catch { settle('B02_TELEGRAM_TLS_TRANSPORT_DENIED'); destroy(); }
          });
          socket.on('data', chunk => {
            if (job.settled) return;
            if (!job.secured || !Buffer.isBuffer(chunk) || types.isProxy(chunk) ||
                chunk.length > MAX_WIRE - job.bytes || job.chunks.length >= 65_536) {
              settle('B02_TELEGRAM_TLS_RESPONSE_DENIED'); destroy(); return;
            }
            if (chunk.length) { job.bytes += chunk.length; job.chunks.push(Buffer.from(chunk)); }
          });
          socket.on('end', () => {
            if (job.settled) return;
            if (!job.secured || closed) { job.abort(); return; }
            try { settle(null, response(job.chunks, encoded.method)); }
            catch { settle('B02_TELEGRAM_TLS_RESPONSE_DENIED'); }
            destroy();
          });
        } catch {
          settle('B02_TELEGRAM_TLS_TRANSPORT_DENIED');
          if (job.socket) destroy(); else jobs.delete(job);
        }
      });
    },
    close() {
      closed = true;
      for (const job of jobs) job.abort();
      return Object.freeze({ closed, inFlight: jobs.size, resourceReleased: jobs.size === 0 });
    },
    status() { return Object.freeze({ closed, inFlight: jobs.size, resourceReleased: closed && jobs.size === 0 }); }
  });
}

export function createTelegramTlsRequest(config = {}) { return createPort(options(config, false), false); }

// Explicit isolated test seam. This factory supplies no production admission authority.
export function createTelegramTlsRequestForTest(config) { return createPort(options(config, true), true); }
