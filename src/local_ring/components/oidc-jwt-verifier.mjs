import { createHash, createPublicKey, verify as verifySignature, constants } from 'node:crypto';
import { TextDecoder } from 'node:util';

const MAX_TOKEN_BYTES = 16384;
const MAX_HEADER_BYTES = 2048;
const MAX_PAYLOAD_BYTES = 8192;
const MAX_JSON_DEPTH = 16;
const MAX_JSON_MEMBERS = 128;
const MAX_JWKS_KEYS = 16;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const KID = /^[A-Za-z0-9._~+/=-]{1,128}$/;
const VERSION_MAX = Number.MAX_SAFE_INTEGER;
const UTF8 = new TextDecoder('utf-8', { fatal: true });

export class OidcVerificationError extends Error {
  constructor(code) {
    super(code);
    this.name = 'OidcVerificationError';
    this.code = code;
  }
}

function fail(code) { throw new OidcVerificationError(code); }
function safeSecond(value) { return Number.isSafeInteger(value) && value >= 0; }
function safeText(value, maximum = 1024) {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}
function own(value, allowed, required, code) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value) ||
        Object.getPrototypeOf(value) !== Object.prototype) fail(code);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(value);
    if (keys.some(key => typeof key !== 'string' || !allowed.includes(key)) ||
        required.some(key => !Object.hasOwn(descriptors, key))) fail(code);
    const copy = Object.create(null);
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) fail(code);
      copy[key] = descriptor.value;
    }
    return copy;
  } catch (error) {
    if (error instanceof OidcVerificationError) throw error;
    fail(code);
  }
}
function plainArray(value, minimum, maximum, code) {
  try {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype ||
        value.length < minimum || value.length > maximum) fail(code);
    const keys = Reflect.ownKeys(value);
    if (keys.length !== value.length + 1 || keys.some(key =>
      key !== 'length' && (typeof key !== 'string' || !/^(0|[1-9][0-9]*)$/u.test(key) ||
        Number(key) >= value.length))) fail(code);
    const copy = [];
    for (let index = 0; index < value.length; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) fail(code);
      copy.push(descriptor.value);
    }
    return copy;
  } catch (error) {
    if (error instanceof OidcVerificationError) throw error;
    fail(code);
  }
}
function canonicalBase64url(segment, limit, code) {
  if (typeof segment !== 'string' || segment.length === 0 ||
      segment.length > Math.ceil(limit * 4 / 3) + 4 || !BASE64URL.test(segment)) fail(code);
  let bytes;
  try { bytes = Buffer.from(segment, 'base64url'); } catch { fail(code); }
  if (bytes.length === 0 || bytes.length > limit || bytes.toString('base64url') !== segment) fail(code);
  return bytes;
}
function wellFormed(value) {
  return Buffer.from(value, 'utf8').toString('utf8') === value;
}
function strictJson(bytes, code) {
  let source;
  try { source = UTF8.decode(bytes); } catch { fail(code); }
  if (!source || source.charCodeAt(0) === 0xfeff) fail(code);
  let offset = 0;
  const whitespace = () => {
    while (offset < source.length && /[ \t\r\n]/u.test(source[offset])) offset++;
  };
  const string = () => {
    if (source[offset] !== '"') throw new SyntaxError('string');
    const start = offset++;
    while (offset < source.length) {
      const character = source[offset];
      if (character === '"') {
        offset++;
        const decoded = JSON.parse(source.slice(start, offset));
        if (!wellFormed(decoded)) throw new SyntaxError('surrogate');
        return decoded;
      }
      if (character === '\\') {
        offset++;
        const escape = source[offset];
        if (escape === 'u') {
          if (!/^[a-fA-F0-9]{4}$/u.test(source.slice(offset + 1, offset + 5))) {
            throw new SyntaxError('unicode_escape');
          }
          offset += 5;
        } else if (escape && '"\\/bfnrt'.includes(escape)) {
          offset++;
        } else {
          throw new SyntaxError('escape');
        }
      } else {
        if (source.charCodeAt(offset) < 0x20) throw new SyntaxError('control');
        offset++;
      }
    }
    throw new SyntaxError('unterminated_string');
  };
  const value = depth => {
    if (depth > MAX_JSON_DEPTH) throw new SyntaxError('depth');
    whitespace();
    const character = source[offset];
    if (character === '"') return string();
    if (character === '{') {
      offset++;
      whitespace();
      const result = Object.create(null);
      const names = new Set();
      if (source[offset] === '}') { offset++; return result; }
      let members = 0;
      while (offset < source.length) {
        if (++members > MAX_JSON_MEMBERS) throw new SyntaxError('members');
        const key = string();
        if (key === '__proto__' || key === 'prototype' || key === 'constructor' || names.has(key)) {
          throw new SyntaxError('key');
        }
        names.add(key);
        whitespace();
        if (source[offset++] !== ':') throw new SyntaxError('colon');
        result[key] = value(depth + 1);
        whitespace();
        if (source[offset] === '}') { offset++; return result; }
        if (source[offset++] !== ',') throw new SyntaxError('comma');
        whitespace();
      }
      throw new SyntaxError('object');
    }
    if (character === '[') {
      offset++;
      whitespace();
      const result = [];
      if (source[offset] === ']') { offset++; return result; }
      while (offset < source.length) {
        if (result.length >= MAX_JSON_MEMBERS) throw new SyntaxError('items');
        result.push(value(depth + 1));
        whitespace();
        if (source[offset] === ']') { offset++; return result; }
        if (source[offset++] !== ',') throw new SyntaxError('comma');
      }
      throw new SyntaxError('array');
    }
    for (const [literal, parsed] of [['true', true], ['false', false], ['null', null]]) {
      if (source.startsWith(literal, offset)) { offset += literal.length; return parsed; }
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(source.slice(offset));
    if (number) {
      offset += number[0].length;
      const parsed = Number(number[0]);
      if (!Number.isFinite(parsed)) throw new SyntaxError('number');
      return parsed;
    }
    throw new SyntaxError('value');
  };
  try {
    const parsed = value(0);
    whitespace();
    if (offset !== source.length || parsed === null || Array.isArray(parsed) ||
        typeof parsed !== 'object') throw new SyntaxError('root');
    return parsed;
  } catch { fail(code); }
}
function validIssuer(value) {
  if (!safeText(value, 1024) || value.endsWith('/')) return false;
  try {
    const uri = new URL(value);
    return uri.protocol === 'https:' && uri.username === '' && uri.password === '' &&
      uri.search === '' && uri.hash === '' && uri.pathname !== '/' && uri.toString() === value;
  } catch { return false; }
}
function modulusBits(bytes) {
  if (bytes.length === 0 || bytes[0] === 0) return 0;
  return (bytes.length - 1) * 8 + Math.floor(Math.log2(bytes[0])) + 1;
}
function publicKey(record) {
  const key = own(record, ['kid','kty','alg','use','key_ops','n','e'],
    ['kid','kty','alg','use','n','e'], 'jwks_invalid');
  if (typeof key.kid !== 'string' || !KID.test(key.kid) ||
      key.kty !== 'RSA' || key.alg !== 'RS256' || key.use !== 'sig') {
    fail('jwks_invalid');
  }
  if (Object.hasOwn(key, 'key_ops')) {
    const operations = plainArray(key.key_ops, 1, 1, 'jwks_invalid');
    if (operations[0] !== 'verify') fail('jwks_invalid');
  }
  const modulus = canonicalBase64url(key.n, 1024, 'jwks_invalid');
  const exponent = canonicalBase64url(key.e, 4, 'jwks_invalid');
  const bits = modulusBits(modulus);
  if (bits < 2048 || bits > 8192 || exponent[0] === 0) fail('jwks_invalid');
  let exponentValue = 0;
  for (const byte of exponent) exponentValue = exponentValue * 256 + byte;
  if (exponentValue < 3 || exponentValue % 2 !== 1) fail('jwks_invalid');
  let imported;
  try {
    imported = createPublicKey({ key: { kty: 'RSA', n: key.n, e: key.e }, format: 'jwk' });
  } catch { fail('jwks_invalid'); }
  if (imported.asymmetricKeyType !== 'rsa') fail('jwks_invalid');
  return { kid: key.kid, n: key.n, e: key.e, imported, signatureBytes: modulus.length };
}

function createPinnedJwtCore(cfg) {
  let lastNow = -1;
  let lastVersion = 0;
  let lastFingerprint = null;
  const now = floor => {
    let current;
    try { current = cfg.clock(); } catch { fail('clock_unknown'); }
    if (!safeSecond(current)) fail('clock_unknown');
    if (current < lastNow || (floor !== undefined && current < floor)) fail('clock_regressed');
    lastNow = current;
    return current;
  };
  const verifiedSnapshot = (untrusted, current) => {
    const snapshot = own(untrusted,
      ['jwksUri','snapshotVersion','fetchedAtSeconds','expiresAtSeconds','keys'],
      ['jwksUri','snapshotVersion','fetchedAtSeconds','expiresAtSeconds','keys'],
      'jwks_invalid');
    if (snapshot.jwksUri !== cfg.jwksUri || !Number.isSafeInteger(snapshot.snapshotVersion) ||
        snapshot.snapshotVersion < 1 || snapshot.snapshotVersion > VERSION_MAX ||
        !safeSecond(snapshot.fetchedAtSeconds) || !safeSecond(snapshot.expiresAtSeconds) ||
        !Array.isArray(snapshot.keys)) fail('jwks_invalid');
    if (snapshot.fetchedAtSeconds > current || snapshot.expiresAtSeconds <= current ||
        snapshot.expiresAtSeconds <= snapshot.fetchedAtSeconds ||
        snapshot.expiresAtSeconds - snapshot.fetchedAtSeconds > cfg.maxJwksAgeSeconds) {
      fail('jwks_stale');
    }
    const keys = plainArray(snapshot.keys, 1, MAX_JWKS_KEYS, 'jwks_invalid').map(publicKey);
    if (new Set(keys.map(key => key.kid)).size !== keys.length) fail('jwks_invalid');
    const fingerprint = createHash('sha256').update(JSON.stringify(keys
      .map(key => [key.kid, key.n, key.e]).sort((a, b) => a[0].localeCompare(b[0])))).digest('hex');
    if (snapshot.snapshotVersion < lastVersion ||
        (snapshot.snapshotVersion === lastVersion && fingerprint !== lastFingerprint)) {
      fail('jwks_stale');
    }
    lastVersion = snapshot.snapshotVersion;
    lastFingerprint = fingerprint;
    return { keys, expiresAtSeconds: snapshot.expiresAtSeconds };
  };
  const verifyCompactJwt = async (token, acceptedTypes) => {
    const started = now();
    const segments = token.split('.');
    if (segments.length !== 3) fail('jwt_invalid');
    const headerBytes = canonicalBase64url(segments[0], MAX_HEADER_BYTES, 'jwt_invalid');
    const payloadBytes = canonicalBase64url(segments[1], MAX_PAYLOAD_BYTES, 'jwt_invalid');
    const signature = canonicalBase64url(segments[2], 1024, 'jwt_invalid');
    const header = strictJson(headerBytes, 'jwt_invalid');
    const payload = strictJson(payloadBytes, 'jwt_invalid');
    if (Object.keys(header).some(key => !['alg','kid','typ'].includes(key)) ||
        header.alg !== 'RS256' || typeof header.kid !== 'string' || !KID.test(header.kid) ||
        !acceptedTypes.includes(header.typ)) {
      fail('jwt_invalid');
    }
    let loaded;
    try { loaded = await cfg.loadPinnedJwks({ jwksUri: cfg.jwksUri }); }
    catch { fail('jwks_unavailable'); }
    const afterLoader = now(started);
    const snapshot = verifiedSnapshot(loaded, afterLoader);
    const key = snapshot.keys.find(candidate => candidate.kid === header.kid);
    if (!key || signature.length !== key.signatureBytes) fail('jwt_invalid');
    const signingInput = `${segments[0]}.${segments[1]}`;
    let valid;
    try {
      valid = verifySignature('RSA-SHA256', Buffer.from(signingInput, 'ascii'),
        { key: key.imported, padding: constants.RSA_PKCS1_PADDING }, signature);
    } catch { fail('jwt_invalid'); }
    if (valid !== true) fail('jwt_invalid');
    const verifiedAt = now(afterLoader);
    if (verifiedAt >= snapshot.expiresAtSeconds) fail('jwks_stale');
    return { header, payload, verifiedAt };
  };
  return Object.freeze({ verifyCompactJwt });
}

export function createOidcJwtVerifier(options) {
  const cfg = own(options,
    ['issuer','clientId','ownerSubject','jwksUri','maxJwksAgeSeconds','loadPinnedJwks','clock'],
    ['issuer','clientId','ownerSubject','jwksUri','maxJwksAgeSeconds','loadPinnedJwks','clock'],
    'invalid_config');
  if (!validIssuer(cfg.issuer) || !safeText(cfg.clientId, 256) ||
      !safeText(cfg.ownerSubject, 256) || cfg.jwksUri !== `${cfg.issuer}/.well-known/jwks.json` ||
      !Number.isSafeInteger(cfg.maxJwksAgeSeconds) || cfg.maxJwksAgeSeconds < 1 ||
      cfg.maxJwksAgeSeconds > 86400 || typeof cfg.loadPinnedJwks !== 'function' ||
      typeof cfg.clock !== 'function') fail('invalid_config');

  const core = createPinnedJwtCore(cfg);

  const verifyIdentity = async input => {
    const request = own(input, ['idToken','issuer','clientId'],
      ['idToken','issuer','clientId'], 'invalid_input');
    if (request.issuer !== cfg.issuer || request.clientId !== cfg.clientId ||
        typeof request.idToken !== 'string' || request.idToken.length < 3 ||
        request.idToken.length > MAX_TOKEN_BYTES ||
        !/^[A-Za-z0-9._-]+$/u.test(request.idToken)) fail('invalid_input');
    const { payload, verifiedAt } = await core.verifyCompactJwt(request.idToken, [undefined, 'JWT']);
    if (Object.hasOwn(payload, 'tokenUse') || Object.hasOwn(payload, 'verified') ||
        payload.token_use !== 'id' || payload.iss !== cfg.issuer ||
        payload.aud !== cfg.clientId || payload.sub !== cfg.ownerSubject ||
        (payload.azp !== undefined && payload.azp !== cfg.clientId) ||
        !safeText(payload.nonce, 512) || !safeSecond(payload.exp) ||
        !safeSecond(payload.iat) || payload.exp <= verifiedAt ||
        payload.iat > verifiedAt || payload.iat >= payload.exp ||
        (payload.nbf !== undefined && (!safeSecond(payload.nbf) || payload.nbf > verifiedAt))) {
      fail('identity_invalid');
    }
    const claims = { verified: true, sub: payload.sub, iss: payload.iss,
      aud: payload.aud, exp: payload.exp, iat: payload.iat,
      tokenUse: 'id', nonce: payload.nonce };
    if (payload.azp !== undefined) claims.azp = payload.azp;
    return claims;
  };
  return Object.freeze({ verifyIdentity });
}

function validHttpsResource(value) {
  if (!safeText(value, 1024)) return false;
  try {
    const uri = new URL(value);
    return uri.protocol === 'https:' && uri.username === '' && uri.password === '' &&
      uri.hash === '' && uri.toString() === value;
  } catch { return false; }
}

function scopeSet(value, code) {
  const scopes = plainArray(value, 1, 32, code);
  if (scopes.some(scope => typeof scope !== 'string' || scope.length > 128 ||
      !/^[\x21\x23-\x5B\x5D-\x7E]+$/u.test(scope)) || new Set(scopes).size !== scopes.length) {
    fail(code);
  }
  return scopes;
}

export function createOidcAccessTokenVerifier(options) {
  const cfg = own(options,
    ['issuer','resource','audience','requiredScopes','jwksUri','maxJwksAgeSeconds',
      'maximumTokenLifetimeSeconds','loadPinnedJwks','clock'],
    ['issuer','resource','audience','requiredScopes','jwksUri','maxJwksAgeSeconds',
      'maximumTokenLifetimeSeconds','loadPinnedJwks','clock'],
    'invalid_config');
  const requiredScopes = scopeSet(cfg.requiredScopes, 'invalid_config');
  if (!validIssuer(cfg.issuer) || !validHttpsResource(cfg.resource) || !safeText(cfg.audience, 256) ||
      cfg.jwksUri !== `${cfg.issuer}/.well-known/jwks.json` ||
      !Number.isSafeInteger(cfg.maxJwksAgeSeconds) || cfg.maxJwksAgeSeconds < 1 ||
      cfg.maxJwksAgeSeconds > 86400 || !Number.isSafeInteger(cfg.maximumTokenLifetimeSeconds) ||
      cfg.maximumTokenLifetimeSeconds < 1 || cfg.maximumTokenLifetimeSeconds > 3600 ||
      typeof cfg.loadPinnedJwks !== 'function' || typeof cfg.clock !== 'function') {
    fail('invalid_config');
  }
  const core = createPinnedJwtCore(cfg);
  const verifyAccessToken = async input => {
    const request = own(input, ['accessToken'], ['accessToken'], 'invalid_input');
    if (typeof request.accessToken !== 'string' || request.accessToken.length < 3 ||
        request.accessToken.length > MAX_TOKEN_BYTES || !/^[A-Za-z0-9._-]+$/u.test(request.accessToken)) {
      fail('invalid_input');
    }
    const { payload, verifiedAt } = await core.verifyCompactJwt(request.accessToken, ['at+jwt']);
    let grantedScopes;
    if (typeof payload.scope === 'string' && payload.scope.length <= 2048 &&
        payload.scope === payload.scope.trim() && !payload.scope.includes('  ')) {
      grantedScopes = scopeSet(payload.scope.split(' '), 'access_invalid');
    } else {
      fail('access_invalid');
    }
    const required = [...requiredScopes].sort();
    const granted = [...grantedScopes].sort();
    if (Object.hasOwn(payload, 'tokenUse') || Object.hasOwn(payload, 'verified') ||
        payload.token_use !== 'access' ||
        payload.iss !== cfg.issuer || payload.aud !== cfg.audience ||
        payload.resource !== cfg.resource || !safeText(payload.sub, 256) ||
        !safeSecond(payload.exp) || !safeSecond(payload.iat) || payload.exp <= verifiedAt ||
        payload.iat > verifiedAt || payload.iat >= payload.exp ||
        payload.exp - payload.iat > cfg.maximumTokenLifetimeSeconds ||
        (payload.nbf !== undefined && (!safeSecond(payload.nbf) || payload.nbf > verifiedAt)) ||
        required.length !== granted.length || required.some((scope, index) => scope !== granted[index])) {
      fail('access_invalid');
    }
    return Object.freeze({ verified: true, tokenUse: 'access', sub: payload.sub,
      iss: payload.iss, aud: payload.aud, resource: payload.resource,
      scope: Object.freeze([...requiredScopes]), exp: payload.exp, iat: payload.iat });
  };
  return Object.freeze({ verifyAccessToken });
}

export function createCognitoResourceBoundAccessTokenVerifier(options) {
  const cfg = own(options,
    ['issuer','clientId','resource','requiredScopes','jwksUri','maxJwksAgeSeconds',
      'maximumTokenLifetimeSeconds','loadPinnedJwks','clock'],
    ['issuer','clientId','resource','requiredScopes','jwksUri','maxJwksAgeSeconds',
      'maximumTokenLifetimeSeconds','loadPinnedJwks','clock'],
    'invalid_config');
  const requiredScopes = scopeSet(cfg.requiredScopes, 'invalid_config');
  if (!validIssuer(cfg.issuer) || !safeText(cfg.clientId, 256) ||
      !validHttpsResource(cfg.resource) || cfg.jwksUri !== `${cfg.issuer}/.well-known/jwks.json` ||
      !Number.isSafeInteger(cfg.maxJwksAgeSeconds) || cfg.maxJwksAgeSeconds < 1 ||
      cfg.maxJwksAgeSeconds > 86400 || !Number.isSafeInteger(cfg.maximumTokenLifetimeSeconds) ||
      cfg.maximumTokenLifetimeSeconds < 1 || cfg.maximumTokenLifetimeSeconds > 300 ||
      typeof cfg.loadPinnedJwks !== 'function' || typeof cfg.clock !== 'function') {
    fail('invalid_config');
  }
  const core = createPinnedJwtCore(cfg);
  const verifyAccessToken = async input => {
    const request = own(input, ['accessToken'], ['accessToken'], 'invalid_input');
    if (typeof request.accessToken !== 'string' || request.accessToken.length < 3 ||
        request.accessToken.length > MAX_TOKEN_BYTES || !/^[A-Za-z0-9._-]+$/u.test(request.accessToken)) {
      fail('invalid_input');
    }
    const { payload, verifiedAt } = await core.verifyCompactJwt(request.accessToken, [undefined, 'JWT']);
    let grantedScopes;
    if (typeof payload.scope === 'string' && payload.scope.length <= 2048 &&
        payload.scope === payload.scope.trim() && !payload.scope.includes('  ')) {
      grantedScopes = scopeSet(payload.scope.split(' '), 'access_invalid');
    } else {
      fail('access_invalid');
    }
    const required = [...requiredScopes].sort();
    const granted = [...grantedScopes].sort();
    if (Object.hasOwn(payload, 'tokenUse') || Object.hasOwn(payload, 'verified') ||
        Object.hasOwn(payload, 'resource') || payload.token_use !== 'access' ||
        payload.iss !== cfg.issuer || payload.client_id !== cfg.clientId ||
        payload.aud !== cfg.resource || !safeText(payload.sub, 256) ||
        !safeSecond(payload.exp) || !safeSecond(payload.iat) || payload.exp <= verifiedAt ||
        payload.iat > verifiedAt || payload.iat >= payload.exp ||
        payload.exp - payload.iat > cfg.maximumTokenLifetimeSeconds ||
        (payload.nbf !== undefined && (!safeSecond(payload.nbf) || payload.nbf > verifiedAt)) ||
        required.length !== granted.length || required.some((scope, index) => scope !== granted[index])) {
      fail('access_invalid');
    }
    return Object.freeze({ verified: true, tokenUse: 'access', sub: payload.sub,
      iss: payload.iss, aud: payload.aud, resource: payload.aud,
      scope: Object.freeze([...requiredScopes]), exp: payload.exp, iat: payload.iat });
  };
  return Object.freeze({ verifyAccessToken });
}
