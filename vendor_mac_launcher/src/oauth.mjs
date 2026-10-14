import { randomBytes, createHash } from 'node:crypto';
import { request as httpsRequest } from 'node:https';
import { join } from 'node:path';
import { coded } from './config.mjs';
import { writeSecretFile, readSecretFile } from './state.mjs';

const PENDING = 'pkce-pending.json';
const B64U43 = /^[A-Za-z0-9_-]{43}$/u;
export const PKCE_TTL_MS = 600_000;

// Builds the Cognito authorize URL. The verifier is returned only inside `record` (persisted 0600 by the caller), never in the URL.
export function buildLogin(cfg, { now = Date.now(), random = randomBytes } = {}) {
  const verifier = random(32).toString('base64url');
  const state = random(32).toString('base64url');
  const url = new URL(cfg.authorizeUrl);
  url.search = new URLSearchParams({ response_type: 'code', client_id: cfg.clientId, redirect_uri: cfg.redirectUri,
    scope: cfg.scopes.join(' '), state, code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256', resource: cfg.resource }).toString();
  return { url: url.href, record: { schema: 'ring-mac-pkce-pending-v1', state, verifier, createdAt: now, expiresAt: now + PKCE_TTL_MS, consumed: false } };
}
export async function savePending(dirs, record) { await writeSecretFile(join(dirs.oauth, PENDING), JSON.stringify(record)); }
export async function readPending(dirs) {
  const text = await readSecretFile(join(dirs.oauth, PENDING));
  if (text === null) return null;
  try { return JSON.parse(text); } catch { throw coded('PKCE_STATE_CORRUPT'); }
}
// Single use: the verifier is blanked before the code is exchanged, so a retry always needs a fresh login-url.
export async function consumePending(dirs, { now = Date.now() } = {}) {
  const p = await readPending(dirs);
  if (!p || p.schema !== 'ring-mac-pkce-pending-v1' || p.consumed === true || !B64U43.test(p.state ?? '') || !B64U43.test(p.verifier ?? '')) throw coded('PKCE_NOT_PENDING');
  if (!Number.isSafeInteger(p.expiresAt) || now >= p.expiresAt) throw coded('PKCE_EXPIRED');
  await writeSecretFile(join(dirs.oauth, PENDING), JSON.stringify({ schema: p.schema, state: p.state, verifier: '', createdAt: p.createdAt, expiresAt: p.expiresAt, consumed: true }));
  return { state: p.state, verifier: p.verifier };
}
export function parseCallbackUrl(value, cfg) {
  let u; try { u = new URL(value); } catch { throw coded('CALLBACK_URL_INVALID'); }
  if (u.origin + u.pathname !== cfg.redirectUri || u.username || u.password || u.hash) throw coded('CALLBACK_URL_INVALID');
  const keys = [...u.searchParams.keys()];
  if (u.searchParams.has('error')) { const e = u.searchParams.get('error'); throw coded('CALLBACK_LOGIN_ERROR_' + (/^[a-z_]{1,40}$/u.test(e) ? e : 'unknown')); }
  if (keys.length !== 2 || !u.searchParams.has('code') || !u.searchParams.has('state')) throw coded('CALLBACK_URL_INVALID');
  const code = u.searchParams.get('code'), state = u.searchParams.get('state');
  if (!/^[A-Za-z0-9._~-]{1,2048}$/u.test(code) || !B64U43.test(state)) throw coded('CALLBACK_URL_INVALID');
  return { code, state };
}
function jwtExpMs(token) {
  try { const exp = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')).exp; return Number.isSafeInteger(exp) ? exp * 1000 : null; } catch { return null; }
}
// Public-client PKCE exchange (same body shape as the cloud's own createCognitoCodeExchange). The returned token lives in memory only.
export function exchangeCode(cfg, { code, verifier }, { requestImpl = httpsRequest, timeoutMs = 5000, now = Date.now } = {}) {
  const body = new URLSearchParams({ grant_type: 'authorization_code', client_id: cfg.clientId, redirect_uri: cfg.redirectUri, code, code_verifier: verifier }).toString();
  return new Promise((resolve, reject) => {
    let done = false; let req;
    const finish = (err, val) => { if (done) return; done = true; clearTimeout(timer); if (err) { req?.destroy(); reject(coded(err)); } else resolve(val); };
    const timer = setTimeout(() => finish('OAUTH_TOKEN_TIMEOUT'), timeoutMs);
    try {
      req = requestImpl(new URL(cfg.tokenUrl), { method: 'POST', minVersion: 'TLSv1.2', rejectUnauthorized: true,
        headers: { 'content-type': 'application/x-www-form-urlencoded', 'content-length': Buffer.byteLength(body), accept: 'application/json' } }, res => {
        const chunks = []; let size = 0;
        res.on('data', c => { size += c.length; if (size > 65536) { res.destroy(); finish('OAUTH_TOKEN_RESPONSE_SIZE'); } else chunks.push(c); });
        res.on('error', () => finish('OAUTH_TOKEN_UNAVAILABLE'));
        res.on('end', () => {
          let json; try { json = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return finish('OAUTH_TOKEN_RESPONSE_JSON'); }
          if (res.statusCode !== 200) return finish('OAUTH_TOKEN_HTTP_' + res.statusCode + (typeof json?.error === 'string' && /^[a-z_]{1,40}$/u.test(json.error) ? '_' + json.error : ''));
          const t = json?.access_token;
          if (typeof t !== 'string' || t.length < 16 || t.length > 16384 || /[\s\x00-\x1f\x7f]/u.test(t) || !(json.token_type === undefined || /^bearer$/iu.test(json.token_type))) return finish('OAUTH_TOKEN_RESPONSE');
          const lifeMs = Number.isSafeInteger(json.expires_in) && json.expires_in > 0 ? json.expires_in * 1000 : 300000;
          const exp = Math.min(now() + lifeMs, jwtExpMs(t) ?? Infinity);
          finish(null, { accessToken: t, expiresAtMs: exp });   // id_token / refresh_token in the response are discarded unread
        });
      });
      req.on('error', () => finish('OAUTH_TOKEN_UNAVAILABLE'));
      req.end(body);
    } catch { finish('OAUTH_TOKEN_UNAVAILABLE'); }
  });
}
