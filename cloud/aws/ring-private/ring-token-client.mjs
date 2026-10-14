import { request as httpsRequest } from 'node:https';

// Token-only Ring client for the owner bootstrap. It holds no client id/secret: it presents a caller-supplied,
// Ring-issued OAuth access token (Ring Playground sandbox) to Ring's Users API and returns the Ring account id
// from the JSON:API document. It never logs and never echoes the token, request headers or the response body.
export const RING_USERS_ME_URL = 'https://api.amazonvision.com/v1/users/me';
export const RING_ACCESS_TOKEN_MAX_LENGTH = 8192;
export const RING_ACCESS_TOKEN_PATTERN = /^[A-Za-z0-9._~+/=-]{1,8192}$/u;
const MAX_RESPONSE_BYTES = 32768;
const MAX_ACCOUNT_ID_LENGTH = 256;
const TOTAL_TIMEOUT_MS = 3000;
function deny() { throw new TypeError('ring_token_denied'); }
// 401/403 from Ring is the only DEFINITE rejection of the presented token; every other failure is indeterminate ('ring_token_denied').

export function createRingTokenClient({ requestImpl = httpsRequest, timeoutMs = TOTAL_TIMEOUT_MS } = {}) {
  if (typeof requestImpl !== 'function' || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > TOTAL_TIMEOUT_MS) deny();
  return Object.freeze({ async getAccountId(accessToken) {
    if (typeof accessToken !== 'string' || !RING_ACCESS_TOKEN_PATTERN.test(accessToken)) deny();
    return new Promise((resolve, reject) => {
      let done = false;
      let req;
      let timer;
      const finish = (error, value) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        try { req?.destroy(); } catch { /* the outcome is already decided */ }
        if (error) reject(new TypeError(error === 'rejected' ? 'ring_token_rejected' : 'ring_token_denied')); else resolve(value);
      };
      timer = setTimeout(() => finish(true), timeoutMs);
      try {
        req = requestImpl(new URL(RING_USERS_ME_URL), { method: 'GET', minVersion: 'TLSv1.2', rejectUnauthorized: true, timeout: timeoutMs,
          headers: { authorization: `Bearer ${accessToken}`, accept: 'application/json', 'user-agent': 'ring-home-mcp-hub/1.0' } }, res => {
          // Anything other than a plain 200 (including every 3xx) is a denial; redirects are never followed.
          if (res.statusCode !== 200) { res.resume(); finish(res.statusCode === 401 || res.statusCode === 403 ? 'rejected' : true); return; }
          const declared = Number(res.headers?.['content-length']);
          if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) { res.destroy?.(); finish(true); return; }
          let bytes = 0;
          const chunks = [];
          res.on('data', chunk => {
            bytes += chunk.length;
            if (bytes > MAX_RESPONSE_BYTES) { res.destroy?.(); finish(true); } else chunks.push(chunk);
          });
          res.on('error', () => finish(true));
          res.on('end', () => {
            try {
              const document = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
              const data = document?.data;
              if (!data || typeof data !== 'object' || Array.isArray(data) || data.type !== 'users' || typeof data.id !== 'string' ||
                  data.id.length < 1 || data.id.length > MAX_ACCOUNT_ID_LENGTH) { finish(true); return; }
              finish(false, data.id);
            } catch { finish(true); }
          });
        });
        req.on('timeout', () => finish(true));
        req.on('error', () => finish(true));
        req.end();
      } catch { finish(true); }
    });
  } });
}
