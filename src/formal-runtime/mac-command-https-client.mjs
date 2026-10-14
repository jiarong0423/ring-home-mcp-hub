import { MAC_PROOF_HEADER } from './mac-command-proof.mjs';
import { request as httpsRequest } from 'node:https';
import { receipt, deny } from './mac-command-contract.mjs';

export function createMacCommandHttpsClient({ baseUrl, expectedHostname, getAccessToken, proofSigner, timeoutMs = 2500, request = httpsRequest } = {}) {
  let base;
  try { base = new URL(baseUrl); } catch { deny('MAC_HTTPS_CONFIG'); }
  if (base.protocol !== 'https:' || base.hostname !== expectedHostname || !/^[a-z0-9]{10}\.execute-api\.[a-z0-9-]+\.amazonaws\.com$/u.test(expectedHostname) ||
      base.port && base.port !== '443' || base.username || base.password || base.search || base.hash || !/^\/[A-Za-z0-9_-]+\/?$/u.test(base.pathname) ||
      typeof getAccessToken !== 'function' || typeof request !== 'function' || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 3000) deny('MAC_HTTPS_CONFIG');
  const prefix = base.href.replace(/\/$/u, '');
  if (!proofSigner || typeof proofSigner.signRequest !== 'function' || proofSigner.audience !== prefix + '/mcp') deny('MAC_HTTPS_PROOF_CONFIG');
  async function post(path, payload) {
    const token = await getAccessToken();
    if (typeof token !== 'string' || token.length < 16 || token.length > 16_384 || /[\s\x00-\x1f\x7f]/u.test(token)) deny('MAC_HTTPS_AUTHORITY');
    const proof = proofSigner.signRequest({ operation: path.endsWith('/fetch') ? 'fetch' : 'receipt', token, payload });
    const body = Buffer.from(JSON.stringify(payload));
    if (body.length > 16_384) deny('MAC_HTTPS_PAYLOAD');
    return new Promise((resolve, reject) => {
      let finished = false; let req; let timer;
      function finish(error, value) {
        if (finished) return; finished = true; clearTimeout(timer);
        if (error) { req?.destroy(); reject(Object.assign(new Error(error), { code: error })); } else resolve(value);
      }
      try {
        req = request(new URL(prefix + path), { method: 'POST', minVersion: 'TLSv1.2', rejectUnauthorized: true,
          headers: { [MAC_PROOF_HEADER]: proof, authorization: 'Bearer ' + token, 'content-type': 'application/json', accept: 'application/json', 'content-length': String(body.length) } }, response => {
          if (response.statusCode !== 200 || !/^application\/json(?:;|$)/iu.test(response.headers['content-type'] ?? '')) {
            response.resume(); finish('MAC_HTTPS_RESPONSE'); return;
          }
          const chunks = []; let size = 0;
          response.on('data', chunk => { size += chunk.length; if (size > 65_536) { response.destroy(); finish('MAC_HTTPS_RESPONSE_SIZE'); } else chunks.push(chunk); });
          response.on('error', () => finish('MAC_HTTPS_RESPONSE'));
          response.on('aborted', () => finish('MAC_HTTPS_RESPONSE'));
          response.on('end', () => {
            if (finished) return;
            try { finish(null, JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { finish('MAC_HTTPS_RESPONSE_JSON'); }
          });
        });
        req.on('error', () => finish('MAC_HTTPS_UNAVAILABLE'));
        timer = setTimeout(() => finish('MAC_HTTPS_TIMEOUT'), timeoutMs);
        req.end(body);
      } catch { finish('MAC_HTTPS_UNAVAILABLE'); }
    });
  }
  return Object.freeze({ fetch: () => post('/mac/commands/fetch', {}), receipt: value => post('/mac/commands/receipt', receipt(value)) });
}
