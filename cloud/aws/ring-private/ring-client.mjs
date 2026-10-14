import { ProtocolError, requireOpaque } from './protocol.mjs';

const TOKEN_URL = 'https://oauth.ring.com/oauth/token';
const USER_URL = 'https://api.amazonvision.com/v1/users/me';
const INTEGRATION_URL = 'https://api.amazonvision.com/v1/accounts/me/app-integrations';

function text(value, limit) {
  requireOpaque(value, limit);
  if (Buffer.byteLength(value) > limit || Buffer.from(value).toString('utf8') !== value) throw new ProtocolError('invalid_field');
  return value;
}
function options(value) {
  try {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ProtocolError('code_deadline_invalid');
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).some(key => !['deadline', 'clock'].includes(key)) ||
      Object.values(descriptors).some(item => !Object.hasOwn(item, 'value'))) throw new ProtocolError('code_deadline_invalid');
  const deadline = descriptors.deadline?.value;
  const clock = descriptors.clock?.value ?? Date.now;
  if (!Number.isSafeInteger(deadline) || deadline < 1 || typeof clock !== 'function') throw new ProtocolError('code_deadline_invalid');
  return { deadline, clock };
  } catch { throw new ProtocolError('code_deadline_invalid'); }
}
async function readBoundedJson(response, signal) {
  const reader = response.body?.getReader();
  if (!reader) throw new ProtocolError('upstream_empty');
  const chunks = [];
  let size = 0;
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener('abort', cancel, { once: true });
  if (signal.aborted) cancel();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 32_768) {
        void reader.cancel().catch(() => {});
        throw new ProtocolError('upstream_oversize');
      }
      chunks.push(Buffer.from(value));
    }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
  } catch (error) {
    if (error instanceof ProtocolError) throw error;
    throw new ProtocolError('upstream_json');
  } finally {
    signal.removeEventListener('abort', cancel);
    reader.releaseLock();
  }
}
export function createRingClient({ fetchImpl = globalThis.fetch, timeoutMs = 4000, clientId, clientSecret } = {}) {
  if (typeof fetchImpl !== 'function' || !Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10_000) throw new ProtocolError('client_config');
  text(clientId, 512);
  text(clientSecret, 4096);
  async function request(url, method, headers, body, deadlineOptions, unauthorizedCode) {
    let timeout = timeoutMs;
    if (deadlineOptions) {
      let now;
      try { now = deadlineOptions.clock(); } catch { throw new ProtocolError('code_deadline_invalid'); }
      if (!Number.isSafeInteger(now) || now < 0) throw new ProtocolError('code_deadline_invalid');
      if (now >= deadlineOptions.deadline) throw new ProtocolError('code_expired');
      timeout = Math.min(timeout, deadlineOptions.deadline - now);
    }
    const mutating = method === 'POST' || method === 'PATCH';
    const controller = new AbortController();
    let timer;
    const expiration = new Promise((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new ProtocolError(mutating ? 'provider_outcome_unknown' : 'upstream_unavailable'));
      }, timeout);
    });
    const operation = (async () => {
      const response = await fetchImpl(url, { method, headers, body, redirect: 'error', signal: controller.signal });
      if (response.status === 401 && unauthorizedCode !== undefined) throw new ProtocolError(unauthorizedCode);
      if (response.status !== 200 || response.redirected === true) throw new ProtocolError('upstream_status');
      if (!/^application\/(json|[A-Za-z0-9.+-]+\+json)(\s*;|\s*$)/i.test(response.headers.get('content-type') ?? '')) throw new ProtocolError('upstream_content_type');
      return readBoundedJson(response, controller.signal);
    })();
    try { return await Promise.race([operation, expiration]); }
    catch (error) {
      if (error instanceof ProtocolError && error.code === unauthorizedCode) throw error;
      if (mutating) throw new ProtocolError('provider_outcome_unknown');
      if (error instanceof ProtocolError) throw error;
      throw new ProtocolError('upstream_unavailable');
    } finally {
      clearTimeout(timer);
      controller.abort();
    }
  }
  function tokenPair(data, priorRefreshToken) {
    try {
      if (data?.token_type !== 'Bearer' || !Number.isSafeInteger(data?.expires_in) || data.expires_in <= 0 ||
          data.expires_in > Math.floor(Number.MAX_SAFE_INTEGER / 1000)) throw new ProtocolError('token_schema');
      const accessToken = text(data.access_token, 8192);
      const refreshToken = text(data.refresh_token, 8192);
      if (priorRefreshToken !== undefined && refreshToken === priorRefreshToken) throw new ProtocolError('token_schema');
      return Object.freeze({ accessToken, refreshToken, expiresIn: data.expires_in });
    } catch { throw new ProtocolError('provider_outcome_unknown'); }
  }
  return Object.freeze({
    async exchangeCode(code, value) {
      text(code, 2048);
      const deadline = options(value);
      const form = new URLSearchParams({ grant_type: 'authorization_code', client_id: clientId, client_secret: clientSecret, code });
      const data = await request(TOKEN_URL, 'POST', { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' }, form.toString(), deadline);
      return tokenPair(data);
    },
    async refreshTokens(refreshToken, value) {
      text(refreshToken, 8192);
      const deadline = options(value);
      const form = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: clientId,
        client_secret: clientSecret
      });
      const data = await request(TOKEN_URL, 'POST', {
        'content-type': 'application/x-www-form-urlencoded', accept: 'application/json'
      }, form.toString(), deadline, 'relink_required');
      return tokenPair(data, refreshToken);
    },
    async getAccountId(accessToken) {
      text(accessToken, 8192);
      const data = await request(USER_URL, 'GET', { authorization: 'Bearer ' + accessToken, accept: 'application/json' }, undefined, undefined, 'relink_required');
      if (data?.data?.type !== 'users') throw new ProtocolError('profile_schema');
      return text(data.data.id, 256);
    },
    async confirmLink(accessToken, nonce, accountIdentifier) {
      text(accessToken, 8192);
      if (typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(nonce)) throw new ProtocolError('invalid_nonce');
      text(accountIdentifier, 256);
      const data = await request(INTEGRATION_URL, 'POST', {
        authorization: 'Bearer ' + accessToken, 'content-type': 'application/json', accept: 'application/json'
      }, JSON.stringify({ nonce, account_identifier: accountIdentifier }), undefined, 'relink_required');
      if (data?.data?.type !== 'app-integrations' || data.data.attributes?.status !== 'awaiting') throw new ProtocolError('provider_outcome_unknown');
      try { return text(data.data.id, 256); } catch { throw new ProtocolError('provider_outcome_unknown'); }
    },
    async completeLink(accessToken) {
      text(accessToken, 8192);
      const data = await request(INTEGRATION_URL, 'PATCH', {
        authorization: 'Bearer ' + accessToken, 'content-type': 'application/json', accept: 'application/json'
      }, JSON.stringify({ status: 'completed' }), undefined, 'relink_required');
      if (data?.data?.type !== 'app-integrations' || data.data.attributes?.status !== 'completed') throw new ProtocolError('provider_outcome_unknown');
      try { return text(data.data.id, 256); } catch { throw new ProtocolError('provider_outcome_unknown'); }
    }
  });
}
