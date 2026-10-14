import { request as httpsRequest } from 'node:https';
import { createHash } from 'node:crypto';
import { coded } from './config.mjs';

// Generic HTTPS JSON call. Never throws on HTTP status; returns {status, json|null}. Never logs headers/bodies.
export function callJson(url, { method, bearer, body, timeoutMs = 8000, requestImpl = httpsRequest }) {
  const u = new URL(url); if (u.protocol !== 'https:') throw coded('API_URL');
  if (typeof bearer !== 'string' || bearer.length < 16 || /[\s\x00-\x1f\x7f]/u.test(bearer)) throw coded('API_BEARER');
  const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
  const headers = { authorization: 'Bearer ' + bearer, accept: 'application/json' };
  if (payload) { headers['content-type'] = 'application/json'; headers['content-length'] = String(payload.length); }
  else if (method === 'POST') headers['content-length'] = '0';
  return new Promise((resolve, reject) => {
    let done = false, req;
    const finish = (err, v) => { if (done) return; done = true; clearTimeout(t); if (err) { req?.destroy(); reject(coded(err)); } else resolve(v); };
    const t = setTimeout(() => finish('API_TIMEOUT'), timeoutMs);
    try {
      req = requestImpl(u, { method, minVersion: 'TLSv1.2', rejectUnauthorized: true, headers }, res => {
        const chunks = []; let size = 0;
        res.on('data', c => { size += c.length; if (size > 262144) { res.destroy(); finish('API_RESPONSE_SIZE'); } else chunks.push(c); });
        res.on('error', () => finish('API_UNAVAILABLE'));
        res.on('end', () => { let json = null; try { json = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch {} finish(null, { status: res.statusCode, json }); });
      });
      req.on('error', () => finish('API_UNAVAILABLE'));
      req.end(payload ?? undefined);
    } catch { finish('API_UNAVAILABLE'); }
  });
}
const WORD = /^[a-z][a-z0-9_]{0,40}$/u;
export const genericStatus = json => WORD.test(json?.status ?? '') ? json.status : WORD.test(json?.error ?? '') ? 'error:' + json.error : 'unknown';
export const sha256Hex = s => createHash('sha256').update(s).digest('hex');
const SAFE = /^[A-Za-z0-9_.:-]{1,40}$/u;
const safeWord = v => typeof v === 'string' && SAFE.test(v) ? v : null;
const trunc = id => typeof id === 'string' ? id.slice(0, 6) + '...(' + id.length + ')' : null;

// SAFE summary: never raw account id, token, email or attributes.
export function summarizeMe(res) {
  const d = res.json?.data;
  const id = d && typeof d === 'object' && typeof d.id === 'string' ? d.id : null;
  const h = id === null ? null : sha256Hex(id);
  return { httpStatus: res.status, type: safeWord(d?.type), ringAccountIdSha256: h, accountIdSha256: h, accountIdLength: id?.length ?? null };
}
export function summarizeDevices(res) {
  const list = Array.isArray(res.json?.data) ? res.json.data : [];
  return { httpStatus: res.status, deviceCount: list.length,
    devices: list.slice(0, 20).map(x => { const a = x?.attributes ?? x ?? {};
      const caps = a.capabilities ?? x?.capabilities;
      return { id: trunc(x?.id), type: safeWord(x?.type), status: safeWord(a.status ?? x?.status),
        capabilities: Array.isArray(caps) ? caps.map(c => safeWord(typeof c === 'string' ? c : c?.name ?? c?.type)).filter(Boolean).slice(0, 10) : undefined }; }) };
}
