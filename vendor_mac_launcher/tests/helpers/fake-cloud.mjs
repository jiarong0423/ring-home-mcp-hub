// In-process fake TLS "cloud": mimics POST /mac/commands/fetch|receipt (bearer + x-ring-mac-proof verified with the REAL
// vendored verifyMacProof, nonce replay, single claim) and the Cognito /oauth2/token endpoint (PKCE S256 check).
import { createServer } from 'node:https';
import { request as httpsRequest } from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { verifyMacProof, MAC_PROOF_HEADER } from '../../vendor/mac-command-proof.mjs';
import { command, commandId, envelope, receipt, hash } from '../../vendor/mac-command-contract.mjs';
import { validateFormalMcpWireRequest, formalWireErrorResponse, modernDispatchEnvelope, modernResultResponse } from '../../vendor/stateless-wire.mjs';

export const HOST = 'abcdefghij.execute-api.ap-southeast-1.amazonaws.com';
export const COGNITO_HOST = 'ring-home-mcp-private-abcdefghij.auth.ap-southeast-1.amazoncognito.com';
export function makeCert() {
  const dir = mkdtempSync(join(tmpdir(), 'ring-fake-cert-'));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ed25519', '-nodes', '-keyout', join(dir, 'k.pem'), '-out', join(dir, 'c.pem'), '-days', '2',
    '-subj', '/CN=fake', '-addext', `subjectAltName=DNS:${HOST},DNS:${COGNITO_HOST},DNS:api.amazonvision.com`], { stdio: 'ignore' });
  return { key: readFileSync(join(dir, 'k.pem')), cert: readFileSync(join(dir, 'c.pem')) };
}
export async function startFakeCloud({ enrollment, audience, prefix = '/staging' }) {
  const tls = makeCert();
  const state = { token: 'tok' + randomBytes(24).toString('base64url'), nonces: new Set(), queue: [], commands: new Map(),
    log: [], seen: [], codes: new Map(), ringToken: 'ring' + randomBytes(20).toString('base64url'), ringAccountId: 'acct-' + randomBytes(9).toString('hex'),
    devices: [], ringStatus: 200, ownerResponse: { status: 200, body: null },  receipts: [], tokenLifetimeSeconds: 300, deliverExpired: false };
  const deny = (res, status, reason) => { state.log.push({ status, reason }); res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: reason })); };
  const server = createServer({ key: tls.key, cert: tls.cert, minVersion: 'TLSv1.2' }, (req, res) => {
    const chunks = []; req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      try {
        if (req.url === '/oauth2/token') return token(req, res, raw);
        const json = (st, v) => { res.writeHead(st, { 'content-type': 'application/json' }); res.end(JSON.stringify(v)); };
        if (req.url === '/v1/users/me' || req.url === '/v1/devices') {
          state.seen.push({ url: req.url, method: req.method, authorization: req.headers.authorization });
          if (req.headers.authorization !== 'Bearer ' + state.ringToken) return json(401, { errors: [{ detail: 'secret-detail-should-not-print' }] });
          if (state.ringStatus !== 200) return json(state.ringStatus, { errors: [] });
          return req.url === '/v1/users/me'
            ? json(200, { data: { type: 'user', id: state.ringAccountId, attributes: { email: 'someone@example.com', name: 'Private Person' } } })
            : json(200, { data: state.devices });
        }
        if (req.url === prefix + '/mcp') return mcp(req, res, raw, json);
        if (req.url === prefix + '/owner/bootstrap' || req.url === prefix + '/mac/enroll') {
          state.seen.push({ url: req.url, method: req.method, authorization: req.headers.authorization, contentType: req.headers['content-type'], body: raw });
          if (req.headers.authorization !== 'Bearer ' + state.token) return json(401, { error: 'unauthorized' });
          if (state.ownerResponse.status !== 200) return json(state.ownerResponse.status, state.ownerResponse.body ?? { error: 'denied' });
          return json(200, state.ownerResponse.body ?? { status: req.url.endsWith('bootstrap') ? 'owner_bootstrapped' : 'mac_enrolled' });
        }
        const op = req.url === prefix + '/mac/commands/fetch' ? 'fetch' : req.url === prefix + '/mac/commands/receipt' ? 'receipt' : null;
        if (req.method !== 'POST' || !op) return deny(res, 404, 'NOT_FOUND');
        if (req.headers.authorization !== 'Bearer ' + state.token) return deny(res, 401, 'BEARER_DENIED');
        const payload = JSON.parse(raw);
        let claims;
        try { claims = verifyMacProof({ header: req.headers[MAC_PROOF_HEADER], publicKeySpki: enrollment.publicKeySpki, ownerRef: enrollment.ownerRef,
          associationRevision: enrollment.associationRevision, operation: op, audience, token: state.token, payload, now: Date.now() }); }
        catch (e) { return deny(res, 403, e.code ?? 'PROOF'); }
        const nk = claims.keyId + ':' + claims.nonce;
        if (state.nonces.has(nk)) return deny(res, 403, 'MAC_PROOF_REPLAY');
        state.nonces.add(nk);
        const send = v => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(v)); };
        if (op === 'fetch') {
          const next = state.queue.find(c => c.state === 'PENDING' && (state.deliverExpired || Date.now() < c.command.expiresAt));
          if (!next) return send({ status: 'EMPTY' });
          next.state = 'CLAIMED'; next.claimToken = randomBytes(32).toString('base64url');
          return send({ status: 'CLAIMED', command: next.command, claimToken: next.claimToken });
        }
        const r = receipt(payload); const c = state.commands.get(r.commandId);
        if (!c || c.state !== 'CLAIMED') return deny(res, 409, 'RECEIPT_NOT_CLAIMED_OR_REPLAY');
        if (c.claimToken !== r.claimToken || c.command.envelopeSha256 !== r.envelopeSha256) return deny(res, 403, 'RECEIPT_MISMATCH');
        if (Date.now() >= c.command.expiresAt) return deny(res, 409, 'RECEIPT_AFTER_EXPIRY');
        c.state = 'SUCCEEDED'; c.result = r.result; state.receipts.push(r);
        return send({ commandId: r.commandId, status: 'SUCCEEDED', executed: true, result: r.result });
      } catch (e) { deny(res, 400, 'BAD_REQUEST'); }
    });
  });
  // Mirrors mcp-rest-composition.mjs handle(): content-type check, REAL validateFormalMcpWireRequest, bearer, tools/call dispatch,
  // modernResultResponse; structuredContent shaped like mac-command-service publicResult.
  function mcp(req, res, raw, json) {
    state.seen.push({ url: req.url, method: req.method, headers: { ...req.headers }, body: raw });
    if (req.method !== 'POST' || !['application/json', 'application/json; charset=utf-8'].includes(req.headers['content-type']?.toLowerCase())) return json(400, { error: 'mcp_rest_denied' });
    let env; try { env = JSON.parse(raw); } catch { return json(400, { error: 'mcp_rest_denied' }); }
    let wire;
    try { wire = validateFormalMcpWireRequest({ headers: { ...req.headers }, envelope: env }); }
    catch (error) { const body = formalWireErrorResponse(error, env?.id ?? null); return json(error.status ?? 400, body ?? { error: error.code }); }
    if (req.headers.authorization !== 'Bearer ' + state.token) return json(401, { error: 'B02_FORMAL_ACCESS_TOKEN_REQUIRED' });
    if (wire.routeId !== 'tools/call') return json(400, { error: 'mcp_rest_denied' });
    const e = wire.era === 'MODERN_STATELESS' ? modernDispatchEnvelope(wire) : wire.request;
    const publicResult = row => { const st = row.state === 'SUCCEEDED' ? 'SUCCEEDED' : Date.now() >= row.command.expiresAt ? (row.state === 'CLAIMED' ? 'UNKNOWN' : 'EXPIRED') : 'PENDING';
      return { commandId: row.command.commandId, status: st, executed: st === 'SUCCEEDED', result: st === 'SUCCEEDED' ? row.result : null }; };
    let sc;
    if (e.params.name === 'software_test_switch.set') {
      const a = e.params.arguments; if (Object.keys(a).length !== 1 || typeof a.enabled !== 'boolean') return json(400, { error: 'mcp_rest_denied' });
      const id = commandId(enrollment.ownerRef, 'CloudSession.fake', e.id);
      if (!state.commands.has(id)) api.submit(a.enabled, { id: e.id });
      sc = publicResult(state.commands.get(id));
    } else if (e.params.name === 'home_device.command') {
      const a = e.params.arguments; if (Object.keys(a).length !== 2 || typeof a.deviceId !== 'string' || typeof a.action !== 'string') return json(400, { error: 'mcp_rest_denied' });
      const id = commandId(enrollment.ownerRef, 'CloudSession.fake', e.id);
      try { if (!state.commands.has(id)) api.submitDevice(a.deviceId, a.action, { id: e.id }); } catch { return json(400, { error: 'mcp_rest_denied' }); }
      sc = publicResult(state.commands.get(id));
    } else if (e.params.name === 'software_test_switch.result' || e.params.name === 'home_device.result') {
      const row = state.commands.get(e.params.arguments.commandId); if (!row) return json(503, { error: 'unavailable' });
      sc = publicResult(row);
    } else return json(503, { error: 'unavailable' });
    const out = modernResultResponse({ id: e.id, result: { content: [{ type: 'text', text: JSON.stringify(sc) }], structuredContent: sc, isError: false } });
    if (state.mcpSse) { res.writeHead(200, { 'content-type': 'text/event-stream' }); return res.end('event: message\ndata: ' + JSON.stringify(out) + '\n\n'); }
    return json(200, out);
  }
  function token(req, res, raw) {
    state.tokenCalls = (state.tokenCalls ?? 0) + 1;
    const f = new URLSearchParams(raw); const c = state.codes.get(f.get('code')); state.codes.delete(f.get('code'));
    const bad = r => deny(res, 400, r);
    if (req.headers['content-type'] !== 'application/x-www-form-urlencoded' || f.get('grant_type') !== 'authorization_code' || !c) return bad('invalid_grant');
    if (f.get('client_id') !== c.client_id || f.get('redirect_uri') !== c.redirect_uri) return bad('invalid_grant');
    if (createHash('sha256').update(f.get('code_verifier') ?? '').digest('base64url') !== c.challenge) return bad('invalid_grant');
    const body = { access_token: state.token, id_token: 'unused.id.token', refresh_token: 'unused-refresh-token', expires_in: state.tokenLifetimeSeconds, token_type: 'Bearer' };
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(body));
  }
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const reroute = (url, options, cb) => httpsRequest({ host: '127.0.0.1', port, path: url.pathname + url.search, method: options.method, headers: options.headers,
    ca: tls.cert, servername: url.hostname, minVersion: 'TLSv1.2', rejectUnauthorized: true }, cb);
  const api = {
    state, reroute, port,
    // Simulates the browser leg: validates the authorize URL and returns the callback URL Cognito would redirect to.
    authorize(urlString) {
      const u = new URL(urlString); const q = u.searchParams; const code = 'code' + randomBytes(12).toString('hex');
      if (q.get('code_challenge_method') !== 'S256' || q.get('response_type') !== 'code') throw new Error('bad authorize');
      state.codes.set(code, { challenge: q.get('code_challenge'), client_id: q.get('client_id'), redirect_uri: q.get('redirect_uri') });
      return q.get('redirect_uri') + '?code=' + code + '&state=' + q.get('state');
    },
    submit(enabled, { id = 'req-' + randomBytes(6).toString('hex'), issuedAt = Date.now(), ownerRef = enrollment.ownerRef, associationRevision = enrollment.associationRevision } = {}) {
      const e = envelope({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'software_test_switch.set', arguments: { enabled } } });
      const c = command({ schema: 'ring-mac-command-v1', commandId: commandId(ownerRef, 'CloudSession.fake', e.id), ownerRef, associationRevision, sessionRef: 'CloudSession.fake',
        sessionExpiresAt: issuedAt + 120000, issuedAt, expiresAt: issuedAt + 30000, envelope: e, envelopeSha256: hash(JSON.stringify(e)) });
      state.commands.set(c.commandId, { command: c, state: 'PENDING' }); state.queue.push(state.commands.get(c.commandId)); return c;
    },
    submitDevice(deviceId, action, { id = 'req-' + randomBytes(6).toString('hex'), issuedAt = Date.now(), ownerRef = enrollment.ownerRef, associationRevision = enrollment.associationRevision } = {}) {
      const e = envelope({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'home_device.command', arguments: { deviceId, action } } });
      const c = command({ schema: 'ring-mac-command-v1', commandId: commandId(ownerRef, 'CloudSession.fake', e.id), ownerRef, associationRevision, sessionRef: 'CloudSession.fake',
        sessionExpiresAt: issuedAt + 120000, issuedAt, expiresAt: issuedAt + 30000, envelope: e, envelopeSha256: hash(JSON.stringify(e)) });
      state.commands.set(c.commandId, { command: c, state: 'PENDING' }); state.queue.push(state.commands.get(c.commandId)); return c;
    },
    close: () => new Promise(r => server.close(r))
  };
  return api;
}
