import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { createRingTokenClient, RING_USERS_ME_URL, RING_ACCESS_TOKEN_PATTERN } from '../ring-token-client.mjs';

const TOKEN = 'ring.sandbox-token_SECRET-abc';
// A fake node:https: records the call and plays a scripted response.
function fakeHttps(script) {
  const state = { calls: [], destroyed: 0, logs: [] };
  const impl = (url, options, callback) => {
    state.calls.push({ url: String(url), options });
    const req = new EventEmitter();
    req.destroy = () => { state.destroyed += 1; };
    req.end = () => { setImmediate(() => script({ req, callback, state })); };
    return req;
  };
  return { impl, state };
}
const respond = (statusCode, body, headers = {}) => ({ callback }) => {
  const res = new EventEmitter();
  res.statusCode = statusCode; res.headers = headers; res.resume = () => {}; res.destroy = () => { res.destroyed = true; };
  callback(res);
  for (const chunk of Array.isArray(body) ? body : [body]) if (!res.destroyed) res.emit('data', Buffer.from(chunk));
  if (!res.destroyed) res.emit('end');
};
const doc = (data) => JSON.stringify({ data });
async function rejected(promise) { await assert.rejects(promise, error => error instanceof TypeError && error.message === 'ring_token_rejected' && !String(error.stack).includes(TOKEN)); }
async function denied(promise) { await assert.rejects(promise, error => error instanceof TypeError && error.message === 'ring_token_denied' && !String(error.stack).includes(TOKEN)); }

test('success: fixed URL, bearer + accept json, TLS >= 1.2, certificate verification, 3s timeout; returns data.id', async () => {
  const { impl, state } = fakeHttps(respond(200, doc({ type: 'users', id: 'ring-user-123', attributes: { email: 'x@example.invalid' } })));
  assert.equal(await createRingTokenClient({ requestImpl: impl }).getAccountId(TOKEN), 'ring-user-123');
  assert.equal(RING_USERS_ME_URL, 'https://api.amazonvision.com/v1/users/me');
  assert.equal(state.calls.length, 1);
  assert.equal(state.calls[0].url, RING_USERS_ME_URL);
  const o = state.calls[0].options;
  assert.equal(o.method, 'GET'); assert.equal(o.minVersion, 'TLSv1.2'); assert.equal(o.rejectUnauthorized, true); assert.equal(o.timeout, 3000);
  assert.deepEqual(o.headers, { authorization: `Bearer ${TOKEN}`, accept: 'application/json', 'user-agent': 'ring-home-mcp-hub/1.0' });
});
test('the URL is a constant: nothing from the token can change host or path', async () => {
  const { impl, state } = fakeHttps(respond(200, doc({ type: 'users', id: 'a' })));
  await createRingTokenClient({ requestImpl: impl }).getAccountId('eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2V2aWwuZXhhbXBsZSJ9.sig');
  assert.equal(state.calls[0].url, RING_USERS_ME_URL);
});
test('invalid token shapes never reach the network', async () => {
  const { impl, state } = fakeHttps(respond(200, doc({ type: 'users', id: 'a' })));
  const client = createRingTokenClient({ requestImpl: impl });
  for (const bad of [undefined, null, 1, '', 'a b', 'a\r\nHost: evil', 'x'.repeat(8193), 'é', {}]) await assert.rejects(client.getAccountId(bad), /ring_token_denied/u);
  assert.equal(state.calls.length, 0);
  assert.ok(RING_ACCESS_TOKEN_PATTERN.test('x'.repeat(8192)));
});
test('HTTP errors and redirects are denials (redirects are not followed)', async () => {
  for (const status of [401, 403]) {
    const { impl } = fakeHttps(respond(status, 'nope'));
    await rejected(createRingTokenClient({ requestImpl: impl }).getAccountId(TOKEN));
  }
  for (const status of [301, 302, 307, 400, 404, 408, 429, 500, 502, 503, 204]) {
    const { impl, state } = fakeHttps(respond(status, doc({ type: 'users', id: 'a' }), { location: 'https://evil.example/' }));
    await denied(createRingTokenClient({ requestImpl: impl }).getAccountId(TOKEN));
    assert.equal(state.calls.length, 1, 'exactly one request, no follow-up');
  }
});
test('wrong document shape: bad data.type, missing/non-string/empty/oversize id, arrays, non-JSON, invalid UTF-8', async () => {
  for (const body of [doc({ type: 'accounts', id: 'a' }), doc({ id: 'a' }), doc({ type: 'users' }), doc({ type: 'users', id: 5 }), doc({ type: 'users', id: '' }),
    doc({ type: 'users', id: 'x'.repeat(257) }), JSON.stringify({ data: [{ type: 'users', id: 'a' }] }), JSON.stringify({}), 'null', 'not json', '{"data":']) {
    const { impl } = fakeHttps(respond(200, body));
    await denied(createRingTokenClient({ requestImpl: impl }).getAccountId(TOKEN));
  }
  const { impl } = fakeHttps(respond(200, [Buffer.from([0xff, 0xfe])]));
  await denied(createRingTokenClient({ requestImpl: impl }).getAccountId(TOKEN));
  const ok = fakeHttps(respond(200, doc({ type: 'users', id: 'x'.repeat(256) })));
  assert.equal((await createRingTokenClient({ requestImpl: ok.impl }).getAccountId(TOKEN)).length, 256);
});
test('response over 32 KB is refused (declared length, or streamed bytes) and the socket is destroyed', async () => {
  const declared = fakeHttps(respond(200, doc({ type: 'users', id: 'a' }), { 'content-length': '40000' }));
  await denied(createRingTokenClient({ requestImpl: declared.impl }).getAccountId(TOKEN));
  const chunks = ['x'.repeat(20000), 'y'.repeat(20000)];
  const streamed = fakeHttps(respond(200, chunks));
  await denied(createRingTokenClient({ requestImpl: streamed.impl }).getAccountId(TOKEN));
  assert.ok(streamed.state.destroyed >= 1);
  const exact = fakeHttps(respond(200, doc({ type: 'users', id: 'a', pad: 'p'.repeat(32000) })));
  assert.equal(await createRingTokenClient({ requestImpl: exact.impl }).getAccountId(TOKEN), 'a');
});
test('network error, socket timeout event, and a never-answering server (total timeout) are denials', async () => {
  await denied(createRingTokenClient({ requestImpl: fakeHttps(({ req }) => req.emit('error', new Error('ECONNRESET ' + TOKEN))).impl }).getAccountId(TOKEN));
  await denied(createRingTokenClient({ requestImpl: fakeHttps(({ req }) => req.emit('timeout')).impl }).getAccountId(TOKEN));
  const hang = fakeHttps(() => {});
  const started = Date.now();
  await denied(createRingTokenClient({ requestImpl: hang.impl, timeoutMs: 50 }).getAccountId(TOKEN));
  assert.ok(Date.now() - started < 1000);
  assert.ok(hang.state.destroyed >= 1);
  await denied(createRingTokenClient({ requestImpl: () => { throw new Error('sync ' + TOKEN); } }).getAccountId(TOKEN));
  assert.throws(() => createRingTokenClient({ timeoutMs: 3001 }), /ring_token_denied/u);
});
test('nothing is logged: console is silent for success and failure, and the result is only the id', async () => {
  const logs = [];
  const original = { info: console.info, log: console.log, warn: console.warn, error: console.error, debug: console.debug };
  for (const name of Object.keys(original)) console[name] = (...a) => logs.push(a.join(' '));
  try {
    const ok = fakeHttps(respond(200, doc({ type: 'users', id: 'id-1' })));
    assert.equal(await createRingTokenClient({ requestImpl: ok.impl }).getAccountId(TOKEN), 'id-1');
    await rejected(createRingTokenClient({ requestImpl: fakeHttps(respond(401, 'nope')).impl }).getAccountId(TOKEN));
  } finally { Object.assign(console, original); }
  assert.deepEqual(logs, []);
});
