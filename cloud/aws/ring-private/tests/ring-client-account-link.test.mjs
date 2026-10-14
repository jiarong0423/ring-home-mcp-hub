import test from 'node:test';
import assert from 'node:assert/strict';
import { createRingClient } from '../ring-client.mjs';

const now = 1_790_000_000_000;
const options = () => ({ deadline: now + 60_000, clock: () => now });
const token = () => Response.json({ access_token: 'generated-access', refresh_token: 'generated-refresh', token_type: 'Bearer', expires_in: 14400 });
function client(fetchImpl, timeoutMs = 100) {
  return createRingClient({ fetchImpl, timeoutMs, clientId: 'generated-client', clientSecret: 'generated-secret' });
}
const unknown = error => error.code === 'provider_outcome_unknown' && error.message === 'provider_outcome_unknown';

test('fixed official hosts, exact form/json and redirect guard', async () => {
  const calls = [];
  const port = client(async (url, init) => {
    calls.push({ url, init });
    if (url.includes('oauth.ring.com')) return token();
    if (url.endsWith('/users/me')) return Response.json({ data: { type: 'users', id: 'generated-account' } });
    return Response.json({ data: { type: 'app-integrations', id: 'generated-integration', attributes: { status: init.method === 'POST' ? 'awaiting' : 'completed' } } });
  });
  const credentials = await port.exchangeCode('generated-code &+', options());
  assert.equal(await port.getAccountId(credentials.accessToken), 'generated-account');
  await port.confirmLink(credentials.accessToken, 'A'.repeat(43), 'u***r@example.test');
  await port.completeLink(credentials.accessToken);
  assert.deepEqual(calls.map(row => [row.url, row.init.method]), [
    ['https://oauth.ring.com/oauth/token', 'POST'],
    ['https://api.amazonvision.com/v1/users/me', 'GET'],
    ['https://api.amazonvision.com/v1/accounts/me/app-integrations', 'POST'],
    ['https://api.amazonvision.com/v1/accounts/me/app-integrations', 'PATCH']
  ]);
  assert.deepEqual(Object.fromEntries(new URLSearchParams(calls[0].init.body)), {
    grant_type: 'authorization_code', client_id: 'generated-client', client_secret: 'generated-secret', code: 'generated-code &+'
  });
  assert.deepEqual(JSON.parse(calls[2].init.body), { nonce: 'A'.repeat(43), account_identifier: 'u***r@example.test' });
  assert.deepEqual(JSON.parse(calls[3].init.body), { status: 'completed' });
  assert(calls.every(row => row.init.redirect === 'error' && row.init.signal.aborted));
  assert.equal(calls[0].init.headers['content-type'], 'application/x-www-form-urlencoded');
});

for (const [name, code, config, expected] of [
  ['missing deadline', 'generated-code', undefined, 'code_deadline_invalid'],
  ['at deadline', 'generated-code', { deadline: now, clock: () => now }, 'code_expired'],
  ['past deadline', 'generated-code', { deadline: now - 1, clock: () => now }, 'code_expired'],
  ['unsafe deadline', 'generated-code', { deadline: Number.MAX_SAFE_INTEGER + 1 }, 'code_deadline_invalid'],
  ['invalid clock', 'generated-code', { deadline: now + 1, clock: () => NaN }, 'code_deadline_invalid'],
  ['throwing clock', 'generated-code', { deadline: now + 1, clock: () => { throw Error('private'); } }, 'code_deadline_invalid'],
  ['extra options', 'generated-code', { ...options(), host: 'untrusted' }, 'code_deadline_invalid'],
  ['empty code', '', options(), 'invalid_field'],
  ['oversized code', 'é'.repeat(1100), options(), 'invalid_field'],
  ['control code', 'abc\n', options(), 'invalid_field']
]) {
  test('predispatch deny: ' + name, async () => {
    let calls = 0;
    await assert.rejects(client(async () => { calls += 1; return token(); }).exchangeCode(code, config), error => error.code === expected);
    assert.equal(calls, 0);
  });
}
test('deadline checked immediately before dispatch after validation', async () => {
  let calls = 0;
  const value = { deadline: now, clock: () => now };
  await assert.rejects(client(async () => { calls += 1; return token(); }).exchangeCode('generated-code', value), error => error.code === 'code_expired');
  assert.equal(calls, 0);
});

for (const [name, response] of [
  ['redirect', () => new Response('', { status: 302, headers: { location: 'https://other.example/' } })],
  ['non-json', () => new Response('private upstream text', { headers: { 'content-type': 'text/plain' } })],
  ['oversized', () => Response.json({ text: 'x'.repeat(40_000) })],
  ['malformed json', () => new Response('{', { headers: { 'content-type': 'application/json' } })],
  ['malformed token', () => Response.json({ token_type: 'Bearer', access_token: 'generated-access' })],
  ['network rejection', () => { throw new Error('private-provider-diagnostic'); }]
]) {
  test('dispatched exchange terminal unknown: ' + name, async () => {
    let calls = 0;
    await assert.rejects(client(async () => { calls += 1; return response(); }).exchangeCode('generated-code', options()), unknown);
    assert.equal(calls, 1);
  });
}
test('remaining deadline bounds stalled fetch and aborts once without retry', async () => {
  let calls = 0;
  let signal;
  const start = performance.now();
  await assert.rejects(client(async (_url, init) => {
    calls += 1; signal = init.signal;
    return new Promise((_resolve, reject) => init.signal.addEventListener('abort', () => reject(Error('timeout')), { once: true }));
  }, 1000).exchangeCode('generated-code', { deadline: now + 15, clock: () => now }), unknown);
  assert.equal(calls, 1);
  assert.equal(signal.aborted, true);
  assert(performance.now() - start < 500);
});
test('configured timeout caps longer remaining deadline', async () => {
  let signal;
  const start = performance.now();
  await assert.rejects(client(async (_url, init) => {
    signal = init.signal;
    return new Promise((_resolve, reject) => init.signal.addEventListener('abort', () => reject(Error('timeout')), { once: true }));
  }).exchangeCode('generated-code', options()), unknown);
  assert(signal.aborted);
  assert(performance.now() - start < 700);
});
test('body read timeout is also terminal unknown and bounded', async () => {
  let canceled = false;
  const body = new ReadableStream({ cancel() { canceled = true; } });
  const port = client(async (_url, init) => {
    init.signal.addEventListener('abort', () => { void body.cancel().catch(() => {}); }, { once: true });
    return new Response(body, { headers: { 'content-type': 'application/json' } });
  });
  await assert.rejects(port.exchangeCode('generated-code', { deadline: now + 10, clock: () => now }), unknown);
  assert.equal(canceled, true);
});
for (const method of ['confirmLink', 'completeLink']) {
  test(method + ' network or lost response has finite unknown', async () => {
    let calls = 0;
    const port = client(async () => { calls += 1; throw Error('raw account/token must not echo'); });
    const args = method === 'confirmLink' ? ['generated-access', 'A'.repeat(43), 'masked'] : ['generated-access'];
    await assert.rejects(port[method](...args), unknown);
    assert.equal(calls, 1);
  });
}
test('GET failure retains finite read-only failure class', async () => {
  await assert.rejects(client(async () => { throw Error('raw-private'); }).getAccountId('generated-access'), error => error.code === 'upstream_unavailable');
  await assert.rejects(client(async () => Response.json({ data: { type: 'devices' } })).getAccountId('generated-access'), error => error.code === 'profile_schema');
});
