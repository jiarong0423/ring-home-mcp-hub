import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createAccountLinkHttp } from '../account-link-http.mjs';
import { createCompletionStateCodec } from '../completion-state.mjs';

const initial = 1_790_000_000_000;
const finite = (status, duplicate = false) => ({
  status, duplicate, bindingCompleted: status === 'completed', retryAllowed: false, productionAdmitted: false
});
const error = code => Object.assign(Error('private upstream value must never echo'), { code });
function fixture() {
  let now = initial;
  const tokenTransportContext = Object.freeze({ kind: 'generated-transport' });
  const linkSessionContext = Object.freeze({ kind: 'generated-session' });
  const calls = [];
  const control = {};
  const codec = createCompletionStateCodec({ hmacKey: Buffer.alloc(32, 5), clock: () => now, random: size => Buffer.alloc(size, 8) });
  const workflow = {
    stageFromVerifiedIngress: async value => { calls.push({ operation: 'stage', value }); if (control.stage) return control.stage(value); return finite('unclaimed'); },
    continuePasswordlessLink: async value => { calls.push({ operation: 'link', value }); if (control.link) return control.link(value); return finite('completed'); }
  };
  const ports = { workflow, completionCodec: codec, clock: () => now };
  const http = createAccountLinkHttp(ports);
  const request = (path = '/ring/token', change = {}) => ({
    method: path === '/ring/token' ? 'POST' : 'GET', path,
    headers: path === '/ring/token' ? { 'content-type': 'application/x-www-form-urlencoded' } : {},
    rawQueryString: path === '/ring/link' ? 'time=' + initial + '&nonce=' + 'A'.repeat(43) : '',
    body: path === '/ring/token' ? Buffer.from('code=generated%2Bcode') : Buffer.alloc(0),
    ...(path === '/ring/token' ? { tokenTransportContext } : {}),
    ...(path === '/ring/link' ? { linkSessionContext } : {}),
    ...change
  });
  return {
    http, codec, workflow, ports, calls, control, tokenTransportContext, linkSessionContext, request,
    setNow: value => { now = value; }
  };
}
function cookie(response) { return response.headers['set-cookie'].split(';')[0]; }
function safety(response) {
  assert.equal(response.headers['cache-control'], 'no-store');
  assert.equal(response.headers['referrer-policy'], 'no-referrer');
  assert.equal(response.headers['x-content-type-options'], 'nosniff');
  assert.equal(response.headers['x-frame-options'], 'DENY');
  assert.match(response.headers['content-security-policy'], /default-src 'none'/);
  assert.equal(JSON.stringify(response).includes('private upstream value'), false);
}
function cleared(response) {
  assert.equal(response.headers['set-cookie'], '__Host-ring_link=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  assert.equal(response.headers['set-cookie'].includes('Domain='), false);
}

test('strict token form delegates only raw digest/server timestamp/code and returns finite accepted', async () => {
  const f = fixture(); const request = f.request();
  const response = await f.http.handle(request);
  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), { status: 'accepted', bindingCompleted: false, retryAllowed: false, productionAdmitted: false });
  assert.deepEqual(f.calls, [{ operation: 'stage', value: {
    code: 'generated+code', receivedAt: initial, bodyDigest: createHash('sha256').update(request.body).digest('hex')
  } }]);
  safety(response);
  for (const value of ['generated+code', 'generated%2Bcode', f.calls[0].value.bodyDigest]) assert.equal(JSON.stringify(response).includes(value), false);
});
test('safe duplicate token acknowledgement stays finite accepted', async () => {
  const f = fixture(); f.control.stage = () => finite('unclaimed', true);
  const response = await f.http.handle(f.request());
  assert.equal(response.statusCode, 200); assert.equal(f.calls.length, 1); safety(response);
});
for (const [name, request] of [
  ['token missing transport context', f => {
    const value = f.request(); delete value.tokenTransportContext; return value;
  }],
  ['token carrying link session context', f => ({ ...f.request(), linkSessionContext: f.linkSessionContext })],
  ['link missing session context', f => {
    const value = f.request('/ring/link'); delete value.linkSessionContext; return value;
  }],
  ['link carrying token transport context', f => ({ ...f.request('/ring/link'), tokenTransportContext: f.tokenTransportContext })],
  ['completion carrying token transport context', f => ({ ...f.request('/ring/complete'), tokenTransportContext: f.tokenTransportContext })],
  ['completion carrying link session context', f => ({ ...f.request('/ring/complete'), linkSessionContext: f.linkSessionContext })]
]) test('route-specific context boundary denies before workflow: ' + name, async () => {
  const f = fixture();
  const response = await f.http.handle(request(f));
  assert.equal(response.statusCode, 400);
  assert.equal(f.calls.length, 0);
  safety(response);
});
for (const [name, change] of [
  ['wrong method', { method: 'GET' }], ['query supplied', { rawQueryString: 'code=generated' }],
  ['missing content-type', { headers: {} }], ['parameter content-type', { headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' } }],
  ['JSON content-type', { headers: { 'content-type': 'application/json' } }],
  ['empty form', { body: Buffer.alloc(0) }], ['empty code', { body: Buffer.from('code=') }],
  ['unknown field', { body: Buffer.from('token=generated') }], ['extra identity field', { body: Buffer.from('code=generated&ownerRef=forged') }],
  ['duplicate code', { body: Buffer.from('code=one&code=two') }], ['encoded duplicate', { body: Buffer.from('code=one&%63ode=two') }],
  ['empty trailing field', { body: Buffer.from('code=one&') }], ['malformed percent', { body: Buffer.from('code=%ZZ') }],
  ['malformed UTF8 escape', { body: Buffer.from('code=%C0%AF') }], ['control escape', { body: Buffer.from('code=generated%00') }],
  ['C1 control escape', { body: Buffer.from('code=%C2%85') }], ['raw control', { body: Buffer.from('code=generated\n') }],
  ['invalid raw UTF8', { body: Buffer.from([0xff]) }], ['oversized code', { body: Buffer.from('code=' + 'a'.repeat(2049)) }],
  ['oversized body', { body: Buffer.alloc(4097) }], ['string body', { body: 'code=generated' }],
  ['array headers', { headers: [] }], ['duplicate-style header array', { headers: { 'content-type': ['application/x-www-form-urlencoded'] } }],
  ['case variant header', { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }],
  ['control header', { headers: { 'content-type': 'application/x-www-form-urlencoded\n' } }],
  ['wrong path', { path: '/ring/token/' }], ['caller URL path', { path: 'https://other.example/ring/token' }],
  ['caller identity extra', { actorRef: 'forged' }], ['caller token extra', { token: 'generated-secret' }],
  ['caller classification extra', { classification: 'LIVE' }]
]) test('normalization/token deny before workflow: ' + name, async () => {
  const f = fixture(); const response = await f.http.handle(f.request('/ring/token', change));
  assert.equal(response.statusCode, 400); assert.equal(f.calls.length, 0); safety(response);
});
test('proxy/getter/symbol traps are rejected without invocation at each normalized boundary', async () => {
  const f = fixture(); let invoked = 0;
  const request = f.request();
  const trap = { ownKeys() { invoked += 1; throw Error('private'); }, get() { invoked += 1; throw Error('private'); } };
  const values = [
    new Proxy(request, trap),
    { ...request, headers: new Proxy(request.headers, trap) },
    { ...request, body: new Proxy(request.body, trap) },
    { ...request, tokenTransportContext: new Proxy({}, trap) },
    Object.defineProperty({ ...request }, 'path', { get() { invoked += 1; return '/ring/token'; } }),
    { ...request, headers: Object.defineProperty({}, 'content-type', { enumerable: true, get() { invoked += 1; return 'application/x-www-form-urlencoded'; } }) },
    { ...request, tokenTransportContext: Object.defineProperty({}, 'session', { enumerable: true, get() { invoked += 1; return true; } }) },
    { ...request, [Symbol('private')]: true },
    { ...request, headers: { [Symbol('private')]: true } },
    { ...request, tokenTransportContext: { [Symbol('private')]: true } }
  ];
  for (const value of values) { assert.equal((await f.http.handle(value)).statusCode, 400); }
  assert.equal(invoked, 0); assert.equal(f.calls.length, 0);
});
test('Buffer accessor/extra properties deny without reading getter', async () => {
  const f = fixture(); let invoked = 0;
  const body = Buffer.from('code=generated');
  Object.defineProperty(body, 'length', { get() { invoked += 1; throw Error('private'); } });
  assert.equal((await f.http.handle(f.request('/ring/token', { body }))).statusCode, 400);
  assert.equal(invoked, 0); assert.equal(f.calls.length, 0);
});
for (const [code, statusCode, state] of [
  ['source_not_authorized', 403, 'denied'], ['invalid_field', 403, 'denied'], ['code_expired', 410, 'expired'],
  ['code_exchange_in_progress', 503, 'unavailable'], ['code_outcome_unknown', 503, 'unavailable'],
  ['provider_outcome_unknown', 503, 'unavailable'], ['code_store_unavailable', 503, 'unavailable']
]) test('token finite workflow error mapping: ' + code, async () => {
  const f = fixture(); f.control.stage = () => { throw error(code); };
  const response = await f.http.handle(f.request());
  assert.equal(response.statusCode, statusCode); assert.equal(JSON.parse(response.body).status, state); safety(response);
});
test('unknown workflow error/accessor cannot leak or invoke a code getter', async () => {
  const f = fixture(); let invoked = 0;
  f.control.stage = () => { throw Object.defineProperty(Error('generated-secret'), 'code', { get() { invoked += 1; throw Error('private'); } }); };
  const response = await f.http.handle(f.request());
  assert.equal(response.statusCode, 503); assert.equal(invoked, 0); assert.equal(response.body.includes('generated-secret'), false); safety(response);
});
test('workflow output with extra secret/id or fabricated live flag cannot be promoted', async () => {
  for (const value of [{ ...finite('unclaimed'), accountId: 'generated-secret' }, { ...finite('unclaimed'), productionAdmitted: true }, { ...finite('completed') }]) {
    const f = fixture(); f.control.stage = () => value;
    const response = await f.http.handle(f.request());
    assert.equal(response.statusCode, 503); assert.equal(JSON.stringify(response).includes('generated-secret'), false); safety(response);
  }
});
test('link completion has clean redirect and host cookie; page is static and clears identically', async () => {
  const f = fixture(); const response = await f.http.handle(f.request('/ring/link'));
  assert.equal(response.statusCode, 303); assert.equal(response.headers.location, 'complete'); assert.equal(response.body, '');
  assert.match(response.headers['set-cookie'], /^__Host-ring_link=[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}; Secure; HttpOnly; SameSite=Lax; Path=\/; Max-Age=120$/);
  assert.equal(response.headers['set-cookie'].includes('Domain='), false);
  assert.deepEqual(f.calls, [{ operation: 'link', value: {
    query: { time: String(initial), nonce: 'A'.repeat(43) }, context: f.linkSessionContext
  } }]);
  safety(response);
  const complete = await f.http.handle(f.request('/ring/complete', { headers: { cookie: cookie(response) } }));
  assert.equal(complete.statusCode, 200); assert.match(complete.body, /Ring 綁定完成/); cleared(complete); safety(complete);
  assert.equal(f.calls.length, 1);
  for (const marker of ['<script', '<style', '<iframe', '<img', 'src=', 'href=', 'generated', 'accountId', 'token', 'nonce=']) assert.equal(complete.body.includes(marker), false);
});
for (const state of ['completed','denied','expired','unknown']) test('all valid finite workflow states get signed display-only redirect: ' + state, async () => {
  const f = fixture(); f.control.link = () => finite(state);
  const response = await f.http.handle(f.request('/ring/link'));
  assert.equal(response.statusCode, 303); assert.equal(response.headers.location, 'complete');
  const ticket = cookie(response).slice('__Host-ring_link='.length);
  assert.equal(f.codec.verify(ticket).state, state); assert.equal(f.calls.length, 1); safety(response);
});
for (const [code, state] of [
  ['identity_not_authorized', 'denied'], ['identity_changed', 'denied'], ['link_not_found', 'denied'],
  ['ambiguous_link', 'denied'], ['identity_expired', 'expired'], ['expired_link', 'expired'],
  ['provider_outcome_unknown', 'unknown'], ['link_store_unavailable', 'unknown'], ['link_conflict','unknown']
]) test('finite link failure gets signed ticket and clean redirect: ' + code, async () => {
  const f = fixture(); f.control.link = () => { throw error(code); };
  const response = await f.http.handle(f.request('/ring/link'));
  assert.equal(response.statusCode, 303); assert.equal(response.headers.location, 'complete');
  const ticket = cookie(response).slice('__Host-ring_link='.length);
  assert.equal(f.codec.verify(ticket).state, state); safety(response);
});
for (const [name, change, statusCode = 400] of [
  ['wrong method', { method: 'POST' }], ['body present', { body: Buffer.from('ownerRef=forged') }],
  ['missing query', { rawQueryString: '' }], ['duplicate nonce', { rawQueryString: 'time=' + initial + '&nonce=' + 'A'.repeat(43) + '&nonce=' + 'A'.repeat(43) }],
  ['owner query', { rawQueryString: 'time=' + initial + '&ownerRef=forged' }],
  ['short time', { rawQueryString: 'time=12&nonce=' + 'A'.repeat(43) }],
  ['future time', { rawQueryString: 'time=' + (initial + 1) + '&nonce=' + 'A'.repeat(43) }, 410],
  ['stale time', { rawQueryString: 'time=' + (initial - 600001) + '&nonce=' + 'A'.repeat(43) }, 410],
  ['short nonce', { rawQueryString: 'time=' + initial + '&nonce=bad' }],
  ['noncanonical nonce', { rawQueryString: 'time=' + initial + '&nonce=' + 'A'.repeat(42) + 'B' }],
  ['encoded nonce', { rawQueryString: 'time=' + initial + '&nonce=%41' + 'A'.repeat(42) }],
  ['encoded key', { rawQueryString: '%74ime=' + initial + '&nonce=' + 'A'.repeat(43) }]
]) test('invalid link calls no workflow: ' + name, async () => {
  const f = fixture(); const response = await f.http.handle(f.request('/ring/link', change));
  assert.equal(response.statusCode, statusCode); assert.equal(f.calls.length, 0); assert.equal(response.headers.location, undefined); safety(response);
});
test('link permits reversed exact query order and freshness boundary', async () => {
  const f = fixture();
  const response = await f.http.handle(f.request('/ring/link', { rawQueryString: 'nonce=' + 'A'.repeat(43) + '&time=' + (initial - 600000) }));
  assert.equal(response.statusCode, 303); assert.equal(f.calls.length, 1);
});
test('unknown link error and malformed returned live result never produce a success ticket', async () => {
  for (const behavior of [() => { throw Error('generated-secret'); }, () => ({ ...finite('completed'), token: 'generated-secret' }), () => ({ ...finite('completed'), bindingCompleted: false })]) {
    const f = fixture(); f.control.link = behavior;
    const response = await f.http.handle(f.request('/ring/link'));
    assert.equal(response.statusCode, 503); assert.equal(response.headers['set-cookie'], undefined); assert.equal(JSON.stringify(response).includes('generated-secret'), false);
  }
});
for (const [name, headers] of [
  ['missing cookie', {}], ['unrelated cookie only', { cookie: 'session=generated' }],
  ['empty expected', { cookie: '__Host-ring_link=' }], ['duplicate expected', { cookie: '__Host-ring_link=a; __Host-ring_link=b' }],
  ['malformed cookie', { cookie: 'invalid' }], ['quoted ticket', { cookie: '__Host-ring_link="generated"' }],
  ['tampered ticket', { cookie: '__Host-ring_link=generated.generated' }]
]) test('complete cookie deny is static and mutates no workflow: ' + name, async () => {
  const f = fixture(); const response = await f.http.handle(f.request('/ring/complete', { headers }));
  assert.equal(response.statusCode, 403); assert.match(response.body, /Ring 綁定未完成/); cleared(response); safety(response); assert.equal(f.calls.length, 0);
});
test('expired ticket displays expiry, clears cookie and performs zero workflow work', async () => {
  const f = fixture(); const ticket = f.codec.issue('completed'); f.setNow(initial + 120000);
  const response = await f.http.handle(f.request('/ring/complete', { headers: { cookie: '__Host-ring_link=' + ticket } }));
  assert.equal(response.statusCode, 410); assert.match(response.body, /已逾時/); cleared(response); safety(response); assert.equal(f.calls.length, 0);
});
test('ticket replay and coexistence with an unrelated session cookie remain display-only', async () => {
  const f = fixture(); const ticket = f.codec.issue('completed');
  const request = f.request('/ring/complete', { headers: { cookie: 'session=generated; __Host-ring_link=' + ticket } });
  const first = await f.http.handle(request); const replay = await f.http.handle(request);
  assert.equal(first.statusCode, 200); assert.deepEqual(first, replay); cleared(replay); assert.equal(f.calls.length, 0);
});
for (const [name, change] of [
  ['wrong method', { method: 'POST' }], ['query supplied', { rawQueryString: 'state=completed' }],
  ['body supplied', { body: Buffer.from('state=completed') }]
]) test('invalid completion request cannot verify or call workflow: ' + name, async () => {
  const f = fixture(); const response = await f.http.handle(f.request('/ring/complete', change));
  assert.equal(response.statusCode, 400); cleared(response); assert.equal(f.calls.length, 0); safety(response);
});
test('router clock rollback denies before any new workflow call', async () => {
  const f = fixture(); assert.equal((await f.http.handle(f.request())).statusCode, 200);
  f.setNow(initial - 1);
  const response = await f.http.handle(f.request());
  assert.equal(response.statusCode, 503); assert.equal(f.calls.length, 1); safety(response);
});
test('completion codec clock rollback is finite unknown and clears cookie', async () => {
  let now = initial + 1;
  const codec = createCompletionStateCodec({ hmacKey: Buffer.alloc(32, 5), clock: () => now, random: size => Buffer.alloc(size, 8) });
  const ticket = codec.issue('completed'); now = initial;
  const f = fixture(); const http = createAccountLinkHttp({ ...f.ports, completionCodec: codec });
  const response = await http.handle(f.request('/ring/complete', { headers: { cookie: '__Host-ring_link=' + ticket } }));
  assert.equal(response.statusCode, 503); cleared(response); assert.equal(f.calls.length, 0); safety(response);
});
test('constructor missing ports/getters/proxies fail before workflow activation', () => {
  const f = fixture(); let invoked = 0;
  for (const name of ['workflow','completionCodec','clock']) assert.throws(() => createAccountLinkHttp({ ...f.ports, [name]: undefined }), /http_config/);
  assert.throws(() => createAccountLinkHttp(new Proxy(f.ports, { ownKeys() { invoked += 1; throw Error('private'); } })), /http_config/);
  const workflow = Object.defineProperty({ continuePasswordlessLink() {} }, 'stageFromVerifiedIngress', { get() { invoked += 1; throw Error('private'); } });
  assert.throws(() => createAccountLinkHttp({ ...f.ports, workflow }), /http_config/);
  assert.equal(invoked, 0); assert.equal(f.calls.length, 0);
});
test('codec issue/verify failures are finite and never echo private errors', async () => {
  const f = fixture();
  const codec = { issue() { throw Error('generated-secret'); }, verify() { throw Error('generated-secret'); } };
  const http = createAccountLinkHttp({ ...f.ports, completionCodec: codec });
  const link = await http.handle(f.request('/ring/link')); assert.equal(link.statusCode, 503);
  const complete = await http.handle(f.request('/ring/complete', { headers: { cookie: '__Host-ring_link=generated' } }));
  assert.equal(complete.statusCode, 403); cleared(complete);
  assert.equal(JSON.stringify([link, complete]).includes('generated-secret'), false);
});

for (const [name, prefix] of [
  ['native staging', '/staging'],
  ['root mapping', ''],
  ['custom mapping prefix', '/private/ring-app']
]) test('relative completion redirect preserves mount and clears link query: ' + name, async () => {
  const f = fixture();
  const request = f.request('/ring/link');
  const browserUrl = new URL(`https://ring.generated.invalid${prefix}/ring/link?${request.rawQueryString}`);
  const response = await f.http.handle(request);
  assert.equal(response.statusCode, 303);
  const destination = new URL(response.headers.location, browserUrl);
  assert.equal(destination.origin, browserUrl.origin);
  assert.equal(destination.pathname, `${prefix}/ring/complete`);
  assert.equal(destination.search, '');
  assert.equal(destination.hash, '');
  assert.equal(response.headers.location, 'complete');
  assert.match(response.headers['set-cookie'], /; Secure; HttpOnly; SameSite=Lax; Path=\/; Max-Age=120$/);
  assert.equal(response.headers['set-cookie'].includes('Domain='), false);
  safety(response);
});
