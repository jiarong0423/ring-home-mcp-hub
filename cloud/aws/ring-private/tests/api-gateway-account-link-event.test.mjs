import test from 'node:test';
import assert from 'node:assert/strict';
import { parseRestV1AccountLinkEvent } from '../api-gateway-account-link-event.mjs';
import { createRestV1Dispatcher } from '../rest-v1-dispatcher.mjs';

function event(path = '/ring/token', change = {}) {
  const method = path === '/ring/token' ? 'POST' : 'GET';
  const token = method === 'POST';
  const link = path === '/ring/link';
  const headers = token
    ? { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }
    : path === '/ring/complete'
      ? { Cookie: '__Host-ring_link=generated.generated' }
      : { Accept: 'text/html' };
  const query = link ? { time: '1791327600000', nonce: 'A'.repeat(43) } : null;
  const input = {
    resource: path,
    path,
    httpMethod: method,
    headers,
    multiValueHeaders: Object.fromEntries(Object.entries(headers).map(([key, value]) => [key, [value]])),
    queryStringParameters: query,
    multiValueQueryStringParameters: query === null
      ? null
      : Object.fromEntries(Object.entries(query).map(([key, value]) => [key, [value]])),
    pathParameters: null,
    stageVariables: null,
    requestContext: {
      stage: 'prod',
      httpMethod: method,
      resourcePath: path,
      path: `/prod${path}`,
      requestId: 'generated-request',
      identity: { sourceIp: '192.0.2.1' }
    },
    body: token ? Buffer.from('code=generated').toString('base64') : null,
    isBase64Encoded: token
  };
  return { ...input, ...change };
}

test('exports strict REST-v1 normalization for the exact three routes', () => {
  const token = parseRestV1AccountLinkEvent(event());
  assert.equal(token.method, 'POST');
  assert.equal(token.path, '/ring/token');
  assert.equal(token.headers['content-type'], 'application/x-www-form-urlencoded');
  assert.equal(token.rawQueryString, '');
  assert.deepEqual(token.body, Buffer.from('code=generated'));
  assert.deepEqual(token.transport, {
    method: 'POST', path: '/ring/token', resource: '/ring/token', stage: 'prod'
  });
  assert.equal(Object.isFrozen(token), true);
  assert.equal(Object.isFrozen(token.headers), true);
  assert.equal(Object.isFrozen(token.transport), true);

  const link = parseRestV1AccountLinkEvent(event('/ring/link'));
  assert.equal(link.rawQueryString, `time=1791327600000&nonce=${'A'.repeat(43)}`);
  assert.equal(link.body.length, 0);

  const complete = parseRestV1AccountLinkEvent(event('/ring/complete'));
  assert.equal(complete.headers.cookie, '__Host-ring_link=generated.generated');
  assert.equal(complete.rawQueryString, '');
  assert.equal(complete.body.length, 0);
});

test('requestContext identity is neither copied nor exposed through the transport descriptor', () => {
  const normalized = parseRestV1AccountLinkEvent(event('/ring/link'));
  assert.deepEqual(Object.keys(normalized.transport), ['method', 'path', 'resource', 'stage']);
  assert.equal('requestContext' in normalized, false);
  assert.equal(JSON.stringify(normalized).includes('192.0.2.1'), false);
  assert.equal(JSON.stringify(normalized).includes('generated-request'), false);
});

for (const [name, mutate, code] of [
  ['HTTP API v2 version marker', value => { value.version = '2.0'; }, 'invalid_event'],
  ['unknown route', value => { value.path = value.resource = value.requestContext.resourcePath = '/ring/token-exchange'; }, 'unsupported_route'],
  ['wrong method', value => { value.httpMethod = value.requestContext.httpMethod = 'GET'; }, 'unsupported_route'],
  ['resource mismatch', value => { value.resource = '/ring/link'; }, 'route_conflict'],
  ['request context method mismatch', value => { value.requestContext.httpMethod = 'GET'; }, 'route_conflict'],
  ['request context resource mismatch', value => { value.requestContext.resourcePath = '/ring/link'; }, 'route_conflict'],
  ['request context path mismatch', value => { value.requestContext.path = '/other/ring/token'; }, 'route_conflict'],
  ['invalid stage', value => { value.requestContext.stage = '$default'; }, 'invalid_stage'],
  ['path parameters', value => { value.pathParameters = {}; }, 'invalid_gateway_parameters'],
  ['stage variables', value => { value.stageVariables = {}; }, 'invalid_gateway_parameters']
]) test('rejects non-exact REST-v1 route metadata: ' + name, () => {
  const value = event();
  mutate(value);
  assert.throws(() => parseRestV1AccountLinkEvent(value), new RegExp(code));
});

test('multi-value headers are authoritative, single-valued and exact mirrors', () => {
  const duplicate = event();
  duplicate.multiValueHeaders['Content-Type'].push('application/x-www-form-urlencoded');
  assert.throws(() => parseRestV1AccountLinkEvent(duplicate), /invalid_headers/);

  const conflict = event();
  conflict.headers.Accept = 'text/plain';
  assert.throws(() => parseRestV1AccountLinkEvent(conflict), /header_conflict/);

  const caseDuplicate = event();
  caseDuplicate.headers.accept = caseDuplicate.headers.Accept;
  caseDuplicate.multiValueHeaders.accept = [caseDuplicate.headers.Accept];
  assert.throws(() => parseRestV1AccountLinkEvent(caseDuplicate), /invalid_headers/);

  const missingMulti = event();
  delete missingMulti.multiValueHeaders.Accept;
  assert.throws(() => parseRestV1AccountLinkEvent(missingMulti), /header_conflict/);
});

test('link query requires exact mirrored one-value time and nonce fields', () => {
  const duplicate = event('/ring/link');
  duplicate.multiValueQueryStringParameters.nonce.push('B'.repeat(43));
  assert.throws(() => parseRestV1AccountLinkEvent(duplicate), /invalid_query/);

  const extra = event('/ring/link');
  extra.queryStringParameters.actor = 'forged';
  extra.multiValueQueryStringParameters.actor = ['forged'];
  assert.throws(() => parseRestV1AccountLinkEvent(extra), /invalid_query/);

  const conflict = event('/ring/link');
  conflict.queryStringParameters.time = '1791327600001';
  assert.throws(() => parseRestV1AccountLinkEvent(conflict), /invalid_query/);

  const queryOnToken = event();
  queryOnToken.queryStringParameters = {};
  queryOnToken.multiValueQueryStringParameters = {};
  assert.throws(() => parseRestV1AccountLinkEvent(queryOnToken), /invalid_query/);
});

for (const [name, field, value] of [
  ['time leading zero', 'time', '0791327600000'],
  ['time too short', 'time', '791327600000'],
  ['time too long', 'time', '17913276000000'],
  ['time percent encoded', 'time', '%31' + '79132760000'],
  ['nonce malformed percent', 'nonce', 'A'.repeat(40) + '%ZZ'],
  ['nonce percent encoded valid-looking byte', 'nonce', '%41' + 'A'.repeat(40)],
  ['nonce trailing percent', 'nonce', 'A'.repeat(42) + '%'],
  ['nonce noncanonical pad bits', 'nonce', 'A'.repeat(42) + 'B'],
  ['nonce too short', 'nonce', 'A'.repeat(42)],
  ['nonce too long', 'nonce', 'A'.repeat(44)]
]) test('link query rejects noncanonical lexical value: ' + name, () => {
  const input = event('/ring/link');
  input.queryStringParameters[field] = value;
  input.multiValueQueryStringParameters[field] = [value];
  assert.throws(() => parseRestV1AccountLinkEvent(input), /invalid_query/);
});

test('malformed and percent-bearing link values stop before resolver and router', async () => {
  for (const [field, value] of [
    ['time', '%31' + '79132760000'],
    ['nonce', 'A'.repeat(40) + '%ZZ'],
    ['nonce', '%41' + 'A'.repeat(40)],
    ['nonce', 'A'.repeat(42) + '%'],
    ['nonce', 'A'.repeat(42) + 'B']
  ]) {
    const calls = { resolver: 0, router: 0 };
    const dispatch = createRestV1Dispatcher({
      accountLinkHttp: {
        async handle() {
          calls.router += 1;
          return { statusCode: 200, headers: {}, body: '{}' };
        }
      },
      async tokenTransportResolver() {
        calls.resolver += 1;
        return { admission: 'generated' };
      },
      async linkSessionResolver() {
        calls.resolver += 1;
        return { admission: 'generated' };
      }
    });
    const input = event('/ring/link');
    input.queryStringParameters[field] = value;
    input.multiValueQueryStringParameters[field] = [value];
    const response = await dispatch(input);
    assert.equal(response.statusCode, 400);
    assert.deepEqual(calls, { resolver: 0, router: 0 });
  }
});

test('POST body must be nonempty canonical base64 within the router byte limit', () => {
  const text = event();
  text.body = 'code=generated';
  text.isBase64Encoded = false;
  assert.throws(() => parseRestV1AccountLinkEvent(text), /invalid_body/);

  const padBits = event();
  padBits.body = 'Zh==';
  assert.throws(() => parseRestV1AccountLinkEvent(padBits), /invalid_body/);

  const oversized = event();
  oversized.body = Buffer.alloc(4_097, 0x41).toString('base64');
  assert.throws(() => parseRestV1AccountLinkEvent(oversized), /invalid_body/);

  const getBody = event('/ring/link');
  getBody.body = '';
  assert.throws(() => parseRestV1AccountLinkEvent(getBody), /invalid_body/);
});

test('proxy, accessor and symbol traps are rejected without invoking user code', () => {
  let invoked = 0;
  const trap = {
    ownKeys() { invoked += 1; throw new Error('private'); },
    get() { invoked += 1; throw new Error('private'); }
  };
  const values = [
    new Proxy(event(), trap),
    { ...event(), headers: new Proxy(event().headers, trap) },
    { ...event(), multiValueHeaders: new Proxy(event().multiValueHeaders, trap) },
    { ...event(), requestContext: new Proxy(event().requestContext, trap) },
    Object.defineProperty(event(), 'path', { get() { invoked += 1; return '/ring/token'; } }),
    { ...event(), headers: Object.defineProperty({}, 'accept', { enumerable: true, get() { invoked += 1; return 'x'; } }) },
    { ...event(), [Symbol('private')]: true }
  ];
  for (const value of values) assert.throws(() => parseRestV1AccountLinkEvent(value));
  assert.equal(invoked, 0);
});
