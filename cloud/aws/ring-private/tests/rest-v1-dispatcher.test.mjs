import test from 'node:test';
import assert from 'node:assert/strict';
import { createRestV1Dispatcher } from '../rest-v1-dispatcher.mjs';

function event(path = '/ring/token', change = {}) {
  const method = path === '/ring/token' ? 'POST' : 'GET';
  const headers = method === 'POST'
    ? { 'Content-Type': 'application/x-www-form-urlencoded' }
    : path === '/ring/complete'
      ? { Cookie: '__Host-ring_link=generated.generated' }
      : { Accept: 'text/html' };
  const query = path === '/ring/link' ? { time: '1791327600000', nonce: 'A'.repeat(43) } : null;
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
      stage: 'prod', httpMethod: method, resourcePath: path, path: `/prod${path}`,
      authorizer: { actor: 'forged-event-actor' }, identity: { sourceIp: '192.0.2.9' }
    },
    body: method === 'POST' ? Buffer.from('code=generated').toString('base64') : null,
    isBase64Encoded: method === 'POST'
  };
  return { ...input, ...change };
}

function fixture() {
  const calls = { tokenResolver: [], linkResolver: [], router: [] };
  const response = Object.freeze({
    statusCode: 202,
    headers: Object.freeze({ 'content-type': 'application/json; charset=utf-8' }),
    body: JSON.stringify({ status: 'accepted' })
  });
  const accountLinkHttp = {
    async handle(request) {
      calls.router.push(request);
      return response;
    }
  };
  const tokenTransportResolver = async transport => {
    calls.tokenResolver.push(transport);
    return { admission: { kind: 'generated-token-transport', version: 1 } };
  };
  const linkSessionResolver = async input => {
    calls.linkResolver.push(input);
    return { admission: { kind: 'generated-link-session', version: 1 } };
  };
  return {
    calls,
    response,
    dispatch: createRestV1Dispatcher({ accountLinkHttp, tokenTransportResolver, linkSessionResolver })
  };
}

function telegramEvent(secret = 'generated_webhook_secret_1234567890') {
  const headers = { 'Content-Type': 'application/json', 'X-Telegram-Bot-Api-Secret-Token': secret };
  return { resource: '/telegram/webhook', path: '/telegram/webhook', httpMethod: 'POST', headers,
    multiValueHeaders: Object.fromEntries(Object.entries(headers).map(([key, value]) => [key, [value]])),
    queryStringParameters: null, multiValueQueryStringParameters: null, pathParameters: null, stageVariables: null,
    requestContext: { stage: 'prod', httpMethod: 'POST', resourcePath: '/telegram/webhook', path: '/prod/telegram/webhook' },
    body: Buffer.from('{"update_id":1}').toString('base64'), isBase64Encoded: true };
}

test('exact Telegram webhook bypasses account resolvers and dispatches only parsed minimal input', async () => {
  const calls = [];
  const accepted = Object.freeze({ statusCode: 200, headers: Object.freeze({ 'content-type': 'application/json' }), body: '{}' });
  const dispatch = createRestV1Dispatcher({ accountLinkHttp: { async handle() { throw Error('must-not-run'); } },
    async tokenTransportResolver() { throw Error('must-not-run'); }, async linkSessionResolver() { throw Error('must-not-run'); },
    telegramWebhookHandler: { async handle(input) { calls.push(input); return accepted; } } });
  assert.equal(await dispatch(telegramEvent()), accepted);
  assert.equal(calls.length, 1);
  assert.deepEqual(Object.keys(calls[0]), ['secretToken', 'body', 'transport']);
  assert.equal(Object.isFrozen(calls[0]), true);
});

test('malformed Telegram header stops before Telegram and account handlers', async () => {
  const calls = [];
  const dispatch = createRestV1Dispatcher({ accountLinkHttp: { async handle(value) { calls.push(value); } },
    async tokenTransportResolver(value) { calls.push(value); }, async linkSessionResolver(value) { calls.push(value); },
    telegramWebhookHandler: { async handle(value) { calls.push(value); } } });
  const input = telegramEvent('short');
  assert.equal((await dispatch(input)).statusCode, 400);
  assert.equal(calls.length, 0);
});

test('token route passes only frozen minimal transport to its resolver and exact token context to router', async () => {
  const f = fixture();
  const input = event();
  input.headers.Cookie = 'session=must-not-cross-token-boundary';
  input.multiValueHeaders.Cookie = ['session=must-not-cross-token-boundary'];
  const response = await f.dispatch(input);
  assert.equal(response, f.response);
  assert.equal(f.calls.tokenResolver.length, 1);
  assert.equal(f.calls.linkResolver.length, 0);
  assert.deepEqual(f.calls.tokenResolver[0], {
    method: 'POST', path: '/ring/token', resource: '/ring/token', stage: 'prod'
  });
  assert.equal(Object.isFrozen(f.calls.tokenResolver[0]), true);
  assert.equal(JSON.stringify(f.calls.tokenResolver[0]).includes('forged-event-actor'), false);
  assert.equal(JSON.stringify(f.calls.tokenResolver[0]).includes('192.0.2.9'), false);
  assert.equal(JSON.stringify(f.calls.tokenResolver[0]).includes('must-not-cross-token-boundary'), false);
  assert.equal(f.calls.router.length, 1);
  assert.equal(f.calls.router[0].method, 'POST');
  assert.equal(f.calls.router[0].path, '/ring/token');
  assert.equal(f.calls.router[0].headers['content-type'], 'application/x-www-form-urlencoded');
  assert.deepEqual(f.calls.router[0].body, Buffer.from('code=generated'));
  assert.equal(f.calls.router[0].tokenTransportContext.admission.kind, 'generated-token-transport');
  assert.equal(f.calls.router[0].tokenTransportContext.admission.version, 1);
  assert.equal(Object.hasOwn(f.calls.router[0], 'linkSessionContext'), false);
  assert.equal(Object.getPrototypeOf(f.calls.router[0].tokenTransportContext), null);
  assert.equal(Object.isFrozen(f.calls.router[0].tokenTransportContext), true);
  assert.equal(Object.isFrozen(f.calls.router[0].tokenTransportContext.admission), true);
});

test('link gets exact frozen Cookie-only input; completion invokes neither resolver', async () => {
  const f = fixture();
  const link = event('/ring/link');
  link.headers.Cookie = 'session=generated; preference=bounded';
  link.multiValueHeaders.Cookie = ['session=generated; preference=bounded'];
  link.headers.Authorization = 'must-not-cross-link-boundary';
  link.multiValueHeaders.Authorization = ['must-not-cross-link-boundary'];
  assert.equal(await f.dispatch(link), f.response);
  assert.equal(await f.dispatch(event('/ring/complete')), f.response);
  assert.equal(f.calls.tokenResolver.length, 0);
  assert.equal(f.calls.linkResolver.length, 1);
  assert.deepEqual(Object.keys(f.calls.linkResolver[0]), ['transport', 'headers']);
  assert.equal(Object.isFrozen(f.calls.linkResolver[0]), true);
  assert.deepEqual(f.calls.linkResolver[0].transport, {
    method: 'GET', path: '/ring/link', resource: '/ring/link', stage: 'prod'
  });
  assert.equal(Object.isFrozen(f.calls.linkResolver[0].transport), true);
  assert.deepEqual({ ...f.calls.linkResolver[0].headers }, { cookie: 'session=generated; preference=bounded' });
  assert.equal(Object.isFrozen(f.calls.linkResolver[0].headers), true);
  assert.equal(JSON.stringify(f.calls.linkResolver[0]).includes('must-not-cross-link-boundary'), false);
  assert.equal(JSON.stringify(f.calls.linkResolver[0]).includes('forged-event-actor'), false);
  assert.equal(JSON.stringify(f.calls.linkResolver[0]).includes('192.0.2.9'), false);
  assert.equal(f.calls.router.length, 2);
  assert.equal(f.calls.router[0].linkSessionContext.admission.kind, 'generated-link-session');
  assert.equal(Object.hasOwn(f.calls.router[0], 'tokenTransportContext'), false);
  assert.equal(f.calls.router[1].path, '/ring/complete');
  assert.equal(Object.hasOwn(f.calls.router[1], 'tokenTransportContext'), false);
  assert.equal(Object.hasOwn(f.calls.router[1], 'linkSessionContext'), false);
});

for (const [name, build, statusCode] of [
  ['token-exchange alias', () => event('/ring/token-exchange'), 404],
  ['webhook route', () => event('/ring/webhook'), 404],
  ['HTTP v2 shape', () => ({ ...event(), version: '2.0' }), 400],
  ['path conflict', () => event('/ring/link', { resource: '/ring/token' }), 400],
  ['noncanonical body', () => event('/ring/token', { body: 'Zh==' }), 400],
  ['query smuggling', () => event('/ring/token', { queryStringParameters: { actor: 'forged' }, multiValueQueryStringParameters: { actor: ['forged'] } }), 400]
]) test('unknown or malformed event performs zero resolver and router calls: ' + name, async () => {
  const f = fixture();
  const response = await f.dispatch(build());
  assert.equal(response.statusCode, statusCode);
  assert.equal(f.calls.tokenResolver.length, 0);
  assert.equal(f.calls.linkResolver.length, 0);
  assert.equal(f.calls.router.length, 0);
  assert.equal(JSON.stringify(response).includes('forged'), false);
  assert.equal(response.headers['cache-control'], 'no-store');
});

test('token resolver cannot derive event-provided identity, headers, cookie or body data', async () => {
  const seen = [];
  const routerCalls = [];
  const dispatch = createRestV1Dispatcher({
    accountLinkHttp: {
      async handle(request) {
        routerCalls.push(request);
        return { statusCode: 202, headers: {}, body: '{}' };
      }
    },
    async tokenTransportResolver(transport) {
      seen.push(transport);
      return { opaqueLease: 'generated-by-injected-authority' };
    },
    async linkSessionResolver() { throw Error('must-not-run'); }
  });
  const input = event();
  input.requestContext.authorizer = { actor: 'forged-owner', household: 'forged-home' };
  input.headers['X-Actor'] = 'forged-header';
  input.multiValueHeaders['X-Actor'] = ['forged-header'];
  input.headers.Cookie = 'session=forged-session';
  input.multiValueHeaders.Cookie = ['session=forged-session'];
  const response = await dispatch(input);
  assert.equal(response.statusCode, 202);
  assert.deepEqual(Object.keys(seen[0]), ['method', 'path', 'resource', 'stage']);
  assert.equal(JSON.stringify(seen[0]).includes('forged'), false);
  assert.equal(JSON.stringify(routerCalls[0].tokenTransportContext).includes('forged'), false);
  assert.equal(Object.hasOwn(routerCalls[0], 'linkSessionContext'), false);
});

test('resolver failures and unsafe opaque results are finite, no-echo and stop before router', async () => {
  const cyclic = {};
  cyclic.loop = cyclic;
  for (const resolver of [
    async () => { throw new Error('generated-secret'); },
    async () => new Proxy({}, { ownKeys() { throw new Error('generated-secret'); } }),
    async () => Object.defineProperty({}, 'secret', { enumerable: true, get() { throw new Error('generated-secret'); } }),
    async () => cyclic
  ]) {
    for (const path of ['/ring/token', '/ring/link']) {
      const calls = [];
      const dispatch = createRestV1Dispatcher({
        accountLinkHttp: { async handle(value) { calls.push(value); return { statusCode: 200, headers: {}, body: '{}' }; } },
        tokenTransportResolver: path === '/ring/token' ? resolver : async () => ({ trusted: true }),
        linkSessionResolver: path === '/ring/link' ? resolver : async () => ({ trusted: true })
      });
      const response = await dispatch(event(path));
      assert.equal(response.statusCode, 503);
      assert.equal(calls.length, 0);
      assert.equal(JSON.stringify(response).includes('generated-secret'), false);
    }
  }
});

for (const [name, cookie] of [
  ['duplicate name', 'session=one; session=two'],
  ['missing separator', 'session=one; invalid'],
  ['invalid name', 'bad name=value'],
  ['quoted value', 'session="generated"'],
  ['empty header', '']
]) test('malformed Cookie rejects before either resolver and router: ' + name, async () => {
  const f = fixture();
  const input = event('/ring/link');
  input.headers.Cookie = cookie;
  input.multiValueHeaders.Cookie = [cookie];
  const response = await f.dispatch(input);
  assert.equal(response.statusCode, 400);
  assert.deepEqual(f.calls, { tokenResolver: [], linkResolver: [], router: [] });
});

test('duplicate Cookie header values reject before either resolver and router', async () => {
  const f = fixture();
  const input = event('/ring/link');
  input.headers.Cookie = 'session=one';
  input.multiValueHeaders.Cookie = ['session=one', 'session=two'];
  const response = await f.dispatch(input);
  assert.equal(response.statusCode, 400);
  assert.deepEqual(f.calls, { tokenResolver: [], linkResolver: [], router: [] });
});

test('router failure or malformed response becomes finite unavailable without echo', async () => {
  for (const handle of [
    async () => { throw new Error('generated-secret'); },
    async () => null,
    async () => ({ statusCode: 200, headers: {}, body: Object.defineProperty({}, 'secret', { get() { throw new Error('private'); } }) }),
    async () => ({
      statusCode: 200,
      headers: Object.defineProperty({}, 'x-private', { enumerable: true, get() { throw new Error('generated-secret'); } }),
      body: '{}'
    }),
    async () => Object.defineProperty({ headers: {}, body: '{}' }, 'statusCode', {
      enumerable: true,
      get() { throw new Error('generated-secret'); }
    })
  ]) {
    const dispatch = createRestV1Dispatcher({
      accountLinkHttp: { handle },
      tokenTransportResolver: async () => ({ trusted: true }),
      linkSessionResolver: async () => ({ trusted: true })
    });
    const response = await dispatch(event());
    assert.equal(response.statusCode, 503);
    assert.equal(JSON.stringify(response).includes('generated-secret'), false);
  }
});

test('constructor rejects missing, accessor and proxy dependencies without invoking traps', () => {
  const f = fixture();
  assert.equal(typeof f.dispatch, 'function');
  const complete = {
    accountLinkHttp: { handle() {} },
    tokenTransportResolver: async () => ({}),
    linkSessionResolver: async () => ({})
  };
  assert.throws(() => createRestV1Dispatcher({ ...complete, accountLinkHttp: {} }), /dispatcher_config/);
  assert.throws(() => createRestV1Dispatcher({ ...complete, tokenTransportResolver: null }), /dispatcher_config/);
  assert.throws(() => createRestV1Dispatcher({ ...complete, linkSessionResolver: null }), /dispatcher_config/);
  assert.throws(() => createRestV1Dispatcher({
    accountLinkHttp: { handle() {} }, sharedResolver: async () => ({})
  }), /dispatcher_config/);
  let invoked = 0;
  const trap = new Proxy({}, { ownKeys() { invoked += 1; throw new Error('private'); } });
  assert.throws(() => createRestV1Dispatcher(trap), /dispatcher_config/);
  const getter = Object.defineProperty({
    tokenTransportResolver: async () => ({}), linkSessionResolver: async () => ({})
  }, 'accountLinkHttp', {
    enumerable: true,
    get() { invoked += 1; return { handle() {} }; }
  });
  assert.throws(() => createRestV1Dispatcher(getter), /dispatcher_config/);
  assert.equal(invoked, 0);
});
