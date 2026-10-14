import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

process.env.NODE_ENV = 'test';
const {
  WEBHOOK_DEADLINE_MS,
  handler,
  installDeadlinePrimitivesForTest,
  installMcpRuntimeFactoryForTest,
  installRuntimeFactoryForTest,
  restoreProductionRuntimeForTest
} = await import('../handler.mjs');

function accountEvent(path = '/ring/token') {
  const method = path === '/ring/token' ? 'POST' : 'GET';
  const headers = method === 'POST' ? { 'Content-Type': 'application/x-www-form-urlencoded' } : {};
  const query = path === '/ring/link'
    ? { time: '1791000000000', nonce: 'A'.repeat(43) }
    : null;
  return {
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
    requestContext: { stage: 'staging', httpMethod: method, resourcePath: path, path: `/staging${path}` },
    body: method === 'POST' ? Buffer.from('code=generated').toString('base64') : null,
    isBase64Encoded: method === 'POST'
  };
}

function webhookEvent() {
  const rawBody = Buffer.from(JSON.stringify({
    meta: {
      version: '1.1',
      time: '2026-10-09T16:00:00Z',
      request_id: 'generated-handler-request',
      account_id: 'ava1.ring.account.generated'
    },
    data: {
      id: 'generated-handler-event',
      type: 'motion_detected',
      attributes: {
        source: 'ava1.ring.device.generated',
        source_type: 'devices',
        timestamp: Date.parse('2026-10-09T16:00:00Z')
      }
    }
  }));
  const signature = `sha256=${createHmac('sha256', 'w'.repeat(32)).update(rawBody).digest('hex')}`;
  return {
    resource: '/ring/webhook',
    path: '/ring/webhook',
    httpMethod: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Signature': signature },
    multiValueHeaders: { 'Content-Type': ['application/json'], 'X-Signature': [signature] },
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    pathParameters: null,
    stageVariables: null,
    requestContext: {
      stage: 'staging',
      httpMethod: 'POST',
      resourcePath: '/ring/webhook',
      path: '/staging/ring/webhook'
    },
    body: rawBody.toString('base64'),
    isBase64Encoded: true
  };
}

function mcpEvent(path = '/mcp') {
  const method = path === '/mcp' ? 'POST' : 'GET';
  const headers = method === 'POST' ? {
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream',
    'Mcp-Protocol-Version': '2026-07-28',
    'Mcp-Method': 'tools/list',
    Authorization: 'Bearer generated.token.value'
  } : {};
  const envelope = { jsonrpc: '2.0', id: 1, method: 'tools/list', params: { _meta: {
    'io.modelcontextprotocol/protocolVersion': '2026-07-28',
    'io.modelcontextprotocol/clientInfo': { name: 'handler-test', version: '1.0.0' },
    'io.modelcontextprotocol/clientCapabilities': {}
  } } };
  return {
    resource: path,
    path,
    httpMethod: method,
    headers,
    multiValueHeaders: Object.fromEntries(Object.entries(headers).map(([key, value]) => [key, [value]])),
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    pathParameters: null,
    stageVariables: null,
    requestContext: { apiId: 'generated-api', stage: 'staging', httpMethod: method,
      resourcePath: path, path: `/staging${path}` },
    body: method === 'POST' ? JSON.stringify(envelope) : null,
    isBase64Encoded: false
  };
}

test.beforeEach(() => {
  process.env.RING_BACKEND_STATE = 'enabled';
  process.env.RING_MCP_EXPECTED_API_ID = 'generated-api';
  process.env.RING_MCP_EXPECTED_STAGE = 'staging';
  delete process.env.RING_MCP_STATE;
  restoreProductionRuntimeForTest();
});

test.after(() => {
  restoreProductionRuntimeForTest();
  delete process.env.RING_BACKEND_STATE;
  delete process.env.RING_MCP_STATE;
  delete process.env.RING_MCP_EXPECTED_API_ID;
  delete process.env.RING_MCP_EXPECTED_STAGE;
  delete process.env.NODE_ENV;
});

test('MCP gate returns finite 503 before headers, body or MCP factory are inspected', async () => {
  const event = mcpEvent();
  let inspected = 0;
  let constructed = 0;
  event.headers = new Proxy({}, { ownKeys() { inspected += 1; throw new Error('must-not-read'); } });
  installMcpRuntimeFactoryForTest(() => { constructed += 1; throw new Error('must-not-construct'); });
  const response = await handler(event);
  assert.equal(response.statusCode, 503);
  assert.deepEqual(JSON.parse(response.body), { status: 'not_configured' });
  assert.equal(inspected, 0);
  assert.equal(constructed, 0);
});

test('enabled MCP routes preflight before one cached isolated MCP runtime', async () => {
  process.env.RING_MCP_STATE = 'enabled';
  let constructed = 0;
  const handled = [];
  installMcpRuntimeFactoryForTest(() => {
    constructed += 1;
    return { async handle(event) {
      handled.push(`${event.httpMethod} ${event.path}`);
      return { statusCode: 200, headers: { 'content-type': 'application/json' }, body: '{}' };
    } };
  });
  const malformed = mcpEvent();
  malformed.requestContext.apiId = 'wrong-api';
  assert.equal((await handler(malformed)).statusCode, 400);
  assert.equal(constructed, 0);
  assert.equal((await handler(mcpEvent())).statusCode, 200);
  assert.equal((await handler(mcpEvent('/.well-known/oauth-protected-resource'))).statusCode, 200);
  assert.equal(constructed, 1);
  assert.deepEqual(handled, ['POST /mcp', 'GET /.well-known/oauth-protected-resource']);
});

test('blocked exported runtime returns finite 503 without reading hostile input or constructing runtime', async () => {
  delete process.env.RING_BACKEND_STATE;
  let inspected = 0;
  let constructed = 0;
  const hostile = new Proxy({}, {
    ownKeys() { inspected += 1; throw new Error('must-not-read'); },
    get() { inspected += 1; throw new Error('must-not-read'); }
  });
  installRuntimeFactoryForTest(async () => {
    constructed += 1;
    throw new Error('must-not-construct');
  });
  const response = await handler(hostile);
  assert.equal(response.statusCode, 503);
  assert.deepEqual(JSON.parse(response.body), { status: 'not_configured' });
  assert.equal(inspected, 0);
  assert.equal(constructed, 0);
});

test('enabled malformed supported routes fail preflight before runtime construction', async () => {
  let constructed = 0;
  installRuntimeFactoryForTest(async () => {
    constructed += 1;
    throw new Error('must-not-construct');
  });
  const malformedToken = accountEvent();
  malformedToken.body = '%%%';
  const malformedWebhook = webhookEvent();
  delete malformedWebhook.multiValueHeaders['X-Signature'];
  const hostileWebhook = webhookEvent();
  hostileWebhook.queryStringParameters = { injected: 'true' };
  hostileWebhook.multiValueQueryStringParameters = { injected: ['true'] };
  hostileWebhook.pathParameters = { injected: 'true' };
  hostileWebhook.stageVariables = { injected: 'true' };
  hostileWebhook.requestContext.resourcePath = '/ring/token';
  hostileWebhook.requestContext.path = '/staging/ring/token';
  hostileWebhook.unexpected = 'must-fail-closed';
  assert.equal((await handler(malformedToken)).statusCode, 400);
  assert.equal((await handler(malformedWebhook)).statusCode, 400);
  assert.equal((await handler(hostileWebhook)).statusCode, 400);
  assert.equal((await handler({ httpMethod: 'GET', path: '/missing', resource: '/missing' })).statusCode, 404);
  assert.equal(constructed, 0);
});

test('valid account-link routes use the cached production-shaped runtime', async () => {
  const calls = [];
  installRuntimeFactoryForTest(async options => ({
    async dispatch(event) {
      calls.push(['dispatch', event.path, options.signal]);
      return { statusCode: event.path === '/ring/complete' ? 200 : 202, headers: {}, body: '{}' };
    },
    async webhookHandler() {
      throw new Error('not-webhook');
    }
  }));
  assert.equal((await handler(accountEvent('/ring/token'))).statusCode, 202);
  assert.equal((await handler(accountEvent('/ring/link'))).statusCode, 202);
  assert.equal((await handler(accountEvent('/ring/complete'))).statusCode, 200);
  assert.deepEqual(calls.map(call => call.slice(0, 2)), [
    ['dispatch', '/ring/token'],
    ['dispatch', '/ring/link'],
    ['dispatch', '/ring/complete']
  ]);
  assert.equal(calls.every(call => call[2] === undefined), true);
});

test('webhook deadline is fixed at 4000ms, aborts once, clears its timer and suppresses late 200', async () => {
  let timerCallback;
  let timerDelay;
  let clears = 0;
  let runtimeSignal;
  let webhookSignal;
  let lateResolve;
  installDeadlinePrimitivesForTest({
    now: () => 10_000,
    setTimer(callback, delay) {
      timerCallback = callback;
      timerDelay = delay;
      return Object.freeze({ generated: 'timer' });
    },
    clearTimer() {
      clears += 1;
    }
  });
  installRuntimeFactoryForTest(async ({ signal }) => {
    runtimeSignal = signal;
    return {
      async dispatch() {
        throw new Error('not-account-link');
      },
      webhookHandler(_event, { signal: requestSignal }) {
        webhookSignal = requestSignal;
        return new Promise(resolve => {
          lateResolve = resolve;
        });
      }
    };
  });

  const pending = handler(webhookEvent());
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(timerDelay, WEBHOOK_DEADLINE_MS);
  assert.equal(runtimeSignal, webhookSignal);
  let aborts = 0;
  webhookSignal.addEventListener('abort', () => {
    aborts += 1;
  });
  timerCallback();
  const response = await pending;
  assert.equal(response.statusCode, 503);
  assert.equal(JSON.parse(response.body).status, 'deadline_exceeded');
  assert.equal(webhookSignal.aborted, true);
  assert.equal(aborts, 1);
  assert.equal(clears, 1);
  lateResolve({ statusCode: 200, headers: {}, body: '{}' });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(response.statusCode, 503);
});


test('C4 handler passes the identical Lambda invocation context into the admitted MCP runtime', async () => {
  process.env.RING_BACKEND_STATE = 'enabled';
  process.env.RING_MCP_STATE = 'enabled';
  process.env.RING_MCP_EXPECTED_API_ID = 'generated-api';
  process.env.RING_MCP_EXPECTED_STAGE = 'staging';
  const actual = { functionVersion: 'generated-version', awsRequestId: 'generated-request' };
  let received;
  installMcpRuntimeFactoryForTest(() => ({ async handle(_event, context) {
    received = context; return { statusCode: 503, headers: {}, body: '{}' };
  } }));
  try {
    await handler(mcpEvent(), actual);
    assert.equal(received, actual);
  } finally { restoreProductionRuntimeForTest(); }
});
