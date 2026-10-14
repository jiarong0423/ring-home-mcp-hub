// Real-shape REST API (AWS_PROXY) event tests for the browser login route.
// The event shape below was captured from an actual API Gateway proxy invocation of this API on 2026-10-13
// (requestContext has no deploymentId). Account/request ids are replaced with placeholders.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { admittedGateway, createGatewayTransportPort } from '../mcp-production-ports.mjs';
import { createLambdaInvocationSourcePort } from '../b02-layer-runtime.mjs';
import { createBrowserSessionHttp, parseBrowserSessionEvent } from '../browser-session-http.mjs';

const ADMISSION_FILE = process.env.REAL_ADMISSION_FILE;
const t = ADMISSION_FILE ? test : test.skip;
const resource = 'https://abcdefghij.execute-api.ap-southeast-1.amazonaws.com/staging/mcp';
const config = {
  issuer: 'https://cognito-idp.ap-southeast-1.amazonaws.com/ap-southeast-1_AbCdEfGhI', clientId: 'replacewithyourappclientid', resource,
  requiredScopes: [resource + '/tools.list', resource + '/tools.call'], maximumTokenLifetimeSeconds: 300, maxJwksAgeSeconds: 300,
  expectedGatewayContext: { apiId: 'abcdefghij', stage: 'staging' },
};
const FN_ARN = 'arn:aws:lambda:ap-southeast-1:123456789012:function:ring-home-mcp-private';
const environment = { AWS_LAMBDA_FUNCTION_NAME: 'ring-home-mcp-private', AWS_REGION: 'ap-southeast-1',
  AWS_EXECUTION_ENV: 'AWS_Lambda_nodejs24.x', RING_MCP_FUNCTION_ARN: FN_ARN };
const invocationContext = () => ({ functionName: 'ring-home-mcp-private', awsRequestId: '00000000-0000-4000-8000-000000000000', invokedFunctionArn: FN_ARN });

function realEvent(overrides = {}, drop = []) {
  const single = { Accept: 'text/html', 'Accept-Encoding': 'gzip, deflate, br', 'Accept-Language': 'zh-TW', Host: 'abcdefghij.execute-api.ap-southeast-1.amazonaws.com',
    'User-Agent': 'Mozilla/5.0', 'X-Amzn-Trace-Id': 'Root=1-aaaaaaaa-bbbbbbbbbbbbbbbbbbbbbbbb', 'X-Forwarded-For': '203.0.113.9', 'X-Forwarded-Port': '443', 'X-Forwarded-Proto': 'https' };
  const event = {
    resource: '/auth/login', path: '/auth/login', httpMethod: 'GET', headers: single,
    multiValueHeaders: Object.fromEntries(Object.entries(single).map(([k, v]) => [k, [v]])),
    queryStringParameters: null, multiValueQueryStringParameters: null, pathParameters: null, stageVariables: null,
    requestContext: { resourceId: 'abc123', resourcePath: '/auth/login', httpMethod: 'GET', extendedRequestId: 'XyZ-1234567890abc=',
      requestTime: '13/Oct/2026:03:00:00 +0000', path: '/staging/auth/login', accountId: '123456789012', protocol: 'HTTP/1.1', stage: 'staging',
      domainPrefix: 'abcdefghij', requestTimeEpoch: 1791864000000, requestId: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
      identity: { cognitoIdentityPoolId: null, cognitoIdentityId: null, apiKey: null, principalOrgId: null, cognitoAuthenticationType: null, userArn: null,
        apiKeyId: null, userAgent: 'Mozilla/5.0', accountId: null, caller: null, sourceIp: '203.0.113.9', accessKey: null, cognitoAuthenticationProvider: null, user: null },
      domainName: 'abcdefghij.execute-api.ap-southeast-1.amazonaws.com', apiId: 'abcdefghij' },
    body: null, isBase64Encoded: false,
  };
  Object.assign(event.requestContext, overrides);
  for (const key of drop) delete event.requestContext[key];
  return event;
}

function harness() {
  assert.ok(ADMISSION_FILE, 'REAL_ADMISSION_FILE must point to the built formal-mcp-admission.json');
  const bytes = fs.readFileSync(ADMISSION_FILE);
  const admission = admittedGateway(JSON.parse(bytes.toString('utf8')), config);
  const admissionSha256 = createHash('sha256').update(bytes).digest('hex');
  const transport = createGatewayTransportPort({ admission, admissionSha256, invocationSourcePort: createLambdaInvocationSourcePort({ environment }) });
  const created = [];
  const http = createBrowserSessionHttp({
    config: { domain: 'https://ring-home-mcp-private-abcdefghij.auth.ap-southeast-1.amazoncognito.com',
      callbackUri: 'https://abcdefghij.execute-api.ap-southeast-1.amazonaws.com/staging/auth/callback',
      logoutUri: 'https://abcdefghij.execute-api.ap-southeast-1.amazonaws.com/staging/auth/logout',
      clientId: config.clientId, resource, scopes: config.requiredScopes, stage: 'staging' },
    transport, authorizationPolicy: { authorize: async () => { throw new Error('unused'); } }, issuer: {},
    store: { create: async value => { created.push(value); }, consume: async () => {} },
    exchange: async () => { throw new Error('unused'); },
    digest: async (label, value) => createHash('sha256').update(label + ':' + value).digest('hex'),
  });
  return { http, created };
}

t('real REST proxy event (no requestContext.deploymentId) reaches the Cognito authorize redirect', async () => {
  const { http, created } = harness();
  const response = await http.handle(realEvent(), invocationContext());
  assert.equal(response.statusCode, 303);
  const location = response.headers.location;
  assert.ok(location.startsWith('https://ring-home-mcp-private-abcdefghij.auth.ap-southeast-1.amazoncognito.com/oauth2/authorize?'));
  const q = new URL(location).searchParams;
  assert.equal(q.get('client_id'), 'replacewithyourappclientid');
  assert.equal(q.get('response_type'), 'code');
  assert.equal(q.get('code_challenge_method'), 'S256');
  assert.equal(created.length, 1);
  const cookies = response.multiValueHeaders['set-cookie'];
  assert.equal(cookies.length, 1);
  assert.match(cookies[0], /^__Host-ring_oauth=.*; Secure; HttpOnly; SameSite=Lax; Path=\/;/u);
});

t('forwarded headers are stripped before the parser and counts still match', async () => {
  const prepared = (() => {
    const { http } = harness();
    return http;
  })();
  assert.ok(prepared);
  const parsed = parseBrowserSessionEvent(realEvent());
  assert.equal(parsed.route, 'login');
});

t('a present but different deploymentId still denies (defense kept)', async () => {
  const { http } = harness();
  const response = await http.handle(realEvent({ deploymentId: 'zzzzzz' }), invocationContext());
  assert.equal(response.statusCode, 403);
});

t('a matching deploymentId (if API Gateway ever supplies it) is accepted', async () => {
  const { http } = harness();
  const response = await http.handle(realEvent({ deploymentId: 'abc123' }), invocationContext());
  assert.equal(response.statusCode, 303);
});

for (const [name, overrides] of [
  ['wrong apiId', { apiId: 'otherapi00' }], ['wrong stage', { stage: 'other', path: '/other/auth/login' }],
  ['wrong event accountId', { accountId: '999999999999' }], ['wrong domainPrefix', { domainPrefix: 'otherprefix' }],
  ['wrong domain', { domainName: 'abcdefghij.execute-api.us-east-1.amazonaws.com' }], ['wrong protocol', { protocol: 'HTTP/2' }],
]) {
  t(`denies ${name}`, async () => {
    const { http } = harness();
    const response = await http.handle(realEvent(overrides), invocationContext());
    assert.equal(response.statusCode, 403);
  });
}

t('denies a different invoked function ARN', async () => {
  const { http } = harness();
  const response = await http.handle(realEvent(), { ...invocationContext(), invokedFunctionArn: FN_ARN.replace('ring-home-mcp-private', 'other-fn') });
  assert.equal(response.statusCode, 403);
});
