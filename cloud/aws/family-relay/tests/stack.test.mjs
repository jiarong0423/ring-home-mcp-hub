// Stand-alone family relay stack: template contract + the function-URL handler driven end to end by the real hub client.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { webcrypto, randomBytes } from 'node:crypto';

process.env.NODE_ENV = 'test';
const template = JSON.parse(readFileSync(new URL('../template.json', import.meta.url), 'utf8'));
const { handler, installRelayForTest } = await import('../../ring-private/family-relay-lambda.mjs');
const { createFamilyRelay, createMemoryRelayStore, canonical, phoneKeyId } = await import('../../ring-private/family-relay.mjs');
const { createFamilyRelayHttp } = await import('../../ring-private/family-relay-http.mjs');
const { createRemoteRelay, loadOrCreateRelayKey, relayPublicKeySpki } = await import('../../../../src/remote_relay.mjs');

test('template: only the relay table, its log group, a role limited to that table, the function, its URL and the two URL permissions', () => {
  const r = template.Resources;
  assert.deepEqual(Object.fromEntries(Object.entries(r).map(([k, v]) => [k, v.Type])), {
    RelayTable: 'AWS::DynamoDB::Table', RelayLogGroup: 'AWS::Logs::LogGroup', RelayRole: 'AWS::IAM::Role', RelayFunction: 'AWS::Lambda::Function',
    RelayUrl: 'AWS::Lambda::Url', RelayUrlInvokePermission: 'AWS::Lambda::Permission', RelayFunctionInvokeViaUrlPermission: 'AWS::Lambda::Permission' });
  assert.deepEqual(r.RelayTable.Properties.TimeToLiveSpecification, { AttributeName: 'expires_at', Enabled: true });
  const stmts = r.RelayRole.Properties.Policies[0].PolicyDocument.Statement;
  assert.deepEqual(stmts[0].Action, ['dynamodb:GetItem', 'dynamodb:PutItem']); assert.deepEqual(stmts[0].Resource, { 'Fn::GetAtt': ['RelayTable', 'Arn'] });
  assert.equal(stmts.length, 2); assert.ok(stmts.every((s) => s.Resource !== '*'));
  assert.equal(r.RelayUrl.Properties.AuthType, 'NONE');
  assert.equal(r.RelayUrlInvokePermission.Properties.FunctionUrlAuthType, 'NONE');
  assert.equal(r.RelayFunctionInvokeViaUrlPermission.Properties.InvokedViaFunctionUrl, true, 'public invoke only through the URL');
  assert.equal(r.RelayFunction.Properties.Handler, 'family-relay-lambda.handler');
  assert.match('MCowBQYDK2VwAyEA' + 'a'.repeat(27), new RegExp(template.Parameters.HubPublicKeySpki.AllowedPattern, 'u'));
  assert.doesNotMatch(JSON.stringify(template), /ring-home-mcp-private|RingAuthApi/u, 'never references the formal stack');
});

const v2 = (method, rawPath, body = null, extra = {}) => ({ version: '2.0', rawPath, rawQueryString: '', headers: {}, requestContext: { http: { method } }, body, isBase64Encoded: false, ...extra });

test('function URL routes: page, script, relay; unknown paths, "/family/" and query strings refused; unconfigured -> 503', async () => {
  installRelayForTest(async () => { throw new Error('no table'); });
  assert.equal((await handler(v2('GET', '/family'))).statusCode, 503);
  const hubKey = loadOrCreateRelayKey(join(mkdtempSync(join(tmpdir(), 'fr-')), 'relay.key'));
  installRelayForTest(async () => createFamilyRelayHttp({ relay: createFamilyRelay({ store: createMemoryRelayStore(), macPublicKeySpki: relayPublicKeySpki(hubKey) }) }));
  const page = await handler(v2('GET', '/family'));
  assert.equal(page.statusCode, 200); assert.match(page.headers['content-type'], /text\/html/u); assert.match(page.body, /Remote approval/u);
  assert.equal((await handler(v2('GET', '/family/app.js'))).statusCode, 200);
  for (const [m, p] of [['GET', '/family/'], ['GET', '/'], ['DELETE', '/relay/mac'], ['GET', '/relay/phone']]) assert.equal((await handler(v2(m, p))).statusCode, 404, `${m} ${p}`);
  assert.equal((await handler(v2('GET', '/family', null, { rawQueryString: 'code=X' }))).statusCode, 400);
  assert.equal((await handler(v2('POST', '/relay/phone', '{oops'))).statusCode, 400);
});

test('end to end through the function-URL handler: hub enables, phone enrols and approves, hub verifies and gets the decision', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'fr-'));
  const hubKey = loadOrCreateRelayKey(join(dir, 'relay.key'));
  installRelayForTest(async () => createFamilyRelayHttp({ relay: createFamilyRelay({ store: createMemoryRelayStore(), macPublicKeySpki: relayPublicKeySpki(hubKey) }) }));
  const viaUrl = async (url, init) => { const u = new URL(url); const r = await handler(v2(init.method, u.pathname, init.body)); return { ok: r.statusCode < 300, status: r.statusCode, json: async () => JSON.parse(r.body) }; };
  const decisions = [];
  const hub = createRemoteRelay({ base: 'https://abc123.lambda-url.ap-southeast-1.on.aws/', privateKey: hubKey, storePath: join(dir, 'phones.json'), fetchImpl: viaUrl, onDecision: (d) => decisions.push(d) });
  const { code, url } = await hub.enable({ deviceId: 'phone_admin' });
  assert.equal(url, `https://abc123.lambda-url.ap-southeast-1.on.aws/family#code=${code}`);
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const { kty, crv, x, y } = await webcrypto.subtle.exportKey('jwk', pair.publicKey); const jwk = { kty, crv, x, y }; const keyId = phoneKeyId(jwk);
  const phone = async (op, payload) => { const ts = Date.now(); const nonce = randomBytes(18).toString('base64url');
    const sig = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, Buffer.from(canonical({ op, payload, keyId, ts, nonce })));
    const r = await handler(v2('POST', '/relay/phone', JSON.stringify({ op, payload, keyId, ts, nonce, signature: Buffer.from(sig).toString('base64url') }))); return { status: r.statusCode, body: JSON.parse(r.body) }; };
  assert.equal((await phone('register', { code, jwk, name: 'Amy' })).status, 200);
  await hub.tick();
  assert.equal(hub.status().phones.length, 1);
  const requestId = 'Q'.repeat(22);
  await hub.publishRequest({ requestId, kind: 'ring', label: 'Ring doorbell', hasSnapshot: true, expiresAtMs: Date.now() + 60_000 });
  assert.equal((await phone('pending', {})).body.request.requestId, requestId);
  assert.equal((await phone('decide', { requestId, decision: 'approve' })).status, 200);
  await hub.tick();
  assert.deepEqual(decisions.map((d) => [d.requestId, d.decision, d.approver]), [[requestId, 'approve', 'Amy (remote)']]);
});
