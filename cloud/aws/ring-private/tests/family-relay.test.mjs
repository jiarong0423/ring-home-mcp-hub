import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createPublicKey, randomBytes, sign } from 'node:crypto';

process.env.NODE_ENV = 'test';
const { handler, installFamilyRelayFactoryForTest } = await import('../handler.mjs');
const { createFamilyRelay, createMemoryRelayStore, canonical, MAC_SCHEMA } = await import('../family-relay.mjs');
const { createFamilyRelayHttp, createDynamoRelayStore } = await import('../family-relay-http.mjs');
const { createHash } = await import('node:crypto');

const hub = generateKeyPairSync('ed25519').privateKey;
const spki = createPublicKey(hub).export({ format: 'der', type: 'spki' }).toString('base64url');
const sha = (v) => createHash('sha256').update(v).digest('hex');
function macBody(op, payload) {
  const now = Date.now();
  const claims = { schema: MAC_SCHEMA, op, payloadSha256: sha(canonical(payload)), nonce: randomBytes(18).toString('base64url'), issuedAt: now, expiresAt: now + 10_000 };
  return JSON.stringify({ claims, signature: sign(null, Buffer.from(canonical(claims)), hub).toString('base64url'), payload });
}
const event = (method, path, body = null) => ({ resource: path, path, httpMethod: method, headers: {}, multiValueHeaders: {}, queryStringParameters: null,
  multiValueQueryStringParameters: null, pathParameters: null, stageVariables: null, requestContext: { apiId: 'api123', stage: 'staging' }, body, isBase64Encoded: false });

test('family relay routes are off unless RING_FAMILY_RELAY_STATE=enabled', async () => {
  process.env.RING_BACKEND_STATE = 'enabled'; delete process.env.RING_FAMILY_RELAY_STATE;
  const r = await handler(event('GET', '/family'));
  assert.equal(r.statusCode, 503);
});

test('page, script and hub/phone relay calls through the Lambda handler; wrong stage refused', async () => {
  process.env.RING_BACKEND_STATE = 'enabled'; process.env.RING_FAMILY_RELAY_STATE = 'enabled';
  process.env.RING_MCP_EXPECTED_API_ID = 'api123'; process.env.RING_MCP_EXPECTED_STAGE = 'staging';
  installFamilyRelayFactoryForTest(() => createFamilyRelayHttp({ relay: createFamilyRelay({ store: createMemoryRelayStore(), macPublicKeySpki: spki }) }));
  const page = await handler(event('GET', '/family'));
  assert.equal(page.statusCode, 200); assert.match(page.headers['content-type'], /text\/html/u);
  assert.match(page.headers['content-security-policy'], /script-src 'self'/u);
  assert.match(page.body, /Remote approval/u);
  const js = await handler(event('GET', '/family/app.js'));
  assert.equal(js.statusCode, 200); assert.match(js.body, /crypto\.subtle\.generateKey/u);
  const ok = await handler(event('POST', '/relay/mac', macBody('code', { codeSha256: sha('ABCDEFGH') })));
  assert.equal(ok.statusCode, 200, ok.body); assert.deepEqual(JSON.parse(ok.body), { ok: true });
  const forged = await handler(event('POST', '/relay/mac', macBody('code', { codeSha256: sha('X') }).replace(/"signature":"[^"]+"/u, `"signature":"${Buffer.alloc(64).toString('base64url')}"`)));
  assert.equal(forged.statusCode, 403); assert.equal(JSON.parse(forged.body).error, 'MAC_SIGNATURE_INVALID');
  const junk = await handler(event('POST', '/relay/phone', '{not json'));
  assert.equal(junk.statusCode, 400);
  const big = await handler(event('POST', '/relay/phone', JSON.stringify({ x: 'y'.repeat(9000) })));
  assert.equal(big.statusCode, 413);
  const wrongStage = await handler({ ...event('GET', '/family'), requestContext: { apiId: 'api123', stage: 'prod' } });
  assert.equal(wrongStage.statusCode, 400);
});

test('DynamoDB store: TTL honoured on read; ifNotExists maps a conditional failure to false', async () => {
  const items = new Map(); let now = 1_800_000_000_000;
  const getItem = async ({ Key }) => ({ Item: items.get(Key.pk.S) });
  const putItem = async (input) => {
    if (input.ConditionExpression) {
      const cur = items.get(input.Item.pk.S);
      if (cur && Number(cur.expires_at.N) >= Number(input.ExpressionAttributeValues[':now'].N)) { const e = new Error('x'); e.name = 'ConditionalCheckFailedException'; throw e; }
    }
    items.set(input.Item.pk.S, input.Item);
  };
  const store = createDynamoRelayStore({ getItem, putItem, tableName: 'ring-home-mcp-private-event', clock: () => now });
  assert.equal(await store.put({ pk: 'relay:nonce:a', expiresAtMs: now + 60_000 }, { ifNotExists: true }), true);
  assert.equal(await store.put({ pk: 'relay:nonce:a', expiresAtMs: now + 60_000 }, { ifNotExists: true }), false);
  assert.deepEqual(await store.get('relay:nonce:a'), { pk: 'relay:nonce:a', expiresAtMs: now + 60_000 });
  now += 120_000;
  assert.equal(await store.get('relay:nonce:a'), null, 'expired rows read as absent before DynamoDB TTL deletes them');
  assert.equal(await store.put({ pk: 'relay:nonce:a', expiresAtMs: now + 60_000 }, { ifNotExists: true }), true, 'an expired row can be reused');
});

test('generated family-page.mjs matches family-page/index.html and app.js (run scripts/gen_family_page.mjs after edits)', async () => {
  const { readFileSync } = await import('node:fs');
  const { renderFamilyPageModule } = await import('../../../../scripts/gen_family_page.mjs');
  assert.equal(readFileSync(new URL('../family-page.mjs', import.meta.url), 'utf8'), renderFamilyPageModule());
});
