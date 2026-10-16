import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createPublicKey, randomBytes, sign } from 'node:crypto';

process.env.NODE_ENV = 'test';
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
const ev = (body) => ({ body, isBase64Encoded: false });

// The relay is served by its own stand-alone stack (cloud/aws/family-relay); the formal ring-private stack is not changed.
test('HTTP edge: page with a strict CSP, script, hub calls signature-checked, junk and oversized bodies refused', async () => {
  const http = createFamilyRelayHttp({ relay: createFamilyRelay({ store: createMemoryRelayStore(), macPublicKeySpki: spki }) });
  const page = await http('family-page', ev(null));
  assert.equal(page.statusCode, 200); assert.match(page.headers['content-type'], /text\/html/u);
  assert.match(page.headers['content-security-policy'], /script-src 'self'/u); assert.match(page.body, /Remote approval/u);
  const js = await http('family-js', ev(null));
  assert.equal(js.statusCode, 200); assert.match(js.body, /crypto\.subtle\.generateKey/u);
  const ok = await http('relay-mac', ev(macBody('code', { codeSha256: sha('ABCDEFGH') })));
  assert.equal(ok.statusCode, 200, ok.body); assert.deepEqual(JSON.parse(ok.body), { ok: true });
  const forged = await http('relay-mac', ev(macBody('code', { codeSha256: sha('X') }).replace(/"signature":"[^"]+"/u, `"signature":"${Buffer.alloc(64).toString('base64url')}"`)));
  assert.equal(forged.statusCode, 403); assert.equal(JSON.parse(forged.body).error, 'MAC_SIGNATURE_INVALID');
  assert.equal((await http('relay-phone', ev('{not json'))).statusCode, 400);
  assert.equal((await http('relay-phone', ev(JSON.stringify({ x: 'y'.repeat(9000) })))).statusCode, 413);
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
