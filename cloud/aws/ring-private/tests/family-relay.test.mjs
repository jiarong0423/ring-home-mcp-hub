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

// Runs the generated page script against the real relay (memory store, real P-256 signatures) with a tiny fake DOM and
// manual timers. Seen in video/scenes/v4c_remote_approve.mp4: after Approve, the next poll brought the pending card back
// for ~3 s because the relay still lists the request until the hub posts its result.
test('family page: an answered request is never shown as pending again; "waiting for the hub" stays until the result', async () => {
  const { runInNewContext } = await import('node:vm');
  const { FAMILY_PAGE_JS } = await import('../family-page.mjs');
  const { phoneKeyId } = await import('../family-relay.mjs');
  const store = createMemoryRelayStore();
  const http = createFamilyRelayHttp({ relay: createFamilyRelay({ store, macPublicKeySpki: spki }) });
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const { kty, crv, x, y } = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const keyId = phoneKeyId({ kty, crv, x, y });
  await store.put({ pk: `relay:phone:${keyId}`, jwk: { kty, crv, x, y }, name: 'Amy', active: true });
  const requestId = 'mcp_request_0001';
  const mac = async (op, payload) => assert.equal((await http('relay-mac', ev(macBody(op, payload)))).statusCode, 200);
  await mac('request', { request: { requestId, kind: 'mcp', label: 'AI agent (MCP)', expiresAtMs: Date.now() + 60_000 } });

  const els = new Map(); const node = (id) => { if (!els.has(id)) els.set(id, { id, hidden: id === 'ask', textContent: '', disabled: false, value: '', onclick: null }); return els.get(id); };
  const keys = new Map([['phone', { privateKey: pair.privateKey, keyId, name: 'Amy' }]]);
  const indexedDB = { open() {
    const open = { result: { transaction: () => { const tx = { objectStore: () => ({ get: (k) => ({ result: keys.get(k) }), put: (v, k) => { keys.set(k, v); return {}; } }) }; setImmediate(() => tx.oncomplete?.()); return tx; } } };
    setImmediate(() => open.onsuccess());
    return open;
  } };
  const timers = [];
  const fetch = async (_url, init) => { const r = await http('relay-phone', ev(init.body)); return { ok: r.statusCode < 400, status: r.statusCode, json: async () => JSON.parse(r.body) }; };
  runInNewContext(FAMILY_PAGE_JS, { document: { getElementById: node }, indexedDB, crypto, fetch, TextEncoder, URLSearchParams, btoa,
    location: { hash: '', pathname: '/family' }, history: { replaceState() {} }, setTimeout: (fn) => { timers.push(fn); } });
  const settle = async () => { while (!timers.length) await new Promise((r) => setImmediate(r)); };
  const poll = async () => { await settle(); await timers.shift()(); };
  const status = () => node('status').textContent;

  await settle();
  assert.equal(node('ask').hidden, false, 'the pending request is shown');
  assert.match(node('ask-title').textContent, /AI agent \(MCP\)/u);
  await node('approve').onclick();
  assert.equal(node('ask').hidden, true);
  assert.match(status(), /^Approved\. Waiting for the hub/u);
  for (let i = 0; i < 3; i += 1) {   // the relay still lists the request (no hub result yet): several polls must not bring it back
    await poll();
    assert.equal(node('ask').hidden, true, `poll ${i + 1}: the answered request must not reappear as pending`);
    assert.match(status(), /^Approved\. Waiting for the hub/u);
  }
  await mac('result', { requestId, status: 'approved', receiptId: 'rcpt_0001' });
  await poll();
  assert.equal(node('ask').hidden, true);
  assert.equal(status(), 'Last request: approved (receipt rcpt_0001). Watching for new requests.');

  await mac('request', { request: { requestId: 'mcp_request_0002', kind: 'mcp', label: 'AI agent (MCP)', expiresAtMs: Date.now() + 60_000 } });
  await poll();
  assert.equal(node('ask').hidden, false, 'a new request id is shown again');
  await node('deny').onclick();
  await poll();
  assert.equal(node('ask').hidden, true);
  assert.match(status(), /^Denied\./u);
});
