import test from 'node:test';
import assert from 'node:assert/strict';
import { createTelegramWebhookHandler } from '../telegram-webhook-handler.mjs';

const nowMs = Date.parse('2026-10-07T00:00:00Z');
const versionId = 'v'.repeat(32);
const secret = Object.freeze({ token: 'generated-token', webhookSecret: 'generated-webhook-secret-123456',
  botId: 'bot/generated', username: 'generated_bot', botGeneration: 3 });
const nonce = Buffer.alloc(32, 8).toString('base64url');
function body(change = {}) {
  return Buffer.from(JSON.stringify({ update_id: 7, message: { message_id: 8, date: nowMs / 1000,
    chat: { id: 101, type: 'private' }, from: { id: 101, is_bot: false, first_name: 'Generated' }, text: `/start ${nonce}`, ...change } }));
}
function fixture({ loadedVersion = versionId, identity = { verified: true,
  botId: secret.botId, username: secret.username } } = {}) {
  const calls = [];
  const handler = createTelegramWebhookHandler({ expectedVersionId: versionId, clock: () => nowMs,
    secretLoader: { async loadTelegram(input) { calls.push(['secret', input]); return { secret, metadata: { versionId: loadedVersion } }; } },
    createClient(input) { calls.push(['client', input]); return { async getMe() { calls.push(['getMe']); return identity; } }; },
    ownerAuthority: { async admitPrivateChat(input) { calls.push(['admit', input]); return { ownerEpoch: 1 }; } } });
  return { handler, calls };
}

test('fresh private exact start update is admitted with pinned bot generation', async () => {
  const f = fixture();
  const response = await f.handler.handle({ secretToken: secret.webhookSecret, body: body(), transport: Object.freeze({}) });
  assert.equal(response.statusCode, 200);
  assert.equal(JSON.parse(response.body).status, 'accepted');
  assert.equal(f.calls[0][1].expectedVersionId, versionId);
  assert.equal(f.calls.find(call => call[0] === 'admit')[1].botGeneration, 3);
  assert.equal(JSON.stringify(response).includes('101'), false);
});

test('wrong secret stops before getMe, JSON parse and Dynamo authority', async () => {
  const f = fixture();
  const response = await f.handler.handle({ secretToken: 'wrong-secret-value-123456789012', body: Buffer.from('{'), transport: {} });
  assert.equal(response.statusCode, 401);
  assert.deepEqual(f.calls.map(call => call[0]), ['secret']);
});

test('VersionId and getMe identity drift stop before Dynamo authority', async () => {
  const rotated = fixture({ loadedVersion: 'r'.repeat(32) });
  assert.equal((await rotated.handler.handle({ secretToken: secret.webhookSecret, body: body(), transport: {} })).statusCode, 401);
  assert.deepEqual(rotated.calls.map(call => call[0]), ['secret']);
  const wrongBot = fixture({ identity: { verified: true, botId: 'other', username: secret.username } });
  assert.equal((await wrongBot.handler.handle({ secretToken: secret.webhookSecret, body: body(), transport: {} })).statusCode, 503);
  assert.equal(wrongBot.calls.some(call => call[0] === 'admit'), false);
});

for (const [name, change] of [
  ['group', { chat: { id: 101, type: 'group' } }],
  ['different sender', { from: { id: 102, is_bot: false, first_name: 'Generated' } }],
  ['stale', { date: nowMs / 1000 - 61 }],
  ['not start', { text: '/help' }]
]) test('invalid Telegram update stops before owner mutation: ' + name, async () => {
  const f = fixture();
  const response = await f.handler.handle({ secretToken: secret.webhookSecret, body: body(change), transport: {} });
  assert.equal(response.statusCode, 400);
  assert.equal(f.calls.some(call => call[0] === 'admit'), false);
});


test('official private start with User and Chat names and entities projects only authority fields', async () => {
  const f = fixture();
  const response = await f.handler.handle({ secretToken: secret.webhookSecret, transport: {}, body: body({
    from: { id: 101, is_bot: false, first_name: 'SenderFirst', last_name: 'SenderLast',
      username: 'sender_handle', language_code: 'zh-hant', is_premium: true },
    chat: { id: 101, type: 'private', first_name: 'ChatFirst', last_name: 'ChatLast', username: 'chat_handle' },
    entities: [{ offset: 0, length: 6, type: 'bot_command' }]
  }) });
  assert.equal(response.statusCode, 200);
  assert.deepEqual(f.calls.find(call => call[0] === 'admit')[1], {
    updateId: '7', chatId: '101', userId: '101', chatType: 'private', enrollmentNonce: nonce,
    botId: secret.botId, botGeneration: 3
  });
  for (const metadata of ['SenderFirst', 'SenderLast', 'sender_handle', 'ChatFirst', 'ChatLast', 'chat_handle', 'bot_command']) {
    assert.equal(JSON.stringify({ calls: f.calls, response }).includes(metadata), false);
  }
});

test('unknown message, chat and User metadata does not affect admitted authority', async () => {
  const f = fixture();
  const response = await f.handler.handle({ secretToken: secret.webhookSecret, transport: {}, body: body({
    display_metadata: { label: 'unused-message-metadata' },
    from: { id: 101, is_bot: false, first_name: 'Generated', display_metadata: 'unused-user-metadata' },
    chat: { id: 101, type: 'private', display_metadata: 'unused-chat-metadata' }
  }) });
  assert.equal(response.statusCode, 200);
  assert.deepEqual(f.calls.find(call => call[0] === 'admit')[1], {
    updateId: '7', chatId: '101', userId: '101', chatType: 'private', enrollmentNonce: nonce,
    botId: secret.botId, botGeneration: 3
  });
  assert.equal(JSON.stringify({ calls: f.calls, response }).includes('unused-'), false);
});

test('required User name, bot, nonce, freshness and safe integer guards remain enforced', async () => {
  const updates = [
    { from: { id: 101, is_bot: false } },
    { from: { id: 101, is_bot: false, first_name: 5 } },
    { from: { id: 101, is_bot: true, first_name: 'Generated' } },
    { text: '/start invalid' },
    { text: `/start ${nonce.slice(0, -1)}h` },
    { date: nowMs / 1000 + 6 },
    { from: { id: Number.MAX_SAFE_INTEGER + 1, is_bot: false, first_name: 'Generated' } }
  ].map(change => JSON.parse(body(change)));
  for (const updateId of [0, Number.MAX_SAFE_INTEGER + 1]) {
    updates.push({ ...JSON.parse(body()), update_id: updateId });
  }
  for (const update of updates) {
    const f = fixture();
    const response = await f.handler.handle({ secretToken: secret.webhookSecret, transport: {},
      body: Buffer.from(JSON.stringify(update)) });
    assert.equal(response.statusCode, 400);
    assert.equal(f.calls.some(call => call[0] === 'admit'), false);
  }
});

test('forwarded, business and alternate sender fields are denied before authority', async () => {
  for (const [field, value] of [
    ['sender_chat', { id: -100101, type: 'channel', title: 'Generated Channel' }],
    ['sender_business_bot', { id: 201, is_bot: true, first_name: 'Generated Bot' }],
    ['business_connection_id', 'generated-connection'],
    ['via_bot', { id: 201, is_bot: true, first_name: 'Generated Bot' }],
    ['forward_origin', { type: 'user', date: nowMs / 1000,
      sender_user: { id: 202, is_bot: false, first_name: 'Original Sender' } }],
    ['is_automatic_forward', true],
    ['forward_from', { id: 202, is_bot: false, first_name: 'Original Sender' }],
    ['forward_from_chat', { id: -100101, type: 'channel', title: 'Generated Channel' }],
    ['forward_from_message_id', 9], ['forward_signature', 'Generated Signature'],
    ['forward_sender_name', 'Original Sender'], ['forward_date', nowMs / 1000]
  ]) {
    const f = fixture();
    const response = await f.handler.handle({ secretToken: secret.webhookSecret, transport: {},
      body: body({ [field]: value }) });
    assert.equal(response.statusCode, 400, field);
    assert.equal(f.calls.some(call => call[0] === 'admit'), false, field);
  }
});

test('top-level update accepts only the single message variant', async () => {
  for (const field of ['edited_message', 'callback_query', 'business_message']) {
    for (const includeMessage of [true, false]) {
      const update = JSON.parse(body());
      update[field] = update.message;
      if (!includeMessage) delete update.message;
      const f = fixture();
      const response = await f.handler.handle({ secretToken: secret.webhookSecret, transport: {},
        body: Buffer.from(JSON.stringify(update)) });
      assert.equal(response.statusCode, 400, field);
      assert.equal(f.calls.some(call => call[0] === 'admit'), false, field);
    }
  }
});
