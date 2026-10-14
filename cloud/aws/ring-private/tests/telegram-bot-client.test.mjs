import test from 'node:test';
import assert from 'node:assert/strict';
import {
  TelegramBotClientError,
  createTelegramBotClient
} from '../telegram-bot-client.mjs';

const botId = '20001';
const username = 'Homemcphub_bot';
const generatedToken = () => `${botId}:${'G'.repeat(32)}`;

function getMeResponse(overrides = {}) {
  return Response.json({
    ok: true,
    result: { id: Number(botId), is_bot: true, username, ...overrides }
  });
}

function sendResponse(chatId = '10001', overrides = {}) {
  return Response.json({
    ok: true,
    result: {
      message_id: 41,
      chat: { id: Number(chatId), type: 'private' },
      from: { id: Number(botId), is_bot: true, username },
      ...overrides
    }
  });
}

function client(fetchImpl, timeoutMs = 100) {
  return createTelegramBotClient({
    fetchImpl,
    timeoutMs,
    token: generatedToken(),
    botId,
    username,
    botGeneration: 1
  });
}

function inspectOfficialUrl(value, method) {
  const token = generatedToken();
  const expected = `https://api.telegram.org/bot${token}/${method}`;
  return Object.freeze({
    exact: value === expected,
    httpsOrigin: typeof value === 'string' && value.startsWith('https://api.telegram.org/bot'),
    oneToken: typeof value === 'string' && value.indexOf(token) === value.lastIndexOf(token),
    fixedMethod: typeof value === 'string' && value.endsWith(`/${method}`)
  });
}

function isCode(code) {
  return error => error instanceof TelegramBotClientError && error.code === code && error.message === code;
}

test('getMe uses the exact official runtime-only token path and returns only verified identity', async () => {
  const calls = [];
  const result = await client(async (url, init) => {
    calls.push({ route: inspectOfficialUrl(url, 'getMe'), init });
    return getMeResponse();
  }).getMe();
  assert.deepEqual(result, { botId, username, verified: true });
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].route, {
    exact: true,
    httpsOrigin: true,
    oneToken: true,
    fixedMethod: true
  });
  assert.deepEqual(JSON.parse(calls[0].init.body), {});
  assert.equal(calls[0].init.body.includes(generatedToken()), false);
  assert.equal('authorization' in calls[0].init.headers, false);
  assert.equal(calls[0].init.method, 'POST');
  assert.equal(calls[0].init.redirect, 'error');
  assert.equal(calls[0].init.signal.aborted, true);
  assert.equal(JSON.stringify(result).includes(generatedToken()), false);
});

test('sendPrivate is one bounded private-chat dispatch with an exact body', async () => {
  const calls = [];
  const result = await client(async (url, init) => {
    calls.push({ route: inspectOfficialUrl(url, 'sendMessage'), init });
    return sendResponse();
  }).sendPrivate({ chatId: '10001', text: 'Pairing approved' });
  assert.deepEqual(result, { messageId: 41, delivered: true });
  assert.deepEqual(calls[0].route, {
    exact: true,
    httpsOrigin: true,
    oneToken: true,
    fixedMethod: true
  });
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    chat_id: '10001',
    text: 'Pairing approved',
    disable_notification: true,
    protect_content: true
  });
  assert.equal(calls[0].init.body.includes(generatedToken()), false);
  assert.equal(JSON.stringify(result).includes('Pairing approved'), false);
});

test('configuration is exact, descriptor-safe, and checked before dispatch', async () => {
  const base = {
    fetchImpl: async () => getMeResponse(),
    token: generatedToken(),
    botId,
    username,
    botGeneration: 1
  };
  for (const value of [
    null,
    {},
    { ...base, token: `20002:${'G'.repeat(32)}` },
    { ...base, username: 'Other_bot' },
    { ...base, botGeneration: 0 },
    { ...base, timeoutMs: 10 },
    { ...base, extra: true }
  ]) {
    assert.throws(() => createTelegramBotClient(value), isCode('telegram_client_config'));
  }
  let getterCalls = 0;
  const hostile = { ...base };
  Object.defineProperty(hostile, 'token', {
    enumerable: true,
    get() { getterCalls += 1; throw new Error(generatedToken()); }
  });
  assert.throws(() => createTelegramBotClient(hostile), isCode('telegram_client_config'));
  assert.equal(getterCalls, 0);
});

test('sendPrivate rejects groups, controls, oversized text, and extra fields before dispatch', async () => {
  let calls = 0;
  const port = client(async () => { calls += 1; return sendResponse(); });
  const invalid = [
    { chatId: '-10001', text: 'denied' },
    { chatId: '10001', text: '' },
    { chatId: '10001', text: 'x'.repeat(4097) },
    { chatId: '10001', text: 'line\nbreak' },
    { chatId: '10001', text: 'ok', parseMode: 'HTML' },
    null
  ];
  for (const input of invalid) {
    await assert.rejects(port.sendPrivate(input), isCode('telegram_input_invalid'));
  }
  assert.equal(calls, 0);
});

test('getMe fails closed for a different bot and does not expose response details', async () => {
  const privateDetail = 'generated-private-response-detail';
  await assert.rejects(client(async () => getMeResponse({ id: 20002, privateDetail })).getMe(), error => {
    assert.equal(isCode('telegram_identity_mismatch')(error), true);
    assert.equal(error.message.includes(privateDetail), false);
    assert.equal(JSON.stringify(error).includes(privateDetail), false);
    return true;
  });
});

test('read failures have finite errors, bounded bodies, and no credential echo', async () => {
  const cases = [
    async () => { throw new Error(generatedToken()); },
    async () => new Response('not-json', { headers: { 'content-type': 'text/plain' } }),
    async () => new Response('{', { headers: { 'content-type': 'application/json' } }),
    async () => Response.json({ private: 'x'.repeat(70_000) }),
    async () => new Response('', { status: 302, headers: { location: 'https://other.example/' } })
  ];
  for (const fetchImpl of cases) {
    await assert.rejects(client(fetchImpl).getMe(), error => {
      assert.ok(error instanceof TelegramBotClientError);
      assert.ok(['telegram_unavailable', 'telegram_response_invalid'].includes(error.code));
      assert.equal(error.message.includes(generatedToken()), false);
      assert.equal(JSON.stringify(error).includes(generatedToken()), false);
      assert.equal('cause' in error, false);
      return true;
    });
  }
});

test('a stalled getMe is aborted once and remains read-only unavailable', async () => {
  let calls = 0;
  let signal;
  await assert.rejects(client(async (_url, init) => {
    calls += 1;
    signal = init.signal;
    return new Promise((_resolve, reject) => {
      init.signal.addEventListener('abort', () => reject(new Error(generatedToken())), { once: true });
    });
  }).getMe(), isCode('telegram_unavailable'));
  assert.equal(calls, 1);
  assert.equal(signal.aborted, true);
});

test('a stalled or ambiguous send is terminal unknown and never retried', async () => {
  let calls = 0;
  await assert.rejects(client(async (_url, init) => {
    calls += 1;
    return new Promise((_resolve, reject) => {
      init.signal.addEventListener('abort', () => reject(new Error(generatedToken())), { once: true });
    });
  }).sendPrivate({ chatId: '10001', text: 'single dispatch' }), isCode('telegram_outcome_unknown'));
  assert.equal(calls, 1);

  calls = 0;
  await assert.rejects(client(async () => {
    calls += 1;
    return sendResponse('10002');
  }).sendPrivate({ chatId: '10001', text: 'single dispatch' }), isCode('telegram_outcome_unknown'));
  assert.equal(calls, 1);
});
