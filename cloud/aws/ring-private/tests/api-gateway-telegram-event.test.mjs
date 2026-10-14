import test from 'node:test';
import assert from 'node:assert/strict';
import { parseRestV1TelegramEvent } from '../api-gateway-telegram-event.mjs';

const secret = 'generated_webhook_secret_1234567890';
function event(change = {}) {
  const headers = { 'Content-Type': 'application/json', 'X-Telegram-Bot-Api-Secret-Token': secret };
  const body = Buffer.from('{"update_id":1}').toString('base64');
  return { resource: '/telegram/webhook', path: '/telegram/webhook', httpMethod: 'POST', headers,
    multiValueHeaders: Object.fromEntries(Object.entries(headers).map(([key, value]) => [key, [value]])),
    queryStringParameters: null, multiValueQueryStringParameters: null, pathParameters: null, stageVariables: null,
    requestContext: { stage: 'prod', httpMethod: 'POST', resourcePath: '/telegram/webhook', path: '/prod/telegram/webhook' },
    body, isBase64Encoded: true, ...change };
}

test('exact REST v1 webhook yields only secret, bytes and minimal frozen transport', () => {
  const parsed = parseRestV1TelegramEvent(event());
  assert.equal(parsed.secretToken, secret);
  assert.deepEqual(parsed.body, Buffer.from('{"update_id":1}'));
  assert.deepEqual(parsed.transport, { method: 'POST', path: '/telegram/webhook', resource: '/telegram/webhook', stage: 'prod' });
  assert.equal(Object.isFrozen(parsed), true);
  assert.equal(JSON.stringify(parsed.transport).includes('sourceIp'), false);
});

for (const [name, change] of [
  ['v2', { version: '2.0' }], ['wrong route', { path: '/ring/webhook' }],
  ['query', { queryStringParameters: { x: '1' }, multiValueQueryStringParameters: { x: ['1'] } }],
  ['bad base64', { body: 'Zh==' }], ['plain body', { isBase64Encoded: false }]
]) test('malformed Telegram event is denied: ' + name, () => {
  assert.throws(() => parseRestV1TelegramEvent(event(change)), /telegram_/);
});

test('duplicate or mismatched webhook header is denied', () => {
  const input = event();
  input.multiValueHeaders['X-Telegram-Bot-Api-Secret-Token'] = [secret, secret];
  assert.throws(() => parseRestV1TelegramEvent(input), /telegram_/);
  const mismatch = event();
  mismatch.headers['X-Telegram-Bot-Api-Secret-Token'] = secret + 'x';
  assert.throws(() => parseRestV1TelegramEvent(mismatch), /telegram_/);
});
