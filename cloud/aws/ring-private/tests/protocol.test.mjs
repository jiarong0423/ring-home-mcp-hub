import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { computeNonce, matchUnclaimedNonce, parseVerifiedWebhook, validateLinkQuery, verifyWebhookSignature } from '../protocol.mjs';

const key = 'generated-test-signing-key-not-a-provider-secret';
const now = 1_790_000_000_000;
const time = String(now - 10_000);
const accountId = 'ava1.ring.account.generated-test';

test('nonce matches one unclaimed account with exact URL-safe encoding', () => {
  const nonce = computeNonce(time, accountId, key);
  assert.match(nonce, /^[A-Za-z0-9_-]{43}$/);
  const matched = matchUnclaimedNonce({ time, nonce }, [
    { id: 'wrong', accountId: 'ava1.ring.account.other', status: 'unclaimed' },
    { id: 'right', accountId, status: 'unclaimed' }
  ], key, now);
  assert.equal(matched.id, 'right');
});

test('expired, future, malformed and replayed nonce input is rejected', () => {
  const nonce = computeNonce(time, accountId, key);
  assert.throws(() => validateLinkQuery(String(now - 600_001), nonce, now), /expired_link/);
  assert.throws(() => validateLinkQuery(String(now + 1), nonce, now), /expired_link/);
  assert.throws(() => validateLinkQuery(`${time}.0`, nonce, now), /invalid_time/);
  assert.throws(() => validateLinkQuery(time, `${nonce}=`, now), /invalid_nonce/);
  assert.throws(() => matchUnclaimedNonce({ time, nonce }, [{ id: 'used', accountId, status: 'completed' }], key, now), /link_not_found/);
  assert.throws(() => matchUnclaimedNonce({ time, nonce }, [
    { id: 'a', accountId, status: 'unclaimed' }, { id: 'b', accountId, status: 'unclaimed' }
  ], key, now), /ambiguous_link/);
});

function signed(raw) {
  return `sha256=${createHmac('sha256', key).update(raw).digest('hex')}`;
}

test('webhook validates the exact raw bytes before JSON parsing', () => {
  const body = Buffer.from(JSON.stringify({
    meta: { version: '1.1', time: '2026-09-29T12:00:00Z', request_id: 'generated-request', account_id: accountId },
    data: { id: 'generated-event', type: 'motion_detected' }
  }));
  const signature = signed(body);
  assert.equal(verifyWebhookSignature(body, signature, key), true);
  assert.equal(parseVerifiedWebhook(body, signature, key).requestId, 'generated-request');
  assert.equal(verifyWebhookSignature(Buffer.from(`${body} `), signature, key), false);
  assert.throws(() => parseVerifiedWebhook(body, 'sha256=bad', key), /invalid_signature/);
  assert.equal(verifyWebhookSignature(Buffer.alloc(65_537), signed(Buffer.alloc(65_537)), key), false);
});

test('signed but structurally invalid webhook fails closed', () => {
  const body = Buffer.from('{"meta":{"version":"1.0"},"data":{}}');
  assert.throws(() => parseVerifiedWebhook(body, signed(body), key), /invalid_webhook/);
});

test('weak signing keys cannot form nonces or authenticate direct webhook calls', () => {
  const body = Buffer.from('{"generated":true}');
  const weakSignature = `sha256=${createHmac('sha256', 'x').update(body).digest('hex')}`;
  assert.throws(() => computeNonce(time, accountId, 'x'), /signing_key_config/);
  assert.equal(verifyWebhookSignature(body, weakSignature, 'x'), false);
});
