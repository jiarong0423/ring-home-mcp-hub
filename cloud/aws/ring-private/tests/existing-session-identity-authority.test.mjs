import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import {
  createExistingSessionIdentityAuthority,
  ExistingSessionIdentityAuthorityError
} from '../existing-session-identity-authority.mjs';

const initialNow = 1_800_000_000_000;
const accountId = 'ring-account-generated';
const sessionProof = 'session-proof-generated';
const csrf = 'csrf-generated';
const rejectCode = code => error => error instanceof ExistingSessionIdentityAuthorityError &&
  error.code === code && error.message === code;

function fixture(change = {}) {
  let now = initialNow;
  const calls = [];
  const control = {
    session: {
      productionAdmitted: true,
      serverNow: initialNow,
      ownerEpoch: 7,
      sessionId: 'session-generated',
      sessionGeneration: 3,
      grantId: 'grant-generated',
      grantGeneration: 5,
      sessionExpiresAt: initialNow + 1_200_000,
      idleExpiresAt: initialNow + 900_000,
      trustExpiresAt: initialNow + 1_800_000
    },
    binding: {
      actorRef: 'actor/generated',
      ownerRef: 'owner/generated',
      householdRef: 'household/generated',
      scopeRefs: ['ring/read', 'ring/link'],
      accountIdentifier: accountId,
      epoch: 7,
      expiresAt: initialNow + 1_500_000
    }
  };
  const currentView = () => Object.freeze({ ...control.session, serverNow: now });
  const sessionAuthority = {
    async inspectSession(args) {
      calls.push(['inspect', { ...args }]);
      if (change.inspect) return change.inspect(args, currentView());
      return currentView();
    },
    async withCurrentSession(args, perform) {
      calls.push(['locked', { ...args }]);
      if (change.withCurrent) return change.withCurrent(args, perform, currentView());
      const output = perform(currentView());
      assert.equal(output instanceof Promise, false);
      return output;
    },
    async authenticate() { throw Error('must-not-renew'); },
    async rotate() { throw Error('must-not-rotate'); }
  };
  const adapter = createExistingSessionIdentityAuthority({
    sessionAuthority,
    extractSession(context) {
      calls.push(['extract', context]);
      if (change.extract) return change.extract(context);
      return { sessionProof, csrf };
    },
    resolveAccountBinding(input) {
      calls.push(['binding', input]);
      if (change.binding) return change.binding(input, control.binding);
      return { ...control.binding, scopeRefs: [...control.binding.scopeRefs] };
    },
    ...(change.policy ? { policy: change.policy } : {})
  });
  return {
    adapter,
    calls,
    control,
    context: Object.freeze({ cookie: 'constructor-trusted-cookie-context' }),
    setNow(value) { now = value; },
    resolve() { return adapter.resolveMatchedRingAccount({ accountId, context: this.context }); }
  };
}

test('admitted current session creates a private non-renewing lease and exact recheck', async () => {
  const f = fixture();
  const lease = await f.resolve();
  assert.equal(Object.isFrozen(lease), true);
  assert.deepEqual({ ...lease, proof: undefined }, {
    proof: undefined,
    actorRef: 'actor/generated',
    ownerRef: 'owner/generated',
    householdRef: 'household/generated',
    scopeRefs: ['ring/read', 'ring/link'],
    accountIdentifier: accountId,
    epoch: 7,
    expiresAt: initialNow + 600_000
  });
  assert.equal(Object.getPrototypeOf(lease.proof), null);
  assert.equal(Object.isFrozen(lease.proof), true);
  assert.equal(JSON.stringify(lease.proof), '{}');
  assert.equal(JSON.stringify(lease.proof).includes(sessionProof), false);
  f.setNow(initialNow + 1_000);
  assert.deepEqual(await f.adapter.recheck(lease.proof), lease);
  assert.deepEqual(f.calls.map(([operation]) => operation), [
    'extract', 'inspect', 'locked', 'binding', 'locked', 'binding'
  ]);
  assert.equal(f.calls.filter(([operation]) => operation === 'inspect').length, 1);
  for (const call of f.calls.filter(([operation]) => operation === 'binding')) {
    assert.equal(Object.isFrozen(call[1]), true);
    assert.equal(Object.isFrozen(call[1].session), true);
    assert.equal(call[1].accountId, accountId);
  }
});

for (const [field, value] of [
  ['ownerEpoch', 8],
  ['sessionId', 'session-other'],
  ['sessionGeneration', 4],
  ['grantId', 'grant-other'],
  ['grantGeneration', 6]
]) test('recheck denies pinned session/grant drift: ' + field, async () => {
  const f = fixture();
  const lease = await f.resolve();
  f.control.session[field] = value;
  await assert.rejects(f.adapter.recheck(lease.proof), rejectCode('IDENTITY_SESSION_CHANGED'));
});

for (const [name, mutate] of [
  ['actor tuple', binding => { binding.actorRef = 'actor/changed'; }],
  ['owner tuple', binding => { binding.ownerRef = 'owner/changed'; }],
  ['household tuple', binding => { binding.householdRef = 'household/changed'; }],
  ['scope order', binding => { binding.scopeRefs = ['ring/link', 'ring/read']; }],
  ['provider account', binding => { binding.accountIdentifier = 'ring-account-other'; }],
  ['owner epoch', binding => { binding.epoch = 8; }],
  ['binding expiry', binding => { binding.expiresAt += 1; }]
]) test('recheck denies exact identity binding drift: ' + name, async () => {
  const f = fixture();
  const lease = await f.resolve();
  mutate(f.control.binding);
  await assert.rejects(f.adapter.recheck(lease.proof), error =>
    ['IDENTITY_BINDING_CHANGED', 'IDENTITY_BINDING_DENIED'].includes(error.code));
});

test('session deadline shrink and lease expiry fail closed without renewal', async () => {
  const f = fixture();
  const lease = await f.resolve();
  f.control.session.idleExpiresAt = lease.expiresAt - 1;
  await assert.rejects(f.adapter.recheck(lease.proof), rejectCode('IDENTITY_BINDING_CHANGED'));
  const expired = fixture();
  const expiredLease = await expired.resolve();
  expired.setNow(expiredLease.expiresAt);
  await assert.rejects(expired.adapter.recheck(expiredLease.proof), rejectCode('IDENTITY_EXPIRED'));
});

test('proof capacity is capped and close invalidates proof and future resolution', async () => {
  const f = fixture({ policy: { maxLiveProofs: 1, maxLeaseMs: 600_000, closeTimeoutMs: 100 } });
  const lease = await f.resolve();
  await assert.rejects(f.resolve(), rejectCode('IDENTITY_PROOF_CAPACITY'));
  assert.deepEqual(await f.adapter.close(), { closed: true });
  assert.deepEqual(await f.adapter.close(), { closed: true });
  await assert.rejects(f.adapter.recheck(lease.proof), rejectCode('IDENTITY_CLOSED'));
  await assert.rejects(f.resolve(), rejectCode('IDENTITY_CLOSED'));
});

test('raw Telegram identity fields and values never become authority output', async () => {
  let extracted = 0;
  const f = fixture({ extract(context) { extracted += 1; return { sessionProof, csrf }; } });
  for (const context of [
    { userId: 1001 },
    { chat_id: -1001 },
    { botId: 2001 },
    { botToken: '2001:private-token' },
    { telegramToken: 'private-token' }
  ]) {
    await assert.rejects(
      f.adapter.resolveMatchedRingAccount({ accountId, context }),
      rejectCode('IDENTITY_INPUT_DENIED')
    );
  }
  assert.equal(extracted, 0);
  const rawReference = fixture({ binding(_input, binding) {
    return { ...binding, actorRef: '1001', scopeRefs: [...binding.scopeRefs] };
  } });
  await assert.rejects(rawReference.resolve(), rejectCode('IDENTITY_BINDING_DENIED'));
  assert.equal(JSON.stringify(await f.adapter.close()).includes('private-token'), false);
});

for (const [name, context] of [
  ['telegram_user_id', { telegram_user_id: 1001 }],
  ['telegramChatId', { telegramChatId: -1001 }],
  ['tg_user_id', { tg_user_id: 1001 }],
  ['telegram_bot_token', { telegram_bot_token: '2001:private-token' }],
  ['nested credentials bot-token', { credentials: { 'bot-token': '2001:private-token' } }]
]) test('verifier raw Telegram alias rejects before every port: ' + name, async () => {
  let extracted = 0;
  const f = fixture({ extract() { extracted += 1; return { sessionProof, csrf }; } });
  await assert.rejects(
    f.adapter.resolveMatchedRingAccount({ accountId, context }),
    rejectCode('IDENTITY_INPUT_DENIED')
  );
  assert.equal(extracted, 0);
  assert.equal(f.calls.length, 0);
});

test('constructor and callback boundaries reject proxies, accessors, async binding and extra credential fields', async () => {
  let traps = 0;
  const proxy = new Proxy({}, { get() { traps += 1; throw Error('private'); } });
  assert.throws(() => createExistingSessionIdentityAuthority(proxy), rejectCode('IDENTITY_AUTHORITY_CONFIG'));
  assert.equal(traps, 0);
  const base = fixture();
  const accessor = {};
  Object.defineProperty(accessor, 'sessionProof', { enumerable: true, get() { traps += 1; return sessionProof; } });
  Object.defineProperty(accessor, 'csrf', { enumerable: true, value: csrf });
  const hostile = fixture({ extract() { return accessor; } });
  await assert.rejects(hostile.resolve(), rejectCode('IDENTITY_SESSION_DENIED'));
  assert.equal(traps, 0);
  assert.throws(() => createExistingSessionIdentityAuthority({
    sessionAuthority: { inspectSession() {}, withCurrentSession() {} },
    extractSession() { return { sessionProof, csrf }; },
    async resolveAccountBinding() { return {}; }
  }), rejectCode('IDENTITY_AUTHORITY_CONFIG'));
  const extra = fixture({ extract() { return { sessionProof, csrf, botToken: 'private' }; } });
  await assert.rejects(extra.resolve(), rejectCode('IDENTITY_SESSION_DENIED'));
  await base.adapter.close();
});

test('unknown authority errors are fixed and never echo session credentials or raw identifiers', async () => {
  const sensitive = '2001:private-bot-token';
  const f = fixture({ inspect() { throw Error(sensitive); } });
  await assert.rejects(f.resolve(), error => {
    assert.equal(error.code, 'IDENTITY_AUTHORITY_UNAVAILABLE');
    assert.equal(error.message.includes(sensitive), false);
    assert.equal(JSON.stringify(error).includes(sessionProof), false);
    return true;
  });
});

// Skipped in the public repository: it pins a generated candidate source that is not part of this repo.
test.skip('the real generated session source is rejected and cannot be promoted by this adapter', async () => {
  const sourceUrl = new URL('./generated-candidate-not-shipped.mjs', import.meta.url);
  const source = await readFile(sourceUrl);
  assert.equal(createHash('sha256').update(source).digest('hex'), 'b2a7ef7963de1f8471c64e7b364611757f3a4a3bbe19112678d5ecdc5462d29e');
  const text = source.toString('utf8');
  assert.match(text, /productionAdmitted:false/);
  assert.doesNotMatch(text, /sessionGeneration/);
  let bindingCalls = 0;
  const generatedShape = {
    generatedOnly: true,
    productionAdmitted: false,
    serverNow: initialNow,
    grantId: 'generated-grant',
    grantGeneration: 1,
    ownerEpoch: 1,
    sessionId: 'generated-session',
    sessionExpiresAt: initialNow + 1_000,
    idleExpiresAt: initialNow + 1_000,
    trustExpiresAt: initialNow + 1_000
  };
  const adapter = createExistingSessionIdentityAuthority({
    sessionAuthority: {
      async inspectSession() { return generatedShape; },
      async withCurrentSession(_args, perform) { return perform(generatedShape); }
    },
    extractSession() { return { sessionProof, csrf }; },
    resolveAccountBinding() { bindingCalls += 1; throw Error('must-not-bind'); }
  });
  await assert.rejects(
    adapter.resolveMatchedRingAccount({ accountId, context: Object.freeze({ cookie: 'generated' }) }),
    rejectCode('IDENTITY_SESSION_DENIED')
  );
  assert.equal(bindingCalls, 0);
  await adapter.close();
});
