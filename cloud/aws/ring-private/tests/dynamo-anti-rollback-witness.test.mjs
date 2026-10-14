import test from 'node:test';
import assert from 'node:assert/strict';
import { createDynamoAntiRollbackWitness, dynamoWitnessConstants as K } from '../dynamo-anti-rollback-witness.mjs';

const TX1 = 'transaction.first.0001'; const TX2 = 'transaction.second.002';
const ZERO = K.zeroCommitment;
const C1 = { ...ZERO, bindingRevision: 1, bindingHash: '1'.repeat(64) };
const C2 = { ...C1, cursorRevision: 1, cursorHash: '2'.repeat(64) };
const C3 = { ...C1, journalRevision: 1, journalHash: '3'.repeat(64) };
function conditional() { const e = new Error('generated-conflict'); e.name = 'ConditionalCheckFailedException'; return e; }
function mock() {
  let item; let lost = null; const calls = []; let unavailable = false;
  function check(input) {
    assert.equal(input.TableName, K.tableName);
    if (input.Key) assert.deepEqual(input.Key, { witness_id: { S: K.witnessId } });
    if (unavailable) throw new Error('generated-private-payload-sentinel');
  }
  const ports = {
    async getItem(input, options) {
      calls.push({ kind: 'get', input, options }); check(input);
      assert.equal(input.ConsistentRead, true);
      return item ? { Item: structuredClone(item) } : {};
    },
    async putItem(input, options) {
      calls.push({ kind: 'put', input, options }); check(input);
      assert.equal(input.ConditionExpression, 'attribute_not_exists(#witness_id)');
      assert.deepEqual(input.ExpressionAttributeNames, { '#witness_id': 'witness_id' });
      if (item) throw conditional();
      item = structuredClone(input.Item);
      if (lost === 'put') { lost = null; throw new Error('generated-private-payload-sentinel'); }
      return {};
    },
    async updateItem(input, options) {
      calls.push({ kind: 'update', input, options }); check(input);
      assert.equal(input.ReturnValues, 'ALL_NEW');
      for (const clause of input.ConditionExpression.split(' AND ')) {
        const [name, value] = clause.split(' = ');
        if (JSON.stringify(item?.[input.ExpressionAttributeNames[name]]) !== JSON.stringify(input.ExpressionAttributeValues[value])) throw conditional();
      }
      const parts = input.UpdateExpression.match(/^SET (.*?)(?: REMOVE (.*?))?(?: ADD (.*))?$/);
      assert.ok(parts);
      for (const set of parts[1].split(', ')) {
        const [name, value] = set.split(' = ');
        item[input.ExpressionAttributeNames[name]] = structuredClone(input.ExpressionAttributeValues[value]);
      }
      if (parts[2]) for (const name of parts[2].split(', ')) delete item[input.ExpressionAttributeNames[name]];
      if (parts[3]) {
        const [name, value] = parts[3].split(' '); const key = input.ExpressionAttributeNames[name];
        item[key] = { N: String(Number(item[key].N) + Number(input.ExpressionAttributeValues[value].N)) };
      }
      if (lost === 'update') { lost = null; throw new Error('generated-private-payload-sentinel'); }
      if (lost === 'conditional-update') { lost = null; throw conditional(); }
      return { Attributes: structuredClone(item), $metadata: {} };
    }
  };
  return { ports, calls, snapshot: () => structuredClone(item), replace: v => { item = structuredClone(v); },
    loss: type => { lost = type; }, unavailable: () => { unavailable = true; } };
}
function adapter(m, mode = 'ALLOW_EMPTY_ONCE', extra = {}) {
  return createDynamoAntiRollbackWitness({ ports: m.ports, tableName: K.tableName, witnessId: K.witnessId, mode, nowMs: () => 1_800_000_000_000, ...extra });
}
const advance = (a, expected = ZERO, next = C1, transactionId = TX1, options) => a.compareAndAdvance({ expectedCommitment: expected, nextCommitment: next, transactionId }, options);
const confirm = (a, commitment = C1, transactionId = TX1, options) => a.confirm({ commitment, transactionId }, options);
async function initialized(m) { const a = adapter(m); await advance(a); await confirm(a); return a; }
async function denied(job, code) { await assert.rejects(job, e => e.code === code && e.message === code && !e.stack.includes('generated-private-payload-sentinel')); }

test('default construction has zero effects, missing record is denied; explicit absent proof returns exact zero', async () => {
  const m = mock(); const a = adapter(m, 'REQUIRE_EXISTING'); assert.equal(m.calls.length, 0);
  await denied(a.readCurrent(), 'B02_FORMAL_WITNESS_RECORD_DENIED');
  assert.deepEqual(await adapter(m).readCurrent(), ZERO); assert.equal(m.calls.length, 2);
  await a.close();
});
test('one-time conditional initialize produces ADVANCED, strong read strips all metadata, confirm disarms empty mode', async () => {
  const m = mock(); const a = adapter(m);
  assert.deepEqual(await advance(a), { advanced: true });
  assert.equal(m.snapshot().phase.S, 'ADVANCED'); assert.equal(m.snapshot().sequence.N, '1');
  assert.deepEqual(await a.readCurrent(), C1);
  await confirm(a); assert.equal(m.snapshot().phase.S, 'CONFIRMED');
  m.replace(undefined); await denied(a.readCurrent(), 'B02_FORMAL_WITNESS_RECORD_DENIED');
  await denied(advance(a), 'B02_FORMAL_WITNESS_ADVANCE_DENIED');
  assert.equal(m.calls.filter(c => c.kind === 'put').length, 1); await a.close();
});
test('absent nonzero expected and normal runtime auto-create are denied without writes', async () => {
  const m = mock(); await denied(advance(adapter(m), C1, C2), 'B02_FORMAL_WITNESS_ADVANCE_DENIED');
  await denied(advance(adapter(m, 'REQUIRE_EXISTING')), 'B02_FORMAL_WITNESS_ADVANCE_DENIED');
  assert.equal(m.calls.some(c => c.kind !== 'get'), false);
});
test('two independent initializers use conditional create, exactly one wins', async () => {
  const m = mock(); const a = adapter(m); const b = adapter(m);
  const outcomes = await Promise.allSettled([advance(a), advance(b, ZERO, C1, TX2)]);
  assert.equal(outcomes.filter(x => x.status === 'fulfilled').length, 1);
  assert.equal(outcomes.find(x => x.status === 'rejected').reason.code, 'B02_FORMAL_WITNESS_ADVANCE_DENIED');
  assert.equal(m.calls.filter(c => c.kind === 'put').length, 2); assert.equal(m.snapshot().sequence.N, '1');
});
test('lost initialize response retries same transaction once without reinitializing', async () => {
  const m = mock(); const a = adapter(m); m.loss('put');
  await denied(advance(a), 'B02_FORMAL_WITNESS_UNAVAILABLE');
  assert.deepEqual(await advance(a), { advanced: true });
  assert.equal(m.calls.filter(c => c.kind === 'put').length, 1); await confirm(a);
});
test('existing CAS increments sequence once, preserves initialized timestamp and binds expected six fields', async () => {
  const m = mock(); const a = await initialized(m); const prior = m.snapshot();
  await advance(a, C1, C2, TX2); const after = m.snapshot();
  assert.equal(after.sequence.N, '2'); assert.deepEqual(after.initialized_at_ms, prior.initialized_at_ms);
  assert.equal(after.confirmed_at_ms, undefined); assert.equal(after.phase.S, 'ADVANCED');
  const cas = m.calls.filter(c => c.kind === 'update').at(-1).input;
  for (const name of ['binding_revision', 'binding_hash', 'cursor_revision', 'cursor_hash', 'journal_revision', 'journal_hash', 'schema', 'phase', 'commitment_sha256', 'sequence']) assert.ok(cas.ConditionExpression.includes(`#${name} =`));
  assert.equal(cas.UpdateExpression.endsWith('ADD #sequence :one'), true);
});
test('stale expected and pending different transaction fail closed with no additional write', async () => {
  const m = mock(); const a = await initialized(m); const before = m.calls.length;
  await denied(advance(a, ZERO, C2, TX2), 'B02_FORMAL_WITNESS_ADVANCE_DENIED');
  assert.equal(m.calls.slice(before).some(c => c.kind !== 'get'), false);
  await advance(a, C1, C2, TX2);
  await denied(advance(a, C1, C3, TX1), 'B02_FORMAL_WITNESS_ADVANCE_DENIED');
});
test('concurrent existing writers use expected conditional CAS and exact readback', async () => {
  const m = mock(); const a = await initialized(m); const b = adapter(m, 'REQUIRE_EXISTING');
  const results = await Promise.allSettled([advance(a, C1, C2, TX2), advance(b, C1, C3, TX1)]);
  assert.equal(results.filter(x => x.status === 'fulfilled').length, 1);
  assert.equal(results.find(x => x.status === 'rejected').reason.code, 'B02_FORMAL_WITNESS_ADVANCE_DENIED');
  assert.equal(m.snapshot().sequence.N, '2');
});
test('advance response loss same transaction/commitment retry never rewrites or increments twice', async () => {
  const m = mock(); const a = await initialized(m); m.loss('update');
  await denied(advance(a, C1, C2, TX2), 'B02_FORMAL_WITNESS_UNAVAILABLE');
  await advance(a, C1, C2, TX2); await confirm(a, C2, TX2);
  const writes = m.calls.filter(c => c.kind === 'update').length;
  await advance(a, C1, C2, TX2); assert.equal(m.calls.filter(c => c.kind === 'update').length, writes);
  assert.equal(m.snapshot().phase.S, 'CONFIRMED'); assert.equal(m.snapshot().sequence.N, '2');
  await denied(advance(a, C1, C3, TX2), 'B02_FORMAL_WITNESS_ADVANCE_DENIED');
});
test('conditional failure after accepted CAS resolves through one exact strongly consistent read', async () => {
  const m = mock(); const a = await initialized(m); m.loss('conditional-update');
  const before = m.calls.length; await advance(a, C1, C2, TX2);
  assert.deepEqual(m.calls.slice(before).map(c => c.kind), ['get', 'update', 'get']);
});
test('confirm wrong transaction or commitment causes zero writes; same confirmation retry is idempotent', async () => {
  const m = mock(); const a = adapter(m); await advance(a);
  const before = m.calls.length;
  await denied(confirm(a, C1, TX2), 'B02_FORMAL_WITNESS_CONFIRM_DENIED');
  await denied(confirm(a, C2), 'B02_FORMAL_WITNESS_CONFIRM_DENIED');
  assert.equal(m.calls.slice(before).some(c => c.kind !== 'get'), false);
  m.loss('conditional-update'); const retry = m.calls.length; await confirm(a);
  assert.deepEqual(m.calls.slice(retry).map(c => c.kind), ['get', 'update', 'get']);
  const writes = m.calls.filter(c => c.kind === 'update').length; await confirm(a);
  assert.equal(m.calls.filter(c => c.kind === 'update').length, writes);
});
test('lost confirm response retries confirmed record without rewriting', async () => {
  const m = mock(); const a = adapter(m); await advance(a); m.loss('update');
  await denied(confirm(a), 'B02_FORMAL_WITNESS_UNAVAILABLE'); await confirm(a);
  assert.equal(m.calls.filter(c => c.kind === 'update').length, 1);
});
test('decreasing revision or no forward progress rejects before I/O', async () => {
  const m = mock(); const a = adapter(m);
  await denied(advance(a, C1, ZERO), 'B02_FORMAL_WITNESS_REVERSE_DENIED');
  await denied(advance(a, C1, { ...C1, bindingHash: '9'.repeat(64) }), 'B02_FORMAL_WITNESS_REVERSE_DENIED');
  assert.equal(m.calls.length, 0);
});
test('unknown attributes, malformed typed data, digest, schema, phase and unsafe numbers are denied', async () => {
  const m = mock(); const a = await initialized(m); const good = m.snapshot();
  for (const mutate of [v => { v.token = { S: 'generated-private-payload-sentinel' }; }, v => { v.binding_hash.S = 'ABC'; },
    v => { v.sequence.N = '9007199254740991'; }, v => { v.schema.S = 'wrong'; }, v => { v.phase.S = 'OTHER'; },
    v => { v.binding_revision.N = '01'; }, v => { v.binding_revision.N = '-1'; }, v => { v.binding_hash.N = '1'; },
    v => { v.commitment_sha256.S = '9'.repeat(64); }, v => { delete v.confirmed_at_ms; }]) {
    const bad = structuredClone(good); mutate(bad); m.replace(bad);
    await denied(a.readCurrent(), 'B02_FORMAL_WITNESS_RECORD_DENIED');
  }
});
test('table unavailable and AbortSignal fail closed; signal identity forwards on every call', async () => {
  const m = mock(); const a = adapter(m); const controller = new AbortController();
  const options = { signal: controller.signal };
  await a.readCurrent(options); await advance(a, ZERO, C1, TX1, options); await confirm(a, C1, TX1, options);
  assert.ok(m.calls.every(c => c.options.signal === controller.signal));
  controller.abort(); const before = m.calls.length;
  await denied(a.readCurrent(options), 'B02_FORMAL_WITNESS_UNAVAILABLE'); assert.equal(m.calls.length, before);
  m.unavailable(); await denied(a.readCurrent(), 'B02_FORMAL_WITNESS_UNAVAILABLE');
});
test('table, witness, mode and endpoint drift rejected without I/O; proxies and accessors never execute', async () => {
  const m = mock(); const base = { ports: m.ports, tableName: K.tableName, witnessId: K.witnessId };
  for (const bad of [{ ...base, tableName: 'other' }, { ...base, witnessId: 'other' }, { ...base, mode: 'AUTO' },
    { ...base, endpoint: 'generated.invalid' }, new Proxy(base, {})]) assert.throws(() => createDynamoAntiRollbackWitness(bad), /B02_FORMAL_WITNESS_CONFIG_DENIED/);
  let getterCalls = 0; const bad = { ...base }; Object.defineProperty(bad, 'mode', { enumerable: true, get() { getterCalls++; return 'ALLOW_EMPTY_ONCE'; } });
  assert.throws(() => createDynamoAntiRollbackWitness(bad), /B02_FORMAL_WITNESS_CONFIG_DENIED/);
  assert.equal(getterCalls, 0); assert.equal(m.calls.length, 0);
});
test('instance serializes requests, close rejects queued/new calls and destroys only owned client once', async () => {
  const m = mock(); let released; let active = 0; let maxActive = 0; let destroyed = 0;
  const ports = { ...m.ports, async getItem(...args) { active++; maxActive = Math.max(maxActive, active); await new Promise(r => { released = r; }); active--; return m.ports.getItem(...args); } };
  const a = adapter(m, 'ALLOW_EMPTY_ONCE', { ports, ownedClient: { destroy() { destroyed++; } } });
  const first = a.readCurrent(); const second = a.readCurrent(); await new Promise(r => setImmediate(r));
  const closed = a.close(); const closedAgain = a.close(); assert.equal(closed, closedAgain); released();
  await denied(first, 'B02_FORMAL_WITNESS_CLOSED'); await denied(second, 'B02_FORMAL_WITNESS_CLOSED'); await closed;
  assert.equal(maxActive, 1); assert.equal(destroyed, 1);
  await denied(a.readCurrent(), 'B02_FORMAL_WITNESS_CLOSED');
  const shared = adapter(m); await shared.close(); assert.equal(destroyed, 1);
});
test('sensitive upstream payload never survives thrown error serialization or cause', async () => {
  const m = mock(); m.unavailable(); const a = adapter(m);
  try { await a.readCurrent(); assert.fail(); } catch (e) {
    assert.equal(e.code, 'B02_FORMAL_WITNESS_UNAVAILABLE'); assert.equal(e.cause, undefined);
    assert.equal(JSON.stringify(e).includes('generated-private-payload-sentinel'), false);
  }
});
