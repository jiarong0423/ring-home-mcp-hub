import assert from 'node:assert/strict';

const clone = value => structuredClone(value);
const scalar = av => {
  assert.equal(typeof av, 'object');
  assert.ok(av !== null && !Array.isArray(av));
  assert.equal(Object.keys(av).length, 1);
  if (Object.hasOwn(av, 'S')) { assert.equal(typeof av.S, 'string'); return av.S; }
  if (Object.hasOwn(av, 'N')) {
    assert.match(av.N, /^(0|[1-9][0-9]*)$/);
    const n = Number(av.N);
    assert.ok(Number.isSafeInteger(n));
    return n;
  }
  throw new Error('unsupported AV in offline fixture');
};
const rowOf = item => Object.fromEntries(Object.entries(item).map(([key, value]) => [key, scalar(value)]));
const idOf = (table, pk) => `${table}\u0000${pk}`;
const attribute = (token, names) => {
  assert.match(token, /^#[A-Za-z][A-Za-z0-9]*$/);
  assert.equal(typeof names[token], 'string');
  return names[token];
};
function conditionMatches(action, item) {
  const names = action.ExpressionAttributeNames ?? {};
  const values = action.ExpressionAttributeValues ?? {};
  const row = item === undefined ? {} : rowOf(item);
  const clauses = action.ConditionExpression.split(' AND ');
  assert.ok(clauses.length > 0);
  return clauses.every(clause => {
    let match = /^attribute_(not_)?exists\((#[A-Za-z][A-Za-z0-9]*)\)$/.exec(clause);
    if (match) {
      const exists = Object.hasOwn(row, attribute(match[2], names));
      return match[1] ? !exists : exists;
    }
    match = /^(#[A-Za-z][A-Za-z0-9]*) (=|>) (:[A-Za-z][A-Za-z0-9]*)$/.exec(clause);
    assert.ok(match, `unsupported condition clause ${clause}`);
    assert.ok(Object.hasOwn(values, match[3]));
    const field = attribute(match[1], names);
    const expected = scalar(values[match[3]]);
    if (!Object.hasOwn(row, field)) return false;
    return match[2] === '=' ? row[field] === expected : row[field] > expected;
  });
}
function updateItem(action, previous) {
  assert.ok(previous);
  assert.match(action.UpdateExpression, /^SET /);
  const item = clone(previous);
  for (const part of action.UpdateExpression.slice(4).split(', ')) {
    const match = /^(#[A-Za-z][A-Za-z0-9]*) = (:[A-Za-z][A-Za-z0-9]*)$/.exec(part);
    assert.ok(match, `unsupported update clause ${part}`);
    const field = attribute(match[1], action.ExpressionAttributeNames);
    assert.ok(Object.hasOwn(action.ExpressionAttributeValues, match[2]));
    item[field] = clone(action.ExpressionAttributeValues[match[2]]);
  }
  return item;
}
function conflict(operation, count, failed) {
  if (operation !== 'TransactWriteItems') return Object.assign(new Error('offline conditional'), { name: 'ConditionalCheckFailedException' });
  const reasons = Array.from({ length: count }, (_, index) => ({ Code: failed.includes(index) ? 'ConditionalCheckFailed' : 'None' }));
  return Object.assign(new Error('offline transaction cancelled'), { name: 'TransactionCanceledException', CancellationReasons: reasons });
}

export function createOfflineDynamoFixture({ beforeCommit, afterCommit } = {}) {
  const rows = new Map();
  const calls = { reads: [], writes: [] };
  let preHook = beforeCommit;
  let postHook = afterCommit;
  const getItem = async request => {
    assert.deepEqual(Object.keys(request).sort(), ['ConsistentRead', 'Key', 'TableName']);
    assert.equal(request.ConsistentRead, true);
    assert.match(request.TableName, /^[A-Za-z0-9_.-]{3,255}$/);
    const pk = scalar(request.Key.pk);
    assert.match(pk, /^[a-f0-9]{64}$/);
    calls.reads.push(clone(request));
    const item = rows.get(idOf(request.TableName, pk));
    return item === undefined ? {} : { Item: clone(item) };
  };
  const offlineExecute = async ({ operation, request, decisionNow, deadlineGuards }) => {
    calls.writes.push(clone({ operation, request, deadlineGuards }));
    assert.ok(['PutItem', 'UpdateItem', 'TransactWriteItems'].includes(operation));
    const actions = operation === 'TransactWriteItems'
      ? request.TransactItems.map(value => {
          assert.equal(Object.keys(value).length, 1);
          const type = Object.keys(value)[0];
          assert.ok(['Update', 'Put'].includes(type));
          return { type, value: value[type] };
        })
      : [{ type: operation === 'PutItem' ? 'Put' : 'Update', value: request }];
    if (operation === 'TransactWriteItems') {
      assert.match(request.ClientRequestToken, /^[a-f0-9]{32}$/);
      assert.equal(actions.length, 2);
    }
    const startNow = decisionNow();
    assert.ok(Number.isSafeInteger(startNow) && startNow >= 0);
    if (preHook) await preHook({ operation, request, rows, calls });
    const commitNow = decisionNow();
    assert.ok(Number.isSafeInteger(commitNow) && commitNow >= 0);
    assert.ok(commitNow >= startNow, 'offline commit clock regression');
    assert.ok(Array.isArray(deadlineGuards) && deadlineGuards.length > 0);
    const touched = new Set();
    const staged = new Map(rows);
    const failed = [];
    actions.forEach(({ type, value }, index) => {
      assert.match(value.TableName, /^[A-Za-z0-9_.-]{3,255}$/);
      assert.ok(value.ConditionExpression && value.ExpressionAttributeNames);
      const pk = scalar(type === 'Put' ? value.Item.pk : value.Key.pk);
      assert.match(pk, /^[a-f0-9]{64}$/);
      const id = idOf(value.TableName, pk);
      assert.ok(!touched.has(id), 'duplicate transaction item');
      touched.add(id);
      const previous = rows.get(id);
      if (!conditionMatches(value, previous)) failed.push(index);
      else staged.set(id, type === 'Put' ? clone(value.Item) : updateItem(value, previous));
    });
    if (failed.length) throw conflict(operation, actions.length, failed);
    for (const guard of deadlineGuards) {
      assert.ok(['auth', 'ring', 'identity', 'session_absolute', 'session_idle'].includes(guard.kind));
      assert.ok(Number.isSafeInteger(guard.expiresAt));
      if (commitNow >= guard.expiresAt) throw conflict(operation, actions.length, [0]);
    }
    rows.clear();
    for (const [id, value] of staged) rows.set(id, value);
    if (postHook) await postHook({ operation, request, rows, calls });
    return {};
  };
  return Object.freeze({ rows, calls, getItem, offlineExecute,
    setBeforeCommit: hook => { preHook = hook; },
    setAfterCommit: hook => { postHook = hook; },
    inspect: (table, pk) => {
      const value = rows.get(idOf(table, pk));
      return value === undefined ? null : clone(value);
    },
    seed: (table, item) => rows.set(idOf(table, scalar(item.pk)), clone(item))
  });
}
