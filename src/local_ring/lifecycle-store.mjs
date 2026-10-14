const TABLES = new Set(['localAccounts', 'localClaims', 'localLinks']);
const HEX = /^[a-f0-9]{64}$/;
const ATTRIBUTE = /^[a-z][a-z0-9_]{0,63}$/;
const MAX_ROWS = 16;

function invalid() {
  throw Object.assign(new Error('local_lifecycle_request_invalid'), { code: 'local_lifecycle_request_invalid' });
}

function record(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      Reflect.ownKeys(value).some(key => typeof key !== 'string') ||
      Object.values(Object.getOwnPropertyDescriptors(value)).some(descriptor => !Object.hasOwn(descriptor, 'value'))) invalid();
  return value;
}

function exact(value, allowed, required = allowed) {
  record(value);
  if (Object.keys(value).some(key => !allowed.includes(key)) || required.some(key => !Object.hasOwn(value, key))) invalid();
}

function scalar(value) {
  record(value);
  if (Object.keys(value).length !== 1) invalid();
  if (Object.hasOwn(value, 'S') && typeof value.S === 'string' && value.S.length <= 256) return value.S;
  if (Object.hasOwn(value, 'BOOL') && typeof value.BOOL === 'boolean') return value.BOOL;
  if (Object.hasOwn(value, 'N') && typeof value.N === 'string' && /^(0|[1-9][0-9]*)$/.test(value.N)) {
    const result = Number(value.N);
    if (Number.isSafeInteger(result)) return result;
  }
  invalid();
}

function itemRecord(item) {
  record(item);
  if (Object.keys(item).length > 24 || Object.keys(item).some(key => !ATTRIBUTE.test(key))) invalid();
  for (const value of Object.values(item)) scalar(value);
  if (!HEX.test(item.pk?.S ?? '')) invalid();
  return item;
}

function location(table, key) {
  if (!TABLES.has(table)) invalid();
  exact(key, ['pk']);
  if (!HEX.test(key.pk?.S ?? '') || scalar(key.pk) !== key.pk.S) invalid();
  return `${table}\0${key.pk.S}`;
}

function attribute(token, names) {
  if (!/^#[A-Za-z][A-Za-z0-9]*$/.test(token) || !ATTRIBUTE.test(names?.[token] ?? '')) invalid();
  return names[token];
}

function conditionMatches(action, previous) {
  if (typeof action.ConditionExpression !== 'string' || action.ConditionExpression.length > 2048) invalid();
  record(action.ExpressionAttributeNames);
  const names = action.ExpressionAttributeNames;
  const values = action.ExpressionAttributeValues ?? {};
  record(values);
  const clauses = action.ConditionExpression.split(' AND ');
  if (!clauses.length || clauses.length > 24) invalid();
  let matches = true;
  for (const clause of clauses) {
    let match = /^attribute_(not_)?exists\((#[A-Za-z][A-Za-z0-9]*)\)$/.exec(clause);
    if (match) {
      const exists = previous !== undefined && Object.hasOwn(previous, attribute(match[2], names));
      matches = matches && (match[1] ? !exists : exists);
      continue;
    }
    match = /^(#[A-Za-z][A-Za-z0-9]*) (=|>|>=) (:[A-Za-z][A-Za-z0-9]*)$/.exec(clause);
    if (!match || !Object.hasOwn(values, match[3])) invalid();
    const field = attribute(match[1], names);
    const expected = scalar(values[match[3]]);
    if (previous === undefined || !Object.hasOwn(previous, field)) {
      matches = false;
      continue;
    }
    const actual = scalar(previous[field]);
    if (match[2] !== '=' && (typeof actual !== 'number' || typeof expected !== 'number')) invalid();
    matches = matches && (match[2] === '=' ? actual === expected : match[2] === '>' ? actual > expected : actual >= expected);
  }
  return matches;
}

function updated(action, previous) {
  if (previous === undefined || typeof action.UpdateExpression !== 'string' || action.UpdateExpression.length > 1024) invalid();
  const match = /^SET (.+?)(?: REMOVE (.+))?$/.exec(action.UpdateExpression);
  if (!match) invalid();
  const result = structuredClone(previous);
  for (const part of match[1].split(', ')) {
    const assignment = /^(#[A-Za-z][A-Za-z0-9]*) = (:[A-Za-z][A-Za-z0-9]*)$/.exec(part);
    if (!assignment || !Object.hasOwn(action.ExpressionAttributeValues ?? {}, assignment[2])) invalid();
    const field = attribute(assignment[1], action.ExpressionAttributeNames);
    if (field === 'pk') invalid();
    scalar(action.ExpressionAttributeValues[assignment[2]]);
    result[field] = structuredClone(action.ExpressionAttributeValues[assignment[2]]);
  }
  if (match[2]) {
    for (const part of match[2].split(', ')) {
      const field = attribute(part, action.ExpressionAttributeNames);
      if (field === 'pk') invalid();
      delete result[field];
    }
  }
  return itemRecord(result);
}

function conflict(transaction = false) {
  return Object.assign(new Error('local_lifecycle_conditional_conflict'), {
    name: transaction ? 'TransactionCanceledException' : 'ConditionalCheckFailedException'
  });
}

/** Bounded in-memory evaluator for generated lifecycle rows; it has no external transport. */
export function createLocalLifecycleStore({ now = () => Date.now(), beforeCommit } = {}) {
  if (typeof now !== 'function' || (beforeCommit !== undefined && typeof beforeCommit !== 'function')) invalid();
  const rows = new Map();
  let lastNow = -1;
  const seconds = () => {
    const value = now();
    if (!Number.isSafeInteger(value) || value < 0 || value < lastNow) invalid();
    lastNow = value;
    return Math.floor(value / 1000);
  };
  const seed = (table, item) => {
    itemRecord(item);
    const id = location(table, { pk: item.pk });
    if (rows.has(id) || rows.size >= MAX_ROWS || table === 'localLinks') invalid();
    const fields = table === 'localAccounts'
      ? ['pk', 'status', 'revoked', 'account_epoch', 'integration_ref', 'expires_at']
      : ['pk', 'status', 'account_ref', 'device_ref', 'actor_ref', 'session_ref', 'account_lookup_ref', 'discovery_ref', 'integration_ref', 'account_epoch', 'created_at', 'expires_at', 'session_expires_at', 'link_expires_at'];
    exact(item, fields);
    if (table === 'localAccounts' && (item.status.S !== 'active' || item.revoked.BOOL !== false || item.account_epoch.N !== '1')) invalid();
    if (table === 'localClaims' && (item.status.S !== 'pending' || item.account_epoch.N !== '1')) invalid();
    if (scalar(item.expires_at) <= seconds()) invalid();
    rows.set(id, structuredClone(item));
  };
  const getItem = async request => {
    exact(request, ['TableName', 'Key', 'ConsistentRead']);
    if (request.ConsistentRead !== true) invalid();
    const id = location(request.TableName, request.Key);
    const item = rows.get(id);
    return item === undefined ? {} : { Item: structuredClone(item) };
  };
  const updateItem = async request => {
    exact(request, ['TableName', 'Key', 'ConditionExpression', 'UpdateExpression', 'ExpressionAttributeNames', 'ExpressionAttributeValues', 'ReturnValues']);
    if (request.TableName !== 'localAccounts' || request.ReturnValues !== 'NONE' ||
        request.UpdateExpression !== 'SET #status = :revokedStatus, #revoked = :true, #epoch = :next, #revokedAt = :now, #removalRef = :removalRef REMOVE #expires, #ttl') invalid();
    const id = location(request.TableName, request.Key);
    const started = seconds();
    if (beforeCommit) await beforeCommit({ operation: 'UpdateItem' });
    const commit = seconds();
    if (commit < started) invalid();
    const previous = rows.get(id);
    if (!conditionMatches(request, previous)) throw conflict();
    const candidate = updated(request, previous);
    if (candidate.status.S !== 'revoked' || candidate.revoked.BOOL !== true ||
        scalar(candidate.account_epoch) !== scalar(previous.account_epoch) + 1 ||
        !HEX.test(candidate.removal_ref?.S ?? '') || candidate.expires_at !== undefined ||
        candidate.ttl_delete_after !== undefined) invalid();
    rows.set(id, candidate);
    return {};
  };
  const transactWriteItems = async request => {
    exact(request, ['TransactItems']);
    if (!Array.isArray(request.TransactItems) || request.TransactItems.length !== 3) invalid();
    const expected = [['ConditionCheck', 'localAccounts'], ['Update', 'localClaims'], ['Put', 'localLinks']];
    const actions = request.TransactItems.map((entry, index) => {
      const [type, table] = expected[index];
      exact(entry, [type]);
      const action = entry[type];
      const required = ['TableName', 'ConditionExpression', 'ExpressionAttributeNames'];
      if (type === 'Put') required.push('Item');
      else required.push('Key', 'ExpressionAttributeValues');
      if (type === 'Update') required.push('UpdateExpression');
      exact(action, required);
      if (action.TableName !== table) invalid();
      if (type === 'Put') itemRecord(action.Item);
      if (type === 'Update' && action.UpdateExpression !== 'SET #status = :consumed, #consumedAt = :now') invalid();
      return { type, action, id: location(table, type === 'Put' ? { pk: action.Item.pk } : action.Key) };
    });
    if (new Set(actions.map(action => action.id)).size !== 3) invalid();
    const started = seconds();
    if (beforeCommit) await beforeCommit({ operation: 'TransactWriteItems' });
    const commit = seconds();
    if (commit < started) invalid();
    const staged = new Map(rows);
    for (const { type, action, id } of actions) {
      const previous = rows.get(id);
      if (!conditionMatches(action, previous)) throw conflict(true);
      if (type !== 'Put') {
        const deadlineFields = type === 'ConditionCheck' ? ['expires_at'] : ['expires_at', 'session_expires_at', 'link_expires_at'];
        if (deadlineFields.some(field => scalar(previous[field]) <= commit)) throw conflict(true);
      }
      if (type === 'Update') staged.set(id, updated(action, previous));
      if (type === 'Put') {
        if (scalar(action.Item.expires_at) <= commit) throw conflict(true);
        staged.set(id, structuredClone(action.Item));
      }
    }
    if (staged.size > MAX_ROWS) invalid();
    rows.clear();
    for (const [id, item] of staged) rows.set(id, item);
    return {};
  };
  return Object.freeze({ seed, getItem, updateItem, transactWriteItems,
    inspect(table, pk) {
      const item = rows.get(location(table, { pk: { S: pk } }));
      return item === undefined ? null : structuredClone(item);
    },
    counts() {
      const count = table => [...rows.keys()].filter(id => id.startsWith(`${table}\0`)).length;
      const accounts = [...rows.entries()].filter(([id]) => id.startsWith('localAccounts\0'));
      return Object.freeze({ accounts: count('localAccounts'), claims: count('localClaims'), links: count('localLinks'),
        tombstones: accounts.filter(([, item]) => item.status.S === 'revoked').length });
    }
  });
}
