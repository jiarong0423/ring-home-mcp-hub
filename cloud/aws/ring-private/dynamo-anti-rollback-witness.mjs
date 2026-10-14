import { createHash } from 'node:crypto';
import { types } from 'node:util';

const TABLE = 'ring-home-mcp-private-witness';
const ID = 'formal-runtime-primary-v1';
const SCHEMA = 'ring-b02-dynamodb-anti-rollback-witness-v1';
const WRITER = 'ring-b02-dynamodb-witness-port-v1';
const ZERO_HASH = '0'.repeat(64);
const FIELDS = ['bindingRevision', 'bindingHash', 'cursorRevision', 'cursorHash', 'journalRevision', 'journalHash'];
const ATTRS = ['binding_revision', 'binding_hash', 'cursor_revision', 'cursor_hash', 'journal_revision', 'journal_hash'];
const BASE = ['witness_id', 'schema', 'phase', 'sequence', ...ATTRS, 'commitment_sha256',
  'previous_commitment_sha256', 'transaction_id', 'initialized_at_ms', 'advanced_at_ms', 'writer_contract'];
const ZERO = Object.freeze(Object.fromEntries(FIELDS.map((k, i) => [k, i % 2 ? ZERO_HASH : 0])));

function deny(code) { const e = new Error(code); e.name = 'FormalRuntimeError'; e.code = code; throw e; }
function data(value, required, optional = [], code = 'B02_FORMAL_WITNESS_RECORD_DENIED') {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny(code);
    const d = Object.getOwnPropertyDescriptors(value); const keys = Reflect.ownKeys(d);
    if (required.some(k => !Object.hasOwn(d, k)) || keys.some(k => typeof k !== 'string' ||
        ![...required, ...optional].includes(k) || !d[k].enumerable || !Object.hasOwn(d[k], 'value'))) deny(code);
    return Object.fromEntries(keys.map(k => [k, d[k].value]));
  } catch { deny(code); }
}
function number(value, min = 0, max = Number.MAX_SAFE_INTEGER - 1) {
  if (!Number.isSafeInteger(value) || value < min || value > max) deny('B02_FORMAL_WITNESS_RECORD_DENIED');
  return value;
}
function hash(value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) deny('B02_FORMAL_WITNESS_RECORD_DENIED');
  return value;
}
function transaction(value) {
  if (typeof value !== 'string' || !/^[A-Za-z][A-Za-z0-9:._-]{15,127}$/.test(value)) deny('B02_FORMAL_WITNESS_TRANSACTION_DENIED');
  return value;
}
function commitment(value) {
  const f = data(value, FIELDS, [], 'B02_FORMAL_WITNESS_COMMITMENT_DENIED');
  return Object.freeze(Object.fromEntries(FIELDS.map((k, i) => [k, i % 2 ? hash(f[k]) : number(f[k])])));
}
function digest(value) { return createHash('sha256').update(JSON.stringify(value)).digest('hex'); }
function same(a, b) { return FIELDS.every(k => a[k] === b[k]); }
function attr(value, type) {
  const a = data(value, [type]);
  if (type === 'S') { if (typeof a.S !== 'string') deny('B02_FORMAL_WITNESS_RECORD_DENIED'); return a.S; }
  if (typeof a.N !== 'string' || !/^(0|[1-9][0-9]*)$/.test(a.N)) deny('B02_FORMAL_WITNESS_RECORD_DENIED');
  return number(Number(a.N));
}
function validateItem(value) {
  const raw = data(value, BASE, ['confirmed_at_ms']);
  if (Buffer.byteLength(JSON.stringify(raw)) > 8192) deny('B02_FORMAL_WITNESS_RECORD_DENIED');
  const f = Object.fromEntries(Object.entries(raw).map(([k, v]) => [k, attr(v,
    ['sequence', 'binding_revision', 'cursor_revision', 'journal_revision', 'initialized_at_ms', 'advanced_at_ms', 'confirmed_at_ms'].includes(k) ? 'N' : 'S')]));
  if (f.witness_id !== ID || f.schema !== SCHEMA || f.writer_contract !== WRITER ||
      !['ADVANCED', 'CONFIRMED'].includes(f.phase) || (f.phase === 'CONFIRMED') !== Object.hasOwn(f, 'confirmed_at_ms')) deny('B02_FORMAL_WITNESS_RECORD_DENIED');
  number(f.sequence, 1); number(f.initialized_at_ms, 1, 8_640_000_000_000_000);
  number(f.advanced_at_ms, 1, 8_640_000_000_000_000);
  if (f.phase === 'CONFIRMED') number(f.confirmed_at_ms, 1, 8_640_000_000_000_000);
  transaction(f.transaction_id); hash(f.previous_commitment_sha256); hash(f.commitment_sha256);
  const c = commitment(Object.fromEntries(FIELDS.map((k, i) => [k, f[ATTRS[i]]])));
  if (digest(c) !== f.commitment_sha256) deny('B02_FORMAL_WITNESS_RECORD_DENIED');
  return Object.freeze({ ...f, commitment: c });
}
function method(object, key) {
  try {
    if (!object || typeof object !== 'object' || types.isProxy(object)) deny('B02_FORMAL_WITNESS_CONFIG_DENIED');
    let p = object; let d;
    while (p !== null) { if (types.isProxy(p)) deny('B02_FORMAL_WITNESS_CONFIG_DENIED'); d = Object.getOwnPropertyDescriptor(p, key); if (d) break; p = Object.getPrototypeOf(p); }
    if (!d || !Object.hasOwn(d, 'value') || typeof d.value !== 'function' || types.isProxy(d.value)) deny('B02_FORMAL_WITNESS_CONFIG_DENIED');
    return d.value.bind(object);
  } catch { deny('B02_FORMAL_WITNESS_CONFIG_DENIED'); }
}
function conditional(error) {
  if (!error || typeof error !== 'object' || types.isProxy(error)) return false;
  const d = Object.getOwnPropertyDescriptor(error, 'name');
  return d && Object.hasOwn(d, 'value') && d.value === 'ConditionalCheckFailedException';
}
function encoded(value) { return typeof value === 'number' ? { N: String(value) } : { S: value }; }
function requestOptions(options) {
  if (options === undefined) return undefined;
  const { signal } = data(options, ['signal'], [], 'B02_FORMAL_WITNESS_CONFIG_DENIED');
  if (!(signal instanceof AbortSignal)) deny('B02_FORMAL_WITNESS_CONFIG_DENIED');
  return Object.freeze({ signal });
}

/** Explicitly constructed injection only. No environment discovery or default runtime wiring. */
export function createDynamoAntiRollbackWitness(options) {
  const c = data(options, ['ports', 'tableName', 'witnessId'], ['mode', 'nowMs', 'ownedClient'], 'B02_FORMAL_WITNESS_CONFIG_DENIED');
  const mode = c.mode ?? 'REQUIRE_EXISTING';
  if (c.tableName !== TABLE || c.witnessId !== ID || !['REQUIRE_EXISTING', 'ALLOW_EMPTY_ONCE'].includes(mode)) deny('B02_FORMAL_WITNESS_CONFIG_DENIED');
  const nowMs = c.nowMs ?? Date.now;
  if (typeof nowMs !== 'function' || types.isProxy(nowMs)) deny('B02_FORMAL_WITNESS_CONFIG_DENIED');
  const getItem = method(c.ports, 'getItem'); const putItem = method(c.ports, 'putItem'); const updateItem = method(c.ports, 'updateItem');
  const destroy = c.ownedClient === undefined ? null : method(c.ownedClient, 'destroy');
  const key = Object.freeze({ witness_id: Object.freeze({ S: ID }) });
  let closed = false; let armed = mode === 'ALLOW_EMPTY_ONCE'; let tail = Promise.resolve(); let closePromise;
  function now() { try { return number(nowMs(), 1, 8_640_000_000_000_000); } catch { deny('B02_FORMAL_WITNESS_RECORD_DENIED'); } }
  function active(o) { if (closed) deny('B02_FORMAL_WITNESS_CLOSED'); if (o?.signal.aborted) deny('B02_FORMAL_WITNESS_UNAVAILABLE'); }
  async function serial(fn, options) {
    const o = requestOptions(options); active(o);
    const job = tail.then(async () => { active(o); return fn(o); });
    tail = job.then(() => undefined, () => undefined); return job;
  }
  async function call(fn, input, o, allowConditional = false) {
    active(o);
    try { const result = await fn(input, o); active(o); return result; }
    catch (e) { if (allowConditional && conditional(e)) throw e; if (closed) deny('B02_FORMAL_WITNESS_CLOSED'); deny('B02_FORMAL_WITNESS_UNAVAILABLE'); }
  }
  async function read(o) {
    const result = await call(getItem, { TableName: TABLE, Key: key, ConsistentRead: true }, o);
    try {
      if (!result || typeof result !== 'object' || types.isProxy(result)) deny('B02_FORMAL_WITNESS_RECORD_DENIED');
      const d = Object.getOwnPropertyDescriptor(result, 'Item');
      if (!d) return null;
      if (!Object.hasOwn(d, 'value')) deny('B02_FORMAL_WITNESS_RECORD_DENIED');
      if (d.value === undefined) return null;
      return validateItem(d.value);
    } catch { deny('B02_FORMAL_WITNESS_RECORD_DENIED'); }
  }
  function matches(record, next, tx) {
    return record !== null && record.transaction_id === tx && record.commitment_sha256 === digest(next) && same(record.commitment, next);
  }
  function expression(current, tx, expected) {
    const names = { '#schema': 'schema', '#phase': 'phase', '#commitment_sha256': 'commitment_sha256' };
    const values = { ':schema': encoded(SCHEMA), ':phase': encoded(current), ':commitment_sha256': encoded(digest(expected)) };
    const clauses = ['#schema = :schema', '#phase = :phase', '#commitment_sha256 = :commitment_sha256'];
    ATTRS.forEach((k, i) => { names[`#${k}`] = k; values[`:${k}`] = encoded(expected[FIELDS[i]]); clauses.push(`#${k} = :${k}`); });
    if (tx !== undefined) { names['#transaction_id'] = 'transaction_id'; values[':transaction_id'] = encoded(tx); clauses.push('#transaction_id = :transaction_id'); }
    return { names, values, clauses };
  }
  async function compareAndAdvance(value, options) {
    const v = data(value, ['expectedCommitment', 'nextCommitment', 'transactionId'], [], 'B02_FORMAL_WITNESS_ADVANCE_DENIED');
    const expected = commitment(v.expectedCommitment); const next = commitment(v.nextCommitment); const tx = transaction(v.transactionId);
    const revisions = FIELDS.filter((k, i) => i % 2 === 0);
    if (revisions.some(k => next[k] < expected[k]) || !revisions.some(k => next[k] > expected[k])) deny('B02_FORMAL_WITNESS_REVERSE_DENIED');
    return serial(async o => {
      const current = await read(o);
      if (matches(current, next, tx)) return Object.freeze({ advanced: true });
      if (current === null && (!armed || !same(expected, ZERO))) deny('B02_FORMAL_WITNESS_ADVANCE_DENIED');
      if (current !== null && (current.phase !== 'CONFIRMED' || !same(current.commitment, expected))) deny('B02_FORMAL_WITNESS_ADVANCE_DENIED');
      const timestamp = now();
      if (current !== null) number(current.sequence + 1, 1);
      try {
        if (current === null) {
          const plain = { witness_id: ID, schema: SCHEMA, phase: 'ADVANCED', sequence: 1,
            ...Object.fromEntries(ATTRS.map((k, i) => [k, next[FIELDS[i]]])), commitment_sha256: digest(next),
            previous_commitment_sha256: ZERO_HASH, transaction_id: tx, initialized_at_ms: timestamp, advanced_at_ms: timestamp, writer_contract: WRITER };
          await call(putItem, { TableName: TABLE, Item: Object.fromEntries(Object.entries(plain).map(([k, a]) => [k, encoded(a)])),
            ConditionExpression: 'attribute_not_exists(#witness_id)', ExpressionAttributeNames: { '#witness_id': 'witness_id' } }, o, true);
          if (!matches(await read(o), next, tx)) deny('B02_FORMAL_WITNESS_ADVANCE_DENIED');
        } else {
          const e = expression('CONFIRMED', undefined, expected);
          const sets = ['#phase = :advanced']; e.values[':advanced'] = encoded('ADVANCED');
          ATTRS.forEach((k, i) => { e.values[`:next_${k}`] = encoded(next[FIELDS[i]]); sets.push(`#${k} = :next_${k}`); });
          for (const [k, a] of Object.entries({ previous_commitment_sha256: digest(expected), commitment_sha256: digest(next), transaction_id: tx, advanced_at_ms: timestamp, writer_contract: WRITER })) {
            e.names[`#${k}`] = k; e.values[`:next_${k}`] = encoded(a); sets.push(`#${k} = :next_${k}`);
          }
          e.names['#confirmed_at_ms'] = 'confirmed_at_ms'; e.names['#sequence'] = 'sequence';
          e.values[':expected_sequence'] = encoded(current.sequence); e.values[':one'] = encoded(1); e.clauses.push('#sequence = :expected_sequence');
          const result = await call(updateItem, { TableName: TABLE, Key: key, ConditionExpression: e.clauses.join(' AND '),
            UpdateExpression: `SET ${sets.join(', ')} REMOVE #confirmed_at_ms ADD #sequence :one`,
            ExpressionAttributeNames: e.names, ExpressionAttributeValues: e.values, ReturnValues: 'ALL_NEW' }, o, true);
          const r = validateItem(data(result, ['Attributes'], ['$metadata']).Attributes);
          if (r.phase !== 'ADVANCED' || r.sequence !== current.sequence + 1 || r.initialized_at_ms !== current.initialized_at_ms ||
              r.previous_commitment_sha256 !== digest(expected) || !matches(r, next, tx)) deny('B02_FORMAL_WITNESS_ADVANCE_DENIED');
        }
        return Object.freeze({ advanced: true });
      } catch (e) {
        if (!conditional(e)) throw e;
        if (matches(await read(o), next, tx)) return Object.freeze({ advanced: true });
        deny('B02_FORMAL_WITNESS_ADVANCE_DENIED');
      }
    }, options);
  }
  async function confirm(value, options) {
    const v = data(value, ['commitment', 'transactionId'], [], 'B02_FORMAL_WITNESS_CONFIRM_DENIED');
    const next = commitment(v.commitment); const tx = transaction(v.transactionId);
    return serial(async o => {
      const current = await read(o);
      if (!matches(current, next, tx)) deny('B02_FORMAL_WITNESS_CONFIRM_DENIED');
      if (current.phase === 'CONFIRMED') { armed = false; return Object.freeze({ confirmed: true }); }
      const e = expression('ADVANCED', tx, next);
      e.names['#confirmed_at_ms'] = 'confirmed_at_ms'; e.values[':confirmed'] = encoded('CONFIRMED');
      e.values[':now_ms'] = encoded(now());
      try {
        const result = await call(updateItem, { TableName: TABLE, Key: key, ConditionExpression: e.clauses.join(' AND '),
          UpdateExpression: 'SET #phase = :confirmed, #confirmed_at_ms = :now_ms',
          ExpressionAttributeNames: e.names, ExpressionAttributeValues: e.values, ReturnValues: 'ALL_NEW' }, o, true);
        const r = validateItem(data(result, ['Attributes'], ['$metadata']).Attributes);
        if (r.phase !== 'CONFIRMED' || !matches(r, next, tx) || r.sequence !== current.sequence ||
            r.initialized_at_ms !== current.initialized_at_ms) deny('B02_FORMAL_WITNESS_CONFIRM_DENIED');
      } catch (error) {
        if (!conditional(error)) throw error;
        const r = await read(o);
        if (!matches(r, next, tx) || r.phase !== 'CONFIRMED') deny('B02_FORMAL_WITNESS_CONFIRM_DENIED');
      }
      armed = false; return Object.freeze({ confirmed: true });
    }, options);
  }
  function close() {
    if (!closePromise) { closed = true; closePromise = tail.then(async () => { if (destroy) { try { await destroy(); } catch { deny('B02_FORMAL_WITNESS_UNAVAILABLE'); } } return Object.freeze({ closed: true }); }); }
    return closePromise;
  }
  return Object.freeze({ productionAdmitted: true, external: true, backend: 'aws-dynamodb',
    readCurrent: options => serial(async o => { const r = await read(o); if (r) return r.commitment;
      if (armed) return ZERO; deny('B02_FORMAL_WITNESS_RECORD_DENIED'); }, options), compareAndAdvance, confirm, close });
}

export const dynamoWitnessConstants = Object.freeze({ tableName: TABLE, witnessId: ID, schema: SCHEMA, writerContract: WRITER, zeroCommitment: ZERO });
