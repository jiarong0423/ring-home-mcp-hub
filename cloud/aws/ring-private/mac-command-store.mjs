import { macEnrollmentCondition } from './mac-command-proof-authority.mjs';
import { COMMAND_ID, HASH, COMMAND_TABLE, TOMBSTONE_MS, command, receipt, commandResult, resultMatches, hash, port, record, time, text, deny, freeze } from '../../../src/formal-runtime/mac-command-contract.mjs';

const SCHEMA = 'ring-mac-command-record-v1';
const mailboxKey = owner => 'rpl018:mailbox:' + hash(text(owner));
const commandKey = (owner, id) => 'rpl018:command:' + hash(text(owner)) + ':' + id;
const conditional = error => error?.name === 'ConditionalCheckFailedException' ||
  error?.name === 'TransactionCanceledException' && Array.isArray(error.CancellationReasons) &&
  error.CancellationReasons.some(reason => reason.Code === 'ConditionalCheckFailed');
function item(value) {
  if (!value) return null;
  try {
    const c = command(JSON.parse(value.command_json.S));
    if (value.schema.S !== SCHEMA || !['PENDING', 'CLAIMED', 'SUCCEEDED'].includes(value.state.S)) deny('MAC_COMMAND_STORE_RECORD');
    if (value.command_id?.S !== c.commandId || value.owner_ref?.S !== c.ownerRef || Number(value.association_revision?.N) !== c.associationRevision ||
        Number(value.expires_ms?.N) !== c.expiresAt) deny('MAC_COMMAND_STORE_RECORD');
    const claimHash = value.claim_hash?.S ?? null;
    if (value.state.S !== 'PENDING' && (typeof claimHash !== 'string' || !HASH.test(claimHash))) deny('MAC_COMMAND_STORE_RECORD');
    const macKeyId = value.mac_key_id?.S ?? null; const macRevision = Number(value.mac_key_revision?.N);
    if (value.state.S !== 'PENDING' && (!HASH.test(macKeyId ?? '') || !Number.isSafeInteger(macRevision) || macRevision < 1)) deny('MAC_COMMAND_STORE_RECORD');
    let result = null;
    if (value.state.S === 'SUCCEEDED') {
      const r = record(JSON.parse(value.receipt_json.S), ['commandId', 'envelopeSha256', 'status', 'result']);
      if (r.commandId !== c.commandId || r.envelopeSha256 !== c.envelopeSha256 || r.status !== 'SUCCEEDED') deny('MAC_COMMAND_STORE_RECORD');
      const observed = commandResult(r.result);
      if (!resultMatches(observed, c.envelope) || observed.observedAt < c.issuedAt || observed.observedAt >= c.expiresAt) deny('MAC_COMMAND_STORE_RECORD');
      result = { ...r, result: observed };
    } else if (value.receipt_json) deny('MAC_COMMAND_STORE_RECORD');
    return { command: c, state: value.state.S, claimHash, macKeyId, macRevision, result };
  } catch { deny('MAC_COMMAND_STORE_RECORD'); }
}
export function createDynamoMacCommandStore({ ports, tableName = COMMAND_TABLE, clock = Date.now } = {}) {
  if (tableName !== COMMAND_TABLE || typeof clock !== 'function') deny('MAC_COMMAND_STORE_CONFIG');
  const aws = port(ports, ['getItem', 'transactWrite']);
  const readItem = async key => { try { return (await aws.getItem({ TableName: tableName, Key: { pk: { S: key } }, ConsistentRead: true }))?.Item ?? null; } catch { deny('MAC_COMMAND_STORE_UNAVAILABLE'); } };
  async function read(ownerRef, commandId) {
    if (typeof commandId !== 'string' || !COMMAND_ID.test(commandId)) deny('MAC_COMMAND_ID');
    const value = item(await readItem(commandKey(ownerRef, commandId)));
    if (value && (value.command.ownerRef !== ownerRef || value.command.commandId !== commandId)) deny('MAC_COMMAND_STORE_RECORD');
    return value;
  }
  return Object.freeze({
    async enqueue(value) {
      const c = command(value); const now = time(clock());
      if (now >= c.expiresAt) deny('MAC_COMMAND_EXPIRED');
      const pk = commandKey(c.ownerRef, c.commandId); const mailbox = mailboxKey(c.ownerRef);
      const attributes = { pk: { S: pk }, schema: { S: SCHEMA }, state: { S: 'PENDING' }, command_json: { S: JSON.stringify(c) },
        command_id: { S: c.commandId }, owner_ref: { S: c.ownerRef }, association_revision: { N: String(c.associationRevision) },
        expires_ms: { N: String(c.expiresAt) }, expires_at: { N: String(Math.ceil((c.sessionExpiresAt + TOMBSTONE_MS) / 1000)) } };
      try {
        await aws.transactWrite({ TransactItems: [
          { Put: { TableName: tableName, Item: attributes, ConditionExpression: 'attribute_not_exists(pk)' } },
          { Put: { TableName: tableName, Item: { pk: { S: mailbox }, command_id: { S: c.commandId }, owner_ref: { S: c.ownerRef },
            available_after_ms: { N: String(c.expiresAt) }, expires_at: attributes.expires_at },
            ConditionExpression: 'attribute_not_exists(pk) OR available_after_ms <= :now', ExpressionAttributeValues: { ':now': { N: String(now) } } } }
        ] });
        return freeze({ command: c, state: 'PENDING', result: null });
      } catch (error) {
        const existing = await read(c.ownerRef, c.commandId);
        if (existing) {
          if (existing.command.envelopeSha256 !== c.envelopeSha256 || existing.command.associationRevision !== c.associationRevision ||
              existing.command.sessionExpiresAt !== c.sessionExpiresAt) deny('MAC_COMMAND_ID_CONFLICT');
          return freeze(existing);
        }
        if (conditional(error)) deny('MAC_COMMAND_MAILBOX_BUSY');
        deny('MAC_COMMAND_STORE_OUTCOME_UNKNOWN');
      }
    },
    async claim({ ownerRef, associationRevision, claimToken, mac }) {
      text(ownerRef); const now = time(clock());
      if (!mac || mac.ownerRef !== ownerRef || mac.associationRevision !== associationRevision || !HASH.test(mac.keyId ?? '') || !Number.isSafeInteger(mac.revision) || mac.revision < 1) deny('MAC_COMMAND_MAC_REQUIRED');
      if (!Number.isSafeInteger(associationRevision) || associationRevision < 1 || typeof claimToken !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(claimToken)) deny('MAC_COMMAND_CLAIM');
      const mailbox = await readItem(mailboxKey(ownerRef));
      if (!mailbox) return null;
      if (mailbox.owner_ref?.S !== ownerRef || typeof mailbox.command_id?.S !== 'string') deny('MAC_COMMAND_STORE_RECORD');
      const current = await read(ownerRef, mailbox.command_id.S);
      if (!current || current.state !== 'PENDING' || now >= current.command.expiresAt) return null;
      if (current.command.ownerRef !== ownerRef || current.command.associationRevision !== associationRevision) deny('MAC_COMMAND_OWNER');
      try {
        await aws.transactWrite({ TransactItems: [macEnrollmentCondition(mac, tableName, time(clock())), { Update: { TableName: tableName,
          Key: { pk: { S: commandKey(ownerRef, current.command.commandId) } },
          UpdateExpression: 'SET #state = :claimed, claim_hash = :claim, mac_key_id = :macKey, mac_key_revision = :macRevision',
          ConditionExpression: '#state = :pending AND expires_ms > :now AND association_revision = :revision AND owner_ref = :owner',
          ExpressionAttributeNames: { '#state': 'state' }, ExpressionAttributeValues: {
            ':macKey': { S: mac.keyId }, ':macRevision': { N: String(mac.revision) }, ':claimed': { S: 'CLAIMED' }, ':pending': { S: 'PENDING' }, ':claim': { S: hash(claimToken) },
            ':now': { N: String(time(clock())) }, ':revision': { N: String(associationRevision) }, ':owner': { S: ownerRef }
          } } }] });
      } catch (error) {
        if (conditional(error)) return null;
        deny('MAC_COMMAND_CLAIM_OUTCOME_UNKNOWN');
      }
      if (time(clock()) >= current.command.expiresAt) deny('MAC_COMMAND_EXPIRED');
      return current.command;
    },
    async complete({ ownerRef, associationRevision, value, mac }) {
      const r = receipt(value); const current = await read(ownerRef, r.commandId); const now = time(clock());
      if (!mac || mac.ownerRef !== ownerRef || mac.associationRevision !== associationRevision || !current || current.macKeyId !== mac.keyId || current.macRevision !== mac.revision || current.command.ownerRef !== ownerRef || current.command.associationRevision !== associationRevision ||
          current.command.envelopeSha256 !== r.envelopeSha256 || current.claimHash !== hash(r.claimToken)) deny('MAC_COMMAND_RECEIPT_DENIED');
      const result = freeze({ commandId: r.commandId, envelopeSha256: r.envelopeSha256, status: r.status, result: r.result });
      if (current.state === 'SUCCEEDED') {
        if (JSON.stringify(current.result) !== JSON.stringify(result)) deny('MAC_COMMAND_RECEIPT_CONFLICT');
        return current.result;
      }
      if (now >= current.command.expiresAt || r.result.observedAt < current.command.issuedAt || r.result.observedAt >= current.command.expiresAt ||
          !resultMatches(r.result, current.command.envelope)) deny('MAC_COMMAND_EXPIRED');
      try {
        await aws.transactWrite({ TransactItems: [
          macEnrollmentCondition(mac, tableName, time(clock())),
          { Update: { TableName: tableName, Key: { pk: { S: commandKey(ownerRef, r.commandId) } },
            UpdateExpression: 'SET #state = :succeeded, receipt_json = :receipt',
            ConditionExpression: '#state = :claimed AND claim_hash = :claim AND expires_ms > :now AND association_revision = :revision AND mac_key_id = :macKey AND mac_key_revision = :macRevision',
            ExpressionAttributeNames: { '#state': 'state' }, ExpressionAttributeValues: { ':macKey': { S: mac.keyId }, ':macRevision': { N: String(mac.revision) }, ':succeeded': { S: 'SUCCEEDED' }, ':claimed': { S: 'CLAIMED' },
              ':claim': { S: hash(r.claimToken) }, ':receipt': { S: JSON.stringify(result) }, ':now': { N: String(time(clock())) }, ':revision': { N: String(associationRevision) } } } },
          { Update: { TableName: tableName, Key: { pk: { S: mailboxKey(ownerRef) } },
            UpdateExpression: 'SET available_after_ms = :zero', ConditionExpression: 'command_id = :id',
            ExpressionAttributeValues: { ':zero': { N: '0' }, ':id': { S: r.commandId } } } }
        ] });
        return result;
      } catch {
        const observed = await read(ownerRef, r.commandId);
        if (observed?.state === 'SUCCEEDED' && JSON.stringify(observed.result) === JSON.stringify(result)) return observed.result;
        deny('MAC_COMMAND_RECEIPT_OUTCOME_UNKNOWN');
      }
    },
    async read({ ownerRef, commandId }) { return freeze(await read(ownerRef, commandId)); }
  });
}
