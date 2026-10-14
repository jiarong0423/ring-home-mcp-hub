import { generateKeyPairSync } from 'node:crypto';
import { createDynamoMacCommandStore } from '../mac-command-store.mjs';
import { createMacCommandService } from '../mac-command-service.mjs';
import { createMacCommandProofSigner, MAC_PROOF_HEADER } from '../../../../src/formal-runtime/mac-command-proof.mjs';
import { createMacCommandProofAuthority, macEnrollmentKey } from '../mac-command-proof-authority.mjs';
export const AUDIENCE = 'https://abcdefghij.execute-api.ap-northeast-1.amazonaws.com/live/mcp';
export const TOKEN = 'synthetic-local-owner-token';
export const rpc = (id = 'test-command', enabled = true) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'software_test_switch.set', arguments: { enabled } } });
export function memoryDynamo() {
  const rows = new Map(); let fault = null;
  const scalar = value => value?.BOOL ?? value?.S ?? (value?.N === undefined ? undefined : Number(value.N));
  const cond = (expression, row, names = {}, values = {}) => {
    const atom = input => {
      const s = input.trim();
      if (s === 'attribute_not_exists(pk)') return !row;
      const m = /^(\S+) (=|<=|>) (:\w+)$/u.exec(s); if (!m) throw new Error('Unknown fixture condition');
      const left = scalar(row?.[names[m[1]] ?? m[1]]); const right = scalar(values[m[3]]);
      return m[2] === '=' ? left === right : m[2] === '<=' ? left <= right : left > right;
    };
    return expression.split(' OR ').some(part => part.split(' AND ').every(atom));
  };
  return {
    rows, failNext(value) { fault = value; },
    ports: {
      async getItem({ Key }) { return { Item: structuredClone(rows.get(Key.pk.S)) }; },
      async transactWrite({ TransactItems }) {
        const commandTransaction = !TransactItems.some(a => a.Put?.Item.pk.S.startsWith('rpl018:mac-proof:'));
        if (commandTransaction && fault === 'before') { fault = null; throw new Error('Synthetic unavailable'); }
        const pending = new Map();
        for (const action of TransactItems) {
          const op = action.Put ?? action.Update ?? action.ConditionCheck; const key = (op.Item ?? op.Key).pk.S; const row = rows.get(key);
          if (!cond(op.ConditionExpression, row, op.ExpressionAttributeNames, op.ExpressionAttributeValues)) {
            throw Object.assign(new Error('Conditional conflict'), { name: 'TransactionCanceledException', CancellationReasons: [{ Code: 'ConditionalCheckFailed' }] });
          }
          if (action.Put) pending.set(key, structuredClone(op.Item));
          else if (action.Update) {
            const next = structuredClone(row ?? { pk: op.Key.pk });
            for (const assignment of op.UpdateExpression.slice(4).split(', ')) {
              const [field, parameter] = assignment.split(' = ');
              next[op.ExpressionAttributeNames?.[field] ?? field] = structuredClone(op.ExpressionAttributeValues[parameter]);
            }
            pending.set(key, next);
          }
        }
        for (const [key, value] of pending) rows.set(key, value);
        if (commandTransaction && fault === 'after') { fault = null; throw new Error('Synthetic lost response'); }
        return {};
      }
    }
  };
}
export function fixture({ ownerRef = 'owner-a', clock: suppliedClock } = {}) {
  let now = 1_800_000_000_000; let current = true; const db = memoryDynamo();
  const clock = suppliedClock ?? (() => now); now = clock();
  const store = createDynamoMacCommandStore({ ports: db.ports, clock });
  const actor = Object.freeze({}); const browser = Object.freeze({ owner: ownerRef, session: 'browser-a' }); const mac = Object.freeze({ owner: ownerRef, session: 'mac-a' });
  const requests = new WeakSet([browser, mac]); const sessionExpiry = now + 120_000;
  const authorize = async ({ request, actor: supplied }) => {
    if (!requests.has(request) || supplied !== actor) throw new Error('AUTH_DENIED');
    return { ownerRef: request.owner, associationRevision: 1, sessionRef: request.session, expiresAt: sessionExpiry, assertCurrent: () => current };
  };
  const signer = createMacCommandProofSigner({ privateKey: generateKeyPairSync('ed25519').privateKey, ownerRef, associationRevision: 1, audience: AUDIENCE, clock });
  const enrollment = { pk: { S: macEnrollmentKey(ownerRef) }, schema: { S: 'ring-mac-enrollment-v1' }, owner_ref: { S: ownerRef }, association_revision: { N: '1' },
    revision: { N: '1' }, key_id: { S: signer.keyId }, public_key_spki: { S: signer.publicKeySpki }, expires_ms: { N: String(now + 86400000) }, approval_sha256: { S: 'a'.repeat(64) }, revoked: { BOOL: false } };
  db.rows.set(enrollment.pk.S, enrollment);
  const macProofAuthority = createMacCommandProofAuthority({ ports: db.ports, audience: AUDIENCE, clock });
  const service = createMacCommandService({ store, authorize, macProofAuthority, clock });
  function signedRequest(operation, payload, signing = signer) {
    const request = Object.freeze({ owner: ownerRef, session: 'mac-a', headers: Object.freeze({ authorization: 'Bearer ' + TOKEN,
      [MAC_PROOF_HEADER]: signing.signRequest({ operation, token: TOKEN, payload }) }) }); requests.add(request); return request;
  }
  const submit = (e = rpc(), request = browser) => service.submit({ request, actor, envelope: e });
  const fetch = () => service.fetch({ request: signedRequest('fetch', {}), actor });
  const accept = receipt => service.receipt({ request: signedRequest('receipt', receipt), actor, receipt });
  const makeReceipt = entry => ({ schema: 'ring-mac-receipt-v1', commandId: entry.command.commandId, envelopeSha256: entry.command.envelopeSha256,
    claimToken: entry.claimToken, status: 'SUCCEEDED', result: { kind: 'software-test-switch', enabled: entry.command.envelope.params.arguments.enabled, revision: 1, observedAt: now } });
  return { signer, signedRequest, macProofAuthority, enrollment, db, store, service, actor, browser, mac, requests, authorize, clock, submit, fetch, accept, makeReceipt,
    advance(ms) { now += ms; }, revoke() { current = false; } };
}
