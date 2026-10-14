import { randomBytes as secureRandomBytes } from 'node:crypto';
import { cloudAssociationKey } from './cloud-owner-association.mjs';

function deny() { throw new TypeError('cloud_browser_session_denied'); }
const COOKIE_PROOF = '__Host-ring_session';
const COOKIE_CSRF = '__Host-ring_csrf';
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
export function extractCloudSessionCookies(headers) {
  if (!headers || typeof headers !== 'object') deny();
  const raw = headers.cookie;
  if (typeof raw !== 'string' || raw.length > 4096 || /[\x00-\x1f\x7f]/u.test(raw)) deny();
  const cookies = new Map();
  for (const component of raw.split(';')) {
    const match = /^\s*([^=\s;]+)=([^;]*)$/u.exec(component);
    if (!match || cookies.has(match[1])) deny();
    cookies.set(match[1], match[2]);
  }
  const sessionProof = cookies.get(COOKIE_PROOF), csrf = cookies.get(COOKIE_CSRF);
  if (!TOKEN.test(sessionProof ?? '') || !TOKEN.test(csrf ?? '')) deny();
  return Object.freeze({ sessionProof, csrf });
}
export function createCloudBrowserSessionIssuer({ associationReader, transactWrite, tableName, digest,
  clock = Date.now, randomBytes = secureRandomBytes }) {
  if (typeof associationReader?.authorize !== 'function' || typeof associationReader?.readForSubject !== 'function' ||
      typeof transactWrite !== 'function' || typeof digest !== 'function') deny();
  return Object.freeze({ async issue({ request, actor }) {
    const auth = await associationReader.authorize({ request, actor });
    const record = await associationReader.readForSubject(actor.subject);
    // A fresh read invalidates the prior in-memory lease; the second authorization binds this exact request again.
    const current = await associationReader.authorize({ request, actor });
    if (auth.ownerRef !== record.ownerRef || current.ownerRef !== record.ownerRef || current.associationRevision !== record.revision) deny();
    const proofBytes = randomBytes(32), csrfBytes = randomBytes(32);
    if (!Buffer.isBuffer(proofBytes) || proofBytes.length !== 32 || !Buffer.isBuffer(csrfBytes) || csrfBytes.length !== 32) deny();
    const sessionProof = proofBytes.toString('base64url'), csrf = csrfBytes.toString('base64url');
    const sessionDigest = await digest('session-proof', sessionProof), csrfDigest = await digest('session-csrf', csrf),
      grantDigest = await digest('session-trust', csrf);
    const expiresAt = Math.floor(Math.min(current.expiresAt, record.expiresAt) / 1000);
    const now = clock();
    if (!Number.isSafeInteger(now) || expiresAt * 1000 <= now) deny();
    const ownerValue = { S: record.ownerRef }, epochValue = { N: String(record.ownerEpoch) };
    const grantId = `Trust.${grantDigest}`, sessionId = `Session.${sessionDigest}`;
    current.assertCurrent();
    const outcome = await transactWrite({ TransactItems: [
      { ConditionCheck: { TableName: tableName, Key: cloudAssociationKey(record.subjectDigest),
        ConditionExpression: 'revision = :revision AND owner_ref = :owner AND owner_epoch = :epoch AND revoked = :false AND expires_at >= :expires',
        ExpressionAttributeValues: { ':revision': { N: String(record.revision) }, ':owner': ownerValue,
          ':epoch': epochValue, ':false': { BOOL: false }, ':expires': { N: String(expiresAt) } } } },
      { ConditionCheck: { TableName: tableName, Key: { PK: { S: 'OWNER#CURRENT' }, SK: { S: 'META' } },
        ConditionExpression: '#state = :active AND owner_ref = :owner AND owner_epoch = :epoch',
        ExpressionAttributeNames: { '#state': 'status' }, ExpressionAttributeValues: { ':active': { S: 'ACTIVE' }, ':owner': ownerValue, ':epoch': epochValue } } },
      { ConditionCheck: { TableName: tableName, Key: { PK: { S: `ACCOUNT#${record.accountDigest}` }, SK: { S: 'IDENTITY' } },
        ConditionExpression: 'owner_ref = :owner AND owner_epoch = :epoch AND account_generation = :generation AND revoked = :false AND expires_at >= :expires',
        ExpressionAttributeValues: { ':owner': ownerValue, ':epoch': epochValue, ':generation': { N: String(record.accountGeneration) }, ':false': { BOOL: false }, ':expires': { N: String(expiresAt) } } } },
      { Put: { TableName: tableName, ConditionExpression: 'attribute_not_exists(PK)', Item: {
        PK: { S: `OWNER#${record.ownerRef}` }, SK: { S: `GRANT#${grantDigest}` }, grant_id: { S: grantId }, grant_digest: { S: grantDigest },
        grant_generation: { N: '1' }, owner_epoch: epochValue, scope_refs: { L: record.scopeRefs.map(S => ({ S })) },
        expires_at: { N: String(expiresAt) }, revoked: { BOOL: false } } } },
      { Put: { TableName: tableName, ConditionExpression: 'attribute_not_exists(PK)', Item: {
        PK: { S: `SESSION#${sessionDigest}` }, SK: { S: 'META' }, session_id: { S: sessionId }, session_generation: { N: '1' },
        csrf_digest: { S: csrfDigest }, owner_ref: ownerValue, owner_epoch: epochValue, grant_id: { S: grantId }, grant_digest: { S: grantDigest },
        grant_generation: { N: '1' }, session_expires_at: { N: String(expiresAt) }, idle_expires_at: { N: String(expiresAt) }, trust_expires_at: { N: String(expiresAt) },
        expires_at: { N: String(expiresAt) }, production_admitted: { BOOL: true }, revoked: { BOOL: false },
        account_digest: { S: record.accountDigest }, account_generation: { N: String(record.accountGeneration) }, projection_revision: { N: '1' } } } }
    ] });
    if (!outcome || typeof outcome !== 'object') deny();
    current.assertCurrent();
    const attributes = `; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=${Math.max(0, Math.floor((expiresAt * 1000 - clock()) / 1000))}`;
    return Object.freeze({ expiresAt: expiresAt * 1000, setCookie: Object.freeze([
      `${COOKIE_PROOF}=${sessionProof}${attributes}`, `${COOKIE_CSRF}=${csrf}${attributes}`
    ]) });
  } });
}
