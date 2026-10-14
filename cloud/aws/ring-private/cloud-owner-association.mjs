import { createHash } from 'node:crypto';
import { lookupFormalVerifiedLogin } from '../../../src/formal-runtime/request-authorization-policy.mjs';

const HASH = /^[a-f0-9]{64}$/u;
const REF = /^[A-Za-z][A-Za-z0-9._/@-]{2,255}$/u;
export const associationSha256 = value => createHash('sha256').update(value).digest('hex');
function deny(code = 'cloud_owner_association_denied') { throw new TypeError(code); }
function text(item, key) { const value = item?.[key]?.S; if (typeof value !== 'string' || !value) deny(); return value; }
function integer(item, key) { const raw = item?.[key]?.N; if (typeof raw !== 'string' || !/^[1-9][0-9]*$/u.test(raw)) deny(); const n = Number(raw); if (!Number.isSafeInteger(n)) deny(); return n; }
function time(clock) { const n = clock(); if (!Number.isSafeInteger(n) || n < 1) deny('cloud_identity_clock_denied'); return n; }
export function cloudAssociationKey(subjectDigest) {
  if (!HASH.test(subjectDigest)) deny();
  return { PK: { S: `OAUTH#${subjectDigest}` }, SK: { S: 'RING_ASSOCIATION' } };
}
function activeRecord(item, subjectDigest, profile, now) {
  if (!item || text(item, 'schema') !== 'ring-cloud-owner-association-v1' || text(item, 'subject_digest') !== subjectDigest ||
      text(item, 'issuer') !== profile.issuer || text(item, 'resource') !== profile.resource || item.revoked?.BOOL !== false) deny();
  const ownerRef = text(item, 'owner_ref'), accountDigest = text(item, 'account_digest');
  const scopes = item.scope_refs?.L?.map(s => s.S);
  const ringScopeRefs = item.ring_scope_refs?.L?.map(s => s.S);
  if (!Array.isArray(ringScopeRefs) || ringScopeRefs.length < 1 || ringScopeRefs.length > 16 || ringScopeRefs.some(s => typeof s !== 'string' || !REF.test(s)) || new Set(ringScopeRefs).size !== ringScopeRefs.length ||
      !REF.test(ownerRef) || !HASH.test(accountDigest) || !Array.isArray(scopes) || scopes.length !== profile.scopes.length ||
      [...scopes].sort().some((s, i) => s !== [...profile.scopes].sort()[i]) || !HASH.test(text(item, 'approval_evidence_sha256'))) deny();
  const record = { ownerRef, accountDigest, subjectDigest, ownerEpoch: integer(item, 'owner_epoch'),
    revision: integer(item, 'revision'), accountGeneration: integer(item, 'account_generation'),
    expiresAt: integer(item, 'expires_at') * 1000, scopes: Object.freeze(scopes), scopeRefs: Object.freeze(ringScopeRefs) };
  if (record.expiresAt <= now) deny('cloud_owner_association_expired');
  return Object.freeze(record);
}
export function createCloudOwnerAssociationReader({ getItem, transactGet, tableName, digest, profile, clock = Date.now }) {
  if (typeof getItem !== 'function' || typeof transactGet !== 'function' || typeof digest !== 'function' ||
      typeof tableName !== 'string' || !/^[A-Za-z0-9_.-]{3,255}$/u.test(tableName) || !Array.isArray(profile?.scopes) || !profile.scopes.length) deny();
  let closed = false;
  let lastNow = 0;
  function nowChecked() { const now = time(clock); if (now < lastNow) { cache.clear(); deny('cloud_identity_clock_regressed'); } lastNow = now; return now; }
  const cache = new Map();
  async function readForSubject(subject) {
    if (closed || typeof subject !== 'string' || subject.length < 1 || subject.length > 256) deny();
    const subjectDigest = await digest('oauth-subject', `${profile.issuer}\0${subject}`);
    const Key = cloudAssociationKey(subjectDigest);
    cache.delete(subjectDigest);
    const first = await getItem({ TableName: tableName, Key, ConsistentRead: true });
    const preliminary = activeRecord(first?.Item, subjectDigest, profile, nowChecked());
    const transaction = await transactGet({ TransactItems: [Key,
      { PK: { S: 'OWNER#CURRENT' }, SK: { S: 'META' } },
      { PK: { S: `ACCOUNT#${preliminary.accountDigest}` }, SK: { S: 'IDENTITY' } }
    ].map(key => ({ Get: { TableName: tableName, Key: key } })) });
    if (!Array.isArray(transaction?.Responses) || transaction.Responses.length !== 3) deny();
    const [association, owner, account] = transaction.Responses.map(response => response.Item);
    const record = activeRecord(association, subjectDigest, profile, nowChecked());
    if (record.accountDigest !== preliminary.accountDigest || record.revision !== preliminary.revision ||
        text(owner, 'status') !== 'ACTIVE' || text(owner, 'owner_ref') !== record.ownerRef || integer(owner, 'owner_epoch') !== record.ownerEpoch ||
        account?.revoked?.BOOL !== false || text(account, 'owner_ref') !== record.ownerRef ||
        text(account, 'account_digest') !== record.accountDigest || integer(account, 'owner_epoch') !== record.ownerEpoch ||
        integer(account, 'account_generation') !== record.accountGeneration || integer(account, 'expires_at') * 1000 < record.expiresAt) deny();
    for (const [key, value] of cache) if (value.expiresAt <= nowChecked()) cache.delete(key);
    if (!cache.has(subjectDigest) && cache.size >= 128) deny('cloud_identity_capacity');
    cache.set(subjectDigest, record);
    return record;
  }
  async function authorize({ request, actor }) {
    const evidence = lookupFormalVerifiedLogin({ request, actor });
    const now = nowChecked();
    if (!evidence || evidence.issuer !== profile.issuer || evidence.resource !== profile.resource ||
        evidence.issuedAtMs > now || evidence.expiresAtMs <= now ||
        evidence.scopes.length !== profile.scopes.length || [...evidence.scopes].sort().some((s, i) => s !== [...profile.scopes].sort()[i])) deny('cloud_verified_login_required');
    const record = await readForSubject(actor.subject);
    const expiresAt = Math.min(evidence.expiresAtMs, record.expiresAt, evidence.issuedAtMs + 300000);
    const sessionRef = `Session.${associationSha256(`${profile.issuer}\0${evidence.tokenDigest}`)}`;
    const lease = Object.freeze({ ownerRef: record.ownerRef, associationRevision: record.revision, sessionRef, expiresAt,
      assertCurrent() {
        if (closed || lookupFormalVerifiedLogin({ request, actor }) !== evidence || nowChecked() >= expiresAt ||
            cache.get(record.subjectDigest) !== record) deny('cloud_request_binding_changed');
        return true;
      } });
    lease.assertCurrent();
    return lease;
  }
  return Object.freeze({ readForSubject, authorize, invalidate(subjectDigest) { cache.delete(subjectDigest); },
    async close() { closed = true; cache.clear(); return { closed: true }; } });
}

// Shared by the operator installer and the callback-bound owner bootstrap so both write byte-identical items.
// `approval` carries ownerRef/actorRef/householdRef/ownerMode/accountMode/expectedRevision/revision/ownerEpoch/
// accountGeneration/ringScopeRefs/expiresAt; the caller is responsible for validating it.
export function buildOwnerAssociationItems({ tableName, profile, approval: a, subjectDigest, accountDigest, envelope, approvalSha256 }) {
    const expires = String(Math.floor(a.expiresAt / 1000));
    const owner = { PK: { S: 'OWNER#CURRENT' }, SK: { S: 'META' }, status: { S: 'ACTIVE' },
      owner_ref: { S: a.ownerRef }, actor_ref: { S: a.actorRef }, household_ref: { S: a.householdRef }, owner_epoch: { N: String(a.ownerEpoch) } };
    const association = { ...cloudAssociationKey(subjectDigest), schema: { S: 'ring-cloud-owner-association-v1' },
      subject_digest: { S: subjectDigest }, issuer: { S: profile.issuer }, resource: { S: profile.resource }, owner_ref: { S: a.ownerRef },
      owner_epoch: { N: String(a.ownerEpoch) }, revision: { N: String(a.revision) }, account_digest: { S: accountDigest },
      account_generation: { N: String(a.accountGeneration) }, ring_scope_refs: { L: a.ringScopeRefs.map(S => ({ S })) }, scope_refs: { L: profile.scopes.map(S => ({ S })) },
      expires_at: { N: expires }, revoked: { BOOL: false }, approval_evidence_sha256: { S: approvalSha256 } };
    const account = { PK: { S: `ACCOUNT#${accountDigest}` }, SK: { S: 'IDENTITY' }, account_digest: { S: accountDigest },
      owner_ref: { S: a.ownerRef }, owner_epoch: { N: String(a.ownerEpoch) }, identity_epoch: { N: String(a.ownerEpoch) }, account_generation: { N: String(a.accountGeneration) },
      projection_revision: { N: '1' }, expires_at: { N: expires }, revoked: { BOOL: false },
      account_identifier_envelope: { M: { version: { N: String(envelope.version) }, purpose: { S: envelope.purpose }, key_id: { S: envelope.keyId },
        encrypted_data_key: { S: envelope.encryptedDataKey }, nonce: { S: envelope.nonce }, auth_tag: { S: envelope.authTag }, ciphertext: { S: envelope.ciphertext } } } };
    const ownerWrite = a.ownerMode === 'create'
      ? { Put: { TableName: tableName, Item: owner, ConditionExpression: 'attribute_not_exists(PK)' } }
      : { ConditionCheck: { TableName: tableName, Key: { PK: owner.PK, SK: owner.SK },
        ConditionExpression: '#state = :active AND owner_ref = :owner AND owner_epoch = :epoch',
        ExpressionAttributeNames: { '#state': 'status' }, ExpressionAttributeValues: { ':active': { S: 'ACTIVE' }, ':owner': owner.owner_ref, ':epoch': owner.owner_epoch } } };
    return [ownerWrite,
      { Put: { TableName: tableName, Item: association,
        ConditionExpression: a.expectedRevision === 0 ? 'attribute_not_exists(PK)' : 'revision = :revision AND owner_ref = :owner AND owner_epoch = :epoch',
        ...(a.expectedRevision === 0 ? {} : { ExpressionAttributeValues: { ':revision': { N: String(a.expectedRevision) }, ':owner': owner.owner_ref, ':epoch': owner.owner_epoch } }) } },
      a.accountMode === 'create' ? { Put: { TableName: tableName, Item: account, ConditionExpression: 'attribute_not_exists(PK)' } }
        : { ConditionCheck: { TableName: tableName, Key: { PK: account.PK, SK: account.SK },
          ConditionExpression: 'owner_ref = :owner AND owner_epoch = :epoch AND account_generation = :generation AND revoked = :false AND expires_at >= :expires',
          ExpressionAttributeValues: { ':owner': owner.owner_ref, ':epoch': owner.owner_epoch, ':generation': { N: String(a.accountGeneration) }, ':false': { BOOL: false }, ':expires': { N: expires } } } }
    ];
}

// This installer is an operator ceremony API. No HTTP route is exported. The pinned approval
// bytes are chosen by the deployment owner, and the Ring account is obtained from the live provider.
export function createCloudOwnerAssociationInstaller({ transactWrite, tableName, digest, identityEnvelope,
  ringClient, approvalSha256, profile, clock = Date.now }) {
  if (typeof transactWrite !== 'function' || typeof digest !== 'function' || typeof ringClient?.getAccountId !== 'function' ||
      typeof identityEnvelope?.seal !== 'function' || !HASH.test(approvalSha256)) deny('cloud_association_installer_config');
  return Object.freeze({ async install({ request, actor, ringAccessToken, approvalBytes }) {
    const login = lookupFormalVerifiedLogin({ request, actor });
    const now = time(clock);
    if (!login || login.issuer !== profile.issuer || login.resource !== profile.resource || login.expiresAtMs <= now ||
        login.issuedAtMs > now || !Buffer.isBuffer(approvalBytes) || approvalBytes.length > 16384 ||
        associationSha256(approvalBytes) !== approvalSha256) deny('cloud_association_approval_denied');
    const a = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(approvalBytes));
    const subjectDigest = await digest('oauth-subject', `${profile.issuer}\0${actor.subject}`);
    if (a.schema !== 'ring-owner-association-approval-v1' || a.issuer !== profile.issuer || a.resource !== profile.resource ||
        a.subjectDigest !== subjectDigest || !REF.test(a.ownerRef) || !REF.test(a.actorRef) || !REF.test(a.householdRef) ||
        !['create', 'existing'].includes(a.ownerMode) || !['create', 'existing'].includes(a.accountMode) ||
        !Number.isSafeInteger(a.expectedRevision) || a.expectedRevision < 0 || a.revision !== a.expectedRevision + 1 ||
        !Number.isSafeInteger(a.ownerEpoch) || a.ownerEpoch < 1 || !Number.isSafeInteger(a.accountGeneration) || a.accountGeneration < 1 ||
        !Number.isSafeInteger(a.expiresAt) || a.expiresAt <= now || a.expiresAt > now + 86400000 ||
        !Array.isArray(a.ringScopeRefs) || a.ringScopeRefs.length < 1 || a.ringScopeRefs.length > 16 ||
        a.ringScopeRefs.some(s => typeof s !== 'string' || !REF.test(s)) || new Set(a.ringScopeRefs).size !== a.ringScopeRefs.length ||
        !Array.isArray(a.scopes) || a.scopes.length !== profile.scopes.length ||
        [...a.scopes].sort().some((s, i) => s !== [...profile.scopes].sort()[i]) ||
        login.scopes.length !== profile.scopes.length || [...login.scopes].sort().some((s, i) => s !== [...profile.scopes].sort()[i])) deny('cloud_association_approval_denied');
    const accountId = await ringClient.getAccountId(ringAccessToken);
    if (typeof accountId !== 'string' || !accountId || accountId.length > 256) deny('cloud_ring_profile_denied');
    const accountDigest = await digest('ring-account', accountId);
    if (accountDigest !== a.accountDigest) deny('cloud_ring_owner_mismatch');
    const envelope = await identityEnvelope.seal(accountId, { accountDigest, ownerRef: a.ownerRef,
      ownerEpoch: a.ownerEpoch, accountGeneration: a.accountGeneration });
    if (time(clock) >= Math.min(login.expiresAtMs, a.expiresAt)) deny('cloud_association_approval_expired');
    const outcome = await transactWrite({ TransactItems: buildOwnerAssociationItems({ tableName, profile, approval: a,
      subjectDigest, accountDigest, envelope, approvalSha256 }) });
    if (!outcome || typeof outcome !== 'object') deny('cloud_association_outcome_unknown');
    return Object.freeze({ installed: true, ownerRef: a.ownerRef, associationRevision: a.revision, accountDigest, approvalSha256 });
  } });
}
