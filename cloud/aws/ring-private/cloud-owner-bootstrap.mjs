import { createHash, timingSafeEqual } from 'node:crypto';
import { lookupFormalVerifiedLogin } from '../../../src/formal-runtime/request-authorization-policy.mjs';
import { associationSha256, buildOwnerAssociationItems, cloudAssociationKey } from './cloud-owner-association.mjs';
import { RING_ACCESS_TOKEN_PATTERN } from './ring-token-client.mjs';

// First-owner bootstrap AND owner renewal (Ring sandbox token mode). Both are reachable ONLY through the bearer-verified route
// POST /owner/bootstrap (same formal policy + transport evidence as POST /mac/enroll). There is no direct-invoke path,
// no operator-supplied event and no /auth/callback hook. The SAME pinned approval file selects the operation by its schema:
//   * OWNER#CURRENT absent  -> bootstrap; only a 'ring-owner-bootstrap-approval-v1' document is accepted.
//   * OWNER#CURRENT present -> renewal;   only a 'ring-owner-renewal-approval-v1' document (mode 'renew') is accepted.
// A bootstrap approval can therefore never act as a renewal and vice versa (different exact key sets, schema, latch prefix).
// Bootstrap writes only when ALL of these hold:
//   * the verified Cognito login satisfies the same checks as the operator installer,
//   * OWNER#CURRENT does not exist (strongly consistent read),
//   * the approval bytes hash to the pinned deployment value and bind this exact Cognito subject inside a <=24h window,
//   * the caller-supplied Ring-issued access token resolves (Ring Users API) to a Ring account id whose sha256 equals the approval's
//     ringAccountIdSha256 (compared in constant time before the id is used for anything else),
//   * fewer than MAX_FAILURES counted failed attempts exist for this approval (counter row with a 1h expires_at that is also checked
//     explicitly here; only DEFINITE rejections count: Ring HTTP 401/403, or a Ring-reported id that does not match the pin),
//   * a single-use latch (OWNER_BOOTSTRAP#<approvalSha256>) and a token replay marker (RING_TOKEN#<sha256(token)>, 1h TTL, hash only)
//     are created in the SAME transaction.
// Renewal (see renew() below) can only move the expiry of the EXISTING binding forward; it never creates a new owner, subject,
// Ring account, scope, epoch, generation or association revision.
const HASH = /^[a-f0-9]{64}$/u;
const REF = /^[A-Za-z][A-Za-z0-9._/@-]{2,255}$/u;
const DAY_MS = 86400000;
export const OWNER_BOOTSTRAP_MAX_FAILURES = 3;
const TOKEN_MARKER_TTL_MS = 3600000;
const ATTEMPTS_TTL_MS = 3600000;
const IDENTITY_SOURCE = 'ring-sandbox-token';
const APPROVAL_KEYS = ['schema', 'issuer', 'resource', 'cognitoSub', 'ringAccountIdSha256', 'ownerRef', 'actorRef', 'householdRef',
  'ringScopeRefs', 'scopes', 'issuedAt', 'notAfter', 'expiresAt'];
export const OWNER_BOOTSTRAP_APPROVAL_SCHEMA = 'ring-owner-bootstrap-approval-v1';
const RENEWAL_KEYS = ['schema', 'mode', 'issuer', 'resource', 'cognitoSub', 'ringAccountIdSha256', 'bootstrapApprovalSha256', 'ownerRef',
  'ownerEpoch', 'associationRevision', 'accountGeneration', 'ringScopeRefs', 'scopes', 'issuedAt', 'notAfter', 'expiresAt'];
export const OWNER_RENEWAL_APPROVAL_SCHEMA = 'ring-owner-renewal-approval-v1';
const BOOTSTRAP_LATCH_SCHEMA = 'ring-owner-bootstrap-latch-v1';
function deny(code = 'owner_bootstrap_denied') { throw new TypeError(code); }
const sameSet = (a, b) => Array.isArray(a) && Array.isArray(b) && a.length === b.length && new Set(a).size === a.length && [...a].sort().every((v, i) => v === [...b].sort()[i]);
const safeInt = v => Number.isSafeInteger(v) && v > 0;
const exactKeys = (a, list) => { const keys = Object.keys(a); return keys.length === list.length && keys.every(k => list.includes(k)) && list.every(k => Object.hasOwn(a, k)); };
const refList = v => Array.isArray(v) && v.length >= 1 && v.length <= 16 && v.every(s => typeof s === 'string' && REF.test(s)) && new Set(v).size === v.length;
// issuedAt <= now <= notAfter, 0 < notAfter-issuedAt <= 24h, now < expiresAt <= now+24h
const windowOk = (a, now) => safeInt(a.issuedAt) && safeInt(a.notAfter) && a.notAfter > a.issuedAt && a.notAfter - a.issuedAt <= DAY_MS &&
  now >= a.issuedAt && now <= a.notAfter && safeInt(a.expiresAt) && a.expiresAt > now && a.expiresAt <= now + DAY_MS;
const seconds = attr => { const raw = attr?.N; return typeof raw === 'string' && /^[1-9][0-9]{0,15}$/u.test(raw) && Number.isSafeInteger(Number(raw)) ? Number(raw) : null; };

export function ownerBootstrapAttemptsKey(approvalSha256) {
  if (!HASH.test(approvalSha256)) deny();
  return { PK: { S: `OWNER_BOOTSTRAP_ATTEMPTS#${approvalSha256}` }, SK: { S: 'META' } };
}
export function ringTokenMarkerKey(tokenSha256) {
  if (!HASH.test(tokenSha256)) deny();
  return { PK: { S: `RING_TOKEN#${tokenSha256}` }, SK: { S: 'META' } };
}
export function ownerBootstrapLatchKey(approvalSha256) {
  if (!HASH.test(approvalSha256)) deny();
  return { PK: { S: `OWNER_BOOTSTRAP#${approvalSha256}` }, SK: { S: 'META' } };
}
export function ownerRenewalLatchKey(approvalSha256) {
  if (!HASH.test(approvalSha256)) deny();
  return { PK: { S: `OWNER_RENEWAL#${approvalSha256}` }, SK: { S: 'META' } };
}

export function createCloudOwnerBootstrap({ getItem, transactWrite, tableName, digest, identityEnvelope, profile,
  loadApproval, approvalSha256, ringTokenClient, clock = Date.now } = {}) {
  if (typeof getItem !== 'function' || typeof transactWrite !== 'function' || typeof digest !== 'function' ||
      typeof identityEnvelope?.seal !== 'function' || typeof loadApproval !== 'function' || typeof ringTokenClient?.getAccountId !== 'function' ||
      typeof clock !== 'function' || typeof tableName !== 'string' || !/^[A-Za-z0-9_.-]{3,255}$/u.test(tableName) ||
      !HASH.test(approvalSha256) || !Array.isArray(profile?.scopes) || !profile.scopes.length ||
      typeof profile.issuer !== 'string' || typeof profile.resource !== 'string') deny('owner_bootstrap_config');
  const time = () => { const n = clock(); if (!Number.isSafeInteger(n) || n < 1) deny('owner_bootstrap_clock'); return n; };

  // Pinned approval bytes -> plain JSON object (exact keys are checked by the caller for its own schema).
  async function pinnedApproval(prefix) {
    let approvalBytes;
    try { approvalBytes = await loadApproval(); } catch { deny(`${prefix}_approval_denied`); }
    if (!Buffer.isBuffer(approvalBytes) || approvalBytes.length < 2 || approvalBytes.length > 16384 ||
        associationSha256(approvalBytes) !== approvalSha256) deny(`${prefix}_approval_denied`);
    let a;
    try { a = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(approvalBytes)); } catch { deny(`${prefix}_approval_denied`); }
    if (!a || typeof a !== 'object' || Array.isArray(a)) deny(`${prefix}_approval_denied`);
    return a;
  }

  // Budget: only failures AFTER the approved Cognito subject, approval hash and window were verified AND that are definite rejections
  // count. Timeouts, network errors, Ring 5xx/429, unexpected shapes, Cognito expiry and store errors never count.
  // One counter row per approval hash (bootstrap and renewal approvals always have different hashes).
  async function openBudget(prefix) {
    const attempts = ownerBootstrapAttemptsKey(approvalSha256);
    let counter;
    try { counter = await getItem({ TableName: tableName, Key: attempts, ConsistentRead: true }); } catch { deny(`${prefix}_read_denied`); }
    const nowSeconds = Math.floor(time() / 1000);
    let failures = 0;
    if (counter?.Item) {
      const expiresAtSeconds = Number(counter.Item.expires_at?.N);
      failures = Number(counter.Item.failures?.N);
      if (!Number.isSafeInteger(expiresAtSeconds) || !Number.isSafeInteger(failures) || failures < 0) deny(`${prefix}_locked`); // malformed row fails closed
      if (expiresAtSeconds <= nowSeconds) failures = 0; // TTL deletion lags: an expired row is treated as absent
    }
    if (failures >= OWNER_BOOTSTRAP_MAX_FAILURES) deny(`${prefix}_locked`);
    return async function recordFailure() {
      const expires = { ':exp': { N: String(Math.floor((time() + ATTEMPTS_TTL_MS) / 1000)) }, ':now': { N: String(nowSeconds) } };
      const update = failures === 0
        ? { UpdateExpression: 'SET failures = :one, expires_at = :exp', ConditionExpression: 'attribute_not_exists(failures) OR expires_at <= :now',
          ExpressionAttributeValues: { ...expires, ':one': { N: '1' } } }
        : { UpdateExpression: 'ADD failures :one SET expires_at = :exp', ConditionExpression: 'failures < :max AND expires_at > :now',
          ExpressionAttributeValues: { ...expires, ':one': { N: '1' }, ':max': { N: String(OWNER_BOOTSTRAP_MAX_FAILURES) } } };
      try { await transactWrite({ TransactItems: [{ Update: { TableName: tableName, Key: attempts, ...update } }] }); } catch { /* best effort; the denial stands */ }
    };
  }

  // The Ring account is whatever Ring says owns the presented sandbox token; it must hash to the pin (constant time, before any other use).
  async function ringAccountFor(ringAccessToken, pin, prefix, countedDeny) {
    let accountId;
    try { accountId = await ringTokenClient.getAccountId(ringAccessToken); }
    catch (error) { if (error?.message === 'ring_token_rejected') countedDeny(`${prefix}_ring_rejected`); deny(`${prefix}_ring_denied`); }
    if (typeof accountId !== 'string' || accountId.length < 1 || accountId.length > 256) countedDeny(`${prefix}_ring_denied`);
    const actual = createHash('sha256').update(accountId).digest();
    if (!timingSafeEqual(actual, Buffer.from(pin, 'hex'))) countedDeny(`${prefix}_ring_denied`);
    return accountId;
  }

  const tokenMarker = (ringAccessToken, at) => ({ Put: { TableName: tableName, ConditionExpression: 'attribute_not_exists(PK)', Item: {
    ...ringTokenMarkerKey(createHash('sha256').update(ringAccessToken).digest('hex')), schema: { S: 'ring-token-replay-marker-v1' },
    expires_at: { N: String(Math.floor((at + TOKEN_MARKER_TTL_MS) / 1000)) } } } });

  async function bootstrap({ login, actor, ringAccessToken }) {
    // (3) pinned approval bytes
    const a = await pinnedApproval('owner_bootstrap');
    if (!exactKeys(a, APPROVAL_KEYS)) deny('owner_bootstrap_approval_denied');
    // (4) subject binding, window, shape
    const checkedAt = time();
    if (a.schema !== OWNER_BOOTSTRAP_APPROVAL_SCHEMA || a.issuer !== profile.issuer || a.resource !== profile.resource ||
        a.cognitoSub !== actor.subject || typeof a.ringAccountIdSha256 !== 'string' || !HASH.test(a.ringAccountIdSha256) || !REF.test(a.ownerRef) || !REF.test(a.actorRef) || !REF.test(a.householdRef) ||
        !windowOk(a, checkedAt) || !refList(a.ringScopeRefs) || !sameSet(a.scopes, profile.scopes)) deny('owner_bootstrap_approval_denied');
    const recordFailure = await openBudget('owner_bootstrap');
    let counted = false;
    const countedDeny = code => { counted = true; deny(code); };
    try {
    // (5) Ring account must hash to the pin
    const accountId = await ringAccountFor(ringAccessToken, a.ringAccountIdSha256, 'owner_bootstrap', countedDeny);
    const accountDigest = await digest('ring-account', accountId);
    if (!HASH.test(accountDigest)) deny('owner_bootstrap_ring_denied');
    const subjectDigest = await digest('oauth-subject', `${profile.issuer}\0${actor.subject}`);
    // (6) same item set as the installer, create/create at revision 0 -> 1, epoch 1, generation 1
    const approval = { ownerRef: a.ownerRef, actorRef: a.actorRef, householdRef: a.householdRef, ownerMode: 'create', accountMode: 'create',
      expectedRevision: 0, revision: 1, ownerEpoch: 1, accountGeneration: 1, ringScopeRefs: a.ringScopeRefs, expiresAt: a.expiresAt };
    const envelope = await identityEnvelope.seal(accountId, { accountDigest, ownerRef: a.ownerRef, ownerEpoch: 1, accountGeneration: 1 });
    const sealedAt = time();
    if (sealedAt >= Math.min(login.expiresAtMs, a.expiresAt, a.notAfter)) deny('owner_bootstrap_expired');
    const items = buildOwnerAssociationItems({ tableName, profile, approval, subjectDigest, accountDigest, envelope, approvalSha256 });
    // Readers ignore unknown attributes; this records where the Ring account binding came from.
    for (const item of items) { const body = item.Put; if (body) body.Item.identity_source = { S: IDENTITY_SOURCE }; }
    // (7) single-use latch in the same transaction; it is never deleted by revocation of the owner (and has no expires_at, so no TTL)
    const latch = { Put: { TableName: tableName, ConditionExpression: 'attribute_not_exists(PK)', Item: {
      ...ownerBootstrapLatchKey(approvalSha256), schema: { S: BOOTSTRAP_LATCH_SCHEMA }, approval_sha256: { S: approvalSha256 },
      owner_ref: { S: a.ownerRef }, subject_digest: { S: subjectDigest }, account_digest: { S: accountDigest }, identity_source: { S: IDENTITY_SOURCE },
      created_at_ms: { N: String(sealedAt) } } } };
    // replay marker: only the hash of the Ring token is stored; the conditional Put makes a token single use
    let outcome;
    try { outcome = await transactWrite({ TransactItems: [...items, latch, tokenMarker(ringAccessToken, sealedAt)] }); } catch { deny('owner_bootstrap_write_denied'); }
    if (!outcome || typeof outcome !== 'object') deny('owner_bootstrap_outcome_unknown');
    return Object.freeze({ bootstrapped: true, associationRevision: 1 });
    } catch (error) { if (counted) await recordFailure(); throw error; }
  }

  // Renewal. Anchor = the bootstrap latch OWNER_BOOTSTRAP#<bootstrapApprovalSha256> (written once by bootstrap, no expires_at, never
  // TTL-deleted). It records the subject digest, the Ring account digest and the ownerRef of the ORIGINAL binding; renewal accepts
  // only that exact triple, so it can never add or swap a subject or a Ring account. The association/account rows carry expires_at,
  // which is also the link table's TTL attribute: after expiry DynamoDB may delete them at any time. Each of the two rows is therefore
  // handled on its own: present -> every identity field must equal the approval/anchor and only expires_at moves forward (conditional
  // Update on the exact previous value); absent -> re-created byte-identically to bootstrap (shared builder, attribute_not_exists) at the
  // approval's pinned revision/epoch/generation. OWNER#CURRENT is only condition-checked (never written).
  async function renew({ login, actor, ringAccessToken, owner }) {
    const a = await pinnedApproval('owner_renewal');
    if (!exactKeys(a, RENEWAL_KEYS)) deny('owner_renewal_approval_denied');
    const checkedAt = time();
    if (a.schema !== OWNER_RENEWAL_APPROVAL_SCHEMA || a.mode !== 'renew' || a.issuer !== profile.issuer || a.resource !== profile.resource ||
        a.cognitoSub !== actor.subject || typeof a.ringAccountIdSha256 !== 'string' || !HASH.test(a.ringAccountIdSha256) ||
        typeof a.bootstrapApprovalSha256 !== 'string' || !HASH.test(a.bootstrapApprovalSha256) ||
        !REF.test(a.ownerRef) || !safeInt(a.ownerEpoch) || !safeInt(a.associationRevision) || !safeInt(a.accountGeneration) ||
        !windowOk(a, checkedAt) || !refList(a.ringScopeRefs) || !sameSet(a.scopes, profile.scopes)) deny('owner_renewal_approval_denied');
    // Bootstrap only ever writes ownerEpoch 1 / revision 1 / generation 1; a binding later changed by the operator installer is not
    // described by the anchor latch and cannot be renewed here.
    if (a.ownerEpoch !== 1 || a.associationRevision !== 1 || a.accountGeneration !== 1) deny('owner_renewal_approval_denied');
    // current owner: ACTIVE, same ownerRef and epoch
    if (owner.status?.S !== 'ACTIVE' || owner.owner_ref?.S !== a.ownerRef || owner.owner_epoch?.N !== String(a.ownerEpoch)) deny('owner_renewal_owner_denied');
    const subjectDigest = await digest('oauth-subject', `${profile.issuer}\0${actor.subject}`);
    if (!HASH.test(subjectDigest)) deny('owner_renewal_approval_denied');
    const read = async Key => { try { return (await getItem({ TableName: tableName, Key, ConsistentRead: true }))?.Item; } catch { deny('owner_renewal_read_denied'); } };
    // The anchor is looked up BY bootstrapApprovalSha256, must carry the same approval_sha256, and is condition-checked again in the write.
    const anchorKey = ownerBootstrapLatchKey(a.bootstrapApprovalSha256);
    const anchor = await read(anchorKey);
    if (!anchor || anchor.schema?.S !== BOOTSTRAP_LATCH_SCHEMA || anchor.approval_sha256?.S !== a.bootstrapApprovalSha256 || anchor.owner_ref?.S !== a.ownerRef ||
        anchor.subject_digest?.S !== subjectDigest || !HASH.test(anchor.account_digest?.S ?? '')) deny('owner_renewal_anchor_denied');
    const accountDigest = anchor.account_digest.S;
    const newExpires = Math.floor(a.expiresAt / 1000);
    const associationKey = cloudAssociationKey(subjectDigest);
    const association = await read(associationKey);
    const associationPrevious = association ? seconds(association.expires_at) : null;
    if (association && (association.schema?.S !== 'ring-cloud-owner-association-v1' || association.subject_digest?.S !== subjectDigest ||
        association.issuer?.S !== profile.issuer || association.resource?.S !== profile.resource || association.owner_ref?.S !== a.ownerRef ||
        association.owner_epoch?.N !== String(a.ownerEpoch) || association.revision?.N !== String(a.associationRevision) ||
        association.account_digest?.S !== accountDigest || association.account_generation?.N !== String(a.accountGeneration) ||
        association.revoked?.BOOL !== false || !sameSet(association.ring_scope_refs?.L?.map(s => s.S), a.ringScopeRefs) ||
        !sameSet(association.scope_refs?.L?.map(s => s.S), profile.scopes) || associationPrevious === null || newExpires <= associationPrevious)) deny('owner_renewal_association_denied');
    const accountKey = { PK: { S: `ACCOUNT#${accountDigest}` }, SK: { S: 'IDENTITY' } };
    const account = await read(accountKey);
    const accountPrevious = account ? seconds(account.expires_at) : null;
    if (account && (account.account_digest?.S !== accountDigest || account.owner_ref?.S !== a.ownerRef || account.owner_epoch?.N !== String(a.ownerEpoch) ||
        account.account_generation?.N !== String(a.accountGeneration) || account.revoked?.BOOL !== false ||
        accountPrevious === null || newExpires <= accountPrevious)) deny('owner_renewal_account_denied');
    const recordFailure = await openBudget('owner_renewal');
    let counted = false;
    const countedDeny = code => { counted = true; deny(code); };
    try {
    const accountId = await ringAccountFor(ringAccessToken, a.ringAccountIdSha256, 'owner_renewal', countedDeny);
    const actualDigest = await digest('ring-account', accountId);
    if (!HASH.test(actualDigest)) deny('owner_renewal_ring_denied');
    // The pinned id must be the SAME Ring account that bootstrap bound (anchor); a pin for any other account is a definite rejection.
    if (!timingSafeEqual(Buffer.from(actualDigest, 'hex'), Buffer.from(accountDigest, 'hex'))) countedDeny('owner_renewal_ring_denied');
    const fields = { ownerRef: a.ownerRef, ownerEpoch: a.ownerEpoch, accountGeneration: a.accountGeneration };
    // A sealed envelope is only needed when a row has to be re-created after TTL deletion.
    const envelope = association && account ? null : await identityEnvelope.seal(accountId, { accountDigest, ...fields });
    const renewedAt = time();
    if (renewedAt >= Math.min(login.expiresAtMs, a.expiresAt, a.notAfter)) deny('owner_renewal_expired');
    // Shared builder (same bytes as bootstrap/installer). Only its association Put [1] and account Put [2] are used; the owner entry [0]
    // is replaced by ownerCheck below, so actorRef/householdRef are never written (placeholders only satisfy the builder's shape).
    const rebuilt = envelope && buildOwnerAssociationItems({ tableName, profile, subjectDigest, accountDigest, envelope, approvalSha256, approval: {
      ...fields, actorRef: 'unused/actor', householdRef: 'unused/household', ownerMode: 'existing', accountMode: 'create', expectedRevision: 0,
      revision: a.associationRevision, ringScopeRefs: a.ringScopeRefs, expiresAt: a.expiresAt } });
    if (rebuilt) for (const item of rebuilt) { const body = item.Put; if (body) body.Item.identity_source = { S: IDENTITY_SOURCE }; }
    const v = { owner: { S: a.ownerRef }, epoch: { N: String(a.ownerEpoch) }, generation: { N: String(a.accountGeneration) }, account: { S: accountDigest },
      subject: { S: subjectDigest }, expires: { N: String(newExpires) } };
    const ownerCheck = { ConditionCheck: { TableName: tableName, Key: { PK: { S: 'OWNER#CURRENT' }, SK: { S: 'META' } },
      ConditionExpression: '#state = :active AND owner_ref = :owner AND owner_epoch = :epoch', ExpressionAttributeNames: { '#state': 'status' },
      ExpressionAttributeValues: { ':active': { S: 'ACTIVE' }, ':owner': v.owner, ':epoch': v.epoch } } };
    const anchorCheck = { ConditionCheck: { TableName: tableName, Key: anchorKey,
      ConditionExpression: 'approval_sha256 = :bootstrap AND owner_ref = :owner AND subject_digest = :subject AND account_digest = :account',
      ExpressionAttributeValues: { ':bootstrap': { S: a.bootstrapApprovalSha256 }, ':owner': v.owner, ':subject': v.subject, ':account': v.account } } };
    const associationWrite = association
      ? { Update: { TableName: tableName, Key: associationKey, UpdateExpression: 'SET expires_at = :expires, approval_evidence_sha256 = :evidence',
        ConditionExpression: '#schema = :schema AND #issuer = :issuer AND #resource = :resource AND subject_digest = :subject AND owner_ref = :owner AND owner_epoch = :epoch AND revision = :revision AND account_digest = :account AND account_generation = :generation AND revoked = :false AND expires_at = :previous',
        ExpressionAttributeNames: { '#schema': 'schema', '#issuer': 'issuer', '#resource': 'resource' },
        ExpressionAttributeValues: { ':schema': { S: 'ring-cloud-owner-association-v1' }, ':issuer': { S: profile.issuer }, ':resource': { S: profile.resource }, ':expires': v.expires, ':evidence': { S: approvalSha256 }, ':subject': v.subject, ':owner': v.owner, ':epoch': v.epoch,
          ':revision': { N: String(a.associationRevision) }, ':account': v.account, ':generation': v.generation, ':false': { BOOL: false }, ':previous': { N: String(associationPrevious) } } } }
      : rebuilt[1];
    const accountWrite = account
      ? { Update: { TableName: tableName, Key: accountKey, UpdateExpression: 'SET expires_at = :expires',
        ConditionExpression: 'account_digest = :account AND owner_ref = :owner AND owner_epoch = :epoch AND account_generation = :generation AND revoked = :false AND expires_at = :previous',
        ExpressionAttributeValues: { ':expires': v.expires, ':account': v.account, ':owner': v.owner, ':epoch': v.epoch, ':generation': v.generation,
          ':false': { BOOL: false }, ':previous': { N: String(accountPrevious) } } } }
      : rebuilt[2];
    // single-use renewal latch (no expires_at -> never TTL-deleted)
    const latch = { Put: { TableName: tableName, ConditionExpression: 'attribute_not_exists(PK)', Item: {
      ...ownerRenewalLatchKey(approvalSha256), schema: { S: 'ring-owner-renewal-latch-v1' }, approval_sha256: { S: approvalSha256 },
      bootstrap_approval_sha256: { S: a.bootstrapApprovalSha256 }, owner_ref: { S: a.ownerRef }, subject_digest: { S: subjectDigest },
      account_digest: { S: accountDigest }, association_revision: { N: String(a.associationRevision) }, owner_epoch: { N: String(a.ownerEpoch) },
      account_generation: { N: String(a.accountGeneration) }, ring_scope_refs: { L: a.ringScopeRefs.map(S => ({ S })) }, renewed_until_ms: { N: String(newExpires * 1000) },
      association_action: { S: association ? 'extended' : 'recreated' }, account_action: { S: account ? 'extended' : 'recreated' },
      identity_source: { S: IDENTITY_SOURCE }, created_at_ms: { N: String(renewedAt) } } } };
    let outcome;
    try { outcome = await transactWrite({ TransactItems: [ownerCheck, anchorCheck, associationWrite, accountWrite, latch, tokenMarker(ringAccessToken, renewedAt)] }); }
    catch { deny('owner_renewal_write_denied'); }
    if (!outcome || typeof outcome !== 'object') deny('owner_renewal_outcome_unknown');
    return Object.freeze({ renewed: true, associationRevision: a.associationRevision });
    } catch (error) { if (counted) await recordFailure(); throw error; }
  }

  return Object.freeze({ async ensureWithRingToken({ request, actor, ringAccessToken }) {
    if (typeof ringAccessToken !== 'string' || !RING_ACCESS_TOKEN_PATTERN.test(ringAccessToken)) deny('owner_bootstrap_token_denied');
    // (1) same verified-login checks as the installer (issuer, resource, exact scopes, live lifetime)
    const login = lookupFormalVerifiedLogin({ request, actor });
    const now = time();
    if (!login || login.issuer !== profile.issuer || login.resource !== profile.resource || login.expiresAtMs <= now ||
        login.issuedAtMs > now || !sameSet(login.scopes, profile.scopes) || typeof actor?.subject !== 'string' ||
        !actor.subject || actor.subject.length > 256) deny('owner_bootstrap_login_denied');
    // (2) strongly consistent read: the presence of an owner selects renewal, its absence bootstrap
    let existing;
    try { existing = await getItem({ TableName: tableName, Key: { PK: { S: 'OWNER#CURRENT' }, SK: { S: 'META' } }, ConsistentRead: true }); } catch { deny('owner_bootstrap_read_denied'); }
    if (existing?.Item) return renew({ login, actor, ringAccessToken, owner: existing.Item });
    return bootstrap({ login, actor, ringAccessToken });
  } });
}
