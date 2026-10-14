import { macPublicKey, verifyMacProof, MAC_PROOF_HEADER } from '../../../src/formal-runtime/mac-command-proof.mjs';
import { COMMAND_TABLE, hash, port, record, text, time, deny, freeze } from '../../../src/formal-runtime/mac-command-contract.mjs';
export const macEnrollmentKey = ownerRef => 'rpl018:mac-enrollment:' + hash(text(ownerRef));
export function macEnrollmentCondition(mac, tableName, now) {
  return { ConditionCheck: { TableName: tableName, Key: { pk: { S: macEnrollmentKey(mac.ownerRef) } },
    ConditionExpression: 'key_id = :key AND revision = :revision AND association_revision = :association AND revoked = :false AND expires_ms > :now',
    ExpressionAttributeValues: { ':key': { S: mac.keyId }, ':revision': { N: String(mac.revision) }, ':association': { N: String(mac.associationRevision) }, ':false': { BOOL: false }, ':now': { N: String(now) } } } };
}
export function createMacCommandProofAuthority({ ports, tableName = COMMAND_TABLE, audience, clock = Date.now }) {
  if (tableName !== COMMAND_TABLE || typeof clock !== 'function') deny('MAC_ENROLLMENT_CONFIG');
  const aws = port(ports, ['getItem', 'transactWrite']);
  return Object.freeze({ async verify({ request, authority, operation, payload }) {
    const authorization = request?.headers?.authorization;
    if (typeof authorization !== 'string' || !authorization.startsWith('Bearer ')) deny('MAC_PROOF_REQUIRED');
    const row = (await aws.getItem({ TableName: tableName, Key: { pk: { S: macEnrollmentKey(authority.ownerRef) } }, ConsistentRead: true }))?.Item;
    const now = time(clock());
    if (!row || row.schema?.S !== 'ring-mac-enrollment-v1' || row.owner_ref?.S !== authority.ownerRef || row.revoked?.BOOL !== false ||
        Number(row.association_revision?.N) !== authority.associationRevision || !Number.isSafeInteger(Number(row.revision?.N)) || Number(row.revision.N) < 1 ||
        !Number.isSafeInteger(Number(row.expires_ms?.N)) || Number(row.expires_ms?.N) <= now || !/^[a-f0-9]{64}$/u.test(row.approval_sha256?.S ?? '')) deny('MAC_ENROLLMENT_REQUIRED');
    const claims = verifyMacProof({ header: request.headers[MAC_PROOF_HEADER], publicKeySpki: row.public_key_spki?.S,
      ownerRef: authority.ownerRef, associationRevision: authority.associationRevision, operation, audience,
      token: authorization.slice(7), payload, now });
    if (claims.keyId !== row.key_id?.S) deny('MAC_ENROLLMENT_KEY');
    const mac = freeze({ ownerRef: authority.ownerRef, associationRevision: authority.associationRevision, keyId: claims.keyId, revision: Number(row.revision.N) });
    try { await aws.transactWrite({ TransactItems: [macEnrollmentCondition(mac, tableName, time(clock())),
      { Put: { TableName: tableName, Item: { pk: { S: 'rpl018:mac-proof:' + hash(claims.keyId + ':' + claims.nonce) },
        expires_at: { N: String(Math.ceil(claims.expiresAt / 1000) + 60) } }, ConditionExpression: 'attribute_not_exists(pk)' } }
    ] }); } catch { deny('MAC_PROOF_REPLAY_OR_UNAVAILABLE'); }
    if (time(clock()) >= claims.expiresAt) deny('MAC_PROOF_EXPIRED');
    if (authority.assertCurrent() !== true) deny('MAC_COMMAND_AUTHORITY_REVOKED'); return mac;
  } });
}
export function createMacEnrollmentInstaller({ ports, tableName = COMMAND_TABLE, authorize, approvalSha256, clock = Date.now }) {
  if (tableName !== COMMAND_TABLE || typeof authorize !== 'function' || typeof approvalSha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(approvalSha256)) deny('MAC_ENROLLMENT_CONFIG');
  const aws = port(ports, ['getItem', 'transactWrite']);
  return Object.freeze({ async install({ request, actor, approvalBytes }) {
    if (!Buffer.isBuffer(approvalBytes) || approvalBytes.length > 8192 || hash(approvalBytes) !== approvalSha256) deny('MAC_ENROLLMENT_APPROVAL');
    let raw; try { raw = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(approvalBytes)); } catch { deny('MAC_ENROLLMENT_APPROVAL'); }
    const a = record(raw, ['schema', 'ownerRef', 'associationRevision', 'keyId', 'publicKeySpki', 'expectedRevision', 'revision', 'expiresAt']);
    const auth = await authorize({ request, actor }); const key = macPublicKey(a.publicKeySpki); const now = time(clock());
    if (a.schema !== 'ring-mac-enrollment-approval-v1' || a.ownerRef !== auth.ownerRef || a.associationRevision !== auth.associationRevision ||
        a.keyId !== key.keyId || !Number.isSafeInteger(a.expectedRevision) || a.expectedRevision < 0 || a.revision !== a.expectedRevision + 1 ||
        !Number.isSafeInteger(a.expiresAt) || a.expiresAt <= now || a.expiresAt > now + 86400000) deny('MAC_ENROLLMENT_APPROVAL');
    if (auth.assertCurrent() !== true) deny('MAC_COMMAND_AUTHORITY_REVOKED');
    await aws.transactWrite({ TransactItems: [{ Put: { TableName: tableName, Item: {
      pk: { S: macEnrollmentKey(a.ownerRef) }, schema: { S: 'ring-mac-enrollment-v1' }, owner_ref: { S: a.ownerRef },
      association_revision: { N: String(a.associationRevision) }, key_id: { S: key.keyId }, public_key_spki: { S: a.publicKeySpki },
      revision: { N: String(a.revision) }, expires_ms: { N: String(a.expiresAt) }, approval_sha256: { S: approvalSha256 }, revoked: { BOOL: false }
    }, ConditionExpression: a.expectedRevision === 0 ? 'attribute_not_exists(pk)' : 'revision = :expected AND owner_ref = :owner',
    ...(a.expectedRevision === 0 ? {} : { ExpressionAttributeValues: { ':expected': { N: String(a.expectedRevision) }, ':owner': { S: a.ownerRef } } }) } }] });
    if (auth.assertCurrent() !== true) deny('MAC_COMMAND_AUTHORITY_REVOKED'); return freeze({ installed: true, ownerRef: a.ownerRef, associationRevision: a.associationRevision, keyId: key.keyId, revision: a.revision });
  } });
}
