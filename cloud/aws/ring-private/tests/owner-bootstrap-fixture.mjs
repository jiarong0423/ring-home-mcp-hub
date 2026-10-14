// Shared fixtures for the owner-bootstrap tests. Everything here is synthetic; no network, no AWS.
import assert from 'node:assert/strict';
import { createHash, createHmac, generateKeyPairSync, sign } from 'node:crypto';
import { createFormalRequestAuthorizationPolicy } from '../../../../src/formal-runtime/request-authorization-policy.mjs';
import { createCognitoResourceBoundAccessTokenVerifier } from '../../../../src/local_ring/components/oidc-jwt-verifier.mjs';

export const NOW = 1791800000000;
export const ISS = 'https://cognito-idp.ap-southeast-1.amazonaws.com/fixture';
export const RESOURCE = 'https://fixture.example/staging/mcp';
export const SCOPES = Object.freeze(['fixture.read']);
export const CLIENT_ID = 'fixtureclient';
export const SUB = 'fixture-owner';
export const ACCOUNT_ID = 'ring-account-id-SECRET';
export const ACCESS_TOKEN = 'ring-access-token-SECRET';
export const REFRESH_TOKEN = 'ring-refresh-token-SECRET';
export const PROFILE = Object.freeze({ issuer: ISS, resource: RESOURCE, scopes: SCOPES });
export const CONFIG = Object.freeze({ domain: 'https://fixture.auth.ap-southeast-1.amazoncognito.com',
  callbackUri: 'https://fixture.example/staging/auth/callback', logoutUri: 'https://fixture.example/staging/auth/logout',
  resource: RESOURCE, clientId: CLIENT_ID, scopes: SCOPES, stage: 'staging' });
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const digest = async (purpose, source) => createHmac('sha256', 'fixture-record-hmac-key-0123456789').update(`${purpose}\0${source}`).digest('hex');
export const sealed = Object.freeze({ version: 1, purpose: 'RING_ACCOUNT_IDENTIFIER', keyId: 'fixture-key', encryptedDataKey: 'ZWRr', nonce: 'bm9uY2U', authTag: 'dGFn', ciphertext: 'Y3Q' });
export const identityEnvelope = Object.freeze({ calls: [], async seal(accountIdentifier, binding) { identityEnvelope.calls.push({ binding }); return sealed; } });

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'fixturekey', use: 'sig', alg: 'RS256' };

export function jwt(overrides = {}, clockMs = NOW) {
  const h = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'fixturekey', typ: 'JWT' })).toString('base64url');
  const p = Buffer.from(JSON.stringify({ iss: ISS, sub: SUB, token_use: 'access', client_id: CLIENT_ID, aud: RESOURCE,
    scope: SCOPES.join(' '), iat: clockMs / 1000, exp: clockMs / 1000 + 300, ...overrides })).toString('base64url');
  return `${h}.${p}.${sign('RSA-SHA256', Buffer.from(`${h}.${p}`), privateKey).toString('base64url')}`;
}

// A transport that mirrors the real one's contract: evidence only resolves for a request that was bound.
export function createAuth({ clock = () => NOW } = {}) {
  const bound = new WeakSet();
  const transport = { productionAdmitted: true, transportEvidenceKind: 'apigateway-rest-policy-v1',
    async prepareEvent({ event }) { return event; }, bindRequest({ request }) { bound.add(request); },
    async resolve({ request }) { assert.ok(bound.has(request)); return { productionAdmitted: true, encrypted: true, kind: 'apigateway-rest-policy-v1',
      negotiatedProtocol: null, minimumTlsVersion: 'TLSv1.2', evidenceId: 'fixture.gateway', rootDecisionSha256: 'a'.repeat(64), deploymentEvidenceSha256: 'b'.repeat(64) }; } };
  const verifier = createCognitoResourceBoundAccessTokenVerifier({ issuer: ISS, clientId: CLIENT_ID, resource: RESOURCE, requiredScopes: SCOPES,
    jwksUri: ISS + '/.well-known/jwks.json', maxJwksAgeSeconds: 300, maximumTokenLifetimeSeconds: 300, clock: () => clock() / 1000,
    loadPinnedJwks: async () => ({ jwksUri: ISS + '/.well-known/jwks.json', snapshotVersion: 1, fetchedAtSeconds: NOW / 1000, expiresAtSeconds: NOW / 1000 + 300, keys: [jwk] }) });
  const policy = createFormalRequestAuthorizationPolicy({ accessTokenVerifier: verifier, trustedTransportEvidencePort: transport,
    resource: RESOURCE, authorizationServer: ISS, scopes: SCOPES });
  return { transport, policy, async login(overrides = {}) {
    const request = Object.freeze({ method: 'POST', path: '/auth/session', headers: Object.freeze({ authorization: 'Bearer ' + jwt(overrides, NOW) }) });
    transport.bindRequest({ request });
    const { actor } = await policy.authorize({ request });
    return { request, actor };
  } };
}

// ---- in-memory DynamoDB with all-or-nothing transactions and a tiny condition evaluator ----
const pk = key => `${key.PK?.S}\u0000${key.SK?.S}`;
function scalar(value) { return value === undefined ? undefined : value.N !== undefined ? Number(value.N) : value.S ?? value.BOOL; }
function holds(expression, item, names = {}, values = {}) {
  if (expression === undefined) return true;
  if (/\s+OR\s+/u.test(expression)) return expression.split(/\s+OR\s+/u).some(part => holds(part, item, names, values));
  return expression.split(/\s+AND\s+/u).every(term => {
    let m = /^attribute_not_exists\((#?\w+)\)$/u.exec(term);
    if (m) return item === undefined || item[names[m[1]] ?? m[1]] === undefined;
    m = /^attribute_exists\((#?\w+)\)$/u.exec(term);
    if (m) return item !== undefined && item[names[m[1]] ?? m[1]] !== undefined;
    m = /^(#?\w+) (=|>=|<=|>|<) (:\w+)$/u.exec(term);
    if (!m) throw new Error('unsupported fixture condition: ' + term);
    const left = scalar(item?.[names[m[1]] ?? m[1]]), right = scalar(values[m[3]]);
    if (left === undefined || right === undefined) return false;
    return m[2] === '=' ? left === right : m[2] === '>=' ? left >= right : m[2] === '<=' ? left <= right : m[2] === '>' ? left > right : left < right;
  });
}
export function createFakeTable() {
  const items = new Map();
  const table = { items, transactions: [], getCalls: [], failWith: null,
    get(PK, SK) { return items.get(pk({ PK: { S: PK }, SK: { S: SK } })); },
    async getItem(input) { table.getCalls.push(input); return { Item: structuredClone(items.get(pk(input.Key))) }; },
    async transactGet({ TransactItems }) { return { Responses: TransactItems.map(i => ({ Item: structuredClone(items.get(pk(i.Get.Key))) })) }; },
    async transactWrite({ TransactItems }) {
      table.transactions.push(structuredClone(TransactItems));
      if (table.failWith) throw table.failWith;
      for (const op of TransactItems) {
        const body = op.Put ?? op.ConditionCheck ?? op.Update ?? op.Delete;
        const key = op.Put ? op.Put.Item : body.Key;
        if (!holds(body.ConditionExpression, items.get(pk(key)), body.ExpressionAttributeNames, body.ExpressionAttributeValues)) {
          throw Object.assign(new Error('conditional'), { name: 'ConditionalCheckFailedException' });
        }
      }
      for (const op of TransactItems) if (op.Put) items.set(pk(op.Put.Item), structuredClone(op.Put.Item));
      for (const op of TransactItems) if (op.Update) {
        const expr = op.Update.UpdateExpression;
        const values = op.Update.ExpressionAttributeValues;
        const key = pk(op.Update.Key);
        const item = items.get(key) ?? structuredClone(op.Update.Key);
        const add = /ADD (\w+) (:\w+)/u.exec(expr);
        const set = /SET (.+)$/u.exec(expr);
        if (!add && !set) throw new Error('unsupported fixture update: ' + expr);
        if (add) item[add[1]] = { N: String(Number(item[add[1]]?.N ?? 0) + Number(values[add[2]].N)) };
        if (set) for (const part of set[1].split(',')) {
          const m = /^\s*(\w+) = (:\w+)\s*$/u.exec(part);
          if (!m) throw new Error('unsupported fixture update: ' + expr);
          item[m[1]] = structuredClone(values[m[2]]);
        }
        items.set(key, item);
      }
      return {};
    } };
  table.ports = { getItem: table.getItem, transactGet: table.transactGet, transactWrite: table.transactWrite };
  table.writeCount = () => table.transactions.length;
  return table;
}

export function approvalFixture(overrides = {}) {
  const approval = { schema: 'ring-owner-bootstrap-approval-v1', issuer: ISS, resource: RESOURCE, cognitoSub: SUB, ringAccountIdSha256: sha256(ACCOUNT_ID),
    ownerRef: 'owner/fixture', actorRef: 'actor/fixture', householdRef: 'household/fixture',
    ringScopeRefs: ['ring.read', 'ring.link'], scopes: [...SCOPES], issuedAt: NOW - 60000, notAfter: NOW + 3600000, expiresAt: NOW + 7200000, ...overrides };
  const bytes = Buffer.from(JSON.stringify(approval));
  return { approval, bytes, sha: sha256(bytes) };
}
