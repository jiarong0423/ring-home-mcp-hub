import { createHash } from 'node:crypto';

const verifiedLoginRequests = new WeakMap();
export function lookupFormalVerifiedLogin({ request, actor }) {
  const evidence = verifiedLoginRequests.get(request);
  return evidence?.actor === actor ? evidence : null;
}

function fail(status, code, message) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  return error;
}

function exactFormalObject(value, allowed, required, code, status = 503) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) {
    throw fail(status, code, code);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some(key => typeof key !== 'string' || !allowed.includes(key)) ||
      required.some(key => !Object.hasOwn(value, key))) {
    throw fail(status, code, code);
  }
  const copy = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw fail(status, code, code);
    copy[key] = descriptor.value;
  }
  return copy;
}

function exactHttpsUri(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 1024 ||
      /[\u0000-\u001f\u007f]/u.test(value)) return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'https:' && parsed.username === '' && parsed.password === '' &&
      parsed.hash === '' && parsed.toString() === value;
  } catch { return false; }
}

function exactScopeList(value) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype ||
      value.length < 1 || value.length > 32) return null;
  const scopes = [];
  for (let index = 0; index < value.length; index++) {
    if (!Object.hasOwn(value, index) || typeof value[index] !== 'string' ||
        value[index].length > 128 || !/^[\x21\x23-\x5B\x5D-\x7E]+$/u.test(value[index])) return null;
    scopes.push(value[index]);
  }
  if (new Set(scopes).size !== scopes.length || Reflect.ownKeys(value).length !== value.length + 1) return null;
  return scopes;
}

export function createFormalRequestAuthorizationPolicy({ accessTokenVerifier,
  trustedTransportEvidencePort, resource, authorizationServer, scopes }) {
  const fixedScopes = exactScopeList(scopes);
  if (!accessTokenVerifier || typeof accessTokenVerifier.verifyAccessToken !== 'function' ||
      !trustedTransportEvidencePort || trustedTransportEvidencePort.productionAdmitted !== true ||
      typeof trustedTransportEvidencePort.resolve !== 'function' || !exactHttpsUri(resource) ||
      !exactHttpsUri(authorizationServer) || fixedScopes === null) {
    throw new Error('B02_FORMAL_AUTHORIZATION_POLICY_DENIED');
  }
  const metadata = Object.freeze({ resource,
    authorization_servers: Object.freeze([authorizationServer]),
    scopes_supported: Object.freeze([...fixedScopes]),
    bearer_methods_supported: Object.freeze(['header']) });
  const trustedTransport = async request => {
    if (!request || request.headers === null || typeof request.headers !== 'object' ||
        Array.isArray(request.headers)) {
      throw fail(403, 'B02_FORMAL_TLS_EVIDENCE_DENIED', 'Trusted TLS evidence required');
    }
    const headerNames = Reflect.ownKeys(request.headers).map(name =>
      typeof name === 'string' ? name.toLowerCase() : '');
    if (headerNames.some(name => ['forwarded', 'x-forwarded-for', 'x-forwarded-host',
      'x-forwarded-port', 'x-forwarded-proto'].includes(name))) {
      throw fail(403, 'B02_FORMAL_FORWARDED_HEADER_DENIED', 'Forwarded transport claims are denied');
    }
    let untrusted;
    try { untrusted = await trustedTransportEvidencePort.resolve({ request }); }
    catch { throw fail(403, 'B02_FORMAL_TLS_EVIDENCE_DENIED', 'Trusted TLS evidence required'); }
    if (trustedTransportEvidencePort.transportEvidenceKind === 'apigateway-rest-policy-v1') {
      const evidence = exactFormalObject(untrusted,
        ['productionAdmitted', 'encrypted', 'kind', 'negotiatedProtocol', 'minimumTlsVersion',
          'evidenceId', 'rootDecisionSha256', 'deploymentEvidenceSha256'],
        ['productionAdmitted', 'encrypted', 'kind', 'negotiatedProtocol', 'minimumTlsVersion',
          'evidenceId', 'rootDecisionSha256', 'deploymentEvidenceSha256'],
        'B02_FORMAL_TLS_EVIDENCE_DENIED', 403);
      if (evidence.productionAdmitted !== true || evidence.encrypted !== true ||
          evidence.kind !== 'apigateway-rest-policy-v1' || evidence.negotiatedProtocol !== null ||
          !['TLSv1.2', 'TLSv1.3'].includes(evidence.minimumTlsVersion) ||
          typeof evidence.evidenceId !== 'string' || !/^[A-Za-z0-9._:-]{1,128}$/u.test(evidence.evidenceId) ||
          typeof evidence.rootDecisionSha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(evidence.rootDecisionSha256) ||
          typeof evidence.deploymentEvidenceSha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(evidence.deploymentEvidenceSha256)) {
        throw fail(403, 'B02_FORMAL_TLS_EVIDENCE_DENIED', 'Admitted gateway policy evidence required');
      }
      return Object.freeze({ kind: evidence.kind, negotiatedProtocol: null,
        minimumTlsVersion: evidence.minimumTlsVersion, evidenceId: evidence.evidenceId });
    }
    const evidence = exactFormalObject(untrusted,
      ['productionAdmitted', 'encrypted', 'protocol', 'evidenceId'],
      ['productionAdmitted', 'encrypted', 'protocol', 'evidenceId'],
      'B02_FORMAL_TLS_EVIDENCE_DENIED', 403);
    if (evidence.productionAdmitted !== true || evidence.encrypted !== true ||
        !['TLSv1.2', 'TLSv1.3'].includes(evidence.protocol) ||
        typeof evidence.evidenceId !== 'string' ||
        !/^[A-Za-z0-9._:-]{1,128}$/u.test(evidence.evidenceId)) {
      throw fail(403, 'B02_FORMAL_TLS_EVIDENCE_DENIED', 'Trusted TLS evidence required');
    }
    return Object.freeze({ protocol: evidence.protocol, evidenceId: evidence.evidenceId });
  };
  const authorize = async ({ request }) => {
    verifiedLoginRequests.delete(request);
    const transport = await trustedTransport(request);
    const header = request.headers.authorization;
    if (typeof header !== 'string' || !/^Bearer [A-Za-z0-9._-]{3,16384}$/u.test(header)) {
      throw fail(401, 'B02_FORMAL_ACCESS_TOKEN_REQUIRED', 'Bearer access token required');
    }
    let claims;
    try { claims = await accessTokenVerifier.verifyAccessToken({ accessToken: header.slice(7) }); }
    catch { throw fail(401, 'B02_FORMAL_ACCESS_TOKEN_DENIED', 'Access token denied'); }
    const verified = exactFormalObject(claims,
      ['verified', 'tokenUse', 'sub', 'iss', 'aud', 'resource', 'scope', 'exp', 'iat'],
      ['verified', 'tokenUse', 'sub', 'iss', 'aud', 'resource', 'scope', 'exp', 'iat'],
      'B02_FORMAL_ACCESS_TOKEN_DENIED', 401);
    const grantedScopes = exactScopeList(verified.scope);
    if (verified.verified !== true || verified.tokenUse !== 'access' ||
        typeof verified.sub !== 'string' || verified.sub.length === 0 || verified.sub.length > 256 ||
        verified.resource !== resource || grantedScopes === null ||
        fixedScopes.length !== grantedScopes.length ||
        [...fixedScopes].sort().some((scope, index) => scope !== [...grantedScopes].sort()[index])) {
      throw fail(401, 'B02_FORMAL_ACCESS_TOKEN_DENIED', 'Access token denied');
    }
    const actor = Object.freeze({ authority: 'oauth-access-token', subject: verified.sub,
      resource: verified.resource, scopes: Object.freeze([...grantedScopes]) });
    if (verified.iss === authorizationServer && verified.aud === resource &&
        Number.isSafeInteger(verified.iat) && verified.iat >= 0 &&
        Number.isSafeInteger(verified.exp) && verified.exp > verified.iat &&
        verified.exp - verified.iat <= 300 && Number.isSafeInteger(verified.exp * 1000)) {
      verifiedLoginRequests.set(request, Object.freeze({ actor, issuer: verified.iss,
        resource, scopes: actor.scopes, issuedAtMs: verified.iat * 1000,
        expiresAtMs: verified.exp * 1000,
        tokenDigest: createHash('sha256').update(header.slice(7)).digest('hex') }));
    }
    return Object.freeze({ actor, transport });
  };
  const protectedResourceMetadata = async ({ request }) => {
    await trustedTransport(request);
    return metadata;
  };
  return Object.freeze({ productionAdmitted: true, authorize, protectedResourceMetadata });
}

