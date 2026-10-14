// Deployment constants for YOUR stack (not secrets). Set them in the environment before starting the console or the CLI:
//   RING_HUB_API_BASE        https://<api-id>.execute-api.<region>.amazonaws.com/<stage>
//   RING_HUB_COGNITO_DOMAIN  https://<domain-prefix>.auth.<region>.amazoncognito.com
//   RING_HUB_CLIENT_ID       <public PKCE app client id>
// The defaults below are syntactically valid placeholders only; nothing is contacted unless you run a cloud action.
const env = typeof process === 'object' && process.env ? process.env : {};
export const DEFAULT_CONFIG = Object.freeze({
  apiBase: env.RING_HUB_API_BASE || 'https://abcdefghij.execute-api.us-east-1.amazonaws.com/staging',
  cognitoDomain: env.RING_HUB_COGNITO_DOMAIN || 'https://your-prefix-abcdefghij.auth.us-east-1.amazoncognito.com',
  clientId: env.RING_HUB_CLIENT_ID || 'replacewithyourappclientid',
  ringApi: 'https://api.amazonvision.com'
});
export function resolveConfig(input = DEFAULT_CONFIG) {
  const apiBase = new URL(input.apiBase);
  if (apiBase.protocol !== 'https:' || !/^[a-z0-9]{10}\.execute-api\.[a-z0-9-]+\.amazonaws\.com$/u.test(apiBase.hostname) ||
      !/^\/[A-Za-z0-9_-]+$/u.test(apiBase.pathname) || apiBase.search || apiBase.hash) throw coded('CONFIG_API_BASE');
  const domain = new URL(input.cognitoDomain);
  if (domain.protocol !== 'https:' || !/^[-a-z0-9]+\.auth\.[a-z0-9-]+\.amazoncognito\.com$/u.test(domain.hostname) || domain.pathname !== '/') throw coded('CONFIG_COGNITO_DOMAIN');
  if (!/^[a-z0-9]{10,64}$/u.test(input.clientId)) throw coded('CONFIG_CLIENT_ID');
  const base = apiBase.origin + apiBase.pathname;
  const resource = base + '/mcp';
  return Object.freeze({ apiBase: base, expectedHostname: apiBase.hostname, audience: resource, resource,
    redirectUri: base + '/auth/callback', cognitoDomain: domain.origin, authorizeUrl: domain.origin + '/oauth2/authorize',
    tokenUrl: domain.origin + '/oauth2/token', ringApi: input.ringApi ?? DEFAULT_CONFIG.ringApi, clientId: input.clientId,
    scopes: Object.freeze([resource + '/tools.list', resource + '/tools.call']) });
}
export function coded(code) { const e = new Error(code); e.code = code; return e; }
