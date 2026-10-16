// Stand-alone family relay Lambda behind a Lambda function URL (stack cloud/aws/family-relay/template.json), separate from
// the ring-home-mcp-private stack so its API deployment (and the formal MCP admission pinned to it) is never touched.
// Same relay logic and page as the in-stack routes: family-relay.mjs / family-relay-http.mjs / family-page.mjs.
// Routes (function URL, payload v2): GET /family, GET /family/app.js, POST /relay/mac, POST /relay/phone.
import { createDynamoRelayStore, createFamilyRelayHttp } from './family-relay-http.mjs';
import { createFamilyRelay } from './family-relay.mjs';

// "/family/" is not served: the page's relative URLs (family/app.js, relay/phone) only resolve from "/family".
const ROUTES = Object.freeze({ 'GET /family': 'family-page', 'GET /family/app.js': 'family-js',
  'POST /relay/mac': 'relay-mac', 'POST /relay/phone': 'relay-phone' });
const BASE_HEADERS = Object.freeze({ 'cache-control': 'no-store', 'content-type': 'application/json; charset=utf-8', 'x-content-type-options': 'nosniff' });

let factory = null; let http = null;
export function installRelayForTest(make) { factory = make; http = null; }
async function production() {
  const { DynamoDBClient, GetItemCommand, PutItemCommand } = await import('@aws-sdk/client-dynamodb');   // in the Lambda Node.js runtime
  const client = new DynamoDBClient({});
  const store = createDynamoRelayStore({ tableName: process.env.RELAY_TABLE,
    getItem: (input) => client.send(new GetItemCommand(input)), putItem: (input) => client.send(new PutItemCommand(input)) });
  return createFamilyRelayHttp({ relay: createFamilyRelay({ store, macPublicKeySpki: process.env.RELAY_MAC_KEY_SPKI }) });
}

export async function handler(event) {
  const method = event?.requestContext?.http?.method ?? '';
  const route = ROUTES[`${method} ${event?.rawPath ?? ''}`];
  if (!route) return { statusCode: 404, headers: BASE_HEADERS, body: '{"error":"NOT_FOUND"}' };
  if (event.rawQueryString) return { statusCode: 400, headers: BASE_HEADERS, body: '{"error":"QUERY_NOT_ALLOWED"}' };
  try { http ??= await (factory ?? production)(); }
  catch { console.error(JSON.stringify({ event: 'family_relay', outcome: 'ERROR', reason: 'not_configured' })); return { statusCode: 503, headers: BASE_HEADERS, body: '{"error":"RELAY_UNAVAILABLE"}' }; }
  return http(route, { body: event.body ?? '', isBase64Encoded: event.isBase64Encoded === true });
}
