// HTTP edge for the family relay on the existing Lambda: POST /relay/mac, POST /relay/phone, GET /family, GET /family/app.js,
// and (stand-alone relay only) POST /ring/webhook.
// Storage is the existing event table (GetItem / PutItem only, deterministic keys, TTL attribute expires_at).
import { createFamilyRelay, RelayError } from './family-relay.mjs';
import { FAMILY_PAGE_HTML, FAMILY_PAGE_JS } from './family-page.mjs';   // generated from family-page/ (no file reads at run time)

const MAX_BODY = 8_192;
const MAX_WEBHOOK_BODY = 16_384;
const BASE_HEADERS = Object.freeze({ 'cache-control': 'no-store', 'referrer-policy': 'no-referrer', 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY' });

export function createDynamoRelayStore({ getItem, putItem, tableName, clock = Date.now }) {
  if (typeof getItem !== 'function' || typeof putItem !== 'function' || typeof tableName !== 'string') throw new TypeError('relay dynamo ports required');
  return Object.freeze({
    async get(pk) {
      const out = await getItem({ TableName: tableName, Key: { pk: { S: pk } }, ConsistentRead: true });
      const item = out?.Item;
      if (!item?.data?.S) return null;
      const exp = Number(item.expires_at?.N ?? 0);
      if (exp && exp * 1000 <= clock()) return null;
      return JSON.parse(item.data.S);
    },
    async put(value, { ifNotExists = false } = {}) {
      const nowSec = Math.floor(clock() / 1000);
      const expSec = value.expiresAtMs ? Math.ceil(value.expiresAtMs / 1000) : nowSec + 30 * 86_400;   // rows never outlive 30 days
      const input = { TableName: tableName, Item: { pk: { S: value.pk }, data: { S: JSON.stringify(value) }, expires_at: { N: String(expSec) } } };
      if (ifNotExists) Object.assign(input, { ConditionExpression: 'attribute_not_exists(pk) OR expires_at < :now', ExpressionAttributeValues: { ':now': { N: String(nowSec) } } });
      try { await putItem(input); return true; }
      catch (error) { if (error?.name === 'ConditionalCheckFailedException') return false; throw error; }
    }
  });
}

function respond(statusCode, body, headers = {}) {
  return { statusCode, headers: { ...BASE_HEADERS, 'content-type': 'application/json; charset=utf-8', ...headers }, body: JSON.stringify(body) };
}
function parseBody(event) {
  const raw = event.isBase64Encoded ? Buffer.from(event.body ?? '', 'base64').toString('utf8') : (event.body ?? '');
  if (Buffer.byteLength(raw) > MAX_BODY) throw new RelayError(413, 'RELAY_BODY_TOO_LARGE');
  try { const v = JSON.parse(raw); if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error(); return v; }
  catch { throw new RelayError(400, 'RELAY_JSON_INVALID'); }
}

const pageFiles = () => ({ html: FAMILY_PAGE_HTML, js: FAMILY_PAGE_JS });

export function createFamilyRelayHttp({ relay }) {
  return async function handleFamily(route, event) {
    try {
      if (route === 'family-page') {
        return { statusCode: 200, headers: { ...BASE_HEADERS, 'content-type': 'text/html; charset=utf-8',
          'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" }, body: pageFiles().html };
      }
      if (route === 'family-js') return { statusCode: 200, headers: { ...BASE_HEADERS, 'content-type': 'text/javascript; charset=utf-8' }, body: pageFiles().js };
      if (route === 'ring-webhook') {   // raw bytes: the HMAC covers exactly what Ring sent
        const raw = Buffer.from(event.body ?? '', event.isBase64Encoded ? 'base64' : 'utf8');
        if (raw.length > MAX_WEBHOOK_BODY) throw new RelayError(413, 'RELAY_BODY_TOO_LARGE');
        return respond(200, await relay.ringWebhook({ rawBody: raw, signature: event.headers?.['x-signature'] }));
      }
      const body = parseBody(event);
      const out = route === 'relay-mac' ? await relay.mac(body) : await relay.phone(body);
      return respond(200, out);
    } catch (error) {
      if (error instanceof RelayError) return respond(error.status, { error: error.code });
      console.error(Object.freeze({ event: 'family_relay', outcome: 'ERROR', name: error?.name }));
      return respond(503, { error: 'RELAY_UNAVAILABLE' });
    }
  };
}

export function createProductionFamilyRelayHttp({ ports }) {
  const key = process.env.RING_FAMILY_RELAY_MAC_KEY;
  const store = createDynamoRelayStore({ getItem: ports.getItem, putItem: ports.putItem, tableName: 'ring-home-mcp-private-event' });
  return createFamilyRelayHttp({ relay: createFamilyRelay({ store, macPublicKeySpki: key }) });
}
