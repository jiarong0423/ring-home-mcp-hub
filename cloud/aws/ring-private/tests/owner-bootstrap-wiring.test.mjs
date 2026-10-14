import test from 'node:test';
import assert from 'node:assert/strict';
import { buildOwnerBootstrap, OWNER_BOOTSTRAP_APPROVAL_FILE } from '../browser-session-production.mjs';
import { loadPinnedLayerJson, layerFilePath, LAYER_DIRECTORY, FORMAL_MCP_ADMISSION_PATH } from '../mcp-production-ports.mjs';
import { createRingTokenClient } from '../ring-token-client.mjs';
import { createCloudOwnerBootstrap } from '../cloud-owner-bootstrap.mjs';
import { NOW, ISS, RESOURCE, SCOPES, digest, identityEnvelope, createAuth, createFakeTable, approvalFixture, sha256 } from './owner-bootstrap-fixture.mjs';

const secretLoader = Object.freeze({
  async loadProvider() { return { secret: { nonceKey: 'generated-nonce-key-at-least-thirty-two-bytes' } }; },
  async loadDigest() { return { secret: { recordHmacKey: 'generated-record-key-at-least-thirty-two-bytes' } }; }
});
function resources(table = createFakeTable(), extra = {}) {
  return { ports: { ...table.ports, query: async () => ({ Items: [] }),
    generateDataKey: async () => ({ Plaintext: Buffer.alloc(32, 7), CiphertextBlob: Buffer.from('wrapped') }), decryptDataKey: async () => ({ Plaintext: Buffer.alloc(32, 7) }) },
  tableName: 'ring-test-link', digest, identityEnvelope, secretLoader, ...extra };
}
const baseEnvironment = (extra = {}) => ({ RING_MCP_ISSUER: ISS, RING_MCP_RESOURCE_URI: RESOURCE, RING_MCP_REQUIRED_SCOPES: JSON.stringify(SCOPES),
  RING_TOKEN_KMS_KEY_ID: 'arn:aws:kms:ap-southeast-1:111111111111:key/generated', RING_APPLICATION: 'ring-home-mcp-private', ...extra });

test('state off (absent, blocked, or any value other than the exact string) builds no bootstrap at all', () => {
  for (const state of [undefined, 'blocked', 'ENABLED', 'enabled ', '', 'true']) {
    const environment = baseEnvironment({ ...(state === undefined ? {} : { RING_OWNER_BOOTSTRAP_STATE: state }), RING_OWNER_BOOTSTRAP_APPROVAL_SHA256: 'a'.repeat(64) });
    assert.equal(buildOwnerBootstrap({ environment, resources: resources() }), null, String(state));
  }
});
test('enabled without a valid pinned hash fails closed at construction', () => {
  for (const sha of [undefined, '', 'UNCONFIGURED', 'A'.repeat(64), 'a'.repeat(63)]) {
    const environment = baseEnvironment({ RING_OWNER_BOOTSTRAP_STATE: 'enabled', ...(sha === undefined ? {} : { RING_OWNER_BOOTSTRAP_APPROVAL_SHA256: sha }) });
    assert.throws(() => buildOwnerBootstrap({ environment, resources: resources() }), /owner_bootstrap_not_configured/u);
  }
});
test('enabled: approval comes from the pinned layer file next to the admission file; a Ring token for another account means no owner write', async () => {
  const approval = approvalFixture();
  const reads = [];
  const table = createFakeTable();
  const bootstrap = buildOwnerBootstrap({ environment: baseEnvironment({ RING_OWNER_BOOTSTRAP_STATE: 'enabled', RING_OWNER_BOOTSTRAP_APPROVAL_SHA256: approval.sha }),
    resources: resources(table), clock: () => NOW, readFile: async path => { reads.push(path); return approval.bytes; },
    ringTokenClient: { async getAccountId() { return 'some-other-ring-account'; } } });
  assert.equal(typeof bootstrap.ensureWithRingToken, 'function');
  assert.equal(bootstrap.ensure, undefined);
  const auth = createAuth();
  const login = await auth.login();
  await assert.rejects(bootstrap.ensureWithRingToken({ ...login, ringAccessToken: 'ring-token' }), /owner_bootstrap_ring_denied/u);
  assert.deepEqual(reads, [`${LAYER_DIRECTORY}/${OWNER_BOOTSTRAP_APPROVAL_FILE}`]);
  assert.equal(LAYER_DIRECTORY, FORMAL_MCP_ADMISSION_PATH.slice(0, FORMAL_MCP_ADMISSION_PATH.lastIndexOf('/')));
  assert.equal(OWNER_BOOTSTRAP_APPROVAL_FILE, 'owner-bootstrap-approval-v1.json');
  assert.deepEqual([...table.items.keys()].filter(k => !k.startsWith('OWNER_BOOTSTRAP_ATTEMPTS#')), []);
  // The hash pin is enforced on the file read: a different file under the same name is refused before anything else happens.
  const tampered = buildOwnerBootstrap({ environment: baseEnvironment({ RING_OWNER_BOOTSTRAP_STATE: 'enabled', RING_OWNER_BOOTSTRAP_APPROVAL_SHA256: 'b'.repeat(64) }),
    resources: resources(createFakeTable()), clock: () => NOW, readFile: async () => approval.bytes,
    ringTokenClient: { async getAccountId() { throw new Error('must not be called'); } } });
  await assert.rejects(tampered.ensureWithRingToken({ ...login, ringAccessToken: 'ring-token' }), /owner_bootstrap_approval_denied/u);
  // the default Ring client is the token-only client (no secrets, fixed URL)
  const defaultClient = buildOwnerBootstrap({ environment: baseEnvironment({ RING_OWNER_BOOTSTRAP_STATE: 'enabled', RING_OWNER_BOOTSTRAP_APPROVAL_SHA256: approval.sha }), resources: resources() });
  assert.equal(typeof defaultClient.ensureWithRingToken, 'function');
  assert.equal(typeof createRingTokenClient().getAccountId, 'function');
});
test('loadPinnedLayerJson pins path and sha, rejects traversal, foreign dirs, bad hashes and non-JSON', async () => {
  const bytes = Buffer.from('{"a":1}');
  const good = await loadPinnedLayerJson(layerFilePath('x-approval-v1.json'), sha256(bytes), { readFile: async () => bytes });
  assert.deepEqual(good.value, { a: 1 }); assert.equal(good.bytes, bytes);
  const reject = (path, sha, readFile, pattern) => assert.rejects(loadPinnedLayerJson(path, sha, { readFile }), pattern);
  await reject(layerFilePath('x-approval-v1.json'), 'f'.repeat(64), async () => bytes, /mcp_layer_pin_denied/u);
  await reject(layerFilePath('x-approval-v1.json'), 'UNCONFIGURED', async () => bytes, /mcp_layer_pin_missing/u);
  await reject('/etc/passwd', sha256(bytes), async () => bytes, /mcp_layer_name_denied/u);
  await reject(`${LAYER_DIRECTORY}/../tmp/x.json`, sha256(bytes), async () => bytes, /mcp_layer_name_denied/u);
  await reject(`${LAYER_DIRECTORY}/sub/x.json`, sha256(bytes), async () => bytes, /mcp_layer_name_denied/u);
  await reject(layerFilePath('x-approval-v1.json'), sha256(Buffer.from('nope')), async () => Buffer.from('nope'), /mcp_layer_json_denied/u);
  await reject(layerFilePath('x-approval-v1.json'), sha256(bytes), async () => 'not-a-buffer', /mcp_layer_pin_denied/u);
  assert.throws(() => layerFilePath('../x.json'), /mcp_layer_name_denied/u);
  assert.throws(() => layerFilePath('x.txt'), /mcp_layer_name_denied/u);
});
test('createCloudOwnerBootstrap rejects incomplete configuration', () => {
  const ok = { getItem() {}, transactWrite() {}, tableName: 'ring-test-link', digest, identityEnvelope, profile: { issuer: ISS, resource: RESOURCE, scopes: SCOPES },
    loadApproval() {}, approvalSha256: 'a'.repeat(64), ringTokenClient: { getAccountId() {} } };
  assert.ok(createCloudOwnerBootstrap(ok));
  for (const patch of [{ getItem: undefined }, { transactWrite: undefined }, { digest: undefined }, { identityEnvelope: {} }, { loadApproval: undefined }, { ringTokenClient: undefined }, { ringTokenClient: {} },
    { approvalSha256: 'x' }, { tableName: 'a' }, { profile: { issuer: ISS, resource: RESOURCE, scopes: [] } }, { clock: 1 }]) {
    assert.throws(() => createCloudOwnerBootstrap({ ...ok, ...patch }), /owner_bootstrap_config/u, JSON.stringify(Object.keys(patch)));
  }
});
