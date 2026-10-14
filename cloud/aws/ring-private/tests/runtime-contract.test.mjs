import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const contract = JSON.parse(await readFile(new URL('../config/runtime-contract.json', import.meta.url), 'utf8'));

test('token intake contract separates documented, unknown and local-conservative claims', () => {
  assert.deepEqual(Object.keys(contract.token_intake_evidence), [
    'DOCUMENTED',
    'UNKNOWN',
    'LOCAL_CONSERVATIVE'
  ]);
  assert.equal(contract.token_intake_evidence.DOCUMENTED.length, 2);
  assert.equal(contract.token_intake_evidence.UNKNOWN.length, 4);
  assert.equal(contract.token_intake_evidence.LOCAL_CONSERVATIVE.length, 4);
  assert.equal(contract.source_auth.official_incoming_custom_authorizer, 'UNKNOWN');
  assert.equal(contract.source_auth.incoming_requirement, 'LOCAL_CONSERVATIVE_POST_SHAPE_ONLY');
  assert.equal(JSON.stringify(contract).includes('NONE_BEYOND_STRICT_OFFICIAL_POST_SHAPE'), false);
  assert.equal(JSON.stringify(contract).includes('official_code_post'), false);
});

test('sixty-second intake ceiling, immutable pins and four-second webhook deadline remain qualified', () => {
  assert.equal(contract.one_way.authorization_code_local_receipt_deadline_seconds, 60);
  assert.equal(contract.one_way.authorization_code_deadline_anchor, 'UNKNOWN_PROVIDER_ISSUE_TIME');
  assert.equal(contract.secret_pinning.provider, 'EXACT_VERSION_ID');
  assert.equal(contract.secret_pinning.digest, 'EXACT_VERSION_ID');
  assert.equal(contract.secret_pinning.version_stage_fallback, 'DENIED');
  assert.equal(contract.webhook_deadline.handler_entry_budget_ms, 4000);
  assert.equal(contract.webhook_deadline.request_or_environment_configurable, false);
  assert.equal(contract.webhook_deadline.late_success, 'DENIED');
  assert.equal(contract.lambda_timeout.shared_function_seconds, 10);
  assert.equal(contract.lambda_timeout.webhook_enforcement, 'FIXED_APPLICATION_DEADLINE');
});

test('runtime contract is nonsecret and remains unadmitted with public ingress disabled', () => {
  assert.equal(contract.production_admitted, false);
  assert.equal(contract.public_ingress_default, 'DISABLED');
  const text = JSON.stringify(contract);
  for (const forbidden of [
    'clientSecret',
    'webhookSigningKey',
    'recordHmacKey',
    'cookieHmacKey',
    'accessKeyId',
    'secretAccessKey'
  ]) {
    assert.equal(text.includes(forbidden), false);
  }
});

test('MCP Cognito contract remains disabled and names every missing production port', () => {
  assert.deepEqual(contract.mcp_cognito, {
    state: 'DISABLED',
    production_admitted: false,
    conditional_on_real_pkce_resource_parity: true,
    required_production_ports: [
      'pinned_public_jwks',
      'trusted_tls_evidence',
      'existing_formal_mcp_application'
    ],
    resource_claim: 'ABSENT',
    aud: 'EXACT_MCP_RESOURCE_URI',
    client_id: 'EXACT_PUBLIC_CLIENT',
    maximum_token_lifetime_seconds: 300,
    new_api_lambda_tables: 0,
    metadata_route: '/.well-known/oauth-protected-resource',
    mcp_route: '/mcp',
    artifact: 'FIXED_REVIEWED_CURRENT_IMPORT_CLOSURE',
    missing_ports: 'FINITE_503_NO_FALLBACK'
  });
});

test('MCP contract adds no secret fields and does not weaken existing deadlines or logging', () => {
  const serialized = JSON.stringify(contract.mcp_cognito);
  for (const forbidden of ['secret', 'token_value', 'private_key', 'clientSecret', 'accessKeyId']) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
  assert.equal(contract.webhook_deadline.handler_entry_budget_ms, 4000);
  assert.equal(contract.lambda_timeout.shared_function_seconds, 10);
  assert.equal(contract.logging.retention_days, 14);
  assert.equal(contract.routes.length, 8);
});

test('browser session contract does not promote formal admission or create new services', () => {
  assert.equal(contract.browser_session.production_admitted, false);
  assert.equal(contract.browser_session.state, 'DISABLED_BY_DEFAULT');
  assert.equal(contract.browser_session.new_services, 0);
  assert.deepEqual(contract.browser_session.routes.map(r => r.method + ' ' + r.path), ['GET /auth/login', 'GET /auth/callback', 'GET /auth/logout', 'POST /auth/session']);
  assert.match(contract.browser_session.owner, /separate from Cognito login/);
});
