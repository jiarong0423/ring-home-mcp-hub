import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const template = await readFile(new URL('../template.yaml', import.meta.url), 'utf8');

function resourceBlock(name, nextName) {
  const start = template.indexOf(`  ${name}:\n`);
  const end = nextName ? template.indexOf(`  ${nextName}:\n`, start + 1) : template.indexOf('\nOutputs:', start);
  assert.notEqual(start, -1, `${name} must exist`);
  assert.notEqual(end, -1, `${nextName ?? 'Outputs'} must exist after ${name}`);
  return template.slice(start, end);
}

test('public ingress defaults disabled and requires B02, secret admission and both immutable pins', () => {
  assert.match(template, /PublicIngressState:\n    Type: String\n    Default: DISABLED/);
  assert.match(template, /B02SessionLayerArn:[\s\S]*Default: UNCONFIGURED/);
  assert.match(template, /SecretAdmissionState:[\s\S]*Default: BLOCKED/);
  assert.match(template, /ProviderSecretVersionId:[\s\S]*Default: UNCONFIGURED/);
  assert.match(template, /DigestSecretVersionId:[\s\S]*Default: UNCONFIGURED/);
  assert.match(template, /ProviderSecretVersionPinned: !Not/);
  assert.match(template, /DigestSecretVersionPinned: !Not/);
  const condition = template.slice(template.indexOf('  PublicIngressEnabled:'), template.indexOf('\n\nResources:'));
  for (const required of [
    'PublicIngressState, ENABLED',
    '!Condition B02SessionLayerConfigured',
    'SecretAdmissionState, ADMITTED',
    '!Condition ProviderSecretVersionPinned',
    '!Condition DigestSecretVersionPinned'
  ]) assert.equal(condition.includes(required), true, required);
});

test('shared Lambda keeps ten seconds for token flow while webhook budget is application-owned', () => {
  const block = resourceBlock('RingPrivateFunction', 'RingMcpUserPool');
  assert.match(block, /CodeUri: \.\.\/\.\.\/\.\.\/artifacts\/ring-private/);
  assert.match(block, /Handler: cloud\/aws\/ring-private\/handler\.handler/);
  assert.match(block, /Runtime: nodejs24\.x/);
  assert.match(block, /Timeout: 10/);
  assert.match(block, /RING_BACKEND_STATE: !If \[PublicIngressEnabled, enabled, blocked\]/);
  assert.match(block, /RING_PROVIDER_SECRET_VERSION_ID: !Ref ProviderSecretVersionId/);
  assert.match(block, /RING_DIGEST_SECRET_VERSION_ID: !Ref DigestSecretVersionId/);
  assert.match(block, /RING_MCP_STATE: !If \[FormalMcpEnabled, enabled, blocked\]/);
  assert.doesNotMatch(block, /WEBHOOK_DEADLINE|DEADLINE_MS/);
});

test('all public API resources and invoke permission are conditionally absent by default', () => {
  const names = [
    'RingPrivateApi',
    'RingTokenResource',
    'RingTokenExchangeResource',
    'RingAccountLinkResource',
    'RingCompletionResource',
    'RingWebhookResource',
    'RingTokenExchangeMethod',
    'RingAccountLinkMethod',
    'RingCompletionMethod',
    'RingWebhookMethod',
    'RingPrivateApiDeployment',
    'RingPrivateApiStage',
    'RingPrivateInvokePermission'
  ];
  for (let index = 0; index < names.length; index += 1) {
    const next = names[index + 1];
    const block = resourceBlock(names[index], next);
    assert.match(block, /Condition: PublicIngressEnabled/, names[index]);
  }
  assert.equal((template.match(/AuthorizationType: NONE/g) ?? []).length, 14);
  for (const name of ['RingMacResource', 'RingMacCommandsResource', 'RingMacFetchResource',
    'RingMacReceiptResource', 'RingMacFetchMethod', 'RingMacReceiptMethod',
    'RingMacFetchInvokePermission', 'RingMacReceiptInvokePermission']) {
    assert.match(resourceBlock(name), /Condition: PublicIngressEnabled/, name);
  }
  for (const operation of ['fetch', 'receipt']) {
    assert.ok(template.includes('${RingPrivateApi}/${StageName}/POST/mac/commands/' + operation));
  }
  assert.ok(template.includes('${RingPrivateApi}/${StageName}/POST/mac/enroll\n'));
  assert.ok(template.includes('${RingPrivateApi}/${StageName}/POST/owner/bootstrap\n'));
  assert.doesNotMatch(template, /AuthorizationType: CUSTOM|AWS::ApiGateway::Authorizer/);
});

test('template exposes exactly four conditional Ring URLs and retains safe logging controls', () => {
  for (const value of [
    'PathPart: token',
    'PathPart: link',
    'PathPart: complete',
    'PathPart: webhook',
    'AccountLinkUrl:',
    'DefaultRedirectUrl:',
    'TokenExchangeUrl:',
    'WebhookUrl:'
  ]) assert.equal(template.includes(value), true, value);
  assert.equal((template.match(/!Sub https:\/\//g) ?? []).length, 4);
  assert.match(template, /RetentionInDays: 14/);
  assert.match(template, /DataTraceEnabled: false/);
  assert.doesNotMatch(template, /SecretString:|GenerateSecretString:/);
  assert.doesNotMatch(template, /AWS::ApiGateway::DomainName|AWS::ApiGateway::BasePathMapping/);
});

test('managed Cognito composition is default-off, public, code-only and resource-bound', () => {
  assert.match(template, /CognitoCompositionState:\n[\s\S]*?Default: DISABLED/);
  assert.match(template, /CognitoPkceResourceCompatibility:\n[\s\S]*?Default: BLOCKED/);
  assert.match(template, /FormalMcpAdmissionState:\n[\s\S]*?Default: BLOCKED/);
  for (const name of ['RingMcpUserPool', 'RingMcpResourceServer', 'RingMcpPublicClient', 'RingMcpUserPoolDomain']) {
    assert.match(resourceBlock(name, name === 'RingMcpUserPool' ? 'RingMcpResourceServer'
      : name === 'RingMcpResourceServer' ? 'RingMcpPublicClient'
        : name === 'RingMcpPublicClient' ? 'RingMcpUserPoolDomain' : 'RingPrivateApi'),
    /Condition: ManagedCognitoConfigured/, name);
  }
  const client = resourceBlock('RingMcpPublicClient', 'RingMcpUserPoolDomain');
  assert.match(client, /DependsOn: RingMcpResourceServer/);
  assert.match(client, /GenerateSecret: false/);
  assert.match(client, /AllowedOAuthFlows: \[code\]/);
  assert.match(client, /AccessTokenValidity: 5/);
  assert.match(client, /TokenValidityUnits: \{AccessToken: minutes\}/);
  assert.match(client, /\$\{McpResourceUri\}\/tools\.list/);
  assert.match(client, /\$\{McpResourceUri\}\/tools\.call/);
  assert.doesNotMatch(client, /ClientSecret|GenerateSecret: true/);
});

test('MCP routes reuse the one API and Lambda with exact conditional permissions', () => {
  assert.equal((template.match(/Type: AWS::ApiGateway::RestApi/g) ?? []).length, 1);
  assert.equal((template.match(/Type: AWS::Serverless::Function/g) ?? []).length, 1);
  assert.equal((template.match(/Type: AWS::DynamoDB::Table/g) ?? []).length, 3);
  for (const [name, next] of [
    ['RingMcpResource', 'RingWellKnownResource'],
    ['RingWellKnownResource', 'RingProtectedResourceMetadataResource'],
    ['RingProtectedResourceMetadataResource', 'RingMcpMethod'],
    ['RingMcpMethod', 'RingProtectedResourceMetadataMethod'],
    ['RingProtectedResourceMetadataMethod', 'RingPrivateApiDeployment'],
    ['RingMcpInvokePermission', 'RingMetadataInvokePermission'],
    ['RingMetadataInvokePermission', null]
  ]) assert.match(resourceBlock(name, next), /Condition: PublicIngressEnabled/, name);
  assert.match(template, /RingPrivateApiDeployment:[\s\S]*?DependsOn:[\s\S]*?- RingMcpMethod[\s\S]*?- RingProtectedResourceMetadataMethod/);
  assert.match(template, /RingMcpInvokePermission:[\s\S]*?\$\{StageName\}\/POST\/mcp/);
  assert.match(template, /RingMetadataInvokePermission:[\s\S]*?\$\{StageName\}\/GET\/\.well-known\/oauth-protected-resource/);
});


test('formal MCP activation requires an immutable admission digest and native TLS policy', () => {
  const parameter = resourceBlock('McpAdmissionSha256', 'McpResourceUri');
  assert.match(parameter, /Default: UNCONFIGURED/);
  assert.ok(parameter.includes("AllowedPattern: '^(UNCONFIGURED|[a-f0-9]{64})$'"));
  assert.match(template, /McpAdmissionPinned: !Not \[!Equals \[!Ref McpAdmissionSha256, UNCONFIGURED\]\]/);
  const condition = template.slice(template.indexOf('  FormalMcpEnabled:'), template.indexOf('\nResources:'));
  assert.match(condition, /!Condition ManagedCognitoConfigured/);
  assert.match(condition, /FormalMcpAdmissionState, ADMITTED/);
  assert.match(condition, /!Condition McpAdmissionPinned/);
  assert.match(resourceBlock('RingPrivateFunction', 'RingMcpUserPool'), /RING_MCP_ADMISSION_SHA256: !Ref McpAdmissionSha256/);
  const api = resourceBlock('RingPrivateApi', 'RingTokenResource');
  assert.match(api, /EndpointConfiguration: \{Types: \[REGIONAL\]\}/);
  assert.match(api, /DisableExecuteApiEndpoint: false/);
  assert.match(api, /SecurityPolicy: SecurityPolicy_TLS13_1_2_2021_06/);
  assert.match(api, /EndpointAccessMode: STRICT/);
});

// Evaluate only the CloudFormation condition syntax used by this template, failing on unknown syntax.
function evaluateCondition(name, parameters, visiting = new Set()) {
  assert.equal(visiting.has(name), false, `condition cycle: ${name}`);
  const section = template.split('\nConditions:\n')[1]?.split('\nResources:\n')[0];
  assert.ok(section, 'condition section must exist');
  const entries = [...section.matchAll(/^  ([A-Za-z0-9]+): (.+)((?:\n    .*)*)/gm)];
  const item = entries.find(match => match[1] === name);
  assert.ok(item, `unknown condition: ${name}`);
  const next = new Set(visiting).add(name);
  function expression(source) {
    let match = /^!Condition ([A-Za-z0-9]+)$/.exec(source);
    if (match) return evaluateCondition(match[1], parameters, next);
    match = /^!Equals \[!Ref ([A-Za-z0-9]+), ([A-Za-z0-9]+)\]$/.exec(source);
    if (match) {
      assert.ok(Object.hasOwn(parameters, match[1]), `missing parameter: ${match[1]}`);
      return parameters[match[1]] === match[2];
    }
    match = /^!Not \[(.+)\]$/.exec(source);
    if (match) return !expression(match[1]);
    assert.fail(`unsupported condition expression: ${source}`);
  }
  if (item[2] !== '!And') return expression(item[2]);
  const operands = item[3].split('\n').filter(Boolean).map(line => {
    assert.match(line, /^    - /);
    return expression(line.slice(6));
  });
  assert.ok(operands.length >= 2 && operands.length <= 10, 'CloudFormation And arity');
  return operands.every(Boolean);
}

const provisionedInputs = Object.freeze({
  PublicIngressState: 'ENABLED', B02SessionLayerArn: 'pinned-layer-version',
  SecretAdmissionState: 'ADMITTED', ProviderSecretVersionId: 'pinned-provider-version',
  DigestSecretVersionId: 'pinned-digest-version', CognitoCompositionState: 'ADMITTED',
  CognitoPkceResourceCompatibility: 'BLOCKED', FormalMcpAdmissionState: 'BLOCKED',
  McpAdmissionSha256: 'UNCONFIGURED',
  McpResourceUri: 'https://example.execute-api.ap-southeast-1.amazonaws.com/staging/mcp',
  McpCallbackUri: 'https://example.execute-api.ap-southeast-1.amazonaws.com/staging/auth/callback',
  McpLogoutUri: 'https://example.execute-api.ap-southeast-1.amazonaws.com/staging/auth/logout',
  McpCognitoDomainPrefix: 'ring-home-mcp-contract-test'
});

test('Cognito can provision before PKCE verification only with admitted ingress and all configured inputs', () => {
  assert.equal(evaluateCondition('ManagedCognitoConfigured', provisionedInputs), true);
  assert.equal(evaluateCondition('FormalMcpEnabled', provisionedInputs), false);
  for (const field of ['McpResourceUri', 'McpCallbackUri', 'McpLogoutUri', 'McpCognitoDomainPrefix',
    'B02SessionLayerArn', 'ProviderSecretVersionId', 'DigestSecretVersionId']) {
    assert.equal(evaluateCondition('ManagedCognitoConfigured', { ...provisionedInputs, [field]: 'UNCONFIGURED' }), false, field);
  }
  for (const [field, value] of [['PublicIngressState', 'DISABLED'], ['SecretAdmissionState', 'BLOCKED'], ['CognitoCompositionState', 'DISABLED']]) {
    assert.equal(evaluateCondition('ManagedCognitoConfigured', { ...provisionedInputs, [field]: value }), false, field);
  }
});

test('formal activation independently requires PKCE evidence, explicit admission and immutable digest', () => {
  const admitted = { ...provisionedInputs, CognitoPkceResourceCompatibility: 'VERIFIED',
    FormalMcpAdmissionState: 'ADMITTED', McpAdmissionSha256: 'a'.repeat(64) };
  assert.equal(evaluateCondition('FormalMcpEnabled', admitted), true);
  for (const [field, value] of [['CognitoPkceResourceCompatibility', 'BLOCKED'],
    ['FormalMcpAdmissionState', 'BLOCKED'], ['McpAdmissionSha256', 'UNCONFIGURED'],
    ['CognitoCompositionState', 'DISABLED'], ['McpCallbackUri', 'UNCONFIGURED']]) {
    assert.equal(evaluateCondition('FormalMcpEnabled', { ...admitted, [field]: value }), false, field);
  }
});


test('auth routes reuse the admitted API and Lambda with four exact verb and path permissions', () => {
  function block(name) {
    const all = template.split('\nResources:\n')[1].split('\nOutputs:')[0];
    const match = new RegExp(`^  ${name}:\\n[\\s\\S]*?(?=^  [A-Za-z0-9]+:|$(?![\\s\\S]))`, 'm').exec(all);
    assert.ok(match, name);
    return match[0];
  }
  assert.match(block('RingAuthResource'), /Condition: ManagedCognitoConfigured/);
  assert.match(block('RingAuthResource'), /ParentId: !GetAtt RingPrivateApi.RootResourceId/);
  for (const [label, path, verb] of [['Login', 'login', 'GET'], ['Callback', 'callback', 'GET'],
    ['Logout', 'logout', 'GET'], ['Session', 'session', 'POST']]) {
    const resource = block(`RingAuth${label}Resource`), method = block(`RingAuth${label}Method`);
    const permission = block(`RingAuth${label}InvokePermission`);
    for (const value of [resource, method, permission]) assert.match(value, /Condition: ManagedCognitoConfigured/);
    assert.ok(resource.includes(`PathPart: ${path}\n`));
    assert.match(resource, /ParentId: !Ref RingAuthResource/);
    assert.ok(method.includes(`HttpMethod: ${verb}\n`));
    assert.match(method, /Type: AWS_PROXY/);
    assert.ok(method.includes('${RingPrivateFunction.Arn}/invocations'));
    assert.ok(permission.includes('${RingPrivateApi}/${StageName}/' + verb + '/auth/' + path + '\n'));
    assert.match(permission, /Principal: apigateway.amazonaws.com/);
    assert.match(permission, /FunctionName: !Ref RingPrivateFunction/);
    assert.doesNotMatch(permission, /\*/);
  }
  const deployment = block('RingAuthApiDeploymentV2');
  assert.match(deployment, /Condition: ManagedCognitoConfigured/);
  for (const name of ['RingTokenExchangeMethod', 'RingAccountLinkMethod', 'RingCompletionMethod',
    'RingWebhookMethod', 'RingMcpMethod', 'RingProtectedResourceMetadataMethod', 'RingMacFetchMethod',
    'RingMacReceiptMethod', 'RingMacEnrollMethod', 'RingOwnerBootstrapMethod', 'RingAuthLoginMethod', 'RingAuthCallbackMethod', 'RingAuthLogoutMethod', 'RingAuthSessionMethod']) {
    assert.ok(deployment.includes(`      - ${name}\n`), name);
  }
  assert.match(block('RingPrivateApiDeployment'), /RestApiId: !Ref RingPrivateApi/);
  const stage = block('RingPrivateApiStage');
  assert.ok(stage.includes('DeploymentId: !If [ManagedCognitoConfigured, !Ref RingAuthApiDeploymentV2, !Ref RingPrivateApiDeployment]'));
  assert.match(stage, /LoggingLevel: "OFF"/);
  assert.match(stage, /DataTraceEnabled: false/);
  assert.match(stage, /MetricsEnabled: true/);
  assert.match(stage, /ThrottlingBurstLimit: 10/);
  assert.match(stage, /ThrottlingRateLimit: 5/);
  assert.equal((template.match(/Type: AWS::ApiGateway::RestApi/g) ?? []).length, 1);
  assert.equal((template.match(/Type: AWS::Serverless::Function/g) ?? []).length, 1);
});


test('browser bootstrap uses the coordinated nonsecret OAuth parameters without enabling formal MCP', () => {
  const lambda = resourceBlock('RingPrivateFunction', 'RingMcpUserPool');
  assert.ok(lambda.includes('RING_BROWSER_SESSION_STATE: !If [ManagedCognitoConfigured, enabled, blocked]'));
  assert.ok(lambda.includes("RING_BROWSER_COGNITO_DOMAIN: !If [ManagedCognitoConfigured, !Sub 'https://${McpCognitoDomainPrefix}.auth.${AWS::Region}.amazoncognito.com', UNCONFIGURED]"));
  assert.match(lambda, /RING_BROWSER_CALLBACK_URI: !Ref McpCallbackUri/);
  assert.match(lambda, /RING_BROWSER_LOGOUT_URI: !Ref McpLogoutUri/);
  assert.ok(lambda.includes('RING_MCP_STATE: !If [FormalMcpEnabled, enabled, blocked]'));
  assert.equal(evaluateCondition('FormalMcpEnabled', provisionedInputs), false);
});

test('owner bootstrap and Mac enrollment are parameter gated, default DISABLED, hash pinned and rule protected', () => {
  for (const [name, values] of [['OwnerBootstrapState', '[DISABLED, ENABLED]'], ['MacEnrollmentState', '[DISABLED, ENABLED]']]) {
    const m = new RegExp(`  ${name}:\\n    Type: String\\n    Default: DISABLED\\n    AllowedValues: \\[DISABLED, ENABLED\\]`).test(template);
    assert.equal(m, true, name + values);
  }
  for (const name of ['OwnerBootstrapApprovalSha256', 'MacEnrollmentApprovalSha256']) {
    const m = new RegExp(`  ${name}:\\n    Type: String\\n    Default: UNCONFIGURED\\n(?:    Description: .*\\n)?    AllowedPattern: '\\^\\(UNCONFIGURED\\|\\[a-f0-9\\]\\{64\\}\\)\\$'`).test(template);
    assert.equal(m, true, name);
  }
  assert.match(template, /Rules:\n  OwnerBootstrapRequiresBrowserSession:\n    RuleCondition: !Equals \[!Ref OwnerBootstrapState, ENABLED\]/);
  assert.match(template, /MacEnrollmentRequiresMcpAndBrowserSession:\n    RuleCondition: !Equals \[!Ref MacEnrollmentState, ENABLED\]/);
  for (const rule of ['OwnerBootstrapRequiresBrowserSession', 'MacEnrollmentRequiresMcpAndBrowserSession']) {
    const start = template.indexOf(`  ${rule}:`);
    const body = template.slice(start, template.indexOf('\n\n', start));
    assert.match(body, /!Not \[!Equals \[!Ref (OwnerBootstrap|MacEnrollment)ApprovalSha256, UNCONFIGURED\]\]/);
    assert.match(body, /!Equals \[!Ref CognitoCompositionState, ADMITTED\]/);
  }
  assert.match(template, /MacEnrollmentRequiresMcpAndBrowserSession:[\s\S]*FormalMcpAdmissionState, ADMITTED/);
  const lambda = resourceBlock('RingPrivateFunction', 'RingMcpUserPool');
  assert.ok(lambda.includes('RING_OWNER_BOOTSTRAP_STATE: !If [OwnerBootstrapEnabled, enabled, blocked]'));
  assert.ok(lambda.includes('RING_OWNER_BOOTSTRAP_APPROVAL_SHA256: !Ref OwnerBootstrapApprovalSha256'));
  assert.ok(lambda.includes('RING_MAC_ENROLLMENT_STATE: !If [MacEnrollmentEnabled, enabled, blocked]'));
  assert.ok(lambda.includes('RING_MAC_ENROLLMENT_APPROVAL_SHA256: !Ref MacEnrollmentApprovalSha256'));
  const inputs = { ...provisionedInputs, OwnerBootstrapState: 'DISABLED', OwnerBootstrapApprovalSha256: 'UNCONFIGURED',
    MacEnrollmentState: 'DISABLED', MacEnrollmentApprovalSha256: 'UNCONFIGURED' };
  assert.equal(evaluateCondition('OwnerBootstrapEnabled', inputs), false);
  assert.equal(evaluateCondition('MacEnrollmentEnabled', inputs), false);
  const owner = { ...inputs, OwnerBootstrapState: 'ENABLED', OwnerBootstrapApprovalSha256: 'b'.repeat(64),
    CognitoPkceResourceCompatibility: 'VERIFIED', FormalMcpAdmissionState: 'ADMITTED', McpAdmissionSha256: 'a'.repeat(64) };
  assert.equal(evaluateCondition('OwnerBootstrapEnabled', owner), true);
  assert.equal(evaluateCondition('OwnerBootstrapEnabled', { ...owner, OwnerBootstrapApprovalSha256: 'UNCONFIGURED' }), false);
  assert.equal(evaluateCondition('OwnerBootstrapEnabled', { ...owner, CognitoCompositionState: 'DISABLED' }), false);
  assert.equal(evaluateCondition('OwnerBootstrapEnabled', { ...owner, OwnerBootstrapState: 'DISABLED' }), false);
  assert.equal(evaluateCondition('OwnerBootstrapEnabled', { ...owner, FormalMcpAdmissionState: 'BLOCKED' }), false);
  assert.equal(evaluateCondition('OwnerBootstrapEnabled', { ...owner, McpAdmissionSha256: 'UNCONFIGURED' }), false);
  const mac = { ...inputs, MacEnrollmentState: 'ENABLED', MacEnrollmentApprovalSha256: 'c'.repeat(64),
    CognitoPkceResourceCompatibility: 'VERIFIED', FormalMcpAdmissionState: 'ADMITTED', McpAdmissionSha256: 'a'.repeat(64) };
  assert.equal(evaluateCondition('MacEnrollmentEnabled', mac), true);
  assert.equal(evaluateCondition('MacEnrollmentEnabled', { ...mac, FormalMcpAdmissionState: 'BLOCKED' }), false);
  assert.equal(evaluateCondition('MacEnrollmentEnabled', { ...mac, MacEnrollmentApprovalSha256: 'UNCONFIGURED' }), false);
  // Enabling one feature never enables the other.
  assert.equal(evaluateCondition('MacEnrollmentEnabled', owner), false);
  assert.equal(evaluateCondition('OwnerBootstrapEnabled', mac), false);
});

test('live-deployed Cognito delta is synchronized: MFA ON with software token, managed login v2 and branding', () => {
  const pool = resourceBlock('RingMcpUserPool', 'RingMcpResourceServer');
  assert.match(pool, /MfaConfiguration: 'ON'/);
  assert.match(pool, /EnabledMfas: \[SOFTWARE_TOKEN_MFA\]/);
  assert.match(pool, /DeletionProtection: ACTIVE/);
  const domain = resourceBlock('RingMcpUserPoolDomain', 'RingMcpManagedLoginBranding');
  assert.match(domain, /ManagedLoginVersion: 2/);
  const branding = resourceBlock('RingMcpManagedLoginBranding', 'RingPrivateApi');
  assert.match(branding, /Type: AWS::Cognito::ManagedLoginBranding/);
  assert.match(branding, /Condition: ManagedCognitoConfigured/);
  assert.match(branding, /DependsOn: RingMcpUserPoolDomain/);
  assert.match(branding, /UserPoolId: !Ref RingMcpUserPool/);
  assert.match(branding, /ClientId: !Ref RingMcpPublicClient/);
  assert.match(branding, /UseCognitoProvidedValues: true/);
});

test('Mac enroll resources are gated on PublicIngressEnabled (state switch is the Lambda env); every And/Or has 2..10 operands (Conditions and Rules)', () => {
  for (const name of ['RingMacEnrollResource', 'RingMacEnrollMethod', 'RingMacEnrollInvokePermission']) {
    assert.match(resourceBlock(name), /Condition: PublicIngressEnabled/, name);
  }
  assert.doesNotMatch(template, /Condition: MacEnrollRouteEnabled/, 'MacEnrollRouteEnabled stays defined (live) but gates no resource');
  const inputs = { ...provisionedInputs, OwnerBootstrapState: 'DISABLED', OwnerBootstrapApprovalSha256: 'UNCONFIGURED',
    MacEnrollmentState: 'ENABLED', MacEnrollmentApprovalSha256: 'c'.repeat(64), CognitoPkceResourceCompatibility: 'VERIFIED',
    FormalMcpAdmissionState: 'ADMITTED', McpAdmissionSha256: 'a'.repeat(64) };
  assert.equal(evaluateCondition('MacEnrollRouteEnabled', inputs), true);
  assert.equal(evaluateCondition('MacEnrollRouteEnabled', { ...inputs, MacEnrollmentState: 'DISABLED' }), false);
  assert.equal(evaluateCondition('MacEnrollRouteEnabled', { ...inputs, PublicIngressState: 'DISABLED' }), false);
  for (const m of template.matchAll(/!(And|Or)\n((?:\s+- .*\n)+)/g)) {
    const operands = m[2].split('\n').filter(Boolean).length;
    assert.ok(operands >= 2 && operands <= 10, `${m[1]} with ${operands} operands`);
  }
});

test('owner bootstrap route resources are gated on PublicIngressEnabled exactly like /mac/enroll (state switch is the Lambda env)', () => {
  const next = { RingOwnerResource: 'RingOwnerBootstrapResource', RingOwnerBootstrapResource: 'RingOwnerBootstrapMethod',
    RingOwnerBootstrapMethod: 'RingOwnerBootstrapInvokePermission', RingOwnerBootstrapInvokePermission: 'RingMacReceiptMethod' };
  for (const name of Object.keys(next)) assert.match(resourceBlock(name, next[name]), /Condition: PublicIngressEnabled/, name);
  assert.doesNotMatch(template, /OwnerBootstrapRouteEnabled/);
  assert.match(resourceBlock('RingOwnerResource', 'RingOwnerBootstrapResource'), /PathPart: owner\n/);
  assert.match(resourceBlock('RingOwnerResource', 'RingOwnerBootstrapResource'), /ParentId: !GetAtt RingPrivateApi.RootResourceId/);
  assert.match(resourceBlock('RingOwnerBootstrapResource', 'RingOwnerBootstrapMethod'), /ParentId: !Ref RingOwnerResource/);
  assert.match(resourceBlock('RingOwnerBootstrapResource', 'RingOwnerBootstrapMethod'), /PathPart: bootstrap\n/);
  const method = resourceBlock('RingOwnerBootstrapMethod', 'RingOwnerBootstrapInvokePermission');
  assert.match(method, /HttpMethod: POST/); assert.match(method, /AuthorizationType: NONE/); assert.match(method, /Type: AWS_PROXY/);
  assert.match(method, /ResourceId: !Ref RingOwnerBootstrapResource/);
  const permission = resourceBlock('RingOwnerBootstrapInvokePermission', 'RingMacReceiptMethod');
  assert.ok(permission.includes('${RingPrivateApi}/${StageName}/POST/owner/bootstrap\n'));
  assert.doesNotMatch(permission, /\*/);
  for (const [deployment, after] of [['RingPrivateApiDeployment', 'RingAuthResource'], ['RingAuthApiDeploymentV2', 'RingPrivateApiStage']]) assert.ok(resourceBlock(deployment, after).includes('      - RingOwnerBootstrapMethod\n'), deployment);
  const inputs = { ...provisionedInputs, OwnerBootstrapState: 'ENABLED', OwnerBootstrapApprovalSha256: 'b'.repeat(64), MacEnrollmentState: 'DISABLED', MacEnrollmentApprovalSha256: 'UNCONFIGURED',
    CognitoPkceResourceCompatibility: 'VERIFIED', FormalMcpAdmissionState: 'ADMITTED', McpAdmissionSha256: 'a'.repeat(64) };
  assert.equal(evaluateCondition('PublicIngressEnabled', inputs), true);
  assert.equal(evaluateCondition('OwnerBootstrapEnabled', inputs), true);
  assert.equal(evaluateCondition('OwnerBootstrapEnabled', { ...inputs, OwnerBootstrapState: 'DISABLED' }), false);
  assert.equal(evaluateCondition('OwnerBootstrapEnabled', { ...inputs, OwnerBootstrapApprovalSha256: 'UNCONFIGURED' }), false);
  assert.equal(evaluateCondition('OwnerBootstrapEnabled', { ...inputs, FormalMcpAdmissionState: 'BLOCKED' }), false);
  const rule = template.slice(template.indexOf('  OwnerBootstrapRequiresBrowserSession:'), template.indexOf('  MacEnrollmentRequiresMcpAndBrowserSession:'));
  assert.match(rule, /FormalMcpAdmissionState, ADMITTED/);
  assert.match(rule, /CognitoPkceResourceCompatibility, VERIFIED/);
});

test('round 3 F1: every Deployment DependsOn target is created whenever the deployment is (no condition-excluded DependsOn when a state is DISABLED)', () => {
  for (const [deployment, after] of [['RingPrivateApiDeployment', 'RingAuthResource'], ['RingAuthApiDeploymentV2', 'RingPrivateApiStage']]) {
    const block = resourceBlock(deployment, after);
    const own = /\n    Condition: (\w+)\n/.exec(block)[1];
    const deps = [...block.slice(block.indexOf('DependsOn:')).matchAll(/^      - (\w+)$/gm)].map(m => m[1]);
    assert.ok(deps.includes('RingOwnerBootstrapMethod') && deps.includes('RingMacEnrollMethod'), deployment);
    for (const dep of deps) {
      const cond = /\n    Condition: (\w+)\n/.exec(resourceBlock(dep))[1];
      for (const state of ['ENABLED', 'DISABLED']) {
        const inputs = { ...provisionedInputs, OwnerBootstrapState: state, OwnerBootstrapApprovalSha256: 'b'.repeat(64), MacEnrollmentState: state,
          MacEnrollmentApprovalSha256: 'c'.repeat(64), CognitoPkceResourceCompatibility: 'VERIFIED', FormalMcpAdmissionState: 'ADMITTED', McpAdmissionSha256: 'a'.repeat(64) };
        if (evaluateCondition(own, inputs)) assert.equal(evaluateCondition(cond, inputs), true, `${deployment} -> ${dep} (${cond}) with states ${state}`);
      }
    }
  }
});
