import { createMacCommandProofAuthority, createMacEnrollmentInstaller } from './mac-command-proof-authority.mjs';
import { createHmac, randomBytes } from 'node:crypto';
import { createSecretLoader } from './secret-loader.mjs';
import { createDynamoIdentityAuthorityStore } from './dynamo-identity-authority-store.mjs';
import { createIdentityEnvelope } from './identity-envelope.mjs';
import { createProjectingIdentityAuthority } from './projecting-identity-authority.mjs';
import { createCloudOwnerAssociationReader, createCloudOwnerAssociationInstaller } from './cloud-owner-association.mjs';
import { createCloudBrowserSessionIssuer, extractCloudSessionCookies } from './cloud-browser-session.mjs';
import { createRingClient } from './ring-client.mjs';
import { createFormalRouteSet } from '../../../src/formal-runtime/server-composition.mjs';

function deny(code = 'b02_cloud_layer_denied') { throw new TypeError(code); }
function envString(env, key) { const value = env[key]; if (typeof value !== 'string' || !value || value.length > 2048) deny(`b02_missing_${key}`); return value; }
export async function createCloudIdentityResources({ environment = process.env, awsPorts, clock = Date.now } = {}) {
  let clients = null;
  let ports = awsPorts;
  if (!ports) {
    const sdk = await import('./aws-sdk-v3-ports.mjs');
    clients = sdk.createAwsSdkV3Clients({ region: envString(environment, 'AWS_REGION') });
    ports = sdk.createAwsSdkV3Ports(clients);
  }
  let loader;
  try {
  const tableName = envString(environment, 'RING_LINK_TABLE_NAME');
  loader = createSecretLoader({ getSecretValue: ports.getSecretValue,
    providerSecretArn: envString(environment, 'RING_PROVIDER_SECRET_ARN'),
    providerSecretVersionId: envString(environment, 'RING_PROVIDER_SECRET_VERSION_ID'),
    digestSecretArn: envString(environment, 'RING_DIGEST_SECRET_ARN'),
    digestSecretVersionId: envString(environment, 'RING_DIGEST_SECRET_VERSION_ID'),
    cacheTtlMs: 60000, clock });
  const secret = (await loader.loadDigest()).secret;
  if (typeof secret?.recordHmacKey !== 'string' || secret.recordHmacKey.length < 32) deny('b02_digest_key_missing');
  let closed = false;
  const digest = async (purpose, source) => {
    if (closed || typeof purpose !== 'string' || !/^[a-z-]{1,64}$/u.test(purpose) || typeof source !== 'string' || !source || source.length > 4096) deny();
    return createHmac('sha256', secret.recordHmacKey).update(`${purpose}\0${source}`).digest('hex');
  };
  const store = createDynamoIdentityAuthorityStore({ getItem: ports.getItem, transactWrite: ports.transactWrite, tableName, clock });
  const identityEnvelope = createIdentityEnvelope({ generateDataKey: ports.generateDataKey, decryptDataKey: ports.decryptDataKey,
    keyId: envString(environment, 'RING_TOKEN_KMS_KEY_ID'), application: envString(environment, 'RING_APPLICATION'), tableName, random: randomBytes });
  return Object.freeze({ ports, tableName, store, digest, identityEnvelope,
    async ringClient() {
      if (closed) deny();
      const provider = (await loader.loadProvider()).secret;
      return createRingClient({ clientId: provider.clientId, clientSecret: provider.clientSecret, timeoutMs: 3000 });
    },
    async close() { closed = true; loader.invalidate();
      if (clients) for (const client of Object.values(clients)) client.destroy();
      return { closed: true }; } });
  } catch (error) {
    loader?.invalidate();
    if (clients) for (const client of Object.values(clients)) client.destroy();
    throw error;
  }
}
export function cloudAuthorizationProfile(environment) {
  const issuer = envString(environment, 'RING_MCP_ISSUER');
  const resource = envString(environment, 'RING_MCP_RESOURCE_URI');
  const scopes = JSON.parse(envString(environment, 'RING_MCP_REQUIRED_SCOPES'));
  if (!/^https:\/\/cognito-idp\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?\/[A-Za-z0-9_-]+$/u.test(issuer) ||
      !resource.startsWith('https://') || !Array.isArray(scopes) || !scopes.length || scopes.some(s => !s || !/^[\x21-\x7e]{1,128}$/u.test(s)) || new Set(scopes).size !== scopes.length) deny();
  return Object.freeze({ issuer, resource, scopes: Object.freeze(scopes) });
}
export async function createRingB02SessionSeam({ environment = process.env, resources, clock = Date.now } = {}) {
  const r = resources ?? await createCloudIdentityResources({ environment, clock });
  const projecting = createProjectingIdentityAuthority({ store: r.store, digest: r.digest, identityEnvelope: r.identityEnvelope,
    extractSession(context) {
      if (!context || typeof context.sessionProof !== 'string' || typeof context.csrf !== 'string') deny('b02_link_session_denied');
      return Object.freeze({ sessionProof: context.sessionProof, csrf: context.csrf });
    } });
  return Object.freeze({ identityAuthority: projecting.identityAuthority,
    async resolveLinkSession({ transport, headers }) {
      if (transport?.method !== 'GET' || transport?.path !== '/ring/link' || transport?.resource !== '/ring/link') deny('b02_link_transport_denied');
      // The resulting proof is revalidated against durable owner/session/grant/account state by identityAuthority.
      return extractCloudSessionCookies(headers);
    },
    async close() { try { await projecting.close(); } finally { await r.close(); } return { closed: true }; }
  });
}
export function createLambdaInvocationSourcePort({ environment = process.env } = {}) {
  let closed = false;
  return Object.freeze({ async verifyInvocation({ event, invocationContext, admissionSha256 }) {
    const functionName = envString(environment, 'AWS_LAMBDA_FUNCTION_NAME');
    const region = envString(environment, 'AWS_REGION');
    if (closed || !/^AWS_Lambda_nodejs[0-9]+\.x$/u.test(envString(environment, 'AWS_EXECUTION_ENV')) ||
        invocationContext?.functionName !== functionName || typeof invocationContext.awsRequestId !== 'string' ||
        !/^[a-f0-9-]{36}$/u.test(invocationContext.awsRequestId) || typeof invocationContext.invokedFunctionArn !== 'string' ||
        invocationContext.invokedFunctionArn !== envString(environment, 'RING_MCP_FUNCTION_ARN') ||
        !invocationContext.invokedFunctionArn.startsWith(`arn:aws:lambda:${region}:`) ||
        !invocationContext.invokedFunctionArn.endsWith(`:function:${functionName}`) || !event?.requestContext ||
        typeof admissionSha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(admissionSha256)) deny('b02_lambda_invocation_denied');
    return Object.freeze({ source: 'aws-apigateway-rest-lambda', event, invocationContext, admissionSha256 });
  }, async close() { closed = true; return { closed: true }; } });
}
export async function createRingB02FormalMcpSeam({ environment = process.env, resources, clock = Date.now,
  commandServiceFactory, commandStoreFactory } = {}) {
  const r = resources ?? await createCloudIdentityResources({ environment, clock });
  const authorizationProfile = cloudAuthorizationProfile(environment);
  const reader = createCloudOwnerAssociationReader({ getItem: r.ports.getItem, transactGet: r.ports.transactGet,
    tableName: r.tableName, digest: r.digest, profile: authorizationProfile, clock });
  const createStore = commandStoreFactory ?? (await import('./mac-command-store.mjs')).createDynamoMacCommandStore;
  const createService = commandServiceFactory ?? (await import('./mac-command-service.mjs')).createMacCommandService;
  const store = createStore({ ports: r.ports, tableName: envString(environment, 'RING_EVENT_TABLE_NAME'), clock });
  const macProofAuthority = createMacCommandProofAuthority({ ports: r.ports, tableName: envString(environment, 'RING_EVENT_TABLE_NAME'), audience: authorizationProfile.resource, clock });
  const commands = createService({ store, macProofAuthority, authorize: reader.authorize, clock, randomBytes });
  const contexts = new WeakMap();
  let closed = false;
  const tools = Object.freeze([
    { name: 'software_test_switch.set', description: 'Request the owner Mac software switch change; PENDING is not execution.',
      inputSchema: { type: 'object', properties: { enabled: { type: 'boolean' } }, required: ['enabled'], additionalProperties: false } },
    { name: 'software_test_switch.result', description: 'Read the durable receipt for a previously submitted command.',
      inputSchema: { type: 'object', properties: { commandId: { type: 'string' } }, required: ['commandId'], additionalProperties: false } },
    { name: 'home_device.command', description: 'Request one action on an owner-paired SIMULATED home device via the owner Mac; PENDING is not execution.',
      inputSchema: { type: 'object', properties: {
        deviceId: { type: 'string', enum: ['living_light', 'air_conditioner', 'dehumidifier', 'robot_vacuum', 'camera', 'front_door'] },
        action: { type: 'string', enum: ['on', 'off', 'start', 'pause', 'dock', 'arm', 'lock'] } },
        required: ['deviceId', 'action'], additionalProperties: false } },
    { name: 'home_device.result', description: 'Read the durable receipt for a previously submitted home device command.',
      inputSchema: { type: 'object', properties: { commandId: { type: 'string' } }, required: ['commandId'], additionalProperties: false } }
  ]);
  const formalContextPort = Object.freeze({ async resolve(input) {
    if (closed) deny();
    await reader.authorize({ request: input.request, actor: input.actor });
    const intentHandle = Object.freeze(Object.create(null));
    contexts.set(intentHandle, { request: input.request, actor: input.actor, envelope: input.effectiveEnvelope });
    return Object.freeze({ source: 'remote', serverContext: Object.freeze({ intentHandle }) });
  }, async close() { closed = true; await reader.close(); return { closed: true }; } });
  const profile = Object.freeze({ profile: 'FORMAL', ready: true,
    async list(options = {}) { if (closed || Object.keys(options).length) deny(); return { tools }; },
    async call(envelope, context) {
      const binding = contexts.get(context?.handle?.intentHandle);
      contexts.delete(context?.handle?.intentHandle);
      if (closed || context?.path !== 'remote-encrypted' || !binding || binding.envelope !== envelope) deny('b02_cloud_context_denied');
      let result;
      if (envelope?.params?.name === 'software_test_switch.result' || envelope?.params?.name === 'home_device.result') {
        const args = envelope.params.arguments;
        if (!args || Object.keys(args).length !== 1 || typeof args.commandId !== 'string') deny();
        result = await commands.read({ request: binding.request, actor: binding.actor, commandId: args.commandId });
      } else {
        result = await commands.submit({ request: binding.request, actor: binding.actor, envelope });
      }
      return Object.freeze({ jsonrpc: '2.0', id: envelope.id,
        result: { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result, isError: false } });
    }
  });
  const assembly = Object.freeze({ mode: 'FORMAL', profile, routeSet: createFormalRouteSet(),
    async close() { closed = true; try { await store.close?.(); } finally { await r.close(); } return { closed: true }; } });
  return Object.freeze({ assembly, formalContextPort, invocationSourcePort: createLambdaInvocationSourcePort({ environment }) });
}
// Separate server-owned session route composition. Bearer verification must run first on the same request object.
export async function createRingCloudBrowserSessionIssuer({ environment = process.env, resources, clock = Date.now } = {}) {
  const r = resources ?? await createCloudIdentityResources({ environment, clock });
  const reader = createCloudOwnerAssociationReader({ getItem: r.ports.getItem, transactGet: r.ports.transactGet,
    tableName: r.tableName, digest: r.digest, profile: cloudAuthorizationProfile(environment), clock });
  const issuer = createCloudBrowserSessionIssuer({ associationReader: reader, transactWrite: r.ports.transactWrite,
    tableName: r.tableName, digest: r.digest, clock });
  return Object.freeze({ issue: issuer.issue, async close() { try { await reader.close(); } finally { await r.close(); } return { closed: true }; } });
}

export async function createRingCloudOwnerAssociationInstaller({ environment = process.env, resources, clock = Date.now } = {}) {
  const r = resources ?? await createCloudIdentityResources({ environment, clock });
  try {
    const installer = createCloudOwnerAssociationInstaller({ transactWrite: r.ports.transactWrite, tableName: r.tableName,
      digest: r.digest, identityEnvelope: r.identityEnvelope, ringClient: await r.ringClient(),
      approvalSha256: envString(environment, 'RING_OWNER_ASSOCIATION_APPROVAL_SHA256'), profile: cloudAuthorizationProfile(environment), clock });
    return Object.freeze({ install: installer.install, close: r.close });
  } catch (error) { await r.close(); throw error; }
}
export async function createRingCloudCommandService({ environment = process.env, resources, clock = Date.now } = {}) {
  const r = resources ?? await createCloudIdentityResources({ environment, clock });
  let reader, store;
  try {
    reader = createCloudOwnerAssociationReader({ getItem: r.ports.getItem, transactGet: r.ports.transactGet,
      tableName: r.tableName, digest: r.digest, profile: cloudAuthorizationProfile(environment), clock });
    const { createDynamoMacCommandStore } = await import('./mac-command-store.mjs');
    const { createMacCommandService } = await import('./mac-command-service.mjs');
    store = createDynamoMacCommandStore({ ports: r.ports, tableName: envString(environment, 'RING_EVENT_TABLE_NAME'), clock });
    const macProofAuthority = createMacCommandProofAuthority({ ports: r.ports, tableName: envString(environment, 'RING_EVENT_TABLE_NAME'), audience: cloudAuthorizationProfile(environment).resource, clock });
    const commands = createMacCommandService({ store, macProofAuthority, authorize: reader.authorize, clock, randomBytes });
    return Object.freeze({ commands, async close() {
      try { await reader.close(); await store.close?.(); } finally { await r.close(); }
      return { closed: true };
    } });
  } catch (error) { try { await reader?.close(); await store?.close?.(); } finally { await r.close(); } throw error; }
}

// Operator-only enrollment ceremony; this export is not an HTTP route.
export async function createRingCloudMacEnrollmentInstaller({ environment = process.env, resources, clock = Date.now } = {}) {
  const r = resources ?? await createCloudIdentityResources({ environment, clock });
  let reader;
  try {
    reader = createCloudOwnerAssociationReader({ getItem: r.ports.getItem, transactGet: r.ports.transactGet, tableName: r.tableName, digest: r.digest, profile: cloudAuthorizationProfile(environment), clock });
    const installer = createMacEnrollmentInstaller({ ports: r.ports, tableName: envString(environment, 'RING_EVENT_TABLE_NAME'), authorize: reader.authorize,
      approvalSha256: envString(environment, 'RING_MAC_ENROLLMENT_APPROVAL_SHA256'), clock });
    return Object.freeze({ install: installer.install, async close() { try { await reader.close(); } finally { await r.close(); } return { closed: true }; } });
  } catch (error) { try { await reader?.close(); } finally { await r.close(); } throw error; }
}
