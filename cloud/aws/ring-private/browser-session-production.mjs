import { createHash } from 'node:crypto';
import { createCloudIdentityResources, createLambdaInvocationSourcePort, cloudAuthorizationProfile, createRingCloudOwnerAssociationInstaller } from './b02-layer-runtime.mjs';
import { createCloudOwnerAssociationReader } from './cloud-owner-association.mjs';
import { createCloudOwnerBootstrap } from './cloud-owner-bootstrap.mjs';
import { createRingTokenClient } from './ring-token-client.mjs';
import { createCloudBrowserSessionIssuer } from './cloud-browser-session.mjs';
import { createPinnedCognitoJwksLoader, readRootLayerFile, admittedGateway, createGatewayTransportPort, FORMAL_MCP_ADMISSION_PATH, layerFilePath, loadPinnedLayerJson } from './mcp-production-ports.mjs';
import { parseNonsecretMcpEnvironment } from './mcp-rest-composition.mjs';
import { createFormalRequestAuthorizationPolicy } from '../../../src/formal-runtime/request-authorization-policy.mjs';
import { createCognitoResourceBoundAccessTokenVerifier } from '../../../src/local_ring/components/oidc-jwt-verifier.mjs';
import { createBrowserSessionHttp, createCognitoCodeExchange, createVerifiedOwnerCeremony, parseBrowserSessionEvent } from './browser-session-http.mjs';
export const OWNER_BOOTSTRAP_APPROVAL_FILE='owner-bootstrap-approval-v1.json';
// Returns null (mechanism absent) unless the deployment explicitly enabled it AND pinned an approval hash.
// Consumed only by POST /owner/bootstrap (mcp-rest-composition); the browser session callback never bootstraps.
export function buildOwnerBootstrap({environment=process.env,resources,clock=Date.now,readFile,ringTokenClient=createRingTokenClient()}={}) {
  if(environment.RING_OWNER_BOOTSTRAP_STATE!=='enabled')return null;
  const approvalSha256=environment.RING_OWNER_BOOTSTRAP_APPROVAL_SHA256;
  if(!/^[a-f0-9]{64}$/u.test(approvalSha256??''))throw new TypeError('owner_bootstrap_not_configured');
  const approvalPath=layerFilePath(OWNER_BOOTSTRAP_APPROVAL_FILE);
  return createCloudOwnerBootstrap({getItem:resources.ports.getItem,transactWrite:resources.ports.transactWrite,tableName:resources.tableName,digest:resources.digest,
    identityEnvelope:resources.identityEnvelope,profile:cloudAuthorizationProfile(environment),approvalSha256,clock,
    loadApproval:async()=>(await loadPinnedLayerJson(approvalPath,approvalSha256,readFile?{readFile}:undefined)).bytes,
    ringTokenClient});
}
export async function createProductionBrowserSessionRuntime({environment=process.env, ownerCeremony=false}={}) {
  if(environment.RING_BROWSER_SESSION_STATE!=='enabled')throw new TypeError('browser_session_not_configured');
  // Reuse the configuration parser; this does not construct or activate the FORMAL MCP application.
  const config=parseNonsecretMcpEnvironment({...environment,RING_MCP_STATE:'enabled'});
  const bytes=await readRootLayerFile(FORMAL_MCP_ADMISSION_PATH);
  if(!/^[a-f0-9]{64}$/u.test(config.admissionSha256??'')||createHash('sha256').update(bytes).digest('hex')!==config.admissionSha256)throw new TypeError('browser_admission_pin_denied');
  const admission=admittedGateway(JSON.parse(bytes.toString('utf8')),config);
  const transport=createGatewayTransportPort({admission,admissionSha256:config.admissionSha256,invocationSourcePort:createLambdaInvocationSourcePort({environment})});
  let r,jwks;
  try {
    r=await createCloudIdentityResources({environment});
    jwks=createPinnedCognitoJwksLoader({issuer:config.issuer,maxJwksAgeSeconds:config.maxJwksAgeSeconds,clockSeconds:()=>Math.floor(Date.now()/1000)});
    const verifier=createCognitoResourceBoundAccessTokenVerifier({issuer:config.issuer,clientId:config.clientId,resource:config.resource,requiredScopes:config.requiredScopes,jwksUri:config.issuer+'/.well-known/jwks.json',maxJwksAgeSeconds:config.maxJwksAgeSeconds,maximumTokenLifetimeSeconds:config.maximumTokenLifetimeSeconds,loadPinnedJwks:jwks.loadPinnedJwks,clock:()=>Math.floor(Date.now()/1000)});
    const policy=createFormalRequestAuthorizationPolicy({accessTokenVerifier:verifier,trustedTransportEvidencePort:transport,resource:config.resource,authorizationServer:config.issuer,scopes:config.requiredScopes});
    const associationReader=createCloudOwnerAssociationReader({getItem:r.ports.getItem,transactGet:r.ports.transactGet,tableName:r.tableName,digest:r.digest,profile:cloudAuthorizationProfile(environment)});
    const issuer=createCloudBrowserSessionIssuer({associationReader,transactWrite:r.ports.transactWrite,tableName:r.tableName,digest:r.digest});
    const key=stateDigest=>({PK:{S:`BROWSER_OAUTH#${stateDigest}`},SK:{S:'STATE'}});
    const store={async create({stateDigest,expiresAt}){await r.ports.transactWrite({TransactItems:[{Put:{TableName:r.tableName,Item:{...key(stateDigest),expires_at:{N:String(Math.floor(expiresAt/1000))},expires_ms:{N:String(expiresAt)}},ConditionExpression:'attribute_not_exists(PK)'}}]});},async consume({stateDigest,expiresAt,now}){await r.ports.transactWrite({TransactItems:[{Delete:{TableName:r.tableName,Key:key(stateDigest),ConditionExpression:'expires_ms = :expiry AND expires_ms > :now',ExpressionAttributeValues:{':expiry':{N:String(expiresAt)},':now':{N:String(now)}}}}]});}};
    const browserConfig={domain:environment.RING_BROWSER_COGNITO_DOMAIN,callbackUri:environment.RING_BROWSER_CALLBACK_URI,logoutUri:environment.RING_BROWSER_LOGOUT_URI,clientId:config.clientId,resource:config.resource,scopes:config.requiredScopes,stage:config.expectedGatewayContext.stage};
    const http=createBrowserSessionHttp({config:browserConfig,transport,authorizationPolicy:policy,issuer,store,digest:r.digest,exchange:createCognitoCodeExchange(browserConfig)});
    let operator;
    if(ownerCeremony) {
      const installer=await createRingCloudOwnerAssociationInstaller({environment,resources:r});
      const ceremony=createVerifiedOwnerCeremony({authorizationPolicy:policy,installer});
      operator=async ({event,invocationContext,ringAccessToken,approvalBytes})=>{
        const prepared=await transport.prepareEvent({event,invocationContext});
        const parsed=parseBrowserSessionEvent(prepared);
        if(parsed.route!=='session'||parsed.headers.origin!==new URL(config.resource).origin)throw new TypeError('owner_ceremony_request_denied');
        const request=Object.freeze({method:'POST',path:'/auth/session',headers:Object.freeze(parsed.headers)});
        transport.bindRequest({event:prepared,request});
        return ceremony.install({request,ringAccessToken,approvalBytes});
      };
    }
    return Object.freeze({...(ownerCeremony?{install:operator}:{handle:http.handle}),async close(){try{await jwks.close();}finally{try{await r.close();}finally{await transport.close();}}return{closed:true};}});
  }catch(error){await jwks?.close();await r?.close();await transport.close();throw error;}
}

// Operator-only adapter: not registered as an HTTP handler. Approval/token are private operator arguments.
export function createProductionBrowserOwnerCeremony({environment=process.env}={}) {
  return createProductionBrowserSessionRuntime({environment,ownerCeremony:true});
}
