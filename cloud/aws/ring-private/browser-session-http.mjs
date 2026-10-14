import { createHash, createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { request as httpsRequest } from 'node:https';
import { types } from 'node:util';
const PATHS = new Map([['GET /auth/login','login'],['GET /auth/callback','callback'],['GET /auth/logout','logout'],['POST /auth/session','session']]);
const COOKIE = '__Host-ring_oauth';
const baseHeaders = { 'content-type':'application/json; charset=utf-8','cache-control':'no-store','referrer-policy':'no-referrer','x-content-type-options':'nosniff','content-security-policy':"default-src 'none'; frame-ancestors 'none'" };
function deny() { throw new TypeError('browser_session_denied'); }
function plain(value) { if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value)) deny(); const ds=Object.getOwnPropertyDescriptors(value); if (Reflect.ownKeys(ds).some(k=>typeof k!=='string'||!Object.hasOwn(ds[k],'value'))) deny(); return value; }
export function parseBrowserSessionEvent(event) {
  const e=plain(event), c=plain(e.requestContext);
  const route=PATHS.get(`${e.httpMethod} ${e.path}`);
  if (!route || e.resource!==e.path || c.httpMethod!==e.httpMethod || ![e.path,`/${c.stage}${e.path}`].includes(c.path) || e.isBase64Encoded!==false || (e.body!==null&&e.body!==undefined&&e.body!=='')) deny();
  const headers={}, single=plain(e.headers), multi=plain(e.multiValueHeaders);
  if (Object.keys(single).length>64 || Object.keys(single).length!==Object.keys(multi).length) deny();
  for (const [k,v] of Object.entries(single)) {
    const lower=k.toLowerCase(); const matches=Object.keys(multi).filter(x=>x.toLowerCase()===lower);
    if (!/^[a-z0-9-]{1,64}$/u.test(lower) || Object.hasOwn(headers,lower) || typeof v!=='string' || v.length>4096 || /[\x00-\x1f\x7f]/u.test(v) || matches.length!==1 || !Array.isArray(multi[matches[0]]) || multi[matches[0]].length!==1 || multi[matches[0]][0]!==v) deny();
    headers[lower]=v;
  }
  const q=e.queryStringParameters??{}, qm=e.multiValueQueryStringParameters??{}; plain(q);plain(qm);
  const allowed=route==='callback'?['code','state']:route==='login'?['time','nonce']:[];
  if (Object.keys(q).length!==Object.keys(qm).length || Object.keys(q).some(k=>!allowed.includes(k)||typeof q[k]!=='string'||q[k].length>2048||!Array.isArray(qm[k])||qm[k].length!==1||qm[k][0]!==q[k])) deny();
  if (route==='callback' && (Object.keys(q).length!==2 || !/^[A-Za-z0-9_-]{43}$/u.test(q.state) || !/^[A-Za-z0-9._~-]{1,2048}$/u.test(q.code))) deny();
  if (route==='login' && Object.keys(q).length && (Object.keys(q).length!==2 || !/^[1-9][0-9]{12}$/u.test(q.time) || !/^[A-Za-z0-9_-]{43}$/u.test(q.nonce))) deny();
  return {route,headers,query:{...q}};
}
export function createCognitoCodeExchange({domain,clientId,callbackUri,requestImpl=httpsRequest}) {
  return async ({code,verifier}) => {
    const body=new URLSearchParams({grant_type:'authorization_code',client_id:clientId,redirect_uri:callbackUri,code,code_verifier:verifier}).toString();
    return new Promise((resolve,reject)=>{ let done=false, req, timer; const finish=(error,value)=>{if(done)return;done=true;clearTimeout(timer);req?.destroy();error?reject(new TypeError('browser_token_exchange_denied')):resolve(value);};
      timer=setTimeout(()=>finish(true),3000);
      try { req=requestImpl(new URL('/oauth2/token',domain),{method:'POST',minVersion:'TLSv1.2',rejectUnauthorized:true,timeout:3000,headers:{'content-type':'application/x-www-form-urlencoded','content-length':Buffer.byteLength(body)}},res=>{
        if(res.statusCode!==200){res.resume();finish(true);return;} let bytes=0; const chunks=[];
        res.on('data',chunk=>{bytes+=chunk.length;if(bytes>32768){res.destroy();finish(true);}else chunks.push(chunk);});res.on('error',()=>finish(true));res.on('end',()=>{try{const value=JSON.parse(Buffer.concat(chunks).toString('utf8'));if(typeof value.access_token!=='string'||value.access_token.length>16384||value.token_type?.toLowerCase()!=='bearer')deny();finish(false,value.access_token);}catch{finish(true);}});
      }); req.on('timeout',()=>finish(true));req.on('error',()=>finish(true));req.end(body); }catch{finish(true);}
    });
  };
}
export function createBrowserSessionHttp({config,transport,authorizationPolicy,issuer,store,exchange,digest,clock=Date.now,random=randomBytes}) {
  const domain=new URL(config.domain), callback=new URL(config.callbackUri), logout=new URL(config.logoutUri), resource=new URL(config.resource);
  if (domain.protocol!=='https:'||!/^[-a-z0-9]+\.auth\.[a-z0-9-]+\.amazoncognito\.com$/u.test(domain.hostname)||domain.pathname!=='/'||domain.search||domain.hash||domain.username||domain.password||callback.origin!==resource.origin||logout.origin!==resource.origin||callback.href!==`${resource.origin}/${config.stage}/auth/callback`||logout.href!==`${resource.origin}/${config.stage}/auth/logout`) deny();
  const clear=`${COOKIE}=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`;
  const response=(statusCode,status,extra={})=>({statusCode,headers:{...baseHeaders,...extra.headers},body:JSON.stringify({status,productionAdmitted:false}),...(extra.cookies?{multiValueHeaders:{'set-cookie':extra.cookies}}:{})});
  const key=()=>digest('browser-oauth-key','v1').then(v=>Buffer.from(v,'hex'));
  const consumeCookie=async headers=>{const parts=(headers.cookie??'').split(';').map(x=>x.trim()).filter(x=>x.startsWith(`${COOKIE}=`));if(parts.length!==1)deny();const raw=parts[0].slice(COOKIE.length+1);if(!/^[A-Za-z0-9_-]{32,3500}$/u.test(raw))deny();const b=Buffer.from(raw,'base64url');const d=createDecipheriv('aes-256-gcm',await key(),b.subarray(0,12));d.setAAD(Buffer.from(config.callbackUri));d.setAuthTag(b.subarray(12,28));return JSON.parse(Buffer.concat([d.update(b.subarray(28)),d.final()]).toString());};
  return Object.freeze({ async handle(event,invocationContext) {
    let parsed;
    try {
      const prepared=await transport.prepareEvent({event,invocationContext});parsed=parseBrowserSessionEvent(prepared);
      const {route,query,headers}=parsed;
      if(route==='logout')return response(200,'signed_out',{cookies:[clear,...['__Host-ring_session','__Host-ring_csrf'].map(n=>`${n}=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`)]});
      if(route==='login') {
        const state=random(32).toString('base64url'),verifier=random(32).toString('base64url'), expiresAt=clock()+300000;
        const returnPath=Object.keys(query).length?`/${config.stage}/ring/link?${new URLSearchParams({time:query.time,nonce:query.nonce})}`:`/${config.stage}/ring/complete`;
        const iv=random(12),cipher=createCipheriv('aes-256-gcm',await key(),iv);cipher.setAAD(Buffer.from(config.callbackUri));const data=Buffer.concat([cipher.update(JSON.stringify({state,verifier,expiresAt,returnPath})),cipher.final()]);
        await store.create({stateDigest:await digest('browser-oauth-state',state),expiresAt});
        const url=new URL('/oauth2/authorize',domain);url.search=new URLSearchParams({response_type:'code',client_id:config.clientId,redirect_uri:config.callbackUri,scope:config.scopes.join(' '),state,code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256',resource:config.resource}).toString();
        return response(303,'login_required',{headers:{location:url.href},cookies:[`${COOKIE}=${Buffer.concat([iv,cipher.getAuthTag(),data]).toString('base64url')}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=300`]});
      }
      let returnPath=`/${config.stage}/ring/complete`, token;
      if(route==='callback') {
        const state=await consumeCookie(headers);if(state.state!==query.state||!Number.isSafeInteger(state.expiresAt)||state.expiresAt<=clock()||state.expiresAt>clock()+300000||!/^\/[A-Za-z0-9_-]+\/ring\/(complete|link\?time=[0-9]{13}&nonce=[A-Za-z0-9_-]{43})$/u.test(state.returnPath))deny();
        await store.consume({stateDigest:await digest('browser-oauth-state',query.state),expiresAt:state.expiresAt,now:clock()});
        token=await exchange({code:query.code,verifier:state.verifier}); returnPath=state.returnPath;
      } else if(headers.origin!==resource.origin)deny();
      const request=Object.freeze({method:'POST',path:'/auth/session',headers:Object.freeze({...headers,...(token?{authorization:`Bearer ${token}`}:{})})});
      transport.bindRequest({event:prepared,request});
      const {actor}=await authorizationPolicy.authorize({request});
      const session=await issuer.issue({request,actor});
      return response(route==='callback'?303:200,'session_issued',{...(route==='callback'?{headers:{location:returnPath}}:{}),cookies:[clear,...session.setCookie]});
    }catch{return response(403,'browser_session_denied',{cookies:parsed?.route==='callback'?[clear]:undefined});}
  } });
}
export function createVerifiedOwnerCeremony({authorizationPolicy,installer}) {
  return Object.freeze({async install({request,ringAccessToken,approvalBytes}) {const {actor}=await authorizationPolicy.authorize({request});return installer.install({request,actor,ringAccessToken,approvalBytes});}});
}
