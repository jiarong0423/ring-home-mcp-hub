import { denyFormalRuntime, exactObject } from './protocol.mjs';
import { deriveFormalEntryTransport } from './production-ports.mjs';

export function createDemoMcpProfile({ listTools, dispatchMcpToolCall }) {
  if (typeof listTools !== 'function' || typeof dispatchMcpToolCall !== 'function') denyFormalRuntime('B02_DEMO_PROFILE_DENIED');
  return Object.freeze({ profile: 'DEMO', configured: false, ready: true,
    async list() { return listTools(); },
    async call(envelope, context = {}) { return dispatchMcpToolCall(envelope, context); },
    async close() { return Object.freeze({ closed: true }); }
  });
}

export function createFormalMcpProfile({ runtime, ports, bootEpoch, clock }) {
  if (!runtime || typeof runtime.issueMcpEntry !== 'function' || typeof runtime.consumeMcpEntry !== 'function' ||
      !ports?.formalCapabilityPort || !bootEpoch || !clock) denyFormalRuntime('B02_FORMAL_PROFILE_DENIED');
  return Object.freeze({ profile: 'FORMAL', configured: true,
    get ready() { return runtime.status().state === 'READY'; },
    async list(options = {}) {
      if (runtime.status().state !== 'READY') denyFormalRuntime('B02_FORMAL_RUNTIME_NOT_READY');
      return ports.formalCapabilityPort.list(options);
    },
    async call(envelope, context) { return dispatchFormalMcpToolCall({ envelope, context, runtime, ports, bootEpoch, clock }); },
    async close() { await runtime.close(); return Object.freeze({ closed: true }); }
  });
}

export function createExclusiveMcpProfile({ mode, demo, formal }) {
  if (mode === 'DEMO' && demo && !formal) return createDemoMcpProfile(demo);
  if (mode === 'FORMAL' && formal && !demo) return createFormalMcpProfile(formal);
  denyFormalRuntime('B02_MCP_PROFILE_EXCLUSIVITY_DENIED');
}

export async function dispatchFormalMcpToolCall({ envelope, context, runtime, ports, bootEpoch, clock }) {
  const request = exactObject(envelope, ['jsonrpc', 'id', 'method', 'params'], 'B02_FORMAL_MCP_ENVELOPE_DENIED');
  if (request.jsonrpc !== '2.0' || request.method !== 'tools/call') denyFormalRuntime('B02_FORMAL_MCP_ENVELOPE_DENIED');
  const params = exactObject(request.params, ['name', 'arguments'], 'B02_FORMAL_MCP_ENVELOPE_DENIED');
  const callContext = exactObject(context, ['path', 'handle'], 'B02_FORMAL_MCP_CONTEXT_DENIED');
  const transport = await deriveFormalEntryTransport({ path: callContext.path, handle: callContext.handle, ports,
    bootEpoch, scope: 'mcp', capability: params.name, purpose: 'mcp-entry', clock, envelope });
  const grant = await runtime.issueMcpEntry({ transport, scope: 'mcp', capability: params.name, purpose: 'mcp-entry' });
  const admitted = await runtime.consumeMcpEntry({ grant, transport });
  const result = await ports.formalCapabilityPort.execute({ capability: params.name, arguments: params.arguments,
    admission: admitted, envelope });
  return Object.freeze({ jsonrpc: '2.0', id: request.id, result });
}

export function createDemoRouteSet() {
  return Object.freeze({ routes: Object.freeze(['health', 'initialize', 'tools/list', 'tools/call', 'simulator/read', 'simulator/write']),
    timers: Object.freeze(['simulator.tick']) });
}

export function createFormalRouteSet() {
  return Object.freeze({ routes: Object.freeze(['health', 'oauth/protected-resource', 'initialize',
      'server/discover', 'tools/list', 'tools/call']),
    timers: Object.freeze([]) });
}

export function createServerOwnedFormalCallContext({ source, serverContext }) {
  if (source === 'local') {
    const fields = exactObject(serverContext, ['socketHandle', 'sessionHandle'], 'B02_FORMAL_SERVER_CONTEXT_DENIED');
    return Object.freeze({ path: 'local-encrypted', handle: Object.freeze({
      socketHandle: fields.socketHandle, sessionHandle: fields.sessionHandle }) });
  }
  if (source === 'remote') {
    const fields = exactObject(serverContext, ['intentHandle'], 'B02_FORMAL_SERVER_CONTEXT_DENIED');
    return Object.freeze({ path: 'remote-encrypted', handle: Object.freeze({ intentHandle: fields.intentHandle }) });
  }
  denyFormalRuntime('B02_FORMAL_SERVER_CONTEXT_DENIED');
}

export async function dispatchExecutableFormalRequest({ profile, envelope, source, serverContext }) {
  if (!profile || profile.profile !== 'FORMAL' || typeof profile.call !== 'function') {
    denyFormalRuntime('B02_FORMAL_EXECUTABLE_DENIED');
  }
  return profile.call(envelope, createServerOwnedFormalCallContext({ source, serverContext }));
}

export function routeIdForRequest({ method, pathname, mcpMethod = null }) {
  if (method === 'GET' && pathname === '/health') return 'health';
  if (method === 'GET' && pathname === '/.well-known/oauth-protected-resource') {
    return 'oauth/protected-resource';
  }
  if (method === 'POST' && pathname === '/mcp') {
    if (mcpMethod === 'initialize') return 'initialize';
    if (mcpMethod === 'server/discover') return 'server/discover';
    if (mcpMethod === 'tools/list') return 'tools/list';
    if (mcpMethod === 'tools/call') return 'tools/call';
    return null;
  }
  if (pathname.startsWith('/api/')) return method === 'GET' ? 'simulator/read' : 'simulator/write';
  return null;
}

export function assertAssemblyRouteAllowed(assembly, routeId) {
  if (!assembly || !assembly.routeSet || !Array.isArray(assembly.routeSet.routes) ||
      typeof routeId !== 'string' || !assembly.routeSet.routes.includes(routeId)) {
    denyFormalRuntime('B02_FORMAL_ROUTE_DENIED');
  }
  return routeId;
}

export function createExecutableServerAssembly({ mode, demoFactory, formalFactory }) {
  if (mode === 'DEMO') {
    if (typeof demoFactory !== 'function' || formalFactory !== null) denyFormalRuntime('B02_MCP_PROFILE_EXCLUSIVITY_DENIED');
    const demo = demoFactory();
    const profile = createExclusiveMcpProfile({ mode: 'DEMO', demo, formal: null });
    return Object.freeze({ mode, profile, routeSet: createDemoRouteSet(), listening: false,
      async close() { await profile.close(); return Object.freeze({ closed: true }); } });
  }
  if (mode !== 'FORMAL' || demoFactory !== null || typeof formalFactory !== 'function') {
    denyFormalRuntime('B02_MCP_PROFILE_EXCLUSIVITY_DENIED');
  }
  const formal = formalFactory();
  const profile = createExclusiveMcpProfile({ mode: 'FORMAL', demo: null, formal });
  return Object.freeze({ mode, profile, routeSet: createFormalRouteSet(), listening: false,
    async close() { await profile.close(); return Object.freeze({ closed: true }); } });
}

export async function closeExecutableServerAssembly(assembly) {
  if (!assembly || typeof assembly.close !== 'function') denyFormalRuntime('B02_FORMAL_EXECUTABLE_DENIED');
  return assembly.close();
}
