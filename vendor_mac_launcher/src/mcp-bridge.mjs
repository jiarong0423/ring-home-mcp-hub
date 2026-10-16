// Local stdio MCP server for an AI agent or MCP Inspector. It forwards tools/list and the two home_device tools to the
// owner's cloud /mcp with the Cognito token from ONE owner login, kept in memory and never written to stdout or stderr.
// The device/action allowlist is deliberately NOT duplicated here: the cloud contract, the Mac worker and the local
// console enforce it, so a forbidden action (door unlock, camera disarm) is refused by the cloud itself.
import { randomBytes } from 'node:crypto';
import { createInterface } from 'node:readline';
import { callMcpTool, listMcpTools } from './mcp-client.mjs';

export const BRIDGE_TOOLS = Object.freeze(['home_device.command', 'home_device.result']);
const PROTOCOL_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26'];
const MAX_LINE = 65536;
const CODE = /^[A-Z][A-Za-z0-9_]{1,127}$/u;
const safeCode = error => typeof error?.code === 'string' && CODE.test(error.code) ? error.code : 'BRIDGE_STEP_FAILED';
const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
const rpcError = (id, code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });

export function createBridge({ cfg, getAccessToken, requestImpl, random = randomBytes, log = () => {}, timeoutMs = 8000 }) {
  const rid = () => 'bridge-' + random(9).toString('hex');
  async function tools() {
    const listed = await listMcpTools(cfg, { token: await getAccessToken(), id: rid(), requestImpl, timeoutMs });
    return listed.filter(x => BRIDGE_TOOLS.includes(x.name));
  }
  async function call(params) {
    const name = params?.name;
    if (!BRIDGE_TOOLS.includes(name)) return { content: [{ type: 'text', text: 'Refused by bridge: TOOL_NOT_FORWARDED' }], isError: true };
    const args = params.arguments ?? {};
    if (!plain(args)) return { content: [{ type: 'text', text: 'Refused by bridge: ARGUMENTS_INVALID' }], isError: true };
    try {
      const sc = await callMcpTool(cfg, { token: await getAccessToken(), name, arguments: args, id: rid(), requestImpl, timeoutMs });
      log('tools/call ' + name + ' -> ' + (typeof sc.status === 'string' ? sc.status.slice(0, 32) : 'UNKNOWN') + ' executed=' + (sc.executed === true));
      return { content: [{ type: 'text', text: JSON.stringify(sc) }], structuredContent: sc, isError: false };
    } catch (error) {
      const code = safeCode(error);
      log('tools/call ' + name + ' refused ' + code);
      return { content: [{ type: 'text', text: 'Refused by cloud MCP: ' + code }], isError: true };
    }
  }
  // Returns the JSON-RPC response for one parsed message, or null for notifications.
  async function handle(msg) {
    if (!plain(msg) || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') return rpcError(msg?.id ?? null, -32600, 'Invalid Request');
    if (!Object.hasOwn(msg, 'id')) return null;
    const { id, method, params } = msg;
    if (method === 'initialize') {
      const asked = params?.protocolVersion;
      return { jsonrpc: '2.0', id, result: { protocolVersion: PROTOCOL_VERSIONS.includes(asked) ? asked : PROTOCOL_VERSIONS[0],
        capabilities: { tools: {} }, serverInfo: { name: 'ring-home-mcp-bridge', version: '0.1.0' },
        instructions: 'Forwards home_device.command and home_device.result to the owner\'s cloud MCP. A command counts as executed only when home_device.result reports executed=true, after the owner\'s Mac returned a signed receipt.' } };
    }
    if (method === 'ping') return { jsonrpc: '2.0', id, result: {} };
    if (method === 'tools/list') {
      try { return { jsonrpc: '2.0', id, result: { tools: await tools() } }; }
      catch (error) { log('tools/list refused ' + safeCode(error)); return rpcError(id, -32603, 'Cloud MCP tools/list failed: ' + safeCode(error)); }
    }
    if (method === 'tools/call') return { jsonrpc: '2.0', id, result: await call(params) };
    return rpcError(id, -32601, 'Method not found');
  }
  return Object.freeze({ handle });
}

// Newline-delimited JSON-RPC over stdio. Messages are handled in arrival order; stdout carries JSON-RPC only.
export function serveStdio({ bridge, input, output }) {
  const rl = createInterface({ input, crlfDelay: Infinity });
  let chain = Promise.resolve();
  const write = v => { if (v) output.write(JSON.stringify(v) + '\n'); };
  rl.on('line', line => {
    chain = chain.then(async () => {
      if (!line.trim()) return;
      if (line.length > MAX_LINE) return write(rpcError(null, -32700, 'Parse error'));
      let msg; try { msg = JSON.parse(line); } catch { return write(rpcError(null, -32700, 'Parse error')); }
      write(await bridge.handle(msg));
    });
  });
  return new Promise(resolve => rl.on('close', () => { chain.then(resolve); }));
}
