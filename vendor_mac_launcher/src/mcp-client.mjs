// Minimal MCP client for the cloud /mcp route: MODERN_STATELESS wire (no initialize, no session), one tools/call per POST.
// Wire rules mirrored from src/formal-runtime/stateless-wire.mjs (validateFormalMcpWireRequest); vendored copy in vendor/.
import { request as httpsRequest } from 'node:https';
import { MODERN_MCP_PROTOCOL_VERSION } from '../vendor/stateless-wire.mjs';
import { coded } from './config.mjs';

export function mcpToolCallRequest({ name, arguments: args, id }) {
  const envelope = { jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args, _meta: {
    'io.modelcontextprotocol/protocolVersion': MODERN_MCP_PROTOCOL_VERSION,
    'io.modelcontextprotocol/clientCapabilities': {},
    'io.modelcontextprotocol/clientInfo': { name: 'ring-mac-launcher', version: '0.1.0' } } } };
  const headers = { accept: 'application/json, text/event-stream', 'content-type': 'application/json',
    'mcp-protocol-version': MODERN_MCP_PROTOCOL_VERSION, 'mcp-method': 'tools/call', 'mcp-name': name };
  return { envelope, headers };
}
function parseBody(contentType, text, id) {
  const ct = (contentType ?? '').toLowerCase();
  let messages = [];
  if (ct.startsWith('text/event-stream')) {
    for (const block of text.split(/\r?\n\r?\n/u)) {
      const data = block.split(/\r?\n/u).filter(l => l.startsWith('data:')).map(l => l.slice(5).replace(/^ /u, '')).join('\n');
      if (data) { try { messages.push(JSON.parse(data)); } catch { throw coded('MCP_SSE_JSON'); } }
    }
  } else if (ct.startsWith('application/json')) {
    try { messages = [JSON.parse(text)]; } catch { throw coded('MCP_RESPONSE_JSON'); }
  } else throw coded('MCP_RESPONSE_TYPE');
  const m = messages.find(x => x && x.jsonrpc === '2.0' && x.id === id);
  if (!m) throw coded('MCP_RESPONSE_NO_MATCHING_ID');
  return m;
}
// Returns the tool's structuredContent. Fail-closed with generic codes; never includes bodies or tokens in errors.
export function callMcpTool(cfg, { token, name, arguments: args, id, requestImpl = httpsRequest, timeoutMs = 8000 }) {
  if (typeof token !== 'string' || !/^[A-Za-z0-9._-]{3,16384}$/u.test(token)) return Promise.reject(coded('MCP_BEARER'));
  const { envelope, headers } = mcpToolCallRequest({ name, arguments: args, id });
  const body = Buffer.from(JSON.stringify(envelope));
  return new Promise((resolve, reject) => {
    let done = false, req;
    const finish = (err, v) => { if (done) return; done = true; clearTimeout(t); if (err) { req?.destroy(); reject(coded(err)); } else resolve(v); };
    const t = setTimeout(() => finish('MCP_TIMEOUT'), timeoutMs);
    try {
      req = requestImpl(new URL(cfg.apiBase + '/mcp'), { method: 'POST', minVersion: 'TLSv1.2', rejectUnauthorized: true,
        headers: { ...headers, authorization: 'Bearer ' + token, 'content-length': String(body.length) } }, res => {
        const chunks = []; let size = 0;
        res.on('data', c => { size += c.length; if (size > 65536) { res.destroy(); finish('MCP_RESPONSE_SIZE'); } else chunks.push(c); });
        res.on('error', () => finish('MCP_UNAVAILABLE'));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          if (res.statusCode !== 200) {
            let e = null; try { e = JSON.parse(text); } catch {}
            const code = typeof e?.error === 'string' && /^[A-Za-z0-9_]{1,64}$/u.test(e.error) ? '_' + e.error
              : Number.isSafeInteger(e?.error?.code) ? '_RPC' + e.error.code : '';
            return finish('MCP_HTTP_' + res.statusCode + code);
          }
          let m; try { m = parseBody(res.headers['content-type'], text, id); } catch (err) { return finish(err.code); }
          if (m.error) return finish('MCP_RPC_ERROR' + (Number.isSafeInteger(m.error.code) ? '_' + m.error.code : ''));
          const r = m.result;
          if (!r || typeof r !== 'object' || r.isError === true) return finish('MCP_TOOL_ERROR');
          let sc = r.structuredContent;
          if (!sc && Array.isArray(r.content) && r.content[0]?.type === 'text') { try { sc = JSON.parse(r.content[0].text); } catch {} }
          if (!sc || typeof sc !== 'object') return finish('MCP_RESULT_SHAPE');
          finish(null, sc);
        });
      });
      req.on('error', () => finish('MCP_UNAVAILABLE'));
      req.end(body);
    } catch { finish('MCP_UNAVAILABLE'); }
  });
}
