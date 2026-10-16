#!/usr/bin/env node
// Agent bridge: a local stdio MCP server that forwards home_device.command / home_device.result to your cloud MCP.
//   1. node vendor_mac_launcher/mac-worker.mjs login-url     (open the URL, sign in with MFA, copy the final callback URL)
//   2. start the bridge from your MCP client with env RING_MAC_CALLBACK_URL="<callback URL>", e.g.
//      npx @modelcontextprotocol/inspector -e RING_MAC_CALLBACK_URL="<callback URL>" node vendor_mac_launcher/mcp-bridge.mjs
// The callback is exchanged once at start; the access token stays in memory (about 5 minutes) and is never printed.
import { DEFAULT_CONFIG, resolveConfig } from './src/config.mjs';
import { defaultStateDir } from './src/state.mjs';
import { openBridgeSession } from './src/launcher.mjs';
import { createBridge, serveStdio } from './src/mcp-bridge.mjs';

const log = line => process.stderr.write(new Date().toISOString() + ' mcp-bridge ' + line + '\n');
async function main() {
  const callbackUrl = process.env.RING_MAC_CALLBACK_URL; delete process.env.RING_MAC_CALLBACK_URL;
  if (!callbackUrl) { process.stderr.write('ERROR USAGE: set RING_MAC_CALLBACK_URL to the callback URL from mac-worker.mjs login-url\n'); process.exitCode = 2; return; }
  const cfg = resolveConfig(DEFAULT_CONFIG);
  const session = await openBridgeSession({ stateDir: defaultStateDir(), cfg, callbackUrl });
  log('ready; cognito token exchanged (not shown), valid until ' + new Date(session.expiresAtMs).toISOString());
  await serveStdio({ bridge: createBridge({ cfg, getAccessToken: session.getAccessToken, log }), input: process.stdin, output: process.stdout });
}
main().catch(e => { process.stderr.write('ERROR ' + (typeof e?.code === 'string' ? e.code : 'INTERNAL') + '\n'); process.exitCode = 1; });
