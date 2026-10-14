#!/usr/bin/env bash
# Starts the local owner UI with the Cloud MCP (AWS) panel enabled.
# The Mac key passphrase is NOT handled by this script and never enters the OS environment: the server itself
# prompts for it once on this Terminal (hidden, no echo) before it starts listening.
set +x
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ $# -ne 0 ]]; then
  printf 'Usage: bash scripts/start_cloud_panel_demo.sh\n' >&2
  exit 2
fi
if [[ ! -t 0 || ! -t 1 ]]; then
  printf 'ERROR An interactive terminal is required.\n' >&2
  exit 2
fi
if [[ ! -f "${project_root}/src/server.mjs" || ! -f "${project_root}/src/cloud_mcp_panel.mjs" || ! -f "${project_root}/vendor_mac_launcher/src/launcher.mjs" ]]; then
  printf 'ERROR server, cloud panel module or vendored mac launcher not found.\n' >&2
  exit 2
fi
node_bin="$(command -v node || true)"
if [[ -z "${node_bin}" ]]; then
  for candidate in /opt/homebrew/bin/node /usr/local/bin/node; do
    if [[ -x "${candidate}" ]]; then node_bin="${candidate}"; break; fi
  done
fi
if [[ -z "${node_bin}" ]]; then
  printf 'ERROR Node.js is required.\n' >&2
  exit 2
fi

state_dir="${RING_MAC_STATE_DIR:-${HOME}/.ring-mac-worker}"
if [[ "${state_dir}" != /* ]]; then
  printf 'ERROR RING_MAC_STATE_DIR must be an absolute path.\n' >&2
  exit 2
fi

HOME_MCP_DEMO_PASS="$("${node_bin}" -e 'process.stdout.write(require("node:crypto").randomBytes(24).toString("base64url"))')"
HOME_MCP_RING_OPERATOR_PASS="$("${node_bin}" -e 'process.stdout.write(require("node:crypto").randomBytes(24).toString("base64url"))')"
if [[ "${HOME_MCP_RING_OPERATOR_PASS}" == "${HOME_MCP_DEMO_PASS}" ]]; then
  printf 'ERROR Operator passcode must differ from the demo login passcode.\n' >&2
  exit 2
fi

printf 'Mac key state dir: %s\n' "${state_dir}" > /dev/tty

printf 'Local demo login passcode: %s\n' "${HOME_MCP_DEMO_PASS}" > /dev/tty
printf 'Independent local operator passcode (Ring import/discovery AND every cloud action): %s\n' "${HOME_MCP_RING_OPERATOR_PASS}" > /dev/tty
printf 'These local passcodes change when the server restarts. Next, the server asks for the Mac key passphrase (hidden).\n' > /dev/tty
printf 'Then check the line "Mac key: ready (passphrase source: tty)".\n' > /dev/tty

# Never pass a passphrase (or the test-only env source flag) through the environment.
unset RING_PLAYGROUND_ACCESS_TOKEN RING_MAC_CALLBACK_URL RING_MAC_KEY_PASSPHRASE HOME_MCP_CLOUD_PANEL_PASSPHRASE_SOURCE
export HOME_MCP_PORT="${HOME_MCP_PORT:-8765}"
export HOME_MCP_CLOUD_PANEL=1
export RING_MAC_STATE_DIR="${state_dir}"
export HOME_MCP_DEMO_PASS HOME_MCP_RING_OPERATOR_PASS
cd "${project_root}"
exec "${node_bin}" src/server.mjs
