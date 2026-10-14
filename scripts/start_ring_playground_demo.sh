#!/usr/bin/env bash
set +x
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ $# -ne 0 ]]; then
  printf 'Usage: bash scripts/start_ring_playground_demo.sh\n' >&2
  exit 2
fi
if [[ ! -t 0 || ! -t 1 ]]; then
  printf 'An interactive terminal is required.\n' >&2
  exit 2
fi
if [[ ! -f "${project_root}/src/server.mjs" ]]; then
  printf 'Ring Home MCP Hub server was not found.\n' >&2
  exit 2
fi

if ! command -v node > /dev/null 2>&1; then
  printf 'Node.js is required.\n' >&2
  exit 2
fi
HOME_MCP_DEMO_PASS="$(node -e 'process.stdout.write(require("node:crypto").randomBytes(24).toString("base64url"))')"
HOME_MCP_RING_OPERATOR_PASS="$(node -e 'process.stdout.write(require("node:crypto").randomBytes(24).toString("base64url"))')"
if [[ "${HOME_MCP_RING_OPERATOR_PASS}" == "${HOME_MCP_DEMO_PASS}" ]]; then
  printf 'Operator passcode must differ from the demo login passcode.\n' >&2
  exit 2
fi

printf 'Local demo login passcode: %s\n' "${HOME_MCP_DEMO_PASS}" > /dev/tty
printf 'Independent local operator passcode for Ring import and discovery: %s\n' "${HOME_MCP_RING_OPERATOR_PASS}" > /dev/tty
printf 'These local passcodes change when the server restarts. Copy a fresh Ring token only after opening the UI, then click import.\n' > /dev/tty

unset RING_PLAYGROUND_ACCESS_TOKEN
export HOME_MCP_DEMO_PASS HOME_MCP_RING_OPERATOR_PASS
cd "${project_root}"
exec node src/server.mjs
