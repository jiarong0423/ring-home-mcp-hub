#!/usr/bin/env bash
set +x
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export HOME_MCP_PORT=8765
exec bash "${project_root}/scripts/start_ring_playground_demo.sh"
