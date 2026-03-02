#!/usr/bin/env bash
# Run the VellaVeto shield demo
#
# Usage:
#   ./demos/run-demo.sh             # uses release build
#   ./demos/run-demo.sh debug       # uses debug build
set -euo pipefail
cd "$(dirname "$0")"

PROFILE="${1:-release}"
PROXY="../target/$PROFILE/vellaveto-proxy"

if [ ! -f "$PROXY" ]; then
    echo "Building vellaveto-proxy ($PROFILE)..."
    (cd .. && cargo build --profile "$PROFILE" -p vellaveto-proxy)
fi

python3 demo-client.py "$PROXY" --protect shield -- python3 mock-mcp-server.py
