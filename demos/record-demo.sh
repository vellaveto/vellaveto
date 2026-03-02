#!/usr/bin/env bash
# Record the shield demo as an SVG for the README.
#
# Produces: demos/shield-demo.svg
#
# Requirements: asciinema (pip install asciinema), svg-term-cli (npm i -g svg-term-cli)
set -euo pipefail
cd "$(dirname "$0")"

CAST="shield-demo.cast"
SVG="shield-demo.svg"
PROXY="../target/release/vellaveto-proxy"

if [ ! -f "$PROXY" ]; then
    echo "Building vellaveto-proxy..."
    (cd .. && cargo build --release -p vellaveto-proxy)
fi

echo "Recording demo..."
asciinema rec "$CAST" \
    --cols 88 --rows 28 \
    --overwrite \
    --command "python3 demo-client.py $PROXY --protect shield -- python3 mock-mcp-server.py"

echo "Converting to SVG..."
svg-term --in "$CAST" --out "$SVG" \
    --window \
    --no-cursor \
    --padding 16 \
    --width 88 --height 28 \
    --term iterm2 \
    --profile "Builtin Solarized Dark"

rm -f "$CAST"
echo "Done: $SVG"
