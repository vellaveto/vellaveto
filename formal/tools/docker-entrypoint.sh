#!/usr/bin/env bash
#
# docker-entrypoint.sh — Set up tool symlinks and run the formal mesh
#
# The Dockerfile installs tools at fixed paths (/opt/tla, /opt/verus).
# The Makefile expects some of them relative to the workspace root.
# This script bridges the gap.

set -euo pipefail

# TLA+ — Makefile expects formal/tla/tla2tools.jar
if [ -f /opt/tla/tla2tools.jar ] && [ -d formal/tla ] && [ ! -f formal/tla/tla2tools.jar ]; then
    ln -sf /opt/tla/tla2tools.jar formal/tla/tla2tools.jar
fi

# Lean — fetch toolchain on first run (pinned by formal/lean/lean-toolchain)
if [ -d formal/lean ] && command -v lake >/dev/null 2>&1; then
    (cd formal/lean && lake update 2>/dev/null) || true
fi

exec "$@"
