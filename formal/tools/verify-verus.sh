#!/usr/bin/env bash
#
# verify-verus.sh — Canonical entrypoint for Verus proof verification
#
# Usage:
#   bash formal/tools/verify-verus.sh
#   VERUS_BIN=/path/to/verus bash formal/tools/verify-verus.sh
#   bash formal/tools/verify-verus.sh --list
#
# Exit code: 0 = all proofs verified, non-zero = failure

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

FILES=(
    "formal/verus/verified_core.rs"
    "formal/verus/verified_dlp_core.rs"
    "formal/verus/verified_path.rs"
)

find_verus_bin() {
    if [ -n "${VERUS_BIN:-}" ]; then
        printf '%s\n' "$VERUS_BIN"
        return
    fi

    if command -v verus >/dev/null 2>&1; then
        command -v verus
        return
    fi

    if [ -x "$PROJECT_DIR/verus-bin/verus-x86-linux/verus" ]; then
        printf '%s\n' "$PROJECT_DIR/verus-bin/verus-x86-linux/verus"
        return
    fi

    echo "FAIL: could not find Verus binary. Set VERUS_BIN or install verus." >&2
    exit 1
}

if [ "${1:-}" = "--list" ]; then
    printf '%s\n' "${FILES[@]}"
    exit 0
fi

VERUS="$(find_verus_bin)"
VERUS_FLAGS="${VERUS_FLAGS:---triggers-mode silent}"

echo "=== Verus Verification ==="
echo "Verus binary: $VERUS"
echo ""

for file in "${FILES[@]}"; do
    echo "--- $file ---"
    # shellcheck disable=SC2086
    "$VERUS" $VERUS_FLAGS "$PROJECT_DIR/$file"
    echo ""
done
