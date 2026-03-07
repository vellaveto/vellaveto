#!/usr/bin/env bash
#
# check-verus-parity.sh — Verify Verus proof targets still align with production
#
# Usage: bash formal/tools/check-verus-parity.sh
# Exit code: 0 = all checks passed, 1 = drift detected

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
DRIFT_FOUND=0

fail() {
    echo "  DRIFT: $1"
    DRIFT_FOUND=1
}

pass() {
    echo "  OK: $1"
}

check_file_pair() {
    local label="$1"
    local prod_file="$2"
    local verus_file="$3"

    if [ ! -f "$prod_file" ]; then
        fail "$label — production file not found: $prod_file"
        return
    fi
    if [ ! -f "$verus_file" ]; then
        fail "$label — verus file not found: $verus_file"
        return
    fi

    pass "$label"
}

check_symbol_parity() {
    local label="$1"
    local prod_file="$2"
    local prod_pattern="$3"
    local verus_file="$4"
    local verus_pattern="$5"

    if [ ! -f "$prod_file" ]; then
        fail "$label — production file not found: $prod_file"
        return
    fi
    if [ ! -f "$verus_file" ]; then
        fail "$label — verus file not found: $verus_file"
        return
    fi

    if ! grep -Eq "$prod_pattern" "$prod_file" 2>/dev/null; then
        fail "$label — production pattern '$prod_pattern' not found in $prod_file"
        return
    fi
    if ! grep -Eq "$verus_pattern" "$verus_file" 2>/dev/null; then
        fail "$label — verus pattern '$verus_pattern' not found in $verus_file"
        return
    fi

    pass "$label"
}

echo "=== Verus Proof Target Parity Check ==="
echo ""

PROD_CORE="$PROJECT_DIR/vellaveto-engine/src/verified_core.rs"
VERUS_CORE="$PROJECT_DIR/formal/verus/verified_core.rs"
PROD_DLP="$PROJECT_DIR/vellaveto-mcp/src/inspection/verified_dlp_core.rs"
VERUS_DLP="$PROJECT_DIR/formal/verus/verified_dlp_core.rs"
PROD_CAP="$PROJECT_DIR/vellaveto-mcp/src/capability_token.rs"
VERUS_PATH="$PROJECT_DIR/formal/verus/verified_path.rs"

echo "--- Core Verdict ---"
check_file_pair "verified_core.rs ↔ vellaveto-engine/src/verified_core.rs" "$PROD_CORE" "$VERUS_CORE"
check_symbol_parity \
    "compute_single_verdict exists in production and Verus" \
    "$PROD_CORE" \
    'pub[[:space:]]+fn[[:space:]]+compute_single_verdict' \
    "$VERUS_CORE" \
    'pub[[:space:]]+fn[[:space:]]+compute_single_verdict'
check_symbol_parity \
    "compute_verdict exists in production and Verus" \
    "$PROD_CORE" \
    'pub[[:space:]]+fn[[:space:]]+compute_verdict' \
    "$VERUS_CORE" \
    'pub[[:space:]]+fn[[:space:]]+compute_verdict'
echo ""

echo "--- DLP Buffer Core ---"
check_file_pair "verified_dlp_core.rs ↔ vellaveto-mcp/src/inspection/verified_dlp_core.rs" "$PROD_DLP" "$VERUS_DLP"
for fn in is_utf8_char_boundary extract_tail can_track_field update_total_bytes; do
    check_symbol_parity \
        "$fn exists in production and Verus" \
        "$PROD_DLP" \
        "pub[[:space:]]+fn[[:space:]]+$fn" \
        "$VERUS_DLP" \
        "pub[[:space:]]+fn[[:space:]]+$fn"
done
echo ""

echo "--- Path Normalization Kernel ---"
check_file_pair "verified_path.rs ↔ vellaveto-mcp/src/capability_token.rs" "$PROD_CAP" "$VERUS_PATH"
check_symbol_parity \
    "production capability path normalization entrypoint exists" \
    "$PROD_CAP" \
    'fn[[:space:]]+normalize_path_for_grant' \
    "$VERUS_PATH" \
    'pub[[:space:]]+fn[[:space:]]+normalize_path_bytes'
echo ""

if [ "$DRIFT_FOUND" -ne 0 ]; then
    echo "=== DRIFT DETECTED ==="
    echo "Verus proof targets have drifted from their documented production counterparts."
    exit 1
fi

echo "=== ALL CHECKS PASSED ==="
echo "Verus proof targets still align with production entrypoints."
