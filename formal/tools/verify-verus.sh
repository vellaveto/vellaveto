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
    "formal/verus/verified_audit_append.rs"
    "formal/verus/verified_audit_chain.rs"
    "formal/verus/verified_merkle.rs"
    "formal/verus/verified_merkle_fold.rs"
    "formal/verus/verified_merkle_path.rs"
    "formal/verus/verified_rotation_manifest.rs"
    "formal/verus/verified_capability_attenuation.rs"
    "formal/verus/verified_capability_glob.rs"
    "formal/verus/verified_capability_grant.rs"
    "formal/verus/verified_capability_identity.rs"
    "formal/verus/verified_capability_literal.rs"
    "formal/verus/verified_capability_pattern.rs"
    "formal/verus/verified_constraint_eval.rs"
    "formal/verus/verified_cross_call_dlp.rs"
    "formal/verus/verified_core.rs"
    "formal/verus/verified_entropy_gate.rs"
    "formal/verus/verified_nhi_delegation.rs"
    "formal/verus/verified_dlp_core.rs"
    "formal/verus/verified_path.rs"
    "formal/verus/verified_refinement_safety.rs"
)

MANIFEST="formal/verus/Cargo.toml"

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

find_cargo_verus_bin() {
    if [ -n "${CARGO_VERUS_BIN:-}" ]; then
        printf '%s\n' "$CARGO_VERUS_BIN"
        return
    fi

    if command -v cargo-verus >/dev/null 2>&1; then
        command -v cargo-verus
        return
    fi

    if [ -n "${VERUS_BIN:-}" ]; then
        local verus_dir
        verus_dir="$(cd "$(dirname "$VERUS_BIN")" && pwd)"
        if [ -x "$verus_dir/cargo-verus" ]; then
            printf '%s\n' "$verus_dir/cargo-verus"
            return
        fi
    fi

    if [ -x "$PROJECT_DIR/verus-bin/verus-x86-linux/cargo-verus" ]; then
        printf '%s\n' "$PROJECT_DIR/verus-bin/verus-x86-linux/cargo-verus"
        return
    fi

    return 1
}

if [ "${1:-}" = "--list" ]; then
    printf '%s\n' "${FILES[@]}"
    exit 0
fi

VERUS_FLAGS="${VERUS_FLAGS:---triggers-mode silent}"
USE_CARGO_VERUS="${FORMAL_USE_CARGO_VERUS:-}"
if [ -z "$USE_CARGO_VERUS" ] && [ "${CI:-}" = "true" ]; then
    USE_CARGO_VERUS=1
fi

if [ "$USE_CARGO_VERUS" = "1" ] && [ -f "$PROJECT_DIR/$MANIFEST" ] && CARGO_VERUS="$(find_cargo_verus_bin)"; then
    CARGO_VERUS_TARGET_DIR="${CARGO_VERUS_TARGET_DIR:-${CARGO_TARGET_DIR:-/tmp/vellaveto-formal-verus-target}}"
    echo "=== Verus Verification ==="
    echo "Cargo Verus binary: $CARGO_VERUS"
    echo "Manifest: $PROJECT_DIR/$MANIFEST"
    echo "Cargo target dir: $CARGO_VERUS_TARGET_DIR"
    echo ""
    # shellcheck disable=SC2086
    CARGO_TARGET_DIR="$CARGO_VERUS_TARGET_DIR" \
        "$CARGO_VERUS" verify --manifest-path "$PROJECT_DIR/$MANIFEST" -- $VERUS_FLAGS
    exit 0
fi

if [ "$USE_CARGO_VERUS" = "1" ] && [ ! -f "$PROJECT_DIR/$MANIFEST" ]; then
    echo "INFO: $MANIFEST not found; falling back to per-file Verus verification."
elif [ "$USE_CARGO_VERUS" = "1" ]; then
    echo "INFO: cargo-verus requested but not found; falling back to per-file Verus verification."
else
    echo "INFO: using per-file Verus verification; set FORMAL_USE_CARGO_VERUS=1 to use the manifest entrypoint."
fi
echo ""

VERUS="$(find_verus_bin)"

echo "=== Verus Verification ==="
echo "Verus binary: $VERUS"
echo ""

for file in "${FILES[@]}"; do
    echo "--- $file ---"
    # shellcheck disable=SC2086
    "$VERUS" $VERUS_FLAGS "$PROJECT_DIR/$file"
    echo ""
done
