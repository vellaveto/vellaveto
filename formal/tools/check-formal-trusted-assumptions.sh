#!/usr/bin/env bash
#
# check-formal-trusted-assumptions.sh — Keep non-discharged formal assumptions explicit
#
# The formal suite currently contains a small number of intentional trusted
# assumptions (Verus escape hatches, Lean `axiom`, Coq `Axiom`/`Parameter`).
# This script enforces that every such assumption is listed in the allowlist
# and that stale allowlist entries are removed when proofs are discharged.
#
# Usage: bash formal/tools/check-formal-trusted-assumptions.sh
# Exit code: 0 = inventory matches allowlist, 1 = drift detected

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ALLOWLIST="$PROJECT_DIR/formal/trusted-assumptions.allowlist"
REGISTRY="$PROJECT_DIR/formal/ASSUMPTION_REGISTRY.md"

declare -A allowed=()
declare -A actual=()
unexpected=0
stale=0

normalize_text() {
    printf '%s' "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

check_registry() {
    local missing=0
    local required_entries=(
        "formal/trusted-assumptions.allowlist"
        "formal/MERKLE_TRUST_BOUNDARY.md"
        "formal/AUDIT_FILESYSTEM_TRUST_BOUNDARY.md"
        'VERUS-ESCAPE-1'
        'MERKLE-HASH-1'
        'AUDIT-FS-1'
    )
    local entry

    if [ ! -f "$REGISTRY" ]; then
        echo "FAIL: canonical assumption registry missing: $REGISTRY"
        exit 1
    fi

    for entry in "${required_entries[@]}"; do
        if ! grep -Fq "$entry" "$REGISTRY"; then
            echo "MISSING-REGISTRY-ENTRY: $entry"
            missing=1
        fi
    done

    if [ "$missing" -ne 0 ]; then
        echo ""
        echo "FAIL: canonical assumption registry is missing required entries"
        exit 1
    fi
}

load_allowlist() {
    local kind path text key

    if [ ! -f "$ALLOWLIST" ]; then
        echo "FAIL: trusted assumption allowlist missing: $ALLOWLIST"
        exit 1
    fi

    while IFS=$'\t' read -r kind path text; do
        if [ -z "${kind:-}" ] || [[ "$kind" == \#* ]]; then
            continue
        fi
        key="$kind"$'\t'"$path"$'\t'"$text"
        allowed["$key"]=1
    done < "$ALLOWLIST"
}

scan_hits() {
    local kind="$1"
    local base_dir="$2"
    local include_glob="$3"
    local pattern="$4"
    local line file rest text key

    if [ ! -d "$base_dir" ]; then
        return
    fi

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        file="${line%%:*}"
        rest="${line#*:}"
        rest="${rest#*:}"
        text="$(normalize_text "$rest")"
        key="$kind"$'\t'"${file#$PROJECT_DIR/}"$'\t'"$text"
        actual["$key"]=1
    done < <(grep -RIn --include="$include_glob" -E "$pattern" "$base_dir" || true)
}

report_inventory() {
    local label="$1"
    local prefix="$2"
    local count=0
    local key

    for key in "${!actual[@]}"; do
        if [[ "$key" == "$prefix"$'\t'* ]]; then
            count=$((count + 1))
        fi
    done

    echo "  $label: $count"
}

report_mismatches() {
    local label="$1"
    local -n source_ref="$2"
    local key

    while IFS= read -r key; do
        [ -z "$key" ] && continue
        echo "$label: $key"
    done < <(printf '%s\n' "${!source_ref[@]}" 2>/dev/null | sort)
}

check_registry
load_allowlist

scan_hits "verus-assume" "$PROJECT_DIR/formal/verus" "*.rs" '(^|[^[:alnum:]_])(assume|admit)[[:space:]]*\('
scan_hits "verus-axiom" "$PROJECT_DIR/formal/verus" "*.rs" '(^|[^[:alnum:]_])axiom([^[:alnum:]_]|$)'
scan_hits "verus-external-body" "$PROJECT_DIR/formal/verus" "*.rs" '#\[[[:space:]]*verifier::external_body[[:space:]]*\]'
scan_hits "verus-external-fn-spec" "$PROJECT_DIR/formal/verus" "*.rs" '#\[[[:space:]]*verifier::external_fn_specification([^[:alnum:]_]|$)'
scan_hits "verus-trusted-marker" "$PROJECT_DIR/formal/verus" "*.rs" '(^|[^[:alnum:]_])TRUSTED([^[:alnum:]_]|$)'
scan_hits "lean-axiom" "$PROJECT_DIR/formal/lean" "*.lean" '^[[:space:]]*axiom[[:space:]]'
scan_hits "coq-axiom" "$PROJECT_DIR/formal/coq" "*.v" '^[[:space:]]*(Axiom|Parameter)[[:space:]]'

echo "=== Formal Trusted Assumption Inventory ==="
echo "Canonical registry: $REGISTRY"
echo "Expected entries: ${#allowed[@]}"
echo "Observed entries: ${#actual[@]}"
report_inventory "Verus assume/admit" "verus-assume"
report_inventory "Verus axioms" "verus-axiom"
report_inventory "Verus external bodies" "verus-external-body"
report_inventory "Verus external fn specs" "verus-external-fn-spec"
report_inventory "Verus trusted markers" "verus-trusted-marker"
report_inventory "Lean axioms" "lean-axiom"
report_inventory "Coq axioms/parameters" "coq-axiom"
echo ""

for key in "${!actual[@]}"; do
    if [ -z "${allowed[$key]+set}" ]; then
        unexpected=1
    fi
done

for key in "${!allowed[@]}"; do
    if [ -z "${actual[$key]+set}" ]; then
        stale=1
    fi
done

if [ "$unexpected" -ne 0 ] || [ "$stale" -ne 0 ]; then
    if [ "$unexpected" -ne 0 ]; then
        declare -A unexpected_keys=()
        for key in "${!actual[@]}"; do
            if [ -z "${allowed[$key]+set}" ]; then
                unexpected_keys["$key"]=1
            fi
        done
        report_mismatches "UNEXPECTED" unexpected_keys
    fi

    if [ "$stale" -ne 0 ]; then
        declare -A stale_keys=()
        for key in "${!allowed[@]}"; do
            if [ -z "${actual[$key]+set}" ]; then
                stale_keys["$key"]=1
            fi
        done
        report_mismatches "STALE" stale_keys
    fi

    echo ""
    echo "FAIL: trusted assumption inventory drifted from formal/trusted-assumptions.allowlist"
    exit 1
fi

echo "All trusted assumptions are explicitly allowlisted."
