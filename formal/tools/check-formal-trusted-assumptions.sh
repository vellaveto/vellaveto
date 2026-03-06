#!/usr/bin/env bash
#
# check-formal-trusted-assumptions.sh — Keep non-discharged formal assumptions explicit
#
# The formal suite currently contains a small number of intentional trusted
# assumptions (Verus `assume`, Lean `axiom`, Coq `Axiom`/`Parameter`).
# This script enforces that every such assumption is listed in the allowlist
# and that stale allowlist entries are removed when proofs are discharged.
#
# Usage: bash formal/tools/check-formal-trusted-assumptions.sh
# Exit code: 0 = inventory matches allowlist, 1 = drift detected

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ALLOWLIST="$PROJECT_DIR/formal/trusted-assumptions.allowlist"

declare -A allowed=()
declare -A actual=()
unexpected=0
stale=0

normalize_text() {
    printf '%s' "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
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

load_allowlist

scan_hits "verus" "$PROJECT_DIR/formal/verus" "*.rs" '(assume|admit)[[:space:]]*\('
scan_hits "lean" "$PROJECT_DIR/formal/lean" "*.lean" '^[[:space:]]*axiom[[:space:]]'
scan_hits "coq" "$PROJECT_DIR/formal/coq" "*.v" '^[[:space:]]*(Axiom|Parameter)[[:space:]]'

echo "=== Formal Trusted Assumption Inventory ==="
echo "Expected entries: ${#allowed[@]}"
echo "Observed entries: ${#actual[@]}"
report_inventory "Verus assumptions" "verus"
report_inventory "Lean axioms" "lean"
report_inventory "Coq axioms/parameters" "coq"
echo ""

for key in "${!actual[@]}"; do
    if [ -z "${allowed[$key]+set}" ]; then
        echo "UNEXPECTED: $key"
        unexpected=1
    fi
done

for key in "${!allowed[@]}"; do
    if [ -z "${actual[$key]+set}" ]; then
        echo "STALE: $key"
        stale=1
    fi
done

if [ "$unexpected" -ne 0 ] || [ "$stale" -ne 0 ]; then
    echo ""
    echo "FAIL: trusted assumption inventory drifted from formal/trusted-assumptions.allowlist"
    exit 1
fi

echo "All trusted assumptions are explicitly allowlisted."
