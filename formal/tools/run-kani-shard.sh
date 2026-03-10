#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <shard-index> <shard-count>" >&2
    exit 2
fi

SHARD_INDEX="$1"
SHARD_COUNT="$2"

case "$SHARD_INDEX" in
    ''|*[!0-9]*)
        echo "Invalid shard index: $SHARD_INDEX" >&2
        exit 2
        ;;
esac

case "$SHARD_COUNT" in
    ''|*[!0-9]*)
        echo "Invalid shard count: $SHARD_COUNT" >&2
        exit 2
        ;;
esac

if [ "$SHARD_COUNT" -eq 0 ] || [ "$SHARD_INDEX" -ge "$SHARD_COUNT" ]; then
    echo "Shard index $SHARD_INDEX out of range for shard count $SHARD_COUNT" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
KANI_DIR="$PROJECT_DIR/formal/kani"
LIST_FILE="$KANI_DIR/kani-list.json"

cleanup() {
    rm -f "$LIST_FILE"
}

trap cleanup EXIT

cd "$KANI_DIR"

cargo kani list --format json >/dev/null

mapfile -t ALL_HARNESSES < <(
    rg -o '"proofs::[^"]+"' "$LIST_FILE" | tr -d '"'
)

if [ "${#ALL_HARNESSES[@]}" -eq 0 ]; then
    echo "No Kani harnesses found in $LIST_FILE" >&2
    exit 1
fi

SELECTED_HARNESSES=()
for idx in "${!ALL_HARNESSES[@]}"; do
    if [ $((idx % SHARD_COUNT)) -eq "$SHARD_INDEX" ]; then
        SELECTED_HARNESSES+=("${ALL_HARNESSES[$idx]}")
    fi
done

if [ "${#SELECTED_HARNESSES[@]}" -eq 0 ]; then
    echo "Shard $SHARD_INDEX/$SHARD_COUNT selected no Kani harnesses" >&2
    exit 1
fi

echo "Running Kani shard $((SHARD_INDEX + 1))/$SHARD_COUNT with ${#SELECTED_HARNESSES[@]} harnesses"
printf '  %s\n' "${SELECTED_HARNESSES[@]}"

if [ "${KANI_SHARD_DRY_RUN:-0}" = "1" ]; then
    exit 0
fi

KANI_ARGS=()
if [ -n "${KANI_SOLVER:-}" ]; then
    KANI_ARGS+=(--solver "$KANI_SOLVER")
fi

for harness in "${SELECTED_HARNESSES[@]}"; do
    KANI_ARGS+=(--harness "$harness")
done

cargo kani "${KANI_ARGS[@]}"
