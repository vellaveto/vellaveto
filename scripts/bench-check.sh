#!/usr/bin/env bash
set -euo pipefail

# Benchmark regression check for Sentinel CI.
# Runs all workspace benchmarks and checks for performance regressions.
#
# Usage:
#   ./scripts/bench-check.sh              # Run benchmarks
#   ./scripts/bench-check.sh --save       # Save current results as baseline
#   ./scripts/bench-check.sh --compare    # Compare against saved baseline

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BASELINE_DIR="$PROJECT_DIR/target/criterion-baseline"
THRESHOLD_PERCENT=10

cmd="${1:-run}"

case "$cmd" in
    --save)
        echo "=== Saving benchmark baseline ==="
        cargo bench --workspace -- --save-baseline base
        echo "Baseline saved."
        ;;
    --compare)
        echo "=== Running benchmarks and comparing against baseline ==="
        OUTPUT=$(cargo bench --workspace -- --baseline base 2>&1) || true
        echo "$OUTPUT"

        # Check for regressions by looking for "regressed" in criterion output
        REGRESSIONS=$(echo "$OUTPUT" | grep -i "regressed" || true)
        if [ -n "$REGRESSIONS" ]; then
            echo ""
            echo "=== REGRESSIONS DETECTED ==="
            echo "$REGRESSIONS"
            echo ""
            echo "Review the above regressions. Threshold: ${THRESHOLD_PERCENT}%"
            # Extract percentage changes and check against threshold
            FAILURES=0
            while IFS= read -r line; do
                # Try to extract percentage from criterion output
                PCT=$(echo "$line" | grep -oP '[+-]?\d+\.\d+%' | head -1 | tr -d '%+' || true)
                if [ -n "$PCT" ]; then
                    # Compare absolute value against threshold
                    ABS_PCT=$(echo "$PCT" | tr -d '-')
                    if awk "BEGIN { exit !($ABS_PCT > $THRESHOLD_PERCENT) }"; then
                        echo "FAIL: $line (>${THRESHOLD_PERCENT}% regression)"
                        FAILURES=$((FAILURES + 1))
                    fi
                fi
            done <<< "$REGRESSIONS"

            if [ "$FAILURES" -gt 0 ]; then
                echo ""
                echo "=== $FAILURES benchmark(s) regressed beyond ${THRESHOLD_PERCENT}% threshold ==="
                exit 1
            fi
        fi

        echo ""
        echo "=== All benchmarks within ${THRESHOLD_PERCENT}% threshold ==="
        ;;
    run|*)
        echo "=== Running all workspace benchmarks ==="
        cargo bench --workspace
        echo ""
        echo "=== Benchmarks complete ==="
        echo "To save a baseline: $0 --save"
        echo "To compare against baseline: $0 --compare"
        ;;
esac
