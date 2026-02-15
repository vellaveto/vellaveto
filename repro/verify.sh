#!/usr/bin/env bash
# Compare local benchmark results against pinned reference values.
# Flags results that exceed 2x the pinned value as potential regressions.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PINNED="${REPO_ROOT}/repro/pinned-results.json"
CRITERION_DIR="${REPO_ROOT}/target/criterion"

if [[ ! -f "${PINNED}" ]]; then
  echo "ERROR: No pinned results found at ${PINNED}"
  exit 1
fi

if [[ ! -d "${CRITERION_DIR}" ]]; then
  echo "ERROR: No Criterion results found at ${CRITERION_DIR}"
  echo "       Run benchmarks first: ./repro/bench.sh"
  exit 1
fi

echo "=== Benchmark Verification ==="
echo ""
echo "Pinned results: ${PINNED}"
echo "Local results:  ${CRITERION_DIR}/"
echo ""

# Tolerance: local result must be within this multiplier of pinned value
TOLERANCE=2.0
PASS=0
FAIL=0
SKIP=0

# Read pinned benchmarks and compare against Criterion estimates
while IFS= read -r line; do
  name=$(echo "$line" | jq -r '.name')
  pinned_ns=$(echo "$line" | jq -r '.value_ns')

  # Find corresponding Criterion result
  estimate_file="${CRITERION_DIR}/${name}/new/estimates.json"

  if [[ ! -f "${estimate_file}" ]]; then
    echo "  SKIP  ${name} (no local result)"
    SKIP=$((SKIP + 1))
    continue
  fi

  # Extract point estimate (nanoseconds) from Criterion
  local_ns=$(jq -r '.mean.point_estimate' "${estimate_file}" 2>/dev/null || echo "0")

  if [[ "${local_ns}" == "0" || "${local_ns}" == "null" ]]; then
    echo "  SKIP  ${name} (could not parse local result)"
    SKIP=$((SKIP + 1))
    continue
  fi

  # Compare: local must be within TOLERANCE * pinned
  threshold=$(echo "${pinned_ns} * ${TOLERANCE}" | bc -l)

  if (( $(echo "${local_ns} <= ${threshold}" | bc -l) )); then
    ratio=$(echo "scale=2; ${local_ns} / ${pinned_ns}" | bc -l)
    echo "  PASS  ${name}: ${local_ns}ns (${ratio}x pinned ${pinned_ns}ns)"
    PASS=$((PASS + 1))
  else
    ratio=$(echo "scale=2; ${local_ns} / ${pinned_ns}" | bc -l)
    echo "  FAIL  ${name}: ${local_ns}ns (${ratio}x pinned ${pinned_ns}ns, threshold ${TOLERANCE}x)"
    FAIL=$((FAIL + 1))
  fi
done < <(jq -c '.benchmarks[]' "${PINNED}")

echo ""
echo "--- Summary ---"
echo "  Pass: ${PASS}"
echo "  Fail: ${FAIL}"
echo "  Skip: ${SKIP}"
echo ""

if [[ ${FAIL} -gt 0 ]]; then
  echo "WARNING: ${FAIL} benchmark(s) exceeded ${TOLERANCE}x pinned values."
  echo "         This may indicate a regression, or different hardware."
  echo "         Review the HTML report: ${CRITERION_DIR}/report/index.html"
  exit 1
fi

echo "All benchmarks within ${TOLERANCE}x tolerance."
