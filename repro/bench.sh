#!/usr/bin/env bash
# Vellaveto Benchmark Runner
# Usage: ./repro/bench.sh [--compare] [--crate CRATE]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPARE=false
CRATE=""
RESULTS_DIR="${REPO_ROOT}/target/bench-results"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --compare) COMPARE=true; shift ;;
    --crate) CRATE="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# --- Environment checks ---

echo "=== Vellaveto Benchmark Runner ==="
echo ""

# Rust version
RUST_VERSION=$(rustc --version 2>/dev/null || echo "not found")
echo "Rust:     ${RUST_VERSION}"

# CPU info
if [[ -f /proc/cpuinfo ]]; then
  CPU_MODEL=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)
  CPU_CORES=$(nproc)
  echo "CPU:      ${CPU_MODEL} (${CPU_CORES} cores)"
fi

# OS
if [[ -f /etc/os-release ]]; then
  OS_NAME=$(. /etc/os-release && echo "${PRETTY_NAME}")
else
  OS_NAME=$(uname -s -r)
fi
echo "OS:       ${OS_NAME}"

# Check CPU governor
if [[ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]]; then
  GOVERNOR=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)
  if [[ "$GOVERNOR" != "performance" ]]; then
    echo ""
    echo "WARNING: CPU governor is '${GOVERNOR}', not 'performance'."
    echo "         Results may be noisy. To fix:"
    echo "         sudo cpupower frequency-set -g performance"
    echo ""
  fi
fi

# Check load average
LOAD=$(uptime | awk -F'load average:' '{print $2}' | cut -d, -f1 | xargs)
LOAD_INT=${LOAD%%.*}
if [[ "${LOAD_INT}" -gt 2 ]]; then
  echo ""
  echo "WARNING: Load average is ${LOAD}. Other processes may affect results."
  echo "         Consider running on a quiescent system."
  echo ""
fi

echo ""
echo "Profile:  release (lto=thin, codegen-units=1, opt-level=3)"
echo ""

# --- Build ---

echo "--- Building in release mode ---"
cd "${REPO_ROOT}"
cargo build --release --workspace 2>&1 | tail -1

# --- Run benchmarks ---

mkdir -p "${RESULTS_DIR}"
TIMESTAMP=$(date -u +%Y-%m-%dT%H%M%SZ)

echo ""
echo "--- Running benchmarks ---"
echo ""

if [[ -n "${CRATE}" ]]; then
  echo "Running: cargo bench -p ${CRATE}"
  cargo bench -p "${CRATE}" 2>&1 | tee "${RESULTS_DIR}/bench-${CRATE}-${TIMESTAMP}.log"
else
  for crate in vellaveto-engine vellaveto-mcp vellaveto-audit vellaveto-http-proxy; do
    echo "--- ${crate} ---"
    cargo bench -p "${crate}" 2>&1 | tee -a "${RESULTS_DIR}/bench-all-${TIMESTAMP}.log"
    echo ""
  done
fi

# --- Extract key metrics ---

echo ""
echo "--- Key Metrics ---"
echo ""

# Parse Criterion output for key benchmarks
extract_metric() {
  local name="$1"
  local log="$2"
  local result
  result=$(grep -A2 "^${name}" "${log}" 2>/dev/null | grep "time:" | head -1 | \
           sed 's/.*\[\(.*\)\]/\1/' | awk '{print $1, $2}' || echo "N/A")
  echo "  ${name}: ${result}"
}

echo "Results saved to: ${RESULTS_DIR}/"
echo "HTML reports:     ${REPO_ROOT}/target/criterion/report/index.html"

# --- Compare mode ---

if [[ "${COMPARE}" == "true" ]]; then
  echo ""
  echo "--- Comparison against pinned results ---"
  "${REPO_ROOT}/repro/verify.sh"
fi

echo ""
echo "Done."
