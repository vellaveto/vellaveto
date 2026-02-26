#!/usr/bin/env bash
# generate-sbom.sh — Produce a machine-readable Software Bill of Materials
#
# This script generates SBOM data using cargo metadata, which is available
# without installing additional cargo plugins. The output is a JSON file
# conforming to cargo's metadata format-version 1, containing:
#   - All workspace members and their versions
#   - Complete resolved dependency graph
#   - Source repository and license information for each crate
#
# Usage:
#   ./scripts/generate-sbom.sh                    # writes to sbom/
#   ./scripts/generate-sbom.sh /path/to/output    # writes to specified dir
#
# The output can be post-processed into CycloneDX or SPDX formats using
# third-party tools (e.g., cargo-cyclonedx, cargo-sbom) when needed for
# compliance submissions.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR="${1:-${WORKSPACE_ROOT}/sbom}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTPUT_FILE="${OUTPUT_DIR}/vellaveto-sbom-${TIMESTAMP}.json"

mkdir -p "${OUTPUT_DIR}"

echo "Generating SBOM for Vellaveto workspace..."
echo "  Workspace: ${WORKSPACE_ROOT}"
echo "  Output:    ${OUTPUT_FILE}"

# Generate cargo metadata (complete dependency graph)
cargo metadata \
  --format-version 1 \
  --manifest-path "${WORKSPACE_ROOT}/Cargo.toml" \
  > "${OUTPUT_FILE}"

# Validate the output is valid JSON
if ! python3 -m json.tool "${OUTPUT_FILE}" > /dev/null 2>&1; then
  # Fallback: try jq if python3 is not available
  if command -v jq > /dev/null 2>&1; then
    jq empty "${OUTPUT_FILE}"
  else
    echo "Warning: Could not validate JSON output (no python3 or jq available)"
  fi
fi

# Count packages for summary
if command -v python3 > /dev/null 2>&1; then
  TOTAL=$(python3 -c "
import json, sys
with open('${OUTPUT_FILE}') as f:
    data = json.load(f)
print(len(data.get('packages', [])))
")
  WORKSPACE=$(python3 -c "
import json, sys
with open('${OUTPUT_FILE}') as f:
    data = json.load(f)
members = set(data.get('workspace_members', []))
print(len(members))
")
  echo ""
  echo "SBOM generated successfully:"
  echo "  Workspace crates: ${WORKSPACE}"
  echo "  Total packages:   ${TOTAL} (including transitive dependencies)"
  echo "  Output file:      ${OUTPUT_FILE}"
  echo "  File size:        $(du -h "${OUTPUT_FILE}" | cut -f1)"
elif command -v jq > /dev/null 2>&1; then
  TOTAL=$(jq '.packages | length' "${OUTPUT_FILE}")
  WORKSPACE=$(jq '.workspace_members | length' "${OUTPUT_FILE}")
  echo ""
  echo "SBOM generated successfully:"
  echo "  Workspace crates: ${WORKSPACE}"
  echo "  Total packages:   ${TOTAL} (including transitive dependencies)"
  echo "  Output file:      ${OUTPUT_FILE}"
  echo "  File size:        $(du -h "${OUTPUT_FILE}" | cut -f1)"
else
  echo ""
  echo "SBOM generated successfully:"
  echo "  Output file: ${OUTPUT_FILE}"
  echo "  File size:   $(du -h "${OUTPUT_FILE}" | cut -f1)"
fi

echo ""
echo "To convert to CycloneDX format (if cargo-cyclonedx is installed):"
echo "  cargo cyclonedx --manifest-path ${WORKSPACE_ROOT}/Cargo.toml"
echo ""
echo "To convert to SPDX format (if cargo-sbom is installed):"
echo "  cargo sbom --manifest-path ${WORKSPACE_ROOT}/Cargo.toml"
