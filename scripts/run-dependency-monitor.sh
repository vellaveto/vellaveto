#!/usr/bin/env bash
# run-dependency-monitor.sh — composite dependency/telemetry scan for Batch 3
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR="${1:-${WORKSPACE_ROOT}/target/security}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
AUDIT_JSON="${OUTPUT_DIR}/cargo-audit-${TIMESTAMP}.json"
DENY_JSON="${OUTPUT_DIR}/cargo-deny-${TIMESTAMP}.txt"
METADATA_JSON="${OUTPUT_DIR}/cargo-metadata-${TIMESTAMP}.json"
CARGO_HOME_DIR="${OUTPUT_DIR}/cargo-home"

mkdir -p "${OUTPUT_DIR}"
mkdir -p "${CARGO_HOME_DIR}"
export CARGO_HOME="${CARGO_HOME_DIR}"
if [[ -d "${HOME}/.cargo" ]]; then
  cp -a "${HOME}/.cargo/registry" "${CARGO_HOME_DIR}/" 2>/dev/null || true
  cp -a "${HOME}/.cargo/advisory-db" "${CARGO_HOME_DIR}/" 2>/dev/null || true
  cp -a "${HOME}/.cargo/advisory-dbs" "${CARGO_HOME_DIR}/" 2>/dev/null || true
fi

echo "Running dependency monitoring scan..."
echo "  Audit output: ${AUDIT_JSON}"
echo "  Deny output:  ${DENY_JSON}"
echo "  Metadata:     ${METADATA_JSON}"

echo "1/3: cargo audit"
audit_status=0
if ! cargo audit --json >"${AUDIT_JSON}"; then
  audit_status=$?
  echo "cargo audit detected advisories (exit ${audit_status}). Review ${AUDIT_JSON}."
else
  echo "cargo audit: no advisories"
fi

echo "2/3: cargo deny --all-features check"
deny_status=0
if ! (cargo deny --all-features check | tee "${DENY_JSON}"); then
  deny_status=$?
  echo "cargo deny reported issues (exit ${deny_status}). See ${DENY_JSON}."
else
  echo "cargo deny: clean"
fi

metadata_status=0
echo "3/3: cargo metadata"
if ! cargo metadata --format-version 1 >"${METADATA_JSON}"; then
  metadata_status=$?
  echo "cargo metadata failed (exit ${metadata_status}). Inspect ${CARGO_HOME_DIR} for cached registry data."
fi

echo "Optional CISA Known Exploited Vulnerabilities matching"
CISA_FILE="${CISA_KEV_JSON:-}"
OSINT_DIR="${OSINT_SECURITY_DIR:-}"

if [[ -n "${CISA_FILE}" && -f "${CISA_FILE}" ]]; then
  python3 <<PY
import json, os
metadata_path = '${METADATA_JSON}'
cisa_path = '${CISA_FILE}'
output_dir = '${OUTPUT_DIR}'
with open(metadata_path) as f:
    metadata = json.load(f)
packages = {pkg['name'].lower() for pkg in metadata.get('packages', [])}
with open(cisa_path) as f:
    data = json.load(f)
kev_entries = data.get('vulnerabilities') or data.get('known_exploited_vulnerabilities', [])
matches = []
for entry in kev_entries:
    cve = entry.get('cveID') or entry.get('cveId') or entry.get('cve')
    vendor = entry.get('vendorProject', '')
    product = entry.get('product', '')
    candidates = []
    for value in (vendor, product):
        if isinstance(value, (list, tuple)):
            candidates.extend(value)
        elif value:
            candidates.append(value)
    for candidate in candidates:
        normalized = candidate.lower()
        for dep in packages:
            if dep and dep in normalized and not any(m['dep'] == dep and m['cve'] == cve for m in matches):
                matches.append({'dep': dep, 'cve': cve, 'vendor': vendor, 'product': product, 'entry': candidate})
if matches:
    out_path = os.path.join(output_dir, 'cisa-kev-matches.json')
    with open(out_path, 'w') as out_file:
        json.dump(matches, out_file, indent=2)
    print('CISA KEV matches found:')
    for match in matches:
        print('  -', match['dep'], match['cve'], match['product'])
    print('  Details saved to', out_path)
else:
    print('No CISA KEV matches detected with current CISA file')
PY
else
  echo "  Skipped (set CISA_KEV_JSON to a local Known Exploited Vulnerabilities JSON file)"
fi

if [[ -n "${OSINT_DIR}" && -d "${OSINT_DIR}" ]]; then
  echo "OSINT directory provided: ${OSINT_DIR}"
  echo "  You can drop supply-chain intel notes here (e.g., vendor warnings, malicious packages) and this script will remind you to review them."
  echo "  Latest files:"
  ls -1 "${OSINT_DIR}" | head -n 5
else
  echo "Set OSINT_SECURITY_DIR to an OSINT note directory to link in supply-chain reporting."
fi

echo "Dependency monitoring summary written under ${OUTPUT_DIR}."
final_status=0
if [[ ${audit_status} -ne 0 || ${deny_status} -ne 0 || ${metadata_status} -ne 0 ]]; then
  final_status=1
fi
exit ${final_status}
