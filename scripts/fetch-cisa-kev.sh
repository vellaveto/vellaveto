#!/usr/bin/env bash
# fetch-cisa-kev.sh — grab the latest CISA Known Exploited Vulnerabilities catalog
set -euo pipefail
URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUT_DIR="${1:-$(pwd)/target/security}"
mkdir -p "$OUT_DIR"
OUTPUT="$OUT_DIR/known_exploited_vulnerabilities.json"
echo "Downloading KEV feed to $OUTPUT"
curl -fsSL "$URL" -o "$OUTPUT"
echo "Download complete. Set CISA_KEV_JSON=$OUTPUT when running the dependency monitor."
