#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: $0 <version> [--output path]

Downloads the specified actionlint tarball, computes its SHA256
checksum, and writes an env file consumed by CI.

Example:
  $0 1.7.11
USAGE
}

if [ $# -lt 1 ]; then
  usage
  exit 1
fi

VERSION="$1"
OUTPUT="${2:-tools/actionlint-release.env}"
TMP_TGZ=$(mktemp)
URL="https://github.com/rhysd/actionlint/releases/download/v${VERSION}/actionlint_${VERSION}_linux_amd64.tar.gz"

trap 'rm -f "$TMP_TGZ"' EXIT

curl -fsSL -o "$TMP_TGZ" "$URL"
SHA=$(sha256sum "$TMP_TGZ" | awk '{print $1}')

echo "ACTIONLINT_VERSION=${VERSION}" > "$OUTPUT"
echo "ACTIONLINT_SHA256=${SHA}" >> "$OUTPUT"
echo "Updated $OUTPUT (version=${VERSION}, sha=${SHA})"
