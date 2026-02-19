# Verify Release Artifacts

This playbook verifies release integrity using:

- SHA-256 checksums
- CycloneDX SBOM
- GitHub provenance attestations

## Prerequisites

- `gh` CLI authenticated to GitHub
- `curl`, `jq`, `sha256sum`, `tar`
- read access to `paolovella/vellaveto` releases

## 1) Download release assets

```bash
REPO="paolovella/vellaveto"
TAG="${1:-$(gh release list -R "$REPO" --limit 1 --json tagName --jq '.[0].tagName')}"

mkdir -p verify-release
gh release download "$TAG" -R "$REPO" \
  --pattern 'vellaveto-*-x86_64-linux-musl.tar.gz' \
  --pattern 'checksums-sha256.txt' \
  --pattern 'sbom.cdx.json' \
  --dir verify-release

cd verify-release
```

## 2) Verify checksums

`checksums-sha256.txt` includes the archive and unpacked binaries.
Map unpacked entries to local extraction paths, then verify all.

```bash
ARCHIVE="$(ls vellaveto-*-x86_64-linux-musl.tar.gz)"
mkdir -p extracted
tar -xzf "$ARCHIVE" -C extracted

{
  grep " $ARCHIVE$" checksums-sha256.txt
  grep ' release/' checksums-sha256.txt | sed 's| release/| extracted/|'
} > checksums-local.txt

sha256sum -c checksums-local.txt
```

Expected outcome: all lines report `OK`.

## 3) Validate SBOM shape

```bash
jq -r '.bomFormat, .specVersion, ("components=" + ((.components | length) | tostring))' sbom.cdx.json
```

Expected outcome:

- `bomFormat` is `CycloneDX`
- `components` count is greater than 0

## 4) Verify provenance attestations

```bash
REPO="paolovella/vellaveto"
TAG="${TAG#refs/tags/}"

for artifact in extracted/vellaveto extracted/vellaveto-proxy extracted/vellaveto-http-proxy; do
  gh attestation verify "$artifact" \
    --repo "$REPO" \
    --signer-workflow "$REPO/.github/workflows/release.yml" \
    --source-ref "refs/tags/$TAG" \
    --deny-self-hosted-runners
done
```

Expected outcome: verification succeeds for all three binaries.

## 5) Record evidence

Store these artifacts in your internal evidence bundle:

- `checksums-sha256.txt`
- `checksums-local.txt`
- `sbom.cdx.json`
- attestation verification output

This gives a reproducible integrity trail from release asset to local binary.
