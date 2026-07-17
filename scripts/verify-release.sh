#!/usr/bin/env bash
# Authenticate Premier's aggregate checksum manifest, then verify every downloaded asset.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/distribution.sh
source "$ROOT/scripts/lib/distribution.sh"

DIRECTORY="."
CHECKSUMS="SHA256SUMS"
BUNDLE="SHA256SUMS.sigstore.json"
IDENTITY_REGEXP='^https://github\.com/PremierStudio/premier\.dev/\.github/workflows/release\.yml@refs/tags/v[0-9].*$'
ISSUER='https://token.actions.githubusercontent.com'

usage() {
  echo "Usage: ./scripts/verify-release.sh [--directory PATH] [--checksums PATH] [--bundle PATH]"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --directory) DIRECTORY="${2:?missing directory}"; shift 2 ;;
    --checksums) CHECKSUMS="${2:?missing checksums}"; shift 2 ;;
    --bundle) BUNDLE="${2:?missing bundle}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

[[ "$CHECKSUMS" = /* ]] || CHECKSUMS="$DIRECTORY/$CHECKSUMS"
[[ "$BUNDLE" = /* ]] || BUNDLE="$DIRECTORY/$BUNDLE"
[[ -f "$CHECKSUMS" && -f "$BUNDLE" ]] || { echo "signed checksum manifest is incomplete" >&2; exit 1; }
command -v cosign >/dev/null 2>&1 || { echo "cosign is required" >&2; exit 1; }

cosign verify-blob \
  --bundle "$BUNDLE" \
  --certificate-identity-regexp "$IDENTITY_REGEXP" \
  --certificate-oidc-issuer "$ISSUER" \
  "$CHECKSUMS" >/dev/null

while read -r expected name; do
  [[ -n "$expected" && -n "$name" ]] || continue
  asset="$DIRECTORY/$name"
  [[ -f "$asset" ]] || { echo "missing release asset: $name" >&2; exit 1; }
  [[ "$(distribution_sha256 "$asset")" == "$expected" ]] || { echo "checksum mismatch: $name" >&2; exit 1; }
done <"$CHECKSUMS"

echo "verified Premier release publisher identity and asset checksums"
