#!/usr/bin/env bash
# Compare an installed Premier version with local release metadata.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/distribution.sh
source "$ROOT/scripts/lib/distribution.sh"
PREFIX="${CARGO_HOME:-$HOME/.cargo}"
ARCHIVE=""

usage() { echo "Usage: ./scripts/version-check.sh --archive PATH [--prefix PATH]"; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --archive) ARCHIVE="${2:?missing archive path}"; shift 2 ;;
    --prefix) PREFIX="${2:?missing prefix}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done
[[ -f "$ARCHIVE" ]] || { echo "a local --archive is required" >&2; exit 1; }

STAGING="$(mktemp -d "${TMPDIR:-/tmp}/premier-version.XXXXXX")"
trap 'rm -rf "$STAGING"' EXIT
distribution_safe_extract "$ARCHIVE" "$STAGING"
METADATA="$(find "$STAGING" -type f -name RELEASE-METADATA | head -n 1)"
[[ -f "$METADATA" ]] || { echo "release metadata missing" >&2; exit 1; }
AVAILABLE="$(distribution_metadata_value "$METADATA" VERSION)"
INSTALLED="not installed"
if [[ -x "$PREFIX/bin/premier" ]]; then
  INSTALLED="$("$PREFIX/bin/premier" --version 2>/dev/null | awk 'NR == 1 { print $NF }')"
fi
echo "installed: $INSTALLED"
echo "available: $AVAILABLE"
if [[ "$INSTALLED" == "$AVAILABLE" ]]; then
  echo "status: current"
else
  echo "status: update available"
fi
