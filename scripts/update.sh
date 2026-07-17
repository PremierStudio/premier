#!/usr/bin/env bash
# Update Premier from an explicitly supplied local archive.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVE=""
PREFIX="${CARGO_HOME:-$HOME/.cargo}"
CHECKSUM=""
DRY_RUN=0
ALLOW_UNSIGNED=0
SIGNATURE_BUNDLE=""

usage() { echo "Usage: ./scripts/update.sh --archive PATH [--checksum SHA256] [--signature-bundle PATH] [--prefix PATH] [--dry-run] [--allow-unsigned]"; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --archive) ARCHIVE="${2:?missing archive path}"; shift 2 ;;
    --checksum) CHECKSUM="${2:?missing checksum}"; shift 2 ;;
    --signature-bundle) SIGNATURE_BUNDLE="${2:?missing signature bundle}"; shift 2 ;;
    --allow-unsigned) ALLOW_UNSIGNED=1; shift ;;
    --prefix) PREFIX="${2:?missing prefix}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done
[[ -n "$ARCHIVE" ]] || { echo "a local --archive is required" >&2; exit 1; }
args=(--archive "$ARCHIVE" --prefix "$PREFIX" --force)
[[ -n "$CHECKSUM" ]] && args+=(--checksum "$CHECKSUM")
[[ -n "$SIGNATURE_BUNDLE" ]] && args+=(--signature-bundle "$SIGNATURE_BUNDLE")
[[ "$ALLOW_UNSIGNED" -eq 1 ]] && args+=(--allow-unsigned)
[[ "$DRY_RUN" -eq 1 ]] && args+=(--dry-run)
exec "$ROOT/scripts/install.sh" "${args[@]}"
