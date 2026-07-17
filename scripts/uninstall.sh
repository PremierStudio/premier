#!/usr/bin/env bash
# Remove only the Premier executable at an explicit install prefix.
set -euo pipefail

PREFIX="${CARGO_HOME:-$HOME/.cargo}"
DRY_RUN=0
usage() { echo "Usage: ./scripts/uninstall.sh [--prefix PATH] [--dry-run]"; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) PREFIX="${2:?missing prefix}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done
[[ -n "$PREFIX" && "$PREFIX" != "/" ]] || { echo "refusing unsafe prefix" >&2; exit 1; }
DESTINATION="$PREFIX/bin/premier"
if [[ ! -e "$DESTINATION" && ! -L "$DESTINATION" ]]; then
  echo "Premier is not installed at $DESTINATION"
  exit 0
fi
if [[ ! -f "$DESTINATION" && ! -L "$DESTINATION" ]]; then
  echo "refusing to remove non-file path: $DESTINATION" >&2
  exit 1
fi
if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "would remove $DESTINATION"
else
  rm -- "$DESTINATION"
  echo "removed $DESTINATION"
fi
