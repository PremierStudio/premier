#!/usr/bin/env bash
# Install Premier from a local release archive, or build from source as fallback.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/distribution.sh
source "$ROOT/scripts/lib/distribution.sh"

PREFIX="${CARGO_HOME:-$HOME/.cargo}"
ARCHIVE=""
EXPECTED_CHECKSUM=""
FORCE=0
DRY_RUN=0
SKIP_VIEWER=0
ALLOW_FOREIGN=0
ALLOW_UNSIGNED=0
SIGNATURE_BUNDLE=""
VERIFICATION_KEY=""
CERTIFICATE_IDENTITY_REGEXP='^https://github\.com/PremierStudio/premier\.dev/\.github/workflows/release\.yml@refs/tags/v[0-9].*$'
CERTIFICATE_OIDC_ISSUER='https://token.actions.githubusercontent.com'

usage() {
  cat <<'EOF'
Usage: ./scripts/install.sh [options]

  --archive PATH        Install a supplied local prebuilt archive (preferred)
  --checksum SHA256     Require this archive SHA-256 before extraction
  --signature-bundle PATH
                        Sigstore bundle for the archive (default: ARCHIVE.sigstore.json)
  --verification-key PATH
                        Verify a key-signed bundle instead of GitHub keyless identity
  --certificate-identity-regexp REGEXP
                        Expected keyless signer identity (pinned to Premier release workflow)
  --certificate-oidc-issuer URL
                        Expected keyless OIDC issuer
  --allow-unsigned      Developer-only escape hatch for local archives
  --prefix PATH         Explicit install prefix (default: $CARGO_HOME or ~/.cargo)
  --force               Atomically replace an existing binary
  --dry-run             Print the resolved operation without changing files
  --allow-foreign-architecture
                        Permit installing an archive for a different host
  --skip-viewer         Source fallback: use an existing viewer dist

No URL is accepted and this script never downloads or executes archive content.
If no archive is supplied or found in ./dist, it falls back to a local source build.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --archive) ARCHIVE="${2:?missing archive path}"; shift 2 ;;
    --checksum) EXPECTED_CHECKSUM="${2:?missing checksum}"; shift 2 ;;
    --signature-bundle) SIGNATURE_BUNDLE="${2:?missing signature bundle}"; shift 2 ;;
    --verification-key) VERIFICATION_KEY="${2:?missing verification key}"; shift 2 ;;
    --certificate-identity-regexp) CERTIFICATE_IDENTITY_REGEXP="${2:?missing certificate identity regexp}"; shift 2 ;;
    --certificate-oidc-issuer) CERTIFICATE_OIDC_ISSUER="${2:?missing certificate OIDC issuer}"; shift 2 ;;
    --allow-unsigned) ALLOW_UNSIGNED=1; shift ;;
    --prefix) PREFIX="${2:?missing prefix}"; shift 2 ;;
    --force) FORCE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --skip-viewer) SKIP_VIEWER=1; shift ;;
    --allow-foreign-architecture) ALLOW_FOREIGN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

case "$ARCHIVE" in http://*|https://*) echo "remote archives are not accepted; download and authenticate it separately" >&2; exit 1 ;; esac
HOST_TARGET="$(distribution_host_target || true)"
if [[ -z "$ARCHIVE" && -n "$HOST_TARGET" ]]; then
  for candidate in "$ROOT"/dist/premier-*-"$HOST_TARGET".tar.gz; do
    [[ -f "$candidate" ]] && ARCHIVE="$candidate"
  done
fi

if [[ -z "$ARCHIVE" ]]; then
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "would build Premier from source and install to $PREFIX/bin/premier"
    exit 0
  fi
  command -v cargo >/dev/null 2>&1 || { echo "no local archive found and cargo is unavailable" >&2; exit 1; }
  command -v npm >/dev/null 2>&1 || { echo "no local archive found and npm is unavailable" >&2; exit 1; }
  if [[ "$SKIP_VIEWER" -eq 0 ]]; then
    (cd "$ROOT" && [[ -d node_modules ]] || npm install)
    (cd "$ROOT" && npm run build)
  elif [[ ! -f "$ROOT/apps/viewer/dist/index.html" ]]; then
    echo "apps/viewer/dist/index.html is missing; omit --skip-viewer" >&2
    exit 1
  fi
  args=(install --path "$ROOT/crates/premier-cli" --locked --root "$PREFIX")
  [[ "$FORCE" -eq 1 ]] && args+=(--force)
  cargo "${args[@]}"
  echo "installed locally built Premier to $PREFIX/bin/premier"
  exit 0
fi

[[ -f "$ARCHIVE" ]] || { echo "archive not found: $ARCHIVE" >&2; exit 1; }
if [[ -z "$SIGNATURE_BUNDLE" && -f "$ARCHIVE.sigstore.json" ]]; then
  SIGNATURE_BUNDLE="$ARCHIVE.sigstore.json"
fi
if [[ -n "$SIGNATURE_BUNDLE" ]]; then
  [[ -f "$SIGNATURE_BUNDLE" ]] || { echo "signature bundle not found: $SIGNATURE_BUNDLE" >&2; exit 1; }
  command -v cosign >/dev/null 2>&1 || {
    echo "cosign is required to verify the Premier release signature" >&2
    exit 1
  }
  if [[ -n "$VERIFICATION_KEY" ]]; then
    cosign verify-blob --key "$VERIFICATION_KEY" --bundle "$SIGNATURE_BUNDLE" "$ARCHIVE" >/dev/null
  else
    cosign verify-blob \
      --bundle "$SIGNATURE_BUNDLE" \
      --certificate-identity-regexp "$CERTIFICATE_IDENTITY_REGEXP" \
      --certificate-oidc-issuer "$CERTIFICATE_OIDC_ISSUER" \
      "$ARCHIVE" >/dev/null
  fi
elif [[ "$ALLOW_UNSIGNED" -ne 1 ]]; then
  echo "refusing unsigned release archive; provide --signature-bundle or use --allow-unsigned only for a local developer build" >&2
  exit 1
else
  echo "WARNING: installing an unsigned local developer archive" >&2
fi
ACTUAL_CHECKSUM="$(distribution_sha256 "$ARCHIVE")"
if [[ -z "$EXPECTED_CHECKSUM" && -f "$ARCHIVE.sha256" ]]; then
  EXPECTED_CHECKSUM="$(awk 'NR == 1 { print $1 }' "$ARCHIVE.sha256")"
fi
if [[ -n "$EXPECTED_CHECKSUM" && "$ACTUAL_CHECKSUM" != "$EXPECTED_CHECKSUM" ]]; then
  echo "archive checksum mismatch" >&2
  exit 1
fi

STAGING="$(mktemp -d "${TMPDIR:-/tmp}/premier-install.XXXXXX")"
trap 'rm -rf "$STAGING"' EXIT
distribution_safe_extract "$ARCHIVE" "$STAGING"
METADATA_LIST="$(find "$STAGING" -type f -name RELEASE-METADATA)"
METADATA_COUNT="$(printf '%s\n' "$METADATA_LIST" | awk 'NF { count += 1 } END { print count + 0 }')"
[[ "$METADATA_COUNT" -eq 1 ]] || { echo "archive must contain exactly one release metadata file" >&2; exit 1; }
PACKAGE="$(dirname "$METADATA_LIST")"
VERSION="$(distribution_metadata_value "$PACKAGE/RELEASE-METADATA" VERSION)"
TARGET="$(distribution_metadata_value "$PACKAGE/RELEASE-METADATA" TARGET)"
[[ -n "$VERSION" && -n "$TARGET" ]] || { echo "invalid release metadata" >&2; exit 1; }
if [[ "$ALLOW_FOREIGN" -eq 0 && -n "$HOST_TARGET" && "$TARGET" != "$HOST_TARGET" ]]; then
  echo "archive target $TARGET does not match host $HOST_TARGET" >&2
  exit 1
fi
[[ -f "$PACKAGE/bin/premier" && -f "$PACKAGE/SHA256SUMS" ]] || { echo "incomplete release archive" >&2; exit 1; }
(
  cd "$PACKAGE"
  for path in LICENSE README.md RELEASE-METADATA bin/premier; do
    expected="$(awk -v path="$path" '$2 == path { print $1 }' SHA256SUMS)"
    [[ -n "$expected" && "$(printf '%s\n' "$expected" | wc -l | tr -d ' ')" -eq 1 ]] || {
      echo "missing or duplicate checksum: $path" >&2
      exit 1
    }
    [[ -f "$path" ]] || { echo "missing checksummed file: $path" >&2; exit 1; }
    [[ "$(distribution_sha256 "$path")" == "$expected" ]] || { echo "checksum mismatch: $path" >&2; exit 1; }
  done
)

DESTINATION="$PREFIX/bin/premier"
if [[ -e "$DESTINATION" && "$FORCE" -eq 0 ]]; then
  echo "$DESTINATION already exists; pass --force to replace it" >&2
  exit 1
fi
if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "would install Premier $VERSION ($TARGET) to $DESTINATION"
  exit 0
fi
mkdir -p "$PREFIX/bin"
TEMP_DESTINATION="$PREFIX/bin/.premier.install.$$"
install -m 0755 "$PACKAGE/bin/premier" "$TEMP_DESTINATION"
mv -f "$TEMP_DESTINATION" "$DESTINATION"
echo "installed Premier $VERSION ($TARGET) to $DESTINATION"
if [[ -n "$SIGNATURE_BUNDLE" ]]; then
  echo "archive SHA-256: $ACTUAL_CHECKSUM (publisher signature verified)"
else
  echo "archive SHA-256: $ACTUAL_CHECKSUM (unsigned developer override)"
fi
