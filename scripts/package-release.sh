#!/usr/bin/env bash
# Build a reproducible Premier release archive around one embedded-viewer binary.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/distribution.sh
source "$ROOT/scripts/lib/distribution.sh"

TARGET=""
VERSION=""
BINARY=""
OUTPUT_DIR="$ROOT/dist"
SKIP_VIEWER=0
EXPECT_SIGSTORE=0

usage() {
  cat <<'EOF'
Usage: ./scripts/package-release.sh [options]

  --target TARGET       Rust target triple (defaults to this host)
  --version VERSION     Release version (defaults to workspace Cargo.toml)
  --binary PATH         Package an already-built binary (required for cross packaging)
  --output-dir PATH     Archive destination (default: ./dist)
  --skip-viewer         Use the existing apps/viewer/dist when building locally
  --expect-sigstore     Mark metadata for a Sigstore bundle added by release CI

The output contains the single embedded-viewer binary, README, LICENSE,
release metadata, internal checksums, and an archive checksum sidecar.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="${2:?missing target}"; shift 2 ;;
    --version) VERSION="${2:?missing version}"; shift 2 ;;
    --binary) BINARY="${2:?missing binary}"; shift 2 ;;
    --output-dir) OUTPUT_DIR="${2:?missing output directory}"; shift 2 ;;
    --skip-viewer) SKIP_VIEWER=1; shift ;;
    --expect-sigstore) EXPECT_SIGSTORE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

TARGET="${TARGET:-$(distribution_host_target || true)}"
[[ -n "$TARGET" ]] || { echo "unsupported host; pass --target" >&2; exit 1; }
case "$TARGET" in
  x86_64-apple-darwin|aarch64-apple-darwin|x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu) ;;
  *) echo "unsupported release target: $TARGET" >&2; exit 1 ;;
esac

if [[ -z "$VERSION" ]]; then
  VERSION="$(awk -F' *= *' '/^version = / { gsub(/\"/, "", $2); print $2; exit }' "$ROOT/Cargo.toml")"
fi
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || {
  echo "invalid release version: $VERSION" >&2
  exit 1
}

if [[ -z "$BINARY" ]]; then
  command -v cargo >/dev/null 2>&1 || { echo "cargo is required for a source build" >&2; exit 1; }
  if [[ "$SKIP_VIEWER" -eq 0 ]]; then
    command -v npm >/dev/null 2>&1 || { echo "npm is required to build the embedded viewer" >&2; exit 1; }
    (cd "$ROOT" && [[ -d node_modules ]] || npm install)
    (cd "$ROOT" && npm run build)
  elif [[ ! -f "$ROOT/apps/viewer/dist/index.html" ]]; then
    echo "apps/viewer/dist/index.html is missing; omit --skip-viewer" >&2
    exit 1
  fi
  (cd "$ROOT" && cargo build --release --locked --target "$TARGET" -p premier-cli)
  BINARY="$ROOT/target/$TARGET/release/premier"
fi

[[ -f "$BINARY" && -x "$BINARY" ]] || { echo "binary is not an executable file: $BINARY" >&2; exit 1; }
[[ -f "$ROOT/README.md" ]] || { echo "README.md is missing" >&2; exit 1; }
[[ -f "$ROOT/LICENSE" ]] || { echo "LICENSE is missing" >&2; exit 1; }

NAME="premier-$VERSION-$TARGET"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/premier-release.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
PACKAGE="$WORK/$NAME"
mkdir -p "$PACKAGE/bin" "$OUTPUT_DIR"
install -m 0755 "$BINARY" "$PACKAGE/bin/premier"
install -m 0644 "$ROOT/README.md" "$PACKAGE/README.md"
install -m 0644 "$ROOT/LICENSE" "$PACKAGE/LICENSE"
SIGNATURE="none"
[[ "$EXPECT_SIGSTORE" -eq 1 ]] && SIGNATURE="sigstore-keyless"
cat >"$PACKAGE/RELEASE-METADATA" <<EOF
NAME=premier
VERSION=$VERSION
TARGET=$TARGET
VIEWER=embedded
SIGNATURE=$SIGNATURE
EOF

(
  cd "$PACKAGE"
  for path in LICENSE README.md RELEASE-METADATA bin/premier; do
    printf '%s  %s\n' "$(distribution_sha256 "$path")" "$path"
  done >SHA256SUMS
)

ARCHIVE="$OUTPUT_DIR/$NAME.tar.gz"
python3 - "$PACKAGE" "$ARCHIVE" <<'PY'
import gzip
import pathlib
import tarfile
import sys

source = pathlib.Path(sys.argv[1])
archive_path = pathlib.Path(sys.argv[2])
paths = [source, *sorted(source.rglob("*"), key=lambda path: path.as_posix())]
with open(archive_path, "wb") as raw:
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for path in paths:
                relative = pathlib.Path(source.name) / path.relative_to(source)
                info = archive.gettarinfo(str(path), arcname=relative.as_posix())
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 0
                info.mode = 0o755 if path.is_dir() or relative.as_posix().endswith("/bin/premier") else 0o644
                if path.is_file():
                    with open(path, "rb") as payload:
                        archive.addfile(info, payload)
                else:
                    archive.addfile(info)
PY

ARCHIVE_HASH="$(distribution_sha256 "$ARCHIVE")"
printf '%s  %s\n' "$ARCHIVE_HASH" "$(basename "$ARCHIVE")" >"$ARCHIVE.sha256"
echo "packaged $ARCHIVE"
echo "checksum $ARCHIVE_HASH"
