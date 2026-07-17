#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/premier-distribution.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

fail() {
  echo "distribution test failed: $*" >&2
  exit 1
}

assert_file() {
  [[ -f "$1" ]] || fail "missing file: $1"
}

assert_absent() {
  [[ ! -e "$1" ]] || fail "expected absent: $1"
}

FAKE="$WORK/premier"
cat >"$FAKE" <<'EOF'
#!/usr/bin/env sh
printf 'premier 0.1.0\n'
EOF
chmod +x "$FAKE"

# shellcheck source=scripts/lib/distribution.sh
source "$ROOT/scripts/lib/distribution.sh"
TARGET="$(distribution_host_target)"

OUT="$WORK/dist"
"$ROOT/scripts/package-release.sh" \
  --binary "$FAKE" \
  --target "$TARGET" \
  --version 0.1.0 \
  --output-dir "$OUT"

ARCHIVE="$OUT/premier-0.1.0-$TARGET.tar.gz"
assert_file "$ARCHIVE"
assert_file "$ARCHIVE.sha256"

# Public installs fail closed until publisher identity has been verified.
if "$ROOT/scripts/install.sh" --archive "$ARCHIVE" --prefix "$WORK/unsigned-prefix" >/dev/null 2>&1; then
  fail "installer accepted an unsigned archive without an explicit developer override"
fi

# Deterministic fake cosign validates that the installer authenticates the blob
# before extraction and pins the GitHub workflow identity + OIDC issuer.
FAKE_BIN="$WORK/fake-bin"
mkdir -p "$FAKE_BIN"
cat >"$FAKE_BIN/cosign" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${COSIGN_LOG:?}"
bundle=""
blob="${!#}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle) bundle="$2"; shift 2 ;;
    *) shift ;;
  esac
done
expected="$(awk 'NR == 1 { print $1 }' "$bundle")"
if command -v sha256sum >/dev/null 2>&1; then actual="$(sha256sum "$blob" | awk '{print $1}')"; else actual="$(shasum -a 256 "$blob" | awk '{print $1}')"; fi
[[ "$actual" == "$expected" ]]
EOF
chmod +x "$FAKE_BIN/cosign"
cp "$ARCHIVE.sha256" "$ARCHIVE.sigstore.json"
COSIGN_LOG="$WORK/cosign.log"
export COSIGN_LOG

OUT_AGAIN="$WORK/dist-again"
"$ROOT/scripts/package-release.sh" \
  --binary "$FAKE" \
  --target "$TARGET" \
  --version 0.1.0 \
  --output-dir "$OUT_AGAIN" >/dev/null
cmp "$ARCHIVE" "$OUT_AGAIN/$(basename "$ARCHIVE")" >/dev/null || fail "release archive is not reproducible"

EXTRACTED="$WORK/extracted"
mkdir -p "$EXTRACTED"
tar -xzf "$ARCHIVE" -C "$EXTRACTED"
PACKAGE="$EXTRACTED/premier-0.1.0-$TARGET"
assert_file "$PACKAGE/bin/premier"
assert_file "$PACKAGE/README.md"
assert_file "$PACKAGE/LICENSE"
assert_file "$PACKAGE/RELEASE-METADATA"
assert_file "$PACKAGE/SHA256SUMS"
(cd "$PACKAGE" && shasum -a 256 -c SHA256SUMS >/dev/null)

PREFIX="$WORK/prefix"
PATH="$FAKE_BIN:$PATH" "$ROOT/scripts/install.sh" --archive "$ARCHIVE" --prefix "$PREFIX"
assert_file "$PREFIX/bin/premier"
grep -q -- '--certificate-identity-regexp' "$COSIGN_LOG" || fail "installer did not pin signer identity"
grep -q -- '--certificate-oidc-issuer https://token.actions.githubusercontent.com' "$COSIGN_LOG" || fail "installer did not pin OIDC issuer"

TAMPERED="$WORK/tampered.tar.gz"
cp "$ARCHIVE" "$TAMPERED"
printf 'tamper' >>"$TAMPERED"
if PATH="$FAKE_BIN:$PATH" "$ROOT/scripts/install.sh" --archive "$TAMPERED" --signature-bundle "$ARCHIVE.sigstore.json" --prefix "$WORK/tampered-prefix" >/dev/null 2>&1; then
  fail "installer accepted a blob that did not match its signature bundle"
fi

CHECK_OUTPUT="$("$ROOT/scripts/version-check.sh" --archive "$ARCHIVE" --prefix "$PREFIX")"
[[ "$CHECK_OUTPUT" == *"installed: 0.1.0"* ]] || fail "version check omitted installed version"
[[ "$CHECK_OUTPUT" == *"available: 0.1.0"* ]] || fail "version check omitted archive version"

UPDATED="$WORK/updated"
mkdir -p "$UPDATED"
cp "$PREFIX/bin/premier" "$UPDATED/before"
PATH="$FAKE_BIN:$PATH" "$ROOT/scripts/update.sh" --archive "$ARCHIVE" --prefix "$PREFIX" --dry-run >/dev/null
cmp "$UPDATED/before" "$PREFIX/bin/premier" >/dev/null || fail "dry-run update changed binary"
PATH="$FAKE_BIN:$PATH" "$ROOT/scripts/update.sh" --archive "$ARCHIVE" --prefix "$PREFIX" >/dev/null

"$ROOT/scripts/uninstall.sh" --prefix "$PREFIX" --dry-run >/dev/null
assert_file "$PREFIX/bin/premier"
"$ROOT/scripts/uninstall.sh" --prefix "$PREFIX" >/dev/null
assert_absent "$PREFIX/bin/premier"

# Extraction must reject traversal before writing outside the staging directory.
BAD="$WORK/bad.tar.gz"
python3 - "$BAD" <<'PY'
import io, tarfile, sys
with tarfile.open(sys.argv[1], "w:gz") as archive:
    info = tarfile.TarInfo("../escape")
    data = b"nope"
    info.size = len(data)
    archive.addfile(info, io.BytesIO(data))
PY
if "$ROOT/scripts/install.sh" --archive "$BAD" --prefix "$PREFIX" --allow-unsigned >/dev/null 2>&1; then
  fail "installer accepted a traversal archive"
fi
assert_absent "$WORK/escape"

echo "distribution shell tests passed"
