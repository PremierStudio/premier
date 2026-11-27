#!/bin/sh
# Install Premier from GitHub releases (Linux and macOS).
#
#   sh deploy/install.sh              # latest release
#   sh deploy/install.sh v1.2.3       # one tag
#   PREMIER_PREFIX=$HOME/.local sh deploy/install.sh
#
# Downloads premier-<tag>-<target>.tar.gz and SHA256SUMS from
# https://github.com/PremierStudio/premier/releases, checks SHA-256, and
# installs the premier binary plus ui/. Root installs also copy the UI to
# /opt/premier/ui, which deploy/premier.service expects.
set -eu

repo="${PREMIER_REPO:-PremierStudio/premier}"
case "$repo" in
  */*) ;;
  *)
    echo "PREMIER_REPO must look like owner/name" >&2
    exit 1
    ;;
esac

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

os=$(uname -s)
machine=$(uname -m)

case "$os" in
  Linux) sys=unknown-linux-gnu ;;
  Darwin) sys=apple-darwin ;;
  *)
    echo "unsupported operating system: $os" >&2
    exit 1
    ;;
esac

case "$machine" in
  x86_64|amd64) arch=x86_64 ;;
  aarch64|arm64) arch=aarch64 ;;
  *)
    echo "unsupported architecture: $machine" >&2
    exit 1
    ;;
esac

target="${arch}-${sys}"

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  echo "usage: install.sh [tag]" >&2
  exit 0
fi

if [ -n "${1:-}" ]; then
  tag=$1
else
  effective=$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/${repo}/releases/latest")
  case "$effective" in
    */releases/tag/*) tag=${effective##*/tag/} ;;
    *)
      echo "could not resolve the latest Premier release" >&2
      exit 1
      ;;
  esac
  tag=${tag%%\?*}
fi

case "$tag" in
  *[!A-Za-z0-9._-]*)
    echo "refusing tag: $tag" >&2
    exit 1
    ;;
esac

name="premier-${tag}-${target}"
asset="${name}.tar.gz"
base="https://github.com/${repo}/releases/download/${tag}"

if command -v sha256sum >/dev/null 2>&1; then
  hash_cmd=sha256sum
elif command -v shasum >/dev/null 2>&1; then
  hash_cmd=shasum
else
  echo "sha256sum or shasum is required" >&2
  exit 1
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/premier-install.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

echo "downloading ${asset}"
curl -fsSL "${base}/${asset}" -o "${tmp}/${asset}"
curl -fsSL "${base}/SHA256SUMS" -o "${tmp}/SHA256SUMS"

expected=$(awk -v asset="$asset" '
  {
    name = $NF
    sub(/^\*/, "", name)
    gsub(/\r/, "", name)
    if (name == asset) {
      gsub(/\r/, "", $1)
      print $1
      exit
    }
  }
' "${tmp}/SHA256SUMS")

if [ -z "$expected" ]; then
  echo "SHA256SUMS has no entry for ${asset}" >&2
  exit 1
fi

if [ "$hash_cmd" = sha256sum ]; then
  actual=$(sha256sum "${tmp}/${asset}" | awk '{print $1}')
else
  actual=$(shasum -a 256 "${tmp}/${asset}" | awk '{print $1}')
fi

expected=$(printf '%s' "$expected" | tr 'ABCDEF' 'abcdef')
actual=$(printf '%s' "$actual" | tr 'ABCDEF' 'abcdef')
if [ "$expected" != "$actual" ]; then
  echo "SHA-256 mismatch for ${asset}" >&2
  exit 1
fi

tar -xzf "${tmp}/${asset}" -C "$tmp"
src="${tmp}/${name}"
if [ ! -f "${src}/premier" ] || [ ! -d "${src}/ui" ]; then
  echo "archive does not contain premier and ui/" >&2
  exit 1
fi

if [ -n "${PREMIER_PREFIX:-}" ]; then
  prefix=$PREMIER_PREFIX
elif [ "$(id -u)" -eq 0 ]; then
  prefix=/usr/local
elif [ -w /usr/local ] || [ -w /usr/local/bin ]; then
  prefix=/usr/local
else
  prefix="${HOME}/.local"
fi

bindir="${prefix}/bin"
uidir="${prefix}/share/premier/ui"
mkdir -p "$bindir"
rm -rf "$uidir"
mkdir -p "$uidir"
cp "${src}/premier" "${bindir}/premier"
chmod 755 "${bindir}/premier"
cp -R "${src}/ui/." "$uidir/"

echo "installed ${bindir}/premier"
echo "studio UI ${uidir}"
echo "export PREMIER_STATIC_UI_DIR=\"${uidir}\""

case ":${PATH}:" in
  *":${bindir}:"*) ;;
  *)
    echo "PATH note: add ${bindir} to PATH"
    echo "  export PATH=\"${bindir}:\$PATH\""
    ;;
esac

if [ "$(id -u)" -eq 0 ]; then
  mkdir -p /opt/premier
  rm -rf /opt/premier/ui
  mkdir -p /opt/premier/ui
  cp -R "${src}/ui/." /opt/premier/ui/
  echo "installed /opt/premier/ui for deploy/premier.service"
fi
