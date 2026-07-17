#!/usr/bin/env bash

distribution_host_target() {
  local machine os
  machine="$(uname -m)"
  os="$(uname -s)"
  case "$os:$machine" in
    Darwin:x86_64) printf '%s\n' x86_64-apple-darwin ;;
    Darwin:arm64|Darwin:aarch64) printf '%s\n' aarch64-apple-darwin ;;
    Linux:x86_64|Linux:amd64) printf '%s\n' x86_64-unknown-linux-gnu ;;
    Linux:arm64|Linux:aarch64) printf '%s\n' aarch64-unknown-linux-gnu ;;
    *) return 1 ;;
  esac
}

distribution_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "missing checksum tool: install sha256sum or shasum" >&2
    return 1
  fi
}

distribution_metadata_value() {
  local file="$1" key="$2"
  awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); exit }' "$file"
}

distribution_safe_extract() {
  local archive="$1" destination="$2"
  command -v python3 >/dev/null 2>&1 || {
    echo "python3 is required to validate and extract release archives safely" >&2
    return 1
  }
  python3 - "$archive" "$destination" <<'PY'
import os
import pathlib
import shutil
import sys
import tarfile

archive_path, destination = sys.argv[1:]
destination_path = pathlib.Path(destination).resolve()
destination_path.mkdir(parents=True, exist_ok=True)

with tarfile.open(archive_path, "r:gz") as archive:
    members = archive.getmembers()
    if not members:
        raise SystemExit("release archive is empty")
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise SystemExit(f"unsafe archive path: {member.name}")
        if member.issym() or member.islnk() or member.isdev() or member.isfifo():
            raise SystemExit(f"unsupported archive entry: {member.name}")
        output = (destination_path / pathlib.Path(*path.parts)).resolve()
        if destination_path != output and destination_path not in output.parents:
            raise SystemExit(f"archive path escapes destination: {member.name}")
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        output = destination_path / pathlib.Path(*path.parts)
        if member.isdir():
            output.mkdir(parents=True, exist_ok=True)
            os.chmod(output, 0o755)
        elif member.isfile():
            output.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise SystemExit(f"could not read archive entry: {member.name}")
            with source, open(output, "wb") as target:
                shutil.copyfileobj(source, target)
            os.chmod(output, member.mode & 0o777)
        else:
            raise SystemExit(f"unsupported archive entry: {member.name}")
PY
}
