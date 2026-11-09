#!/usr/bin/env bash
# Packages release archives from the built (and, for macOS and Windows,
# signed) binaries in DIST and writes SHA256SUMS.
#
#   scripts/release/package.sh <dist-dir> <version> <out-dir>
#
# Linux: agentd_<v>_linux_<arch>.tar.gz; Windows: agentd_<v>_windows_<arch>.zip
# (signed .exe files); macOS ZIPs come from sign-macos.sh and are copied as is.
set -euo pipefail
export COPYFILE_DISABLE=1 # no AppleDouble entries when run on macOS
dist=${1:?usage: package.sh <dist-dir> <version> <out-dir>}
version=${2:?}
out=${3:?}
mkdir -p "$out"
dist=$(cd "$dist" && pwd)
out=$(cd "$out" && pwd)
stage=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/agentd-pkg.XXXXXX")

for arch in amd64 arm64; do
  name="agentd_${version}_linux_${arch}"
  mkdir -p "$stage/$name"
  for c in agentd agentserver agentrelay; do
    install -m 0755 "$dist/$c-linux-$arch" "$stage/$name/$c"
  done
  tar -C "$stage" -czf "$out/$name.tar.gz" "$name"

  name="agentd_${version}_windows_${arch}"
  mkdir -p "$stage/$name"
  for c in agentd agentserver agentrelay; do
    cp "$dist/$c-windows-$arch.exe" "$stage/$name/$c.exe"
  done
  (cd "$stage" && zip -q -r "$out/$name.zip" "$name")

  mac="$dist/agentd_${version}_darwin_${arch}.zip"
  if [ -f "$mac" ]; then
    cp "$mac" "$out/"
  else
    echo "missing signed macOS archive $mac" >&2
    exit 1
  fi
done
(cd "$out" && find . -maxdepth 1 -type f ! -name SHA256SUMS | sed "s|^\./||" | LC_ALL=C sort | xargs shasum -a 256 > SHA256SUMS && cat SHA256SUMS)
