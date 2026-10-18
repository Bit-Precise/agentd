#!/usr/bin/env bash
# Linux DEB/RPM and native macOS TGZ/PKG. Windows uses build-windows.ps1.
set -euo pipefail
script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$script_dir/release.py" package "$@"
