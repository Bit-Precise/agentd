#!/usr/bin/env bash
# Linux archives/packages and per-architecture macOS ZIPs. Windows uses build-windows.ps1.
set -euo pipefail
script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$script_dir/release.py" package "$@"
