#!/usr/bin/env bash
# Build one supported release target. Requires Go 1.27+ and Python 3.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/build-release.sh --os OS --arch ARCH [--goarm 5|7] --version VERSION --out DIRECTORY

Supported targets:
  linux: 386, amd64, arm (--goarm 5 => arm; --goarm 7 => armhf), arm64
  darwin: amd64, arm64
  windows: amd64, 386

Builds both agents (server/console) and agentd (client) with CGO_ENABLED=0,
-mod=readonly and -trimpath. SQLite uses the pure-Go modernc driver. Produces a tar.gz
(Linux/macOS) or zip (Windows), plus a verified SHA256SUMS file. Use a separate
output directory for each concurrent invocation. Sequential builds may share it.
EOF
}

target_os=''
target_arch=''
target_arm=''
release_version=''
output_dir=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --os|--arch|--goarm|--version|--out)
      if [[ $# -lt 2 || -z "$2" ]]; then
        printf 'Missing value for %s\n' "$1" >&2
        exit 2
      fi
      case "$1" in
        --os) target_os=$2 ;;
        --arch) target_arch=$2 ;;
        --goarm) target_arm=$2 ;;
        --version) release_version=$2 ;;
        --out) output_dir=$2 ;;
      esac
      shift 2
      ;;
    --help|-h) usage; exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$target_os" || -z "$target_arch" || -z "$release_version" || -z "$output_dir" ]]; then
  usage >&2
  exit 2
fi
if [[ ! "$release_version" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ ]]; then
  printf 'Version must contain only letters, digits, dot, underscore, plus and hyphen.\n' >&2
  exit 2
fi
artifact_arch=$target_arch
case "$target_os/$target_arch" in
  linux/386|linux/amd64|linux/arm64|darwin/amd64|darwin/arm64|windows/amd64|windows/386)
    if [[ -n "$target_arm" ]]; then
      printf '%s/%s does not accept --goarm\n' "$target_os" "$target_arch" >&2
      exit 2
    fi
    ;;
  linux/arm)
    case "$target_arm" in
      5) artifact_arch=arm ;;
      7) artifact_arch=armhf ;;
      *) printf 'linux/arm requires --goarm 5 or --goarm 7\n' >&2; exit 2 ;;
    esac
    ;;
  *) printf 'Unsupported target: %s/%s\n' "$target_os" "$target_arch" >&2; exit 2 ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
output_dir=$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$output_dir")
scratch_dir=$(mktemp -d "${TMPDIR:-/tmp}/agentd-release.XXXXXX")
trap 'rm -rf -- "$scratch_dir"' EXIT
cd "$repo_dir"

binary_name=agentd
server_name=agents
if [[ "$target_os" == windows ]]; then binary_name=agentd.exe; server_name=agents.exe; fi
export CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" GOARM="$target_arm"
# Never inherit an ambient FIPS experiment into ordinary release artifacts.
export GOFIPS140=off
go build -mod=readonly -trimpath -ldflags "-s -w -X main.Version=$release_version" \
  -o "$scratch_dir/$binary_name" ./cmd/agentd
go build -mod=readonly -trimpath -ldflags "-s -w -X main.Version=$release_version" \
  -o "$scratch_dir/$server_name" ./cmd/agents
go list -mod=readonly -deps -json=Module ./cmd/agentd ./cmd/agents > "$scratch_dir/packages.json"
go env -json GOROOT GOVERSION > "$scratch_dir/toolchain.json"

source_commit=$(git rev-parse --verify HEAD 2>/dev/null || true)
source_epoch=${SOURCE_DATE_EPOCH:-}
if [[ -z "$source_epoch" ]]; then source_epoch=$(git log -1 --format=%ct 2>/dev/null || true); fi
source_epoch=${source_epoch:-0}

python3 - "$repo_dir" "$scratch_dir" "$output_dir" "$target_os" "$artifact_arch" "$release_version" "$binary_name" "$source_commit" "$source_epoch" <<'PY'
import datetime
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import zipfile

repo, scratch, output = map(Path, sys.argv[1:4])
target_os, arch, version, binary, commit, epoch_text = sys.argv[4:]
server_binary = 'agents.exe' if target_os == 'windows' else 'agents'
try:
    epoch = int(epoch_text)
    if epoch < 0:
        raise ValueError()
except ValueError:
    raise SystemExit('SOURCE_DATE_EPOCH must be a nonnegative integer')

output.mkdir(parents=True, exist_ok=True)
base = f'agentd-{version}-{target_os}-{arch}'
toolchain = json.loads((scratch / 'toolchain.json').read_text())
goroot = Path(toolchain['GOROOT'])
# Official Go archives keep LICENSE inside GOROOT; Homebrew keeps it beside
# libexec (GOROOT). Both locations refer to the installed toolchain package.
go_license = next((path for path in (goroot / 'LICENSE', goroot.parent / 'LICENSE') if path.is_file()), None)
if go_license is None:
    raise SystemExit(f'Missing installed Go toolchain LICENSE: {goroot}')
files = {
    binary: (scratch / binary, 0o755),
    server_binary: (scratch / server_binary, 0o755),
    'README.md': (repo / 'README.md', 0o644),
    'THIRD_PARTY_NOTICES.md': (repo / 'THIRD_PARTY_NOTICES.md', 0o644),
    'go.mod': (repo / 'go.mod', 0o644),
    'go.sum': (repo / 'go.sum', 0o644),
    'config.example.yaml': (repo / 'examples/agentd/config.yaml', 0o644),
    'agents.example.yaml': (repo / 'examples/agents/config.yaml', 0o644),
    'examples/agentd/config.yaml': (repo / 'examples/agentd/config.yaml', 0o644),
    'examples/agentd/local.yaml': (repo / 'examples/agentd/local.yaml', 0o644),
    'examples/agents/config.yaml': (repo / 'examples/agents/config.yaml', 0o644),
    'docs/local-development.md': (repo / 'docs/local-development.md', 0o644),
    'docs/build-and-release.md': (repo / 'docs/build-and-release.md', 0o644),
    'docs/agentd-config.md': (repo / 'docs/agentd-config.md', 0o644),
    'docs/backend-implementation.md': (repo / 'docs/backend-implementation.md', 0o644),
    'edge/README.md': (repo / 'edge/README.md', 0o644),
    'connection/README.md': (repo / 'connection/README.md', 0o644),
    'transport/xhttp/README.md': (repo / 'transport/xhttp/README.md', 0o644),
    'licenses/xhttp/LICENSE': (repo / 'transport/xhttp/LICENSE', 0o644),
    'licenses/xhttp/NOTICE': (repo / 'transport/xhttp/NOTICE', 0o644),
    'licenses/go/LICENSE': (go_license, 0o644),
}
if (repo / 'LICENSE').is_file():
    files['LICENSE'] = (repo / 'LICENSE', 0o644)

# Read only license/notice files from modules actually compiled into this target.
# The lockfiles retain the full dependency graph and any replacement provenance.
decoder = json.JSONDecoder()
remaining = (scratch / 'packages.json').read_text().lstrip()
found_modules = set()
while remaining:
    package, consumed = decoder.raw_decode(remaining)
    remaining = remaining[consumed:].lstrip()
    module = package.get('Module')
    if not module or module.get('Main') or module['Path'] in found_modules:
        continue
    effective = module.get('Replace', module)
    directory = Path(effective.get('Dir') or module.get('Dir') or '')
    if not directory.is_absolute() or not directory.is_dir():
        raise SystemExit(f'Missing downloaded module directory: {module["Path"]}')
    license_files = []
    for path in directory.iterdir():
        name = path.name.upper()
        if path.is_file() and not path.is_symlink() and name.startswith(('LICENSE', 'COPYING', 'NOTICE')):
            license_files.append(path)
    if not license_files:
        raise SystemExit(f'No license/notice file found for compiled module: {module["Path"]}')
    identity = module['Path'] + '@' + module.get('Version', 'local')
    for path in license_files:
        files[f'licenses/modules/{identity}/{path.name}'] = (path, 0o644)
    found_modules.add(module['Path'])
payloads = {name: (path.read_bytes(), mode) for name, (path, mode) in files.items()}
source = f'https://github.com/bit-precise/agentd/tree/{commit}' if commit else 'https://github.com/bit-precise/agentd'
payloads['BUILDINFO'] = (
    f'version={version}\nplatform={target_os}/{arch}\ncommit={commit or "unknown"}\nsource={source}\ngo_version={toolchain["GOVERSION"]}\nbinaries=agentd,agents\n'.encode(),
    0o644,
)

suffix = '.zip' if target_os == 'windows' else '.tar.gz'
archive = output / (base + suffix)
temporary = output / (archive.name + '.tmp')
try:
    if target_os == 'windows':
        stamp = datetime.datetime.fromtimestamp(max(epoch, 315532800), datetime.timezone.utc).timetuple()[:6]
        with zipfile.ZipFile(temporary, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
            for name, (data, mode) in sorted(payloads.items()):
                info = zipfile.ZipInfo(f'{base}/{name}', stamp)
                info.create_system = 3
                info.external_attr = (0o100000 | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, data)
        with zipfile.ZipFile(temporary) as z:
            if z.testzip() is not None:
                raise SystemExit('zip integrity check failed')
            assert z.read(f'{base}/{binary}') == payloads[binary][0]
            assert z.read(f'{base}/{server_binary}') == payloads[server_binary][0]
    else:
        with temporary.open('wb') as raw:
            with gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=epoch) as gz:
                with tarfile.open(fileobj=gz, mode='w', format=tarfile.PAX_FORMAT) as tar:
                    for name, (data, mode) in sorted(payloads.items()):
                        info = tarfile.TarInfo(f'{base}/{name}')
                        info.size, info.mode, info.mtime = len(data), mode, epoch
                        info.uid = info.gid = 0
                        info.uname = info.gname = ''
                        tar.addfile(info, io.BytesIO(data))
        with tarfile.open(temporary, 'r:gz') as tar:
            assert tar.extractfile(f'{base}/{binary}').read() == payloads[binary][0]
            assert tar.extractfile(f'{base}/{server_binary}').read() == payloads[server_binary][0]
    os.replace(temporary, archive)
finally:
    temporary.unlink(missing_ok=True)

archives = sorted([*output.glob('agentd-*.tar.gz'), *output.glob('agentd-*.zip')])
def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()

checksums = [(sha256(path), path.name) for path in archives]
checksum_temp = output / 'SHA256SUMS.tmp'
checksum_temp.write_text(''.join(f'{digest}  {name}\n' for digest, name in checksums))
os.replace(checksum_temp, output / 'SHA256SUMS')
for digest, name in checksums:
    if sha256(output / name) != digest:
        raise SystemExit(f'checksum verification failed: {name}')
print(archive)
print(output / 'SHA256SUMS')
PY
