#!/usr/bin/env python3
"""Build and verify the cloudflared-shaped agentd release set (standard library only)."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent.parent
GO_VERSION = 'go1.27.2'
FIPS_VERSION = 'v1.0.0-c2097c7c'
NFPM_VERSION = '2.48.0'
LINUX = {'386': ('386', '', '386'), 'amd64': ('amd64', '', 'x86_64'),
         'arm': ('arm', '5', 'arm'), 'armhf': ('arm', '7', 'armhf'),
         'arm64': ('arm64', '', 'aarch64')}


def versions(value):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+\-]*', value):
        raise ValueError('version contains unsupported characters')
    match = re.fullmatch(r'v?(\d+)\.(\d+)\.(\d+)([-+][A-Za-z0-9.+\-]+)?', value)
    if match:
        major, minor, patch = map(int, match.group(1, 2, 3))
        package = f'{major}.{minor}.{patch}' + (match.group(4) or '')
        mac = f'{major}.{minor}.{patch}'
        msi_major = major - 2000 if 2000 <= major <= 2255 else major
        if msi_major > 255 or minor > 255 or patch > 65535:
            raise ValueError('version exceeds MSI numeric limits (calendar years 2000-2255 are mapped)')
        msi = f'{msi_major}.{minor}.{patch}'
    elif value.startswith('dev-'):
        package = '0.0.0-' + value
        mac = msi = '0.0.0'
    else:
        raise ValueError('use vMAJOR.MINOR.PATCH (optional prerelease) or dev-COMMIT')
    return {'version': value, 'packageVersion': package, 'packageRelease': '1', 'pkgVersion': mac, 'msiVersion': msi}


def target(os_name, arch, goarm='', fips=False):
    if arch == 'arm' and goarm == '7':
        arch = 'armhf'
    if os_name == 'linux' and arch in LINUX:
        goarch, arm, rpm = LINUX[arch]
        if goarm and goarm != arm:
            raise ValueError('GOARM does not match the target')
    elif os_name in ('darwin', 'windows') and arch in ('386', 'amd64', 'arm64') and not goarm:
        if (os_name == 'darwin' and arch == '386') or (os_name == 'windows' and arch == 'arm64'):
            raise ValueError('unsupported target')
        goarch, arm, rpm = arch, '', ''
    else:
        raise ValueError('unsupported target')
    if fips and (os_name != 'linux' or arch != 'amd64'):
        raise ValueError('FIPS release is Linux amd64 only')
    return {'os': os_name, 'arch': arch, 'goarch': goarch, 'goarm': arm, 'rpmarch': rpm,
            'fips': fips, 'key': f'{os_name}-{arch}' + ('-fips' if fips else '')}


def names(t):
    if t['os'] == 'linux':
        prefix = 'agentd-fips-linux-' if t['fips'] else 'agentd-linux-'
        return [prefix + t['arch'], prefix + t['arch'] + '.deb', prefix + t['rpmarch'] + '.rpm']
    if t['os'] == 'darwin':
        return [f'agentd-darwin-{t["arch"]}.tgz', f'agentd-{t["arch"]}.pkg']
    return [f'agentd-windows-{t["arch"]}.exe', f'agentd-windows-{t["arch"]}.msi']


def all_targets():
    return [target('linux', arch) for arch in LINUX] + [target('linux', 'amd64', fips=True)] + [target('darwin', arch) for arch in ('amd64', 'arm64')] + [target('windows', arch) for arch in ('386', 'amd64')]


def expected_assets():
    return sorted(name for t in all_targets() for name in names(t))


def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def archive_tree(source, destination, epoch=0):
    destination = Path(destination)
    temporary = destination.with_name(destination.name + '.tmp')
    try:
        with temporary.open('wb') as raw, gzip.GzipFile(fileobj=raw, filename='', mode='wb', mtime=epoch) as gz, tarfile.open(fileobj=gz, mode='w') as tar:
            for path in sorted(Path(source).rglob('*')):
                if path.is_symlink():
                    raise ValueError('archive payload cannot contain symlinks')
                if not path.is_file():
                    continue
                name = path.relative_to(source).as_posix()
                data = path.read_bytes()
                entry = tarfile.TarInfo(name)
                entry.size, entry.uid, entry.gid, entry.mtime = len(data), 0, 0, epoch
                entry.uname = entry.gname = ''
                entry.mode = 0o755 if name in ('agentd', 'agentd.exe') else 0o644
                tar.addfile(entry, io.BytesIO(data))
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def copy_file(source, destination):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def collect_licenses(payload, package_output, toolchain):
    goroot = Path(toolchain['GOROOT'])
    go_license = next((p for p in (goroot / 'LICENSE', goroot.parent / 'LICENSE') if p.is_file()), None)
    if not go_license:
        raise ValueError('Go toolchain LICENSE not found')
    copy_file(go_license, payload / 'licenses/go/LICENSE')
    decoder, remaining, seen = json.JSONDecoder(), package_output.lstrip(), set()
    while remaining:
        package, consumed = decoder.raw_decode(remaining)
        remaining = remaining[consumed:].lstrip()
        module = package.get('Module')
        if not module or module.get('Main') or module['Path'] in seen:
            continue
        effective = module.get('Replace', module)
        directory = Path(effective.get('Dir') or module.get('Dir') or '')
        if not directory.is_absolute() or not directory.is_dir():
            raise ValueError('missing module directory: ' + module['Path'])
        candidates = [p for p in directory.iterdir() if p.is_file() and not p.is_symlink() and p.name.upper().startswith(('LICENSE', 'COPYING', 'NOTICE'))]
        if not candidates:
            raise ValueError('missing module license: ' + module['Path'])
        identity = module['Path'] + '@' + module.get('Version', 'local')
        for path in candidates:
            copy_file(path, payload / 'licenses/modules' / identity / path.name)
        seen.add(module['Path'])


def check_fips(binary, env):
    info = subprocess.check_output(['go', 'version', '-m', str(binary)], env=env, text=True)
    if f'GOFIPS140={FIPS_VERSION}' not in info or not re.search(r'DefaultGODEBUG=(?:[^\n]*,)?fips140=on(?:,|$)', info, re.MULTILINE):
        raise ValueError('FIPS binary is missing pinned module/default runtime mode')
    return info


def build(args):
    t, v = target(args.os, args.arch, args.goarm, args.fips), versions(args.version)
    out = Path(args.out).resolve(); out.mkdir(parents=True, exist_ok=True)
    stage = out / '.staging' / t['key']
    if stage.exists():
        shutil.rmtree(stage)
    payload = stage / 'payload'; payload.mkdir(parents=True)
    binary = payload / ('agentd.exe' if t['os'] == 'windows' else 'agentd')
    env = dict(os.environ, GOOS=t['os'], GOARCH=t['goarch'], GOARM=t['goarm'], CGO_ENABLED='0', GOFIPS140=FIPS_VERSION if t['fips'] else 'off')
    run(['go', 'build', '-mod=readonly', '-trimpath', '-ldflags', '-s -w -X main.Version=' + v['version'], '-o', binary, './cmd/agentd'], cwd=ROOT, env=env)
    binary.chmod(0o755)
    if t['fips']:
        check_fips(binary, env)
    packages = subprocess.check_output(['go', 'list', '-mod=readonly', '-deps', '-json=Module', './cmd/agentd'], cwd=ROOT, env=env, text=True)
    toolchain = json.loads(subprocess.check_output(['go', 'env', '-json', 'GOROOT', 'GOVERSION'], env=env, text=True))
    if t['fips'] and toolchain['GOVERSION'] != GO_VERSION:
        raise ValueError(f'FIPS release requires {GO_VERSION}')
    for source, name in [('README.md', 'README.md'), ('THIRD_PARTY_NOTICES.md', 'THIRD_PARTY_NOTICES.md'), ('go.mod', 'go.mod'), ('go.sum', 'go.sum'), ('examples/agentd/config.yaml', 'config.example.yaml'), ('docs/agentd-config.md', 'docs/agentd-config.md'), ('docs/build-and-release.md', 'docs/build-and-release.md'), ('connection/README.md', 'docs/connection.md'), ('transport/xhttp/README.md', 'docs/xhttp.md'), ('transport/xhttp/LICENSE', 'licenses/xhttp/LICENSE'), ('transport/xhttp/NOTICE', 'licenses/xhttp/NOTICE')]:
        copy_file(ROOT / source, payload / name)
    if (ROOT / 'LICENSE').is_file():
        copy_file(ROOT / 'LICENSE', payload / 'LICENSE')
    collect_licenses(payload, packages, toolchain)
    commit = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.strip()
    metadata = {**t, **v, 'goVersion': toolchain['GOVERSION'], 'goFIPS140': env['GOFIPS140'], 'commit': commit, 'signed': False, 'source': 'https://github.com/bit-precise/agentd/tree/' + commit}
    (payload / 'BUILDINFO.json').write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')
    (stage / 'build.json').write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')
    copy_file(stage / 'build.json', out / '_metadata' / (t['key'] + '.json'))
    license_root = out / '_licenses' / t['key']
    if license_root.exists():
        shutil.rmtree(license_root)
    shutil.copytree(payload / 'licenses', license_root)
    if t['os'] == 'darwin':
        archive_tree(payload, out / names(t)[0])
    else:
        copy_file(binary, out / names(t)[0]); (out / names(t)[0]).chmod(0o755)
    print(json.dumps({'target': t['key'], 'payload': str(payload), 'assets': names(t)}))
    return t, v, out, payload


def package_linux(t, v, out, payload, nfpm):
    if t['os'] != 'linux':
        raise ValueError('Linux packager received another OS')
    nfpm_arch = {'arm': 'arm5', 'armhf': 'arm7'}.get(t['arch'], t['arch'])
    package_name = 'agentd-fips' if t['fips'] else 'agentd'
    contents = []
    for path in sorted(payload.rglob('*')):
        if not path.is_file():
            continue
        relative = path.relative_to(payload).as_posix()
        contents.append({'src': str(path), 'dst': '/usr/bin/agentd' if relative == 'agentd' else '/usr/share/doc/' + package_name + '/' + relative, 'file_info': {'mode': 0o755 if relative == 'agentd' else 0o644}})
    config = {'name': package_name, 'arch': nfpm_arch, 'platform': 'linux', 'version': v['packageVersion'], 'release': '1', 'section': 'net', 'priority': 'optional', 'maintainer': 'bit-precise', 'vendor': 'bit-precise', 'homepage': 'https://github.com/bit-precise/agentd', 'description': 'Authenticated service publishing and domain egress agent', 'license': 'LicenseRef-Proprietary AND MPL-2.0', 'disable_globbing': True, 'contents': contents, 'conflicts': ['agentd' if t['fips'] else 'agentd-fips'], 'rpm': {'buildhost': 'build.agentd.invalid', 'compression': 'gzip'}}
    config_path = payload.parent / 'nfpm.json'; config_path.write_text(json.dumps(config))
    for packager, filename in zip(('deb', 'rpm'), names(t)[1:]):
        run([nfpm, 'package', '--config', config_path, '--packager', packager, '--target', out / filename], env=dict(os.environ, GOFIPS140='off'))


def package_mac(t, v, out, payload, sign_identity='', app_sign_identity=''):
    if sys.platform != 'darwin' or t['os'] != 'darwin':
        raise ValueError('PKG creation must run on native macOS')
    if app_sign_identity:
        run(['codesign', '--force', '--options', 'runtime', '--timestamp', '--sign', app_sign_identity, payload / 'agentd'])
        run(['codesign', '--verify', '--strict', payload / 'agentd'])
        archive_tree(payload, out / names(t)[0])
    root = payload.parent / 'pkg-root'
    for path in payload.rglob('*'):
        if path.is_file():
            relative = path.relative_to(payload).as_posix()
            destination = root / ('usr/local/bin/agentd' if relative == 'agentd' else 'usr/local/share/doc/agentd/' + relative)
            copy_file(path, destination)
            destination.chmod(0o755 if relative == 'agentd' else 0o644)
    command = ['pkgbuild', '--root', root, '--identifier', 'com.bit-precise.agentd', '--version', v['pkgVersion'], '--install-location', '/', '--ownership', 'recommended']
    if sign_identity:
        command += ['--sign', sign_identity]
    run(command + [out / names(t)[1]])
    if sign_identity:
        run(['pkgutil', '--check-signature', out / names(t)[1]])
    # Expanding verifies this is a real installer, rather than a renamed archive.
    expanded = payload.parent / 'expanded-pkg'
    run(['pkgutil', '--expand-full', out / names(t)[1], expanded])
    if not any(path.name == 'PackageInfo' for path in expanded.rglob('PackageInfo')):
        raise ValueError('PKG has no component metadata')
    metadata_path = out / '_metadata' / (t['key'] + '.json')
    metadata = json.loads(metadata_path.read_text()); metadata['signed'] = bool(sign_identity); metadata['binarySigned'] = bool(app_sign_identity)
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')


def checked_relative(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or '..' in path.parts or '\\' in name or '\n' in name or '\r' in name:
        raise ValueError('unsafe manifest path')
    return path


def manifest(out):
    out = Path(out)
    files = [p for p in out.rglob('*') if p.is_file() and not any(part.startswith('.') for part in p.relative_to(out).parts) and p.name != 'SHA256SUMS']
    if any(p.is_symlink() for p in files):
        raise ValueError('manifest cannot contain symlinks')
    (out / 'SHA256SUMS').write_text(''.join(f'{sha256(p)}  {p.relative_to(out).as_posix()}\n' for p in sorted(files)))


def verify_manifest(root):
    root = Path(root)
    lines = (root / 'SHA256SUMS').read_text().splitlines()
    seen = set()
    for line in lines:
        digest, name = line.split('  ', 1)
        checked_relative(name)
        path = root / name
        if name in seen or path.is_symlink() or not path.is_file() or sha256(path) != digest:
            raise ValueError('invalid checksum for ' + name)
        seen.add(name)
    return seen


def collect(incoming, out):
    incoming, out = Path(incoming), Path(out)
    expected, found = set(expected_assets()), set()
    if out.exists() and any(out.iterdir()):
        raise ValueError('collection output must be empty')
    out.mkdir(parents=True, exist_ok=True)
    groups = sorted(incoming.glob('target-*'))
    if len(groups) != len(all_targets()):
        raise ValueError('expected exactly ten target artifacts')
    info = []
    with tempfile.TemporaryDirectory(prefix='agentd-license-merge-') as temporary:
        licenses = Path(temporary)
        for group in groups:
            verified = verify_manifest(group)
            for name in verified:
                path = group / name
                if name in expected:
                    if name in found:
                        raise ValueError('duplicate product: ' + name)
                    copy_file(path, out / name); found.add(name)
                elif name.startswith('_metadata/') and name.endswith('.json'):
                    info.append(json.loads(path.read_text()))
                elif name.startswith('_licenses/'):
                    relative = PurePosixPath(name).parts[2:]
                    target_path = licenses.joinpath(*relative)
                    if target_path.exists() and sha256(target_path) != sha256(path):
                        raise ValueError('different license contents at same path')
                    copy_file(path, target_path)
                else:
                    raise ValueError('unexpected release entry: ' + name)
        if found != expected:
            raise ValueError('release products missing: ' + ', '.join(sorted(expected-found)))
        if len(info) != len(all_targets()) or {i['key'] for i in info} != {t['key'] for t in all_targets()}:
            raise ValueError('release target metadata is incomplete or duplicated')
        if len({i['version'] for i in info}) != 1 or len({i['commit'] for i in info}) != 1:
            raise ValueError('release targets disagree on version/source commit')
        archive_tree(licenses, out / 'agentd-licenses.tgz')
    (out / 'BUILDINFO.json').write_text(json.dumps({'products': expected_assets(), 'targets': sorted(info, key=lambda i:i['key'])}, indent=2, sort_keys=True) + '\n')
    manifest(out)
    print(f'verified {len(found)} products + license bundle + BUILDINFO + SHA256SUMS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    version = commands.add_parser('version'); version.add_argument('--version', required=True)
    commands.add_parser('expected')
    p=commands.add_parser('verify-fips'); p.add_argument('--binary', required=True)
    for command in ('build', 'package'):
        p = commands.add_parser(command)
        p.add_argument('--os', required=True); p.add_argument('--arch', required=True); p.add_argument('--goarm', default='')
        p.add_argument('--version', required=True); p.add_argument('--out', required=True); p.add_argument('--fips', action='store_true')
        if command == 'package':
            p.add_argument('--nfpm', default='nfpm'); p.add_argument('--sign-identity', default=''); p.add_argument('--app-sign-identity', default='')
    for command in ('manifest', 'verify'):
        p=commands.add_parser(command); p.add_argument('--out', required=True)
    p=commands.add_parser('collect'); p.add_argument('--incoming', required=True); p.add_argument('--out', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'version': print(json.dumps(versions(args.version)))
        elif args.command == 'expected': print('\n'.join(expected_assets()))
        elif args.command == 'verify-fips': check_fips(args.binary, os.environ); print('Pinned Go FIPS module and default runtime mode verified')
        elif args.command in ('build', 'package'):
            t,v,out,payload=build(args)
            if args.command == 'package':
                if t['os']=='linux': package_linux(t,v,out,payload,args.nfpm)
                elif t['os']=='darwin': package_mac(t,v,out,payload,args.sign_identity,args.app_sign_identity)
                else: raise ValueError('use scripts/build-windows.ps1 to create native MSI')
            manifest(out)
        elif args.command == 'manifest': manifest(args.out)
        elif args.command == 'verify': verify_manifest(args.out)
        elif args.command == 'collect': collect(args.incoming,args.out)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'release: {error}\n')

if __name__ == '__main__': main()
