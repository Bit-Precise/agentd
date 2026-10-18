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
GORELEASER_VERSION = '2.18.3'
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


def goreleaser_command():
    executable = os.environ.get('GORELEASER', 'goreleaser')
    output = subprocess.check_output([executable, '--version'], text=True)
    if not re.search(r'^GitVersion:\s+' + re.escape(GORELEASER_VERSION) + r'\s*$', output, re.MULTILINE):
        raise ValueError('GoReleaser OSS ' + GORELEASER_VERSION + ' is required')
    return executable


def goreleaser_config(t, v, out, payload, packages=False):
    """Select one target from the checked-in OSS config; never import prebuilt binaries."""
    config = json.loads((ROOT / '.goreleaser.json').read_text())
    config['dist'] = str(payload.parent / 'goreleaser-dist')
    build = config['builds'][0]
    build.update(id='agentd-fips' if t['fips'] else 'agentd', goos=[t['os']], goarch=[t['goarch']])
    build.pop('ignore', None)
    build['goarm'] = [t['goarm']] if t['goarm'] else ['5']
    config['archives'] = [{'ids': [build['id']], 'formats': ['binary'], 'name_template': names(t)[0]}]
    if packages:
        package = config['nfpms'][0]
        package_name = 'agentd-fips' if t['fips'] else 'agentd'
        package.update(id=build['id'], ids=[build['id']], package_name=package_name,
                       conflicts=['agentd' if t['fips'] else 'agentd-fips'])
        package['overrides'] = {
            packager: {'file_name_template': filename.rsplit('.', 1)[0]}
            for packager, filename in zip(('deb', 'rpm'), names(t)[1:])}
        package['contents'] = [
            {'src': str(path), 'dst': '/usr/share/doc/' + package_name + '/' + path.relative_to(payload).as_posix(),
             'file_info': {'mode': 0o644}}
            for path in sorted(payload.rglob('*')) if path.is_file() and path != payload / 'agentd']
    else:
        config['nfpms'] = []
    return config


def compile_target(t, v, out, payload, env, packages=False):
    config = goreleaser_config(t, v, out, payload, packages)
    config_path = payload.parent / 'goreleaser.json'
    config_path.write_text(json.dumps(config, indent=2) + '\n')
    executable = goreleaser_command()
    env = dict(env, AGENTD_SOURCE_VERSION=v['version'], AGENTD_PACKAGE_VERSION=v['packageVersion'],
               AGENTD_GOFIPS140=FIPS_VERSION if t['fips'] else 'off')
    binary = payload / ('agentd.exe' if t['os'] == 'windows' else 'agentd')
    if packages:
        # Snapshot only disables tag/publish validation; version_template preserves
        # the exact package version, including dev-* builds and prereleases.
        run([executable, 'release', '--clean', '--snapshot', '--skip=publish', '--config', config_path], cwd=ROOT, env=env)
        generated = Path(config['dist'])
        artifacts = json.loads((generated / 'artifacts.json').read_text())
        for filename in names(t):
            matches = [item for item in artifacts if item['name'] == filename]
            if len(matches) != 1:
                raise ValueError('GoReleaser must produce exactly one ' + filename)
            source = Path(matches[0]['path'])
            path = source.resolve()
            if not path.is_relative_to(generated.resolve()) or source.is_symlink() or not path.is_file():
                raise ValueError('GoReleaser product is outside its build directory: ' + filename)
            copy_file(path, out / filename)
        copy_file(out / names(t)[0], binary)
    else:
        run([executable, 'build', '--clean', '--snapshot', '--single-target', '--id', config['builds'][0]['id'],
             '--config', config_path, '--output', binary], cwd=ROOT, env=env)
    binary.chmod(0o755)


def build(args, linux_packages=False):
    t, v = target(args.os, args.arch, args.goarm, args.fips), versions(args.version)
    out = Path(args.out).resolve(); out.mkdir(parents=True, exist_ok=True)
    stage = out / '.staging' / t['key']
    if stage.exists():
        shutil.rmtree(stage)
    payload = stage / 'payload'; payload.mkdir(parents=True)
    binary = payload / ('agentd.exe' if t['os'] == 'windows' else 'agentd')
    env = dict(os.environ, GOOS=t['os'], GOARCH=t['goarch'], GOARM=t['goarm'], CGO_ENABLED='0', GOFIPS140=FIPS_VERSION if t['fips'] else 'off')
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
    metadata = {**t, **v, 'sourceVersion': v['version'], 'goVersion': toolchain['GOVERSION'], 'goFIPS140': env['GOFIPS140'], 'goreleaserVersion': GORELEASER_VERSION, 'commit': commit, 'signed': False, 'source': 'https://github.com/bit-precise/agentd/tree/' + commit}
    (payload / 'BUILDINFO.json').write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')
    (stage / 'build.json').write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')
    copy_file(stage / 'build.json', out / '_metadata' / (t['key'] + '.json'))
    license_root = out / '_licenses' / t['key']
    if license_root.exists():
        shutil.rmtree(license_root)
    shutil.copytree(payload / 'licenses', license_root)
    compile_target(t, v, out, payload, env, packages=linux_packages)
    if t['fips']:
        check_fips(binary, env)
    if t['os'] == 'darwin':
        archive_tree(payload, out / names(t)[0])
    else:
        copy_file(binary, out / names(t)[0]); (out / names(t)[0]).chmod(0o755)
    print(json.dumps({'target': t['key'], 'payload': str(payload), 'assets': names(t)}))
    return t, v, out, payload


def package_mac(t, v, out, payload, sign_identity='', app_sign_identity='', sign_keychain='', binary_presigned=False):
    if sys.platform != 'darwin' or t['os'] != 'darwin':
        raise ValueError('PKG creation must run on native macOS')
    payload_info = json.loads((payload / 'BUILDINFO.json').read_text())
    payload_info.update(signed=bool(sign_identity), binarySigned=bool(app_sign_identity or binary_presigned))
    (payload / 'BUILDINFO.json').write_text(json.dumps(payload_info, indent=2, sort_keys=True) + '\n')
    if app_sign_identity:
        command = ['codesign', '--force', '--options', 'runtime', '--timestamp', '--sign', app_sign_identity]
        if sign_keychain: command += ['--keychain', sign_keychain]
        run(command + [payload / 'agentd'])
        run(['codesign', '--verify', '--strict', payload / 'agentd'])
    if app_sign_identity or binary_presigned:
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
    destination = out / names(t)[1]
    unsigned = payload.parent / 'unsigned.pkg' if sign_identity else destination
    run(command + [unsigned])
    if sign_identity:
        command = ['productsign', '--sign', sign_identity, '--timestamp']
        if sign_keychain: command += ['--keychain', sign_keychain]
        run(command + [unsigned, destination])
    if sign_identity:
        run(['pkgutil', '--check-signature', out / names(t)[1]])
    # Expanding verifies this is a real installer, rather than a renamed archive.
    expanded = payload.parent / 'expanded-pkg'
    run(['pkgutil', '--expand-full', out / names(t)[1], expanded])
    if not any(path.name == 'PackageInfo' for path in expanded.rglob('PackageInfo')):
        raise ValueError('PKG has no component metadata')
    metadata_path = out / '_metadata' / (t['key'] + '.json')
    metadata = json.loads(metadata_path.read_text()); metadata['signed'] = bool(sign_identity); metadata['binarySigned'] = bool(app_sign_identity or binary_presigned)
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


def validate_release_signing(info):
    for item in info:
        if item['os'] not in ('windows', 'darwin'): continue
        if item.get('signed') is not True or item.get('binarySigned') is not True:
            raise ValueError('release requires signed installer and binary: ' + item['key'])
        if item['os'] == 'windows' and item.get('timestampVerified') is not True:
            raise ValueError('release requires verified Authenticode timestamp: ' + item['key'])
        if item['os'] == 'darwin' and (item.get('notarized') is not True or item.get('pkgStapled') is not True):
            raise ValueError('release requires notarization and stapled PKG: ' + item['key'])


def collect(incoming, out, require_signed=False):
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
                    # Windows checkouts can use CRLF for repository licenses.
                    # The original bytes were checked by verify_manifest above;
                    # normalize only the merged copy, keeping all other bytes.
                    data = path.read_bytes().replace(b'\r\n', b'\n')
                    if target_path.exists() and target_path.read_bytes() != data:
                        raise ValueError('different license contents at same path: ' + '/'.join(relative))
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    target_path.write_bytes(data)
                else:
                    raise ValueError('unexpected release entry: ' + name)
        if found != expected:
            raise ValueError('release products missing: ' + ', '.join(sorted(expected-found)))
        if len(info) != len(all_targets()) or {i['key'] for i in info} != {t['key'] for t in all_targets()}:
            raise ValueError('release target metadata is incomplete or duplicated')
        if len({i['version'] for i in info}) != 1 or len({i['commit'] for i in info}) != 1:
            raise ValueError('release targets disagree on version/source commit')
        if require_signed: validate_release_signing(info)
        archive_tree(licenses, out / 'agentd-licenses.tgz')
    (out / 'BUILDINFO.json').write_text(json.dumps({'products': expected_assets(), 'targets': sorted(info, key=lambda i:i['key'])}, indent=2, sort_keys=True) + '\n')
    manifest(out)
    print(f'verified {len(found)} products + license bundle + BUILDINFO + SHA256SUMS')


def publish(out, dry_run=False):
    """Import only the verified final assets into a fresh OSS release pipeline."""
    out = Path(out).resolve()
    expected = set(expected_assets()) | {'agentd-licenses.tgz', 'BUILDINFO.json'}
    if verify_manifest(out) != expected:
        raise ValueError('publishing requires exactly 28 checksummed release inputs')
    visible = {path.name for path in out.iterdir() if not path.name.startswith('.')}
    if visible != expected | {'SHA256SUMS'}:
        raise ValueError('publishing requires exactly 29 release files')
    info = json.loads((out / 'BUILDINFO.json').read_text())
    targets = info.get('targets', [])
    if (info.get('products') != expected_assets() or len(targets) != len(all_targets()) or
            {item['key'] for item in targets} != {item['key'] for item in all_targets()} or
            len({item['version'] for item in targets}) != 1 or len({item['commit'] for item in targets}) != 1):
        raise ValueError('release metadata has inconsistent products, targets, version, or commit')
    v = versions(targets[0]['version'])
    if not dry_run:
        validate_release_signing(targets)
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        tag = subprocess.check_output(['git', 'describe', '--tags', '--exact-match', 'HEAD'], cwd=ROOT, text=True).strip()
        if targets[0]['commit'] != commit or v['version'] != tag:
            raise ValueError('release inputs must match the checked-out commit and exact source tag')
    stage = out / '.staging' / 'publish'
    stage.mkdir(parents=True, exist_ok=True)
    config = json.loads((ROOT / '.goreleaser.publish.json').read_text())
    config['dist'] = str(stage / 'goreleaser-dist')
    config_path = stage / 'goreleaser.json'
    config_path.write_text(json.dumps(config, indent=2) + '\n')
    env = dict(os.environ, AGENTD_RELEASE_DIR=str(out), AGENTD_PACKAGE_VERSION=v['packageVersion'])
    command = [goreleaser_command(), 'release', '--clean', '--config', config_path]
    # Always prove the import/checksum path before a real upload. No binary or
    # package is rebuilt, and the original source-version metadata is untouched.
    run(command + ['--snapshot', '--skip=publish'], cwd=ROOT, env=env)
    generated_manifest = Path(config['dist']) / 'SHA256SUMS'
    if generated_manifest.read_bytes() != (out / 'SHA256SUMS').read_bytes():
        raise ValueError('GoReleaser checksum set differs from the verified release manifest')
    copy_file(generated_manifest, out / 'SHA256SUMS')
    verify_manifest(out)
    if not dry_run:
        run(command, cwd=ROOT, env=env)
        if generated_manifest.read_bytes() != (out / 'SHA256SUMS').read_bytes():
            raise ValueError('published checksum set differs from the verified release manifest')
    print('GoReleaser ' + ('verified' if dry_run else 'published') + ' 28 assets + SHA256SUMS')


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
        p.add_argument('--no-manifest', action='store_true', help='defer checksums until external signing and verification finish')
        if command == 'package':
            p.add_argument('--sign-identity', default=''); p.add_argument('--app-sign-identity', default=''); p.add_argument('--sign-keychain', default='')
    for command in ('manifest', 'verify'):
        p=commands.add_parser(command); p.add_argument('--out', required=True)
    p=commands.add_parser('collect'); p.add_argument('--incoming', required=True); p.add_argument('--out', required=True); p.add_argument('--require-signed', action='store_true')
    p=commands.add_parser('publish'); p.add_argument('--out', required=True); p.add_argument('--dry-run', action='store_true', help='verify GoReleaser imports/checksums without publishing')
    args = parser.parse_args()
    try:
        if args.command == 'version': print(json.dumps(versions(args.version)))
        elif args.command == 'expected': print('\n'.join(expected_assets()))
        elif args.command == 'verify-fips': check_fips(args.binary, os.environ); print('Pinned Go FIPS module and default runtime mode verified')
        elif args.command in ('build', 'package'):
            if args.no_manifest: (Path(args.out) / 'SHA256SUMS').unlink(missing_ok=True)
            t,v,out,payload=build(args, linux_packages=args.command == 'package' and args.os == 'linux')
            if args.command == 'package':
                if t['os']=='darwin': package_mac(t,v,out,payload,args.sign_identity,args.app_sign_identity,args.sign_keychain)
                elif t['os']!='linux': raise ValueError('use scripts/build-windows.ps1 to create native MSI')
            if not args.no_manifest: manifest(out)
        elif args.command == 'manifest': manifest(args.out)
        elif args.command == 'verify': verify_manifest(args.out)
        elif args.command == 'collect': collect(args.incoming,args.out,args.require_signed)
        elif args.command == 'publish': publish(args.out,args.dry_run)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'release: {error}\n')

if __name__ == '__main__': main()
