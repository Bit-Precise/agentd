#!/usr/bin/env python3
"""Build and verify agentd's GitHub CLI-shaped release set (standard library only)."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
GO_VERSION = 'go1.27.2'
FIPS_VERSION = 'v1.0.0-c2097c7c'
GORELEASER_VERSION = '2.18.3'
LINUX = {'386': ('386', '', '386'), 'amd64': ('amd64', '', 'x86_64'),
         'arm64': ('arm64', '', 'aarch64'), 'armv6': ('arm', '6', 'armv6hl')}


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
    if os_name == 'linux' and arch == 'arm' and goarm in ('', '6'):
        arch = 'armv6'
    if os_name == 'linux' and arch in LINUX:
        goarch, arm, rpm = LINUX[arch]
        if goarm and goarm != arm:
            raise ValueError('GOARM does not match the target')
    elif os_name in ('darwin', 'windows') and arch in ('386', 'amd64', 'arm64') and not goarm:
        if os_name == 'darwin' and arch == '386':
            raise ValueError('unsupported target')
        goarch, arm, rpm = arch, '', ''
    elif os_name == 'darwin' and arch == 'universal' and not goarm:
        goarch, arm, rpm = 'all', '', ''
    else:
        raise ValueError('unsupported target')
    if fips and (os_name != 'linux' or arch != 'amd64'):
        raise ValueError('local FIPS builds are Linux amd64 only')
    return {'os': os_name, 'arch': arch, 'goarch': goarch, 'goarm': arm, 'rpmarch': rpm,
            'fips': fips, 'key': f'{os_name}-{arch}' + ('-fips' if fips else '')}


def version_info(value):
    return versions(value) if isinstance(value, str) else versions(value['version'])


def product_stem(t, version):
    v = version_info(version)
    platform = 'macOS' if t['os'] == 'darwin' else t['os']
    return f'agentd_{v["packageVersion"]}_{platform}_{t["arch"]}' + ('_fips' if t['fips'] else '')


def names(t, version):
    stem = product_stem(t, version)
    if t['os'] == 'linux':
        return [stem + extension for extension in ('.tar.gz', '.deb', '.rpm')]
    if t['os'] == 'darwin':
        return [stem + ('.pkg' if t['arch'] == 'universal' else '.zip')]
    return [stem + '.zip', stem + '.msi']


def checksum_name(version):
    return f'agentd_{version_info(version)["packageVersion"]}_checksums.txt'


def payload_binary(t):
    return 'agentd.exe' if t['os'] == 'windows' else 'agentd'


def archive_binary(t, version):
    prefix = '' if t['os'] == 'windows' else product_stem(t, version) + '/'
    return prefix + 'bin/' + payload_binary(t)


def all_targets():
    return ([target('linux', arch) for arch in LINUX] +
            [target('darwin', arch) for arch in ('amd64', 'arm64', 'universal')] +
            [target('windows', arch) for arch in ('386', 'amd64', 'arm64')])


def expected_assets(version):
    return sorted(name for t in all_targets() for name in names(t, version))


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
    info = subprocess.check_output(['go', 'version', '-m', str(binary)], env=build_environment(env), text=True)
    if f'GOFIPS140={FIPS_VERSION}' not in info or not re.search(r'DefaultGODEBUG=(?:[^\n]*,)?fips140=on(?:,|$)', info, re.MULTILINE):
        raise ValueError('FIPS binary is missing pinned module/default runtime mode')
    return info


def build_environment(env=None):
    """Signing hooks need identities/keychain access, never exported Apple keys."""
    source = os.environ if env is None else env
    child = {name: value for name, value in source.items()
             if not (name.startswith('APPLE_') and
                     ('P12' in name or 'PASSWORD' in name or name.endswith('_BASE64')))}
    child.setdefault('AGENTD_SIGN_ARTIFACTS', 'false')
    if child['AGENTD_SIGN_ARTIFACTS'] not in ('true', 'false'):
        raise ValueError('AGENTD_SIGN_ARTIFACTS must be true or false')
    return child


def goreleaser_command(env=None):
    env = build_environment(env)
    executable = env.get('GORELEASER', 'goreleaser')
    output = subprocess.check_output([executable, '--version'], env=env, text=True)
    if not re.search(r'^GitVersion:\s+' + re.escape(GORELEASER_VERSION) + r'\s*$', output, re.MULTILINE):
        raise ValueError('GoReleaser OSS ' + GORELEASER_VERSION + ' is required')
    return executable


def goreleaser_config(t, v, out, payload, packages=False):
    """Select one target from the checked-in OSS config; never import prebuilt binaries."""
    config = json.loads((ROOT / '.goreleaser.json').read_text())
    config['dist'] = str(payload.parent / 'goreleaser-dist')
    build_id = 'linux-fips' if t['fips'] else t['os']
    config['builds'] = [item for item in config['builds'] if item['id'] == build_id]
    if len(config['builds']) != 1:
        raise ValueError('GoReleaser configuration must define exactly one build ' + build_id)
    build = config['builds'][0]
    build.update(goos=[t['os']], goarch=[t['goarch']])
    if t['goarm']:
        build['goarm'] = [t['goarm']]
    config['archives'] = [item for item in config['archives'] if item['ids'] == [build_id]]
    if len(config['archives']) != 1:
        raise ValueError('GoReleaser configuration must define exactly one archive for ' + build_id)
    archive = config['archives'][0]
    archive['name_template'] = product_stem(t, v)
    extra_files = [path for path in sorted(payload.rglob('*')) if path.is_file() and
                   path.relative_to(payload).as_posix() not in ('agentd', 'agentd.exe')]
    if any(path.is_symlink() for path in extra_files):
        raise ValueError('release payload cannot contain symlinks')
    archive['files'] = [
        {'src': str(path), 'dst': path.relative_to(payload).parent.as_posix(), 'strip_parent': True,
         'info': {'mode': 0o644, 'owner': 'root', 'group': 'root', 'mtime': '1970-01-01T00:00:00Z'}}
        for path in extra_files]
    if packages:
        if t['os'] != 'linux':
            raise ValueError('nFPM packages are Linux-only')
        config['nfpms'] = [item for item in config['nfpms'] if item['ids'] == [build_id]]
        if len(config['nfpms']) != 1:
            raise ValueError('GoReleaser configuration must define exactly one nFPM entry for ' + build_id)
        package = config['nfpms'][0]
        package_name = package['package_name']
        package['overrides'] = {
            packager: {'file_name_template': filename.rsplit('.', 1)[0]}
            for packager, filename in zip(('deb', 'rpm'), names(t, v)[1:])}
        package['contents'] = [
            {'src': str(path), 'dst': '/usr/share/doc/' + package_name + '/' + path.relative_to(payload).as_posix(),
             'file_info': {'mode': 0o644}}
            for path in extra_files]
    else:
        config['nfpms'] = []
    return config


def compile_target(t, v, out, payload, env, packages=False):
    config = goreleaser_config(t, v, out, payload, packages)
    config_path = payload.parent / 'goreleaser.json'
    config_path.write_text(json.dumps(config, indent=2) + '\n')
    env = dict(build_environment(env), AGENTD_SOURCE_VERSION=v['version'], AGENTD_PACKAGE_VERSION=v['packageVersion'],
               AGENTD_GOFIPS140=FIPS_VERSION if t['fips'] else 'off')
    executable = goreleaser_command(env)
    binary = payload / payload_binary(t)
    # Every platform uses the full build -> signing hook -> archive pipeline.
    # Snapshot only disables tag/publish validation; version_template preserves
    # the exact package version, including dev-* builds and prereleases.
    run([executable, 'release', '--clean', '--snapshot', '--skip=publish', '--config', config_path], cwd=ROOT, env=env)
    generated = Path(config['dist'])
    artifacts = json.loads((generated / 'artifacts.json').read_text())

    def artifact_path(matches, label):
        if len(matches) != 1:
            raise ValueError('GoReleaser must produce exactly one ' + label)
        source = Path(matches[0]['path'])
        path = source.resolve()
        if not path.is_relative_to(generated.resolve()) or source.is_symlink() or not path.is_file():
            raise ValueError('GoReleaser product is outside its build directory: ' + label)
        return path

    built = [item for item in artifacts if item.get('type') == 'Binary' and
             item.get('extra', {}).get('ID') == config['builds'][0]['id'] and
             item.get('extra', {}).get('Builder') == 'go']
    copy_file(artifact_path(built, 'compiled binary'), binary)
    binary.chmod(0o755)
    for filename in names(t, v) if packages else names(t, v)[:1]:
        matches = [item for item in artifacts if item['name'] == filename]
        copy_file(artifact_path(matches, filename), out / filename)
    verify_archive_binary(t, v, out, payload)
    return binary


def build(args, linux_packages=False, build_env=None):
    t, v = target(args.os, args.arch, args.goarm, args.fips), versions(args.version)
    if t['arch'] == 'universal':
        raise ValueError('use the universal command with two completed macOS target artifacts')
    out = Path(args.out).resolve(); out.mkdir(parents=True, exist_ok=True)
    stage = out / '.staging' / t['key']
    if stage.exists():
        shutil.rmtree(stage)
    payload = stage / 'payload'; payload.mkdir(parents=True)
    binary = payload / payload_binary(t)
    env = dict(build_environment(build_env), GOOS=t['os'], GOARCH=t['goarch'], GOARM=t['goarm'], CGO_ENABLED='0', GOFIPS140=FIPS_VERSION if t['fips'] else 'off')
    packages = subprocess.check_output(['go', 'list', '-mod=readonly', '-deps', '-json=Module', './cmd/agentd'], cwd=ROOT, env=env, text=True)
    toolchain = json.loads(subprocess.check_output(['go', 'env', '-json', 'GOROOT', 'GOVERSION'], env=env, text=True))
    if t['fips'] and toolchain['GOVERSION'] != GO_VERSION:
        raise ValueError(f'FIPS release requires {GO_VERSION}')
    for source, name in [('README.md', 'README.md'), ('THIRD_PARTY_NOTICES.md', 'THIRD_PARTY_NOTICES.md'), ('go.mod', 'go.mod'), ('go.sum', 'go.sum'), ('examples/agentd/config.yaml', 'config.example.yaml'), ('docs/agentd-config.md', 'docs/agentd-config.md'), ('docs/build-and-release.md', 'docs/build-and-release.md'), ('connection/README.md', 'docs/connection.md'), ('transport/xhttp/README.md', 'docs/xhttp.md'), ('transport/xhttp/LICENSE', 'licenses/xhttp/LICENSE'), ('transport/xhttp/NOTICE', 'licenses/xhttp/NOTICE')]:
        copy_file(ROOT / source, payload / name)
    if (ROOT / 'LICENSE').is_file():
        copy_file(ROOT / 'LICENSE', payload / 'LICENSE')
    collect_licenses(payload, packages, toolchain)
    commit = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.strip()
    # The hook must successfully sign and verify before GoReleaser can archive.
    # Installer signing/notarization is recorded externally only after completion.
    binary_signed = t['os'] in ('darwin', 'windows') and env['AGENTD_SIGN_ARTIFACTS'] == 'true'
    metadata = {**t, **v, 'sourceVersion': v['version'], 'goVersion': toolchain['GOVERSION'], 'goFIPS140': env['GOFIPS140'], 'goreleaserVersion': GORELEASER_VERSION, 'commit': commit, 'signed': False, 'binarySigned': binary_signed, 'source': 'https://github.com/bit-precise/agentd/tree/' + commit}
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
    metadata.update(archiveSHA256=sha256(out / names(t, v)[0]), archiveBinarySHA256=sha256(binary))
    (out / '_metadata' / (t['key'] + '.json')).write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'target': t['key'], 'payload': str(payload), 'assets': names(t, v)}))
    return t, v, out, payload


def read_payload_archive(t, v, path):
    """Read an archive without extracting paths or accepting links/special files."""
    if t['arch'] == 'universal':
        raise ValueError('universal installers are not payload archives')
    prefix = '' if t['os'] == 'windows' else product_stem(t, v) + '/'
    files, seen, total, found_binary = {}, set(), 0, False

    def add(name, size, directory, regular, read):
        nonlocal total, found_binary
        checked_relative(name)
        if name in seen:
            raise ValueError('duplicate archive entry: ' + name)
        seen.add(name)
        if len(seen) > 4096:
            raise ValueError('archive contains too many entries')
        if prefix and name.rstrip('/') == prefix.rstrip('/') and directory:
            return
        if prefix and not name.startswith(prefix):
            raise ValueError('archive entry is outside the expected version directory')
        relative = name[len(prefix):] if prefix else name
        parts = checked_relative(relative).parts
        if PurePosixPath(relative).as_posix() != relative.rstrip('/'):
            raise ValueError('archive entry path must be canonical')
        if any(part.startswith('.') for part in parts):
            raise ValueError('hidden archive payload entries are not allowed')
        if directory:
            return
        if not regular or size < 0 or size > 512 * 1024 * 1024:
            raise ValueError('archive must contain regular, bounded payload files')
        total += size
        if total > 1024 * 1024 * 1024:
            raise ValueError('archive payload exceeds size limit')
        data = read()
        if len(data) != size:
            raise ValueError('archive entry size does not match its contents')
        if relative == 'bin/' + payload_binary(t):
            found_binary = True
            name = payload_binary(t)
        else:
            name = relative
        if name in files:
            raise ValueError('duplicate normalized archive entry: ' + name)
        files[name] = data

    if str(path).endswith('.zip'):
        with zipfile.ZipFile(path) as archive:
            for entry in archive.infolist():
                file_type = stat.S_IFMT(entry.external_attr >> 16)
                add(entry.filename, entry.file_size, entry.is_dir(), file_type in (0, stat.S_IFREG),
                    lambda entry=entry: archive.read(entry))
    else:
        with tarfile.open(path) as archive:
            for entry in archive:
                add(entry.name, entry.size, entry.isdir(), entry.isfile(),
                    lambda entry=entry: archive.extractfile(entry).read())
    if not found_binary or 'BUILDINFO.json' not in files:
        raise ValueError('archive is missing its binary or BUILDINFO.json')
    return files


def verify_archive_binary(t, v, out, payload=None):
    out = Path(out)
    payload = Path(payload) if payload is not None else out / '.staging' / t['key'] / 'payload'
    data = read_payload_archive(t, v, out / names(t, v)[0])
    binary = payload / payload_binary(t)
    if data[payload_binary(t)] != binary.read_bytes():
        raise ValueError('archive binary differs from the installer payload')
    return {'archive': names(t, v)[0], 'binary': archive_binary(t, v), 'sha256': sha256(binary)}


def prepare_mac_universal(amd64_input, arm64_input, out, version=None, require_signed=False, expected_team=None):
    """Validate immutable per-arch inputs and stage slices plus shared documents."""
    out = Path(out).resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError('universal output directory must be empty')
    t = target('darwin', 'universal')
    payload = out / '.staging' / t['key'] / 'payload'
    payload.mkdir(parents=True)
    inputs, merged, components = [], {}, []
    for arch, directory in (('amd64', amd64_input), ('arm64', arm64_input)):
        directory = Path(directory)
        source_target = target('darwin', arch)
        verified = verify_manifest(directory)
        metadata_name = '_metadata/' + source_target['key'] + '.json'
        if metadata_name not in verified:
            raise ValueError('macOS input is missing checksummed target metadata')
        info = json.loads((directory / metadata_name).read_text())
        if any(info.get(key) != value for key, value in source_target.items()):
            raise ValueError('macOS input metadata does not match ' + arch)
        if version is None:
            version = info['version']
        v = versions(version)
        if info.get('version') != version or info.get('packageVersion') != v['packageVersion']:
            raise ValueError('macOS inputs disagree on version')
        filename = names(source_target, v)[0]
        if filename not in verified:
            raise ValueError('macOS input is missing its checksummed archive')
        data = read_payload_archive(source_target, v, directory / filename)
        embedded = json.loads(data['BUILDINFO.json'])
        if any(embedded.get(key) != info.get(key) for key in ('key', 'version', 'commit')):
            raise ValueError('macOS archive metadata differs from its target metadata')
        archive_hash = sha256(directory / filename)
        binary_hash = hashlib.sha256(data['agentd']).hexdigest()
        if require_signed:
            validate_release_signing([info])
            if info.get('archiveSHA256') != archive_hash or info.get('archiveBinarySHA256') != binary_hash:
                raise ValueError('macOS notarization metadata does not match input bytes')
            if expected_team is not None and info.get('teamID') != expected_team:
                raise ValueError('macOS input signing team differs from the configured team')
        source = payload.parent / 'inputs' / arch / 'agentd'
        source.parent.mkdir(parents=True); source.write_bytes(data['agentd']); source.chmod(0o755)
        for name, contents in data.items():
            if name in ('agentd', 'BUILDINFO.json'):
                continue
            if name.startswith('licenses/'):
                contents = contents.replace(b'\r\n', b'\n')
            if name in merged and merged[name] != contents:
                raise ValueError('macOS inputs contain different shared payload contents: ' + name)
            merged[name] = contents
        components.append({'target': source_target['key'], 'archive': filename,
                           'archiveSHA256': archive_hash, 'binarySHA256': binary_hash})
        inputs.append(info)
    if len({item.get('commit') for item in inputs}) != 1 or not inputs[0].get('commit'):
        raise ValueError('macOS inputs disagree on source commit')
    if len({item.get('goVersion') for item in inputs}) != 1:
        raise ValueError('macOS inputs disagree on Go version')
    if require_signed and len({item.get('teamID') for item in inputs}) != 1:
        raise ValueError('macOS inputs disagree on signing team')
    for name, data in merged.items():
        destination = payload.joinpath(*checked_relative(name).parts)
        destination.parent.mkdir(parents=True, exist_ok=True); destination.write_bytes(data)
    metadata = {**t, **v, 'sourceVersion': version, 'commit': inputs[0]['commit'],
                'goVersion': inputs[0].get('goVersion'), 'goFIPS140': 'off',
                'goreleaserVersion': GORELEASER_VERSION, 'signed': False, 'binarySigned': False,
                'components': components, 'source': inputs[0].get('source', '')}
    (payload / 'BUILDINFO.json').write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')
    copy_file(payload / 'BUILDINFO.json', out / '_metadata' / (t['key'] + '.json'))
    if not (payload / 'licenses').is_dir():
        raise ValueError('macOS inputs are missing bundled licenses')
    shutil.copytree(payload / 'licenses', out / '_licenses' / t['key'])
    return t, v, out, payload


def package_mac_universal(t, v, out, payload, sign_identity='', sign_keychain='', build_env=None):
    if sys.platform != 'darwin' or t['key'] != 'darwin-universal':
        raise ValueError('universal PKG creation must run on native macOS')
    payload_info = json.loads((payload / 'BUILDINFO.json').read_text())
    env = build_environment(build_env)
    binary_signed = payload_info.get('binarySigned') is True
    if (sign_identity or env['AGENTD_SIGN_ARTIFACTS'] == 'true') and not binary_signed:
        raise ValueError('sign the universal CLI before creating a signed PKG')
    if binary_signed:
        run(['codesign', '--verify', '--strict', payload / 'agentd'], env=env)
    binary_hash = sha256(payload / 'agentd')
    if payload_info.get('binarySHA256') != binary_hash:
        raise ValueError('universal CLI differs from its payload metadata')
    root = payload.parent / 'pkg-root'
    for path in payload.rglob('*'):
        if path.is_file():
            relative = path.relative_to(payload).as_posix()
            destination = root / ('usr/local/bin/agentd' if relative == 'agentd' else 'usr/local/share/doc/agentd/' + relative)
            copy_file(path, destination)
            destination.chmod(0o755 if relative == 'agentd' else 0o644)
    command = ['pkgbuild', '--root', root, '--identifier', 'com.bit-precise.agentd', '--version', v['pkgVersion'], '--install-location', '/', '--ownership', 'recommended']
    destination = out / names(t, v)[0]
    unsigned = payload.parent / 'unsigned.pkg' if sign_identity else destination
    run(command + [unsigned], env=env)
    if sign_identity:
        command = ['productsign', '--sign', sign_identity, '--timestamp']
        if sign_keychain: command += ['--keychain', sign_keychain]
        run(command + [unsigned, destination], env=env)
    if sign_identity:
        run(['pkgutil', '--check-signature', destination], env=env)
    # Expanding verifies this is a real installer, rather than a renamed archive.
    expanded = payload.parent / 'expanded-pkg'
    run(['pkgutil', '--expand-full', destination, expanded], env=env)
    if not any(path.name == 'PackageInfo' for path in expanded.rglob('PackageInfo')):
        raise ValueError('PKG has no component metadata')
    metadata_path = out / '_metadata' / (t['key'] + '.json')
    metadata = json.loads(metadata_path.read_text()); metadata['signed'] = bool(sign_identity); metadata['binarySigned'] = binary_signed
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')


def unsigned_mac_universal(args):
    t, v, out, payload = prepare_mac_universal(args.amd64_input, args.arm64_input, args.out, args.version)
    env = build_environment()
    if env['AGENTD_SIGN_ARTIFACTS'] != 'false':
        raise ValueError('use sign-macos.py universal for a signed universal installer')
    if sys.platform != 'darwin':
        raise ValueError('universal macOS builds require native macOS')
    run(['lipo', '-create', '-output', payload / 'agentd', payload.parent / 'inputs/amd64/agentd',
         payload.parent / 'inputs/arm64/agentd'], env=env)
    metadata = json.loads((payload / 'BUILDINFO.json').read_text())
    metadata['binarySHA256'] = sha256(payload / 'agentd')
    (payload / 'BUILDINFO.json').write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')
    copy_file(payload / 'BUILDINFO.json', out / '_metadata' / (t['key'] + '.json'))
    package_mac_universal(t, v, out, payload, build_env=env)
    manifest(out)
    print(json.dumps({'target': t['key'], 'payload': str(payload), 'assets': names(t, v)}))


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
        if item['os'] == 'darwin':
            if item.get('notarized') is not True:
                raise ValueError('release requires Apple notarization: ' + item['key'])
            if item['arch'] == 'universal':
                if item.get('pkgStapled') is not True:
                    raise ValueError('release requires notarization and stapled PKG: ' + item['key'])
            else:
                receipt = item.get('notarization', {}).get('archive', {})
                if (receipt.get('status') != 'Accepted' or not receipt.get('id') or
                        not re.fullmatch(r'[0-9a-f]{64}', str(item.get('archiveSHA256', ''))) or
                        receipt.get('sha256') != item['archiveSHA256'] or
                        not re.fullmatch(r'[0-9a-f]{64}', str(item.get('archiveBinarySHA256', ''))) or
                        not re.fullmatch(r'[A-Za-z0-9]{10}', str(item.get('teamID', '')))):
                    raise ValueError('release requires a matching Accepted archive notarization receipt: ' + item['key'])


def validate_target_metadata(info):
    expected = {item['key']: item for item in all_targets()}
    if len(info) != len(expected) or {item.get('key') for item in info} != set(expected):
        raise ValueError('release target metadata is incomplete or duplicated')
    if len({item.get('version') for item in info}) != 1 or len({item.get('commit') for item in info}) != 1:
        raise ValueError('release targets disagree on version/source commit')
    if not info[0].get('commit'):
        raise ValueError('release target metadata is missing its source commit')
    v = versions(info[0]['version'])
    for item in info:
        if any(item.get(key) != value for key, value in expected[item['key']].items()):
            raise ValueError('release target metadata differs from the release matrix')
        if item.get('packageVersion') != v['packageVersion']:
            raise ValueError('release targets disagree on package version')
    return v


def validate_universal_components(info, out, v):
    by_key = {item['key']: item for item in info}
    components = by_key['darwin-universal'].get('components', [])
    if len(components) != 2 or {item.get('target') for item in components} != {'darwin-amd64', 'darwin-arm64'}:
        raise ValueError('universal installer must identify both macOS input archives')
    for component in components:
        source = by_key[component['target']]
        filename = names(source, v)[0]
        if (not re.fullmatch(r'[0-9a-f]{64}', str(component.get('binarySHA256', ''))) or
                component.get('archive') != filename or component.get('archiveSHA256') != sha256(Path(out) / filename) or
                component.get('binarySHA256') != source.get('archiveBinarySHA256')):
            raise ValueError('universal installer inputs differ from the release macOS archives')


def collect(incoming, out, require_signed=False):
    incoming, out = Path(incoming), Path(out)
    if out.exists() and any(out.iterdir()):
        raise ValueError('collection output must be empty')
    out.mkdir(parents=True, exist_ok=True)
    groups = sorted(incoming.glob('target-*'))
    if len(groups) != len(all_targets()):
        raise ValueError('expected exactly ten target artifacts')
    info, checked = [], []
    for group in groups:
        verified = verify_manifest(group)
        metadata_name = '_metadata/' + group.name.removeprefix('target-') + '.json'
        if metadata_name not in verified:
            raise ValueError('target is missing checksummed metadata: ' + group.name)
        item = json.loads((group / metadata_name).read_text())
        if group.name != 'target-' + item['key']:
            raise ValueError('target artifact name differs from its metadata')
        info.append(item); checked.append((group, verified, metadata_name, item))
    v = validate_target_metadata(info)
    expected, found, licenses = set(expected_assets(v)), set(), {}
    for group, verified, metadata_name, item in checked:
        target_products = set(names(item, v))
        if not any(name.startswith('_licenses/' + item['key'] + '/') for name in verified):
            raise ValueError('target is missing checksummed licenses: ' + item['key'])
        for name in verified:
            path = group / name
            if name in target_products:
                if name in found:
                    raise ValueError('duplicate product: ' + name)
                copy_file(path, out / name); found.add(name)
            elif name == metadata_name:
                continue
            elif name.startswith('_licenses/' + item['key'] + '/'):
                relative = '/'.join(PurePosixPath(name).parts[2:])
                # Verify original target bytes first, then compare only CRLF/LF
                # equivalence. License text stays inside each published package.
                data = path.read_bytes().replace(b'\r\n', b'\n')
                if relative in licenses and licenses[relative] != data:
                    raise ValueError('different license contents at same path: ' + relative)
                licenses[relative] = data
            else:
                raise ValueError('unexpected release entry: ' + name)
    if found != expected:
        raise ValueError('release products missing: ' + ', '.join(sorted(expected-found)))
    validate_universal_components(info, out, v)
    if require_signed: validate_release_signing(info)
    metadata = out / '_metadata' / 'BUILDINFO.json'; metadata.parent.mkdir()
    metadata.write_text(json.dumps({'products': expected_assets(v), 'targets': sorted(info, key=lambda i:i['key']),
                                   'licenses': {name: hashlib.sha256(data).hexdigest() for name, data in sorted(licenses.items())}},
                                  indent=2, sort_keys=True) + '\n')
    manifest(out)
    print(f'verified {len(found)} products; provenance and input checksums remain internal')


def publish(out, dry_run=False):
    """Import only the verified final assets into a fresh OSS release pipeline."""
    out = Path(out).resolve()
    verified = verify_manifest(out)
    metadata_name = '_metadata/BUILDINFO.json'
    if metadata_name not in verified:
        raise ValueError('publishing requires checksummed internal build metadata')
    info = json.loads((out / metadata_name).read_text())
    targets = info.get('targets', [])
    v = validate_target_metadata(targets)
    expected, public_checksum = set(expected_assets(v)), checksum_name(v)
    if info.get('products') != expected_assets(v):
        raise ValueError('release metadata has inconsistent products')
    if verified not in (expected | {metadata_name}, expected | {metadata_name, public_checksum}):
        raise ValueError('publishing requires exactly 21 products and internal provenance')
    visible = {path.relative_to(out).as_posix() for path in out.rglob('*') if path.is_file() and
               not any(part.startswith('.') for part in path.relative_to(out).parts)}
    if visible != verified | {'SHA256SUMS'}:
        raise ValueError('publishing refuses files outside the verified release set')
    validate_universal_components(targets, out, v)
    env = dict(build_environment(), AGENTD_RELEASE_DIR=str(out), AGENTD_PACKAGE_VERSION=v['packageVersion'])
    if not dry_run:
        validate_release_signing(targets)
        tag = v['version']
        if env.get('GITHUB_ACTIONS') == 'true':
            if (env.get('GITHUB_REF_TYPE') != 'tag' or env.get('GITHUB_REF_NAME') != tag or
                    env.get('GITHUB_REF') != 'refs/tags/' + tag):
                raise ValueError('GitHub release ref must match the tag recorded in release metadata')
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, env=env, text=True).strip()
        tag_commit = subprocess.check_output(['git', 'rev-parse', '--verify', 'refs/tags/' + tag + '^{commit}'],
                                             cwd=ROOT, env=env, text=True).strip()
        if targets[0]['commit'] != commit or tag_commit != commit:
            raise ValueError('release inputs must match the checked-out commit and exact source tag')
        # Multiple tags can name this commit. Pin both the validation run and
        # actual upload to the requested tag instead of GoReleaser's discovery.
        env['GORELEASER_CURRENT_TAG'] = tag
    stage = out / '.staging' / 'publish'
    stage.mkdir(parents=True, exist_ok=True)
    config = json.loads((ROOT / '.goreleaser.publish.json').read_text())
    config['dist'] = str(stage / 'goreleaser-dist')
    imports = [{'glob': str(out / name)} for name in sorted(expected)]
    config['checksum']['extra_files'] = imports
    config['release']['extra_files'] = imports
    config_path = stage / 'goreleaser.json'
    config_path.write_text(json.dumps(config, indent=2) + '\n')
    command = [goreleaser_command(env), 'release', '--clean', '--config', config_path]
    # Always prove the import/checksum path before a real upload. No binary or
    # package is rebuilt, and the original source-version metadata is untouched.
    run(command + ['--snapshot', '--skip=publish'], cwd=ROOT, env=env)
    generated_manifest = Path(config['dist']) / public_checksum
    expected_checksums = ''.join(f'{sha256(out / name)}  {name}\n' for name in sorted(expected)).encode()
    if generated_manifest.read_bytes() != expected_checksums:
        raise ValueError('GoReleaser checksum set differs from the verified release manifest')
    copy_file(generated_manifest, out / public_checksum)
    manifest(out)
    verify_manifest(out)
    if not dry_run:
        run(command, cwd=ROOT, env=env)
        if generated_manifest.read_bytes() != expected_checksums:
            raise ValueError('published checksum set differs from the verified release manifest')
    print('GoReleaser ' + ('verified' if dry_run else 'published') + ' 21 products + ' + public_checksum)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    version = commands.add_parser('version'); version.add_argument('--version', required=True)
    p=commands.add_parser('expected'); p.add_argument('--version', required=True)
    p=commands.add_parser('products'); p.add_argument('--os', required=True); p.add_argument('--arch', required=True)
    p.add_argument('--version', required=True); p.add_argument('--fips', action='store_true')
    p=commands.add_parser('verify-archive'); p.add_argument('--os', required=True); p.add_argument('--arch', required=True)
    p.add_argument('--version', required=True); p.add_argument('--out', required=True); p.add_argument('--fips', action='store_true')
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
    p=commands.add_parser('universal'); p.add_argument('--amd64-input', required=True); p.add_argument('--arm64-input', required=True)
    p.add_argument('--version'); p.add_argument('--out', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'version': print(json.dumps(versions(args.version)))
        elif args.command == 'expected': print('\n'.join(expected_assets(args.version)))
        elif args.command == 'products':
            t, v = target(args.os,args.arch,fips=args.fips), versions(args.version)
            print(json.dumps({'target':t,'version':v,'assets':names(t,v),'payloadBinary':payload_binary(t)}))
        elif args.command == 'verify-archive':
            print(json.dumps(verify_archive_binary(target(args.os,args.arch,fips=args.fips),versions(args.version),args.out)))
        elif args.command == 'verify-fips': check_fips(args.binary, os.environ); print('Pinned Go FIPS module and default runtime mode verified')
        elif args.command in ('build', 'package'):
            if args.no_manifest: (Path(args.out) / 'SHA256SUMS').unlink(missing_ok=True)
            t,v,out,payload=build(args, linux_packages=args.command == 'package' and args.os == 'linux')
            if args.command == 'package':
                if args.sign_identity or args.app_sign_identity or args.sign_keychain:
                    raise ValueError('use sign-macos.py for signed macOS archives and universal installers')
                if t['os']=='windows': raise ValueError('use scripts/build-windows.ps1 to create native MSI')
            if not args.no_manifest: manifest(out)
        elif args.command == 'manifest': manifest(args.out)
        elif args.command == 'verify': verify_manifest(args.out)
        elif args.command == 'collect': collect(args.incoming,args.out,args.require_signed)
        elif args.command == 'publish': publish(args.out,args.dry_run)
        elif args.command == 'universal': unsigned_mac_universal(args)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'release: {error}\n')

if __name__ == '__main__': main()
