#!/usr/bin/env python3
"""Install the universal PKG on a disposable macOS runner and verify its payload."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

import release


def run(args, capture=False):
    return subprocess.run([str(value) for value in args], check=True, text=True,
                          stdout=subprocess.PIPE if capture else None).stdout


def verify(out, version, require_signed=False):
    if sys.platform != 'darwin':
        raise ValueError('universal PKG installation requires a native macOS runner')
    out = Path(out).resolve()
    verified = release.verify_manifest(out)
    target = release.target('darwin', 'universal')
    pkg = out / release.names(target, release.versions(version))[0]
    if not {'_metadata/darwin-universal.json', pkg.name}.issubset(verified):
        raise ValueError('manifest must cover both the universal PKG and its metadata')
    metadata = json.loads((out / '_metadata/darwin-universal.json').read_text())
    if any(metadata.get(key) != value for key, value in target.items()) or metadata.get('version') != version:
        raise ValueError('universal package metadata does not match the requested version')
    if not re.fullmatch(r'[0-9a-f]{64}', metadata.get('binarySHA256', '')):
        raise ValueError('universal package metadata must identify the installed binary SHA256')
    if require_signed:
        release.validate_release_signing([metadata])
        run(['pkgutil', '--check-signature', pkg])
        run(['xcrun', 'stapler', 'validate', pkg])
        run(['spctl', '--assess', '--type', 'install', '--verbose=2', pkg])
    installed_binary = Path('/usr/local/bin/agentd')
    documentation = Path('/usr/local/share/doc/agentd')
    if installed_binary.exists() or documentation.exists():
        raise ValueError('use a clean disposable runner without an existing agentd installation')
    installed = False
    try:
        run(['sudo', '-n', 'installer', '-pkg', pkg, '-target', '/'])
        installed = True
        if release.sha256(installed_binary) != metadata.get('binarySHA256'):
            raise ValueError('installed CLI differs from the verified universal binary')
        if run([installed_binary, 'version'], capture=True).strip() != version:
            raise ValueError('installed CLI version does not match the release')
        if set(run(['lipo', '-archs', installed_binary], capture=True).split()) != {'x86_64', 'arm64'}:
            raise ValueError('installed CLI must contain exactly x86_64 and arm64 slices')
        if require_signed:
            run(['codesign', '--verify', '--strict', '--all-architectures', installed_binary])
        for relative in ('README.md', 'config.example.yaml', 'THIRD_PARTY_NOTICES.md', 'licenses/go/LICENSE'):
            if not (documentation / relative).is_file():
                raise ValueError('installed documentation is incomplete: ' + relative)
        print('Universal PKG installation, version, both architectures and binary SHA256 verified.')
    finally:
        if installed:
            run(['sudo', '-n', 'rm', installed_binary])
            run(['sudo', '-n', 'rm', '-r', documentation])
            run(['sudo', '-n', 'pkgutil', '--forget', 'com.bit-precise.agentd'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--require-signed', action='store_true')
    args = parser.parse_args()
    try:
        verify(args.out, args.version, args.require_signed)
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f'macOS package verification: {error}\n')


if __name__ == '__main__':
    main()
