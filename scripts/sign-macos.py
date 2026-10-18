#!/usr/bin/env python3
"""Developer ID signing and notarization; credentials come only from environment."""
import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import shlex
import signal
import subprocess
import sys
import tarfile
import tempfile

import release

REQUIRED = (
    'APPLE_APPLICATION_P12_BASE64', 'APPLE_APPLICATION_P12_PASSWORD',
    'APPLE_INSTALLER_P12_BASE64', 'APPLE_INSTALLER_P12_PASSWORD',
    'APPLE_APPLICATION_IDENTITY', 'APPLE_INSTALLER_IDENTITY', 'APPLE_TEAM_ID',
    'APPLE_NOTARY_KEY_P8_BASE64', 'APPLE_NOTARY_KEY_ID', 'APPLE_NOTARY_ISSUER_ID',
)


def command(args, sensitive=False):
    # Never include argv in exceptions: security import/unlock use passwords.
    result = subprocess.run([str(a) for a in args], text=True, capture_output=True)
    if result.returncode:
        if not sensitive:
            print(result.stderr, file=sys.stderr)
        raise ValueError(f'{Path(str(args[0])).name} {args[1]} failed (exit {result.returncode})')
    return result.stdout


def configuration(env):
    missing = [name for name in REQUIRED if not env.get(name)]
    if missing:
        raise ValueError('missing signing configuration: ' + ', '.join(missing))
    if not env['APPLE_APPLICATION_IDENTITY'].startswith('Developer ID Application: '):
        raise ValueError('APPLE_APPLICATION_IDENTITY must select a Developer ID Application certificate')
    if not env['APPLE_INSTALLER_IDENTITY'].startswith('Developer ID Installer: '):
        raise ValueError('APPLE_INSTALLER_IDENTITY must select a Developer ID Installer certificate')
    team = env['APPLE_TEAM_ID']
    if not team.isalnum() or len(team) != 10:
        raise ValueError('APPLE_TEAM_ID must be the 10-character Apple developer team ID')
    for name in ('APPLE_APPLICATION_IDENTITY', 'APPLE_INSTALLER_IDENTITY'):
        if not env[name].endswith('(' + team + ')'):
            raise ValueError(name + ' does not match APPLE_TEAM_ID')


def private_file(path, encoded):
    path.write_bytes(base64.b64decode(encoded, validate=True))
    path.chmod(0o600)


def notarize(path, key_path, env):
    result = command(['xcrun', 'notarytool', 'submit', path, '--key', key_path,
                      '--key-id', env['APPLE_NOTARY_KEY_ID'], '--issuer', env['APPLE_NOTARY_ISSUER_ID'],
                      '--wait', '--timeout', '25m', '--output-format', 'json'])
    receipt = json.loads(result)
    if receipt.get('status') != 'Accepted' or not receipt.get('id'):
        # Do not dump the complete service response or submission contents.
        raise ValueError('Apple notarization was not Accepted; inspect the submission in notarytool history')
    print(f"Apple accepted {path.name}: {receipt['id']}")
    return {'id': receipt['id'], 'status': 'Accepted', 'sha256': release.sha256(path)}


def sign(args, env):
    configuration(env)
    if sys.platform != 'darwin':
        raise ValueError('Apple signing requires native macOS and Xcode command line tools')
    args.os, args.goarm, args.fips = 'darwin', '', False
    out = Path(args.out).resolve()
    (out / 'SHA256SUMS').unlink(missing_ok=True)
    original_keychains = shlex.split(command(['security', 'list-keychains', '-d', 'user']))
    with tempfile.TemporaryDirectory(prefix='agentd-signing-', dir=env.get('RUNNER_TEMP')) as temp:
        temporary = Path(temp)
        temporary.chmod(0o700)
        keychain = temporary / 'signing.keychain-db'
        password = secrets.token_urlsafe(32)
        created, search_changed = False, False
        try:
            command(['security', 'create-keychain', '-p', password, keychain], sensitive=True)
            created = True
            command(['security', 'set-keychain-settings', '-lut', '21600', keychain])
            command(['security', 'unlock-keychain', '-p', password, keychain], sensitive=True)
            for kind in ('APPLICATION', 'INSTALLER'):
                certificate = temporary / (kind.lower() + '.p12')
                private_file(certificate, env[f'APPLE_{kind}_P12_BASE64'])
                command(['security', 'import', certificate, '-k', keychain,
                         '-P', env[f'APPLE_{kind}_P12_PASSWORD'], '-T', '/usr/bin/codesign',
                         '-T', '/usr/bin/productsign', '-T', '/usr/bin/productbuild'], sensitive=True)
                certificate.unlink()
            command(['security', 'set-key-partition-list', '-S', 'apple-tool:,apple:,codesign:',
                     '-s', '-k', password, keychain], sensitive=True)
            # Preserve the runner's existing search list and default keychain.
            search_changed = True
            command(['security', 'list-keychains', '-d', 'user', '-s', *original_keychains, keychain])
            key_path = temporary / 'notary-key.p8'
            private_file(key_path, env['APPLE_NOTARY_KEY_P8_BASE64'])
            t, v, out, payload = release.build(args)
            release.package_mac(t, v, out, payload, env['APPLE_INSTALLER_IDENTITY'],
                                env['APPLE_APPLICATION_IDENTITY'], str(keychain))
            pkg, tgz = out / release.names(t)[1], out / release.names(t)[0]
            binary_hash = release.sha256(payload / 'agentd')
            # Apple accepts ZIP/PKG/DMG, not TGZ. Submit the exact signed Mach-O
            # distributed inside TGZ; the notarization ticket identifies its CDHash.
            zip_path = temporary / 'agentd-notarization.zip'
            command(['ditto', '-c', '-k', '--keepParent', payload / 'agentd', zip_path])
            receipts = {'archiveBinary': notarize(zip_path, key_path, env),
                        'installer': notarize(pkg, key_path, env)}
            command(['xcrun', 'stapler', 'staple', pkg])
            command(['xcrun', 'stapler', 'validate', pkg])
            command(['spctl', '--assess', '--type', 'install', '--verbose=2', pkg])
            command(['codesign', '--verify', '--strict', payload / 'agentd'])
            if release.sha256(payload / 'agentd') != binary_hash:
                raise ValueError('signed CLI changed during notarization')
            with tarfile.open(tgz) as archive:
                member = archive.extractfile('agentd')
                if member is None or member.read() != (payload / 'agentd').read_bytes():
                    raise ValueError('TGZ does not contain the notarized CLI')
            metadata_path = out / '_metadata' / (t['key'] + '.json')
            metadata = json.loads(metadata_path.read_text())
            metadata.update(signed=True, binarySigned=True, notarized=True, pkgStapled=True,
                            signingProvider='Apple Developer ID', notarization=receipts,
                            archiveBinarySHA256=binary_hash, archiveStapled=False)
            metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')
        finally:
            # Always restore the search list, even when import/build/notary fails.
            try:
                if search_changed:
                    command(['security', 'list-keychains', '-d', 'user', '-s', *original_keychains])
            finally:
                if created:
                    command(['security', 'delete-keychain', keychain], sensitive=True)
    # No checksum exists until signatures, notarization, stapling and cleanup pass.
    release.manifest(out)
    release.verify_manifest(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', required=True, choices=('amd64', 'arm64'))
    parser.add_argument('--version', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    def terminate(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminate)
    try:
        sign(args, os.environ)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        # release.py commands carry identity names, never passwords/private keys.
        parser.exit(1, f'macOS signing: {error}\n')


if __name__ == '__main__':
    main()
