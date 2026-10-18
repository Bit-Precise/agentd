#!/usr/bin/env python3
"""Developer ID signing and notarization; credentials come only from environment."""
import argparse
import base64
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import signal
import subprocess
import sys
import tempfile
import uuid
import zipfile

import release

REQUIRED = (
    'APPLE_APPLICATION_P12_BASE64', 'APPLE_APPLICATION_P12_PASSWORD',
    'APPLE_INSTALLER_P12_BASE64', 'APPLE_INSTALLER_P12_PASSWORD',
    'APPLE_APPLICATION_IDENTITY', 'APPLE_INSTALLER_IDENTITY', 'APPLE_TEAM_ID',
    'APPLE_NOTARY_KEY_P8_BASE64', 'APPLE_NOTARY_KEY_ID', 'APPLE_NOTARY_ISSUER_ID',
)


def child_environment(env):
    """Build/signing tools receive handles and public identity, not key material."""
    allowed_apple = {'APPLE_APPLICATION_IDENTITY', 'APPLE_TEAM_ID'}
    return {name: value for name, value in env.items()
            if not name.startswith('APPLE_') or name in allowed_apple}


def command(args, sensitive=False, env=None, include_stderr=False):
    # Never include argv in exceptions: security import/unlock use passwords.
    result = subprocess.run([str(a) for a in args], text=True, capture_output=True,
                            env=child_environment(os.environ if env is None else env))
    if result.returncode:
        if not sensitive:
            print(result.stderr, file=sys.stderr)
        raise ValueError(f'{Path(str(args[0])).name} {args[1]} failed (exit {result.returncode})')
    return result.stdout + result.stderr if include_stderr else result.stdout


def binary_configuration(env):
    for name in ('AGENTD_MACOS_KEYCHAIN', 'APPLE_APPLICATION_IDENTITY', 'APPLE_TEAM_ID'):
        if not env.get(name):
            raise ValueError('missing binary signing configuration: ' + name)
    identity, team = env['APPLE_APPLICATION_IDENTITY'], env['APPLE_TEAM_ID']
    if not re.fullmatch(r'[A-Z0-9]{10}', team):
        raise ValueError('APPLE_TEAM_ID must be the 10-character Apple developer team ID')
    if not identity.startswith('Developer ID Application: ') or not identity.endswith('(' + team + ')'):
        raise ValueError('APPLE_APPLICATION_IDENTITY must select Developer ID Application for APPLE_TEAM_ID')
    if sys.platform != 'darwin':
        raise ValueError('Apple signing requires native macOS and Xcode command line tools')


def verify_binary(path, env, architectures=None):
    command(['codesign', '--verify', '--strict', '--all-architectures', path], env=env)
    for architecture in architectures or [None]:
        selection = ['--architecture', architecture] if architecture else []
        details = command(['codesign', '--display', '--verbose=4', *selection, path], env=env, include_stderr=True)
        teams = re.findall(r'^TeamIdentifier=(.*)$', details, flags=re.MULTILINE)
        if teams != [env['APPLE_TEAM_ID']]:
            raise ValueError('signed CLI TeamIdentifier does not match APPLE_TEAM_ID')
        if not re.search(r'^Timestamp=.+$', details, flags=re.MULTILINE):
            raise ValueError('signed CLI has no verified signing timestamp')


def verify_architectures(path, expected, env):
    actual = command(['lipo', '-archs', path], env=env).split()
    if len(actual) != len(expected) or set(actual) != set(expected):
        raise ValueError('Mach-O architecture set does not match the requested product')


def verify_archive_binary(archive_path, binary):
    name = archive_path.stem + '/bin/agentd'
    with zipfile.ZipFile(archive_path) as archive:
        if archive.namelist().count(name) != 1 or archive.read(name) != binary.read_bytes():
            raise ValueError('ZIP does not contain the exact signed CLI')


def sign_binary(path, env):
    """GoReleaser build post hook; this function never compiles or archives."""
    mode = env.get('AGENTD_SIGN_ARTIFACTS')
    if mode == 'false':
        print('macOS binary signing disabled for this build')
        return
    if mode != 'true':
        raise ValueError('AGENTD_SIGN_ARTIFACTS must explicitly be true or false')
    binary_configuration(env)
    path, keychain = Path(path), Path(env['AGENTD_MACOS_KEYCHAIN'])
    if path.is_symlink() or not path.is_file() or keychain.is_symlink() or not keychain.is_file():
        raise ValueError('binary and signing keychain must be regular files')
    command(['codesign', '--force', '--options', 'runtime', '--timestamp', '--sign',
             env['APPLE_APPLICATION_IDENTITY'], '--keychain', keychain, path], env=env)
    verify_binary(path, env)


def configuration(env, installer=True):
    required = [name for name in REQUIRED if installer or not name.startswith("APPLE_INSTALLER_")]
    missing = [name for name in required if not env.get(name)]
    if missing:
        raise ValueError('missing signing configuration: ' + ', '.join(missing))
    if not env['APPLE_APPLICATION_IDENTITY'].startswith('Developer ID Application: '):
        raise ValueError('APPLE_APPLICATION_IDENTITY must select a Developer ID Application certificate')
    if installer and not env['APPLE_INSTALLER_IDENTITY'].startswith('Developer ID Installer: '):
        raise ValueError('APPLE_INSTALLER_IDENTITY must select a Developer ID Installer certificate')
    team = env['APPLE_TEAM_ID']
    if not re.fullmatch(r'[A-Z0-9]{10}', team):
        raise ValueError('APPLE_TEAM_ID must be the 10-character Apple developer team ID')
    for name in (('APPLE_APPLICATION_IDENTITY', 'APPLE_INSTALLER_IDENTITY') if installer else ('APPLE_APPLICATION_IDENTITY',)):
        if not env[name].endswith('(' + team + ')'):
            raise ValueError(name + ' does not match APPLE_TEAM_ID')


def private_file(path, encoded):
    path.write_bytes(base64.b64decode(encoded, validate=True))
    path.chmod(0o600)


def notarize(path, key_path, env, receipt_path=None):
    authentication = ['--key', key_path, '--key-id', env['APPLE_NOTARY_KEY_ID'],
                      '--issuer', env['APPLE_NOTARY_ISSUER_ID']]
    source_hash = release.sha256(path)
    result = command(['xcrun', 'notarytool', 'submit', path, *authentication,
                      '--output-format', 'json'], env=env)
    submission = json.loads(result)
    try:
        submission_id = str(uuid.UUID(submission.get('id', '')))
    except (ValueError, TypeError, AttributeError):
        raise ValueError('Apple notarization submission did not return a valid ID') from None
    receipt = {'id': submission_id, 'status': 'Submitted', 'sha256': source_hash}

    def save_receipt():
        if receipt_path is not None:
            receipt_path.parent.mkdir(parents=True, exist_ok=True)
            receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')

    # Flush the ID before any potentially long wait. On timeout the same ID can
    # be queried with notarytool; this function never retries the upload.
    print(f'Apple submitted {path.name}: {submission_id} (sha256 {source_hash})', flush=True)
    save_receipt()
    try:
        result = command(['xcrun', 'notarytool', 'wait', submission_id, *authentication,
                          '--timeout', '25m', '--output-format', 'json'], env=env)
    except (ValueError, OSError, subprocess.SubprocessError):
        receipt['status'] = 'WaitFailed'
        save_receipt()
        raise
    outcome = json.loads(result)
    receipt['status'] = outcome.get('status') if outcome.get('status') in ('Accepted', 'Invalid', 'In Progress') else 'Unknown'
    save_receipt()
    if receipt['status'] != 'Accepted' or outcome.get('id', submission_id) != submission_id:
        # Do not dump the complete service response or submission contents.
        raise ValueError('Apple notarization was not Accepted; inspect the submitted ID in notarytool history')
    print(f'Apple accepted {path.name}: {submission_id}', flush=True)
    return receipt


@contextmanager
def signing_environment(env, installer=False):
    configuration(env, installer=installer)
    if sys.platform != 'darwin':
        raise ValueError('Apple signing requires native macOS and Xcode command line tools')
    child_env = child_environment(env)
    original_keychains = shlex.split(command(['security', 'list-keychains', '-d', 'user'], env=child_env))
    with tempfile.TemporaryDirectory(prefix='agentd-signing-', dir=env.get('RUNNER_TEMP')) as temp:
        temporary = Path(temp)
        temporary.chmod(0o700)
        keychain = temporary / 'signing.keychain-db'
        password = secrets.token_urlsafe(32)
        created, search_changed = False, False
        try:
            command(['security', 'create-keychain', '-p', password, keychain], sensitive=True, env=child_env)
            created = True
            command(['security', 'set-keychain-settings', '-lut', '21600', keychain], env=child_env)
            command(['security', 'unlock-keychain', '-p', password, keychain], sensitive=True, env=child_env)
            for kind in (('APPLICATION', 'INSTALLER') if installer else ('APPLICATION',)):
                certificate = temporary / (kind.lower() + '.p12')
                private_file(certificate, env[f'APPLE_{kind}_P12_BASE64'])
                command(['security', 'import', certificate, '-k', keychain,
                         '-P', env[f'APPLE_{kind}_P12_PASSWORD'], '-T', '/usr/bin/codesign',
                         '-T', '/usr/bin/productsign', '-T', '/usr/bin/productbuild'], sensitive=True, env=child_env)
                certificate.unlink()
            command(['security', 'set-key-partition-list', '-S', 'apple-tool:,apple:,codesign:',
                     '-s', '-k', password, keychain], sensitive=True, env=child_env)
            # Preserve the runner's existing search list and default keychain.
            search_changed = True
            command(['security', 'list-keychains', '-d', 'user', '-s', *original_keychains, keychain], env=child_env)
            key_path = temporary / 'notary-key.p8'
            private_file(key_path, env['APPLE_NOTARY_KEY_P8_BASE64'])
            child_env.update(AGENTD_SIGN_ARTIFACTS='true', AGENTD_MACOS_KEYCHAIN=str(keychain))
            yield child_env, key_path, keychain
        finally:
            try:
                if search_changed:
                    command(['security', 'list-keychains', '-d', 'user', '-s', *original_keychains], env=child_env)
            finally:
                if created:
                    command(['security', 'delete-keychain', keychain], sensitive=True, env=child_env)


def finish_manifest(out):
    # No checksum exists until signing, notarization and key cleanup all pass.
    release.manifest(out)
    release.verify_manifest(out)


def sign(args, env):
    args.os, args.goarm, args.fips = 'darwin', '', False
    out = Path(args.out).resolve()
    (out / 'SHA256SUMS').unlink(missing_ok=True)
    with signing_environment(env) as (child_env, key_path, _):
        t, v, out, payload = release.build(args, build_env=child_env)
        archive = out / release.names(t, v)[0]
        binary = payload / 'agentd'
        architecture = 'x86_64' if t['arch'] == 'amd64' else 'arm64'
        verify_architectures(binary, [architecture], child_env)
        verify_binary(binary, child_env, [architecture])
        verify_archive_binary(archive, binary)
        binary_hash, archive_hash = release.sha256(binary), release.sha256(archive)
        receipt = notarize(archive, key_path, env, payload.parent / 'notarization/archive.json')
        verify_binary(binary, child_env, [architecture])
        if release.sha256(binary) != binary_hash or release.sha256(archive) != archive_hash:
            raise ValueError('signed CLI or ZIP changed during notarization')
        metadata_path = out / '_metadata' / (t['key'] + '.json')
        metadata = json.loads(metadata_path.read_text())
        metadata.update(signed=True, binarySigned=True, notarized=True, archiveStapled=False,
                        signingProvider='Apple Developer ID', teamID=env['APPLE_TEAM_ID'],
                        notarization={'archive': receipt}, archiveSHA256=archive_hash,
                        archiveBinarySHA256=binary_hash)
        metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')
    finish_manifest(out)


def sign_universal(args, env):
    configuration(env)
    if sys.platform != 'darwin':
        raise ValueError('Apple signing requires native macOS and Xcode command line tools')
    out = Path(args.out).resolve()
    inputs = {'amd64': Path(args.amd64_input).resolve(), 'arm64': Path(args.arm64_input).resolve()}
    if any(out == source or out in source.parents or source in out.parents for source in inputs.values()):
        raise ValueError('universal output must be separate from both input targets')
    (out / 'SHA256SUMS').unlink(missing_ok=True)
    manifests = {source: release.sha256(source / 'SHA256SUMS') for source in inputs.values()}
    t, v, out, payload = release.prepare_mac_universal(inputs['amd64'], inputs['arm64'], out,
                                                     args.version, require_signed=True,
                                                     expected_team=env['APPLE_TEAM_ID'])
    metadata_path = out / '_metadata' / (t['key'] + '.json')
    metadata = json.loads(metadata_path.read_text())
    source_archives = {inputs[component['target'].split('-')[-1]] / component['archive']: component['archiveSHA256']
                       for component in metadata['components']}
    architectures = ['x86_64', 'arm64']
    binary = payload / 'agentd'
    with signing_environment(env, installer=True) as (child_env, key_path, keychain):
        thin_binaries = []
        for arch, machine in zip(('amd64', 'arm64'), architectures):
            thin = payload.parent / 'inputs' / arch / 'agentd'
            verify_architectures(thin, [machine], child_env)
            verify_binary(thin, child_env, [machine])
            thin_binaries.append(thin)
        command(['lipo', '-create', *thin_binaries, '-output', binary], env=child_env)
        binary.chmod(0o755)
        verify_architectures(binary, architectures, child_env)
        # Lipo is an intentional new product: sign the assembled Mach-O again,
        # then keep these universal bytes immutable through package/notary steps.
        sign_binary(binary, child_env)
        verify_binary(binary, child_env, architectures)
        binary_hash = release.sha256(binary)
        metadata.update(binarySigned=True, teamID=env['APPLE_TEAM_ID'],
                        binarySHA256=binary_hash, universalBinarySHA256=binary_hash, architectures=architectures)
        encoded = json.dumps(metadata, indent=2, sort_keys=True) + '\n'
        (payload / 'BUILDINFO.json').write_text(encoded)
        metadata_path.write_text(encoded)
        release.package_mac_universal(t, v, out, payload, sign_identity=env['APPLE_INSTALLER_IDENTITY'],
                                      sign_keychain=str(keychain), build_env=child_env)
        if release.sha256(binary) != binary_hash:
            raise ValueError('signed universal CLI changed during installer packaging')
        pkg = out / release.names(t, v)[0]
        receipt = notarize(pkg, key_path, env, payload.parent / 'notarization/installer.json')
        command(['xcrun', 'stapler', 'staple', pkg], env=child_env)
        command(['xcrun', 'stapler', 'validate', pkg], env=child_env)
        command(['spctl', '--assess', '--type', 'install', '--verbose=2', pkg], env=child_env)
        verify_architectures(binary, architectures, child_env)
        verify_binary(binary, child_env, architectures)
        if release.sha256(binary) != binary_hash:
            raise ValueError('signed universal CLI changed during notarization')
        for archive, expected in source_archives.items():
            if release.sha256(archive) != expected:
                raise ValueError('original architecture ZIP changed during universal assembly')
        for source, expected in manifests.items():
            if release.sha256(source / 'SHA256SUMS') != expected:
                raise ValueError('original architecture manifest changed during universal assembly')
            release.verify_manifest(source)
        metadata = json.loads(metadata_path.read_text())
        metadata.update(signed=True, binarySigned=True, notarized=True, pkgStapled=True,
                        signingProvider='Apple Developer ID', teamID=env['APPLE_TEAM_ID'],
                        notarization={'installer': receipt}, binarySHA256=binary_hash, universalBinarySHA256=binary_hash,
                        installerSHA256=release.sha256(pkg))
        metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')
    finish_manifest(out)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    parser = argparse.ArgumentParser(description=__doc__)
    if argv and argv[0] == 'binary':
        parser.add_argument('binary', choices=('binary',))
        parser.add_argument('path')
    elif argv and argv[0] == 'universal':
        parser.add_argument('universal', choices=('universal',))
        parser.add_argument('--amd64-input', required=True)
        parser.add_argument('--arm64-input', required=True)
        parser.add_argument('--out', required=True)
        parser.add_argument('--version')
    else:
        parser.add_argument('--arch', required=True, choices=('amd64', 'arm64'))
        parser.add_argument('--version', required=True)
        parser.add_argument('--out', required=True)
    args = parser.parse_args(argv)
    def terminate(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminate)
    try:
        if hasattr(args, 'binary'):
            sign_binary(args.path, os.environ)
        elif hasattr(args, 'universal'):
            sign_universal(args, os.environ)
        else:
            sign(args, os.environ)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        # release.py commands carry identity names, never passwords/private keys.
        parser.exit(1, f'macOS signing: {error}\n')


if __name__ == '__main__':
    main()
