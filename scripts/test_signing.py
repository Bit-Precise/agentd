"""Exercise fail-closed release gating and private-key cleanup without real keys."""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import release


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MAC = load('mac_signing', 'sign-macos.py')
AZURE = load('azure_signing', 'configure-azure-signing.py')


def apple_config():
    env = {name: 'test-value' for name in MAC.REQUIRED}
    env.update(APPLE_TEAM_ID='ABCDE12345',
               APPLE_APPLICATION_IDENTITY='Developer ID Application: Example (ABCDE12345)',
               APPLE_INSTALLER_IDENTITY='Developer ID Installer: Example (ABCDE12345)')
    for name in MAC.REQUIRED:
        if name.endswith('_BASE64'):
            env[name] = base64.b64encode(b'fake-private-material-for-test').decode()
    return env


SIGNED_DETAILS = 'Authority=Developer ID Application: Example (ABCDE12345)\nTeamIdentifier=ABCDE12345\nTimestamp=Oct 18, 2026 at 10:00:00 AM\n'


def fake_signed_build(root, arch='arm64', directory='dist'):
    out = root / directory
    payload = out / '.staging' / ('darwin-' + arch) / 'payload'
    payload.mkdir(parents=True)
    (payload / 'agentd').write_bytes(('signed-test-binary-' + arch).encode())
    (payload / 'README.md').write_text('test package documentation\n')
    (payload / 'licenses/go').mkdir(parents=True)
    (payload / 'licenses/go/LICENSE').write_text('test license\n')
    target, version = release.target('darwin', arch), release.versions('v1.2.3')
    metadata = {**target, **version, 'commit': 'a' * 40, 'sourceVersion': version['version'],
                'goVersion': release.GO_VERSION, 'signed': False, 'binarySigned': True}
    (payload / 'BUILDINFO.json').write_text(json.dumps(metadata))
    archive_path = out / release.names(target, version)[0]
    with zipfile.ZipFile(archive_path, 'w') as archive:
        for path in payload.rglob('*'):
            if path.is_file():
                name = 'bin/agentd' if path.name == 'agentd' else path.relative_to(payload).as_posix()
                archive.writestr(archive_path.stem + '/' + name, path.read_bytes())
    (out / '_metadata').mkdir()
    (out / ('_metadata/darwin-' + arch + '.json')).write_text(json.dumps(metadata))
    args = argparse.Namespace(arch=arch, version='v1.2.3', out=str(out))
    return args, (target, version, out, payload)


def fake_mac_command(argv, **kwargs):
    if argv[:2] == ['codesign', '--display']:
        return SIGNED_DETAILS
    if argv[:2] == ['codesign', '--force']:
        path = Path(argv[-1]); path.write_bytes(path.read_bytes() + b'-resigned')
    if argv == ['security', 'list-keychains', '-d', 'user']:
        return '\"/original/login.keychain-db\"'
    if argv[:2] == ['security', 'create-keychain']:
        Path(argv[-1]).write_bytes(b'fake-private-keychain')
    if argv[:2] == ['lipo', '-archs']:
        data = Path(argv[-1]).read_bytes()
        return 'x86_64 arm64' if data.startswith(b'universal-fat-cli:') else ('x86_64' if b'amd64' in data else 'arm64')
    if argv[:2] == ['lipo', '-create']:
        Path(argv[-1]).write_bytes(b'universal-fat-cli:' + Path(argv[2]).read_bytes() + Path(argv[3]).read_bytes())
    return ''


class MacBinaryHookTest(unittest.TestCase):
    def test_unsigned_mode_skips_but_missing_or_unknown_mode_fails_closed(self):
        with mock.patch.object(MAC, 'command') as command:
            MAC.sign_binary('unused', {'AGENTD_SIGN_ARTIFACTS': 'false'})
            for value in (None, '', 'TRUE', '1', 'yes'):
                env = {} if value is None else {'AGENTD_SIGN_ARTIFACTS': value}
                with self.assertRaisesRegex(ValueError, 'explicitly be true or false'):
                    MAC.sign_binary('unused', env)
            command.assert_not_called()

    def test_signing_mode_requires_all_public_hook_configuration(self):
        env = {'AGENTD_SIGN_ARTIFACTS': 'true', 'AGENTD_MACOS_KEYCHAIN': 'unused',
               'APPLE_APPLICATION_IDENTITY': 'Developer ID Application: Example (ABCDE12345)',
               'APPLE_TEAM_ID': 'ABCDE12345'}
        with mock.patch.object(MAC, 'command') as command:
            for missing in ('AGENTD_MACOS_KEYCHAIN', 'APPLE_APPLICATION_IDENTITY', 'APPLE_TEAM_ID'):
                with self.assertRaisesRegex(ValueError, 'missing binary signing configuration'):
                    MAC.sign_binary('unused', {key: value for key, value in env.items() if key != missing})
            command.assert_not_called()

    def test_hook_signs_exact_artifact_and_checks_actual_team_and_timestamp(self):
        with tempfile.TemporaryDirectory() as temp:
            binary, keychain = Path(temp) / 'agentd', Path(temp) / 'signing.keychain-db'
            binary.write_bytes(b'test-only-mach-o'); keychain.write_bytes(b'test-only-keychain')
            env = dict(apple_config(), AGENTD_SIGN_ARTIFACTS='true', AGENTD_MACOS_KEYCHAIN=str(keychain))
            with mock.patch.object(MAC.sys, 'platform', 'darwin'), mock.patch.object(MAC, 'command', side_effect=fake_mac_command) as command:
                MAC.sign_binary(binary, env)
            signing = command.call_args_list[0].args[0]
            self.assertEqual(signing[-1], binary)
            self.assertIn('--timestamp', signing)
            self.assertEqual(signing[signing.index('--options') + 1], 'runtime')
            self.assertEqual(signing[signing.index('--keychain') + 1], keychain)
            for details, expected in ((SIGNED_DETAILS.replace('TeamIdentifier=ABCDE12345', 'TeamIdentifier=WRONG12345'), 'TeamIdentifier'),
                                      ('TeamIdentifier=ABCDE12345\n', 'timestamp')):
                def wrong_details(argv, **kwargs):
                    return details if argv[:2] == ['codesign', '--display'] else ''
                with mock.patch.object(MAC.sys, 'platform', 'darwin'), mock.patch.object(MAC, 'command', side_effect=wrong_details):
                    with self.assertRaisesRegex(ValueError, expected):
                        MAC.sign_binary(binary, env)

    def test_codesign_stderr_is_read_without_inheriting_private_environment(self):
        env = dict(apple_config(), PATH='/safe/path', AGENTD_MACOS_KEYCHAIN='/private/keychain')
        result = subprocess.CompletedProcess([], 0, stdout='', stderr=SIGNED_DETAILS)
        with mock.patch.object(MAC.subprocess, 'run', return_value=result) as run:
            details = MAC.command(['codesign', '--display', 'artifact'], env=env, include_stderr=True)
        self.assertEqual(details, SIGNED_DETAILS)
        child = run.call_args.kwargs['env']
        self.assertEqual(child['APPLE_TEAM_ID'], 'ABCDE12345')
        self.assertEqual(child['PATH'], '/safe/path')
        self.assertFalse(any(key.startswith('APPLE_') and key not in ('APPLE_TEAM_ID', 'APPLE_APPLICATION_IDENTITY') for key in child))

    def test_binary_subcommand_preserves_legacy_wrapper_cli(self):
        with mock.patch.object(MAC, 'sign_binary') as binary, mock.patch.object(MAC, 'sign') as wrapper, \
                mock.patch.object(MAC.signal, 'signal'):
            MAC.main(['binary', '/built/agentd'])
            self.assertEqual(binary.call_args.args[0], '/built/agentd')
            wrapper.assert_not_called()
            MAC.main(['--arch', 'arm64', '--version', 'v1.2.3', '--out', '/build'])
            self.assertEqual(wrapper.call_args.args[0].arch, 'arm64')


class ReleaseSigningTest(unittest.TestCase):
    def test_tag_release_rejects_unsigned_missing_notary_and_missing_timestamp(self):
        for target in release.all_targets():
            if target['os'] == 'linux':
                release.validate_release_signing([target])
                continue
            with self.assertRaises(ValueError):
                release.validate_release_signing([target])
            target.update(signed=True, binarySigned=True)
            with self.assertRaises(ValueError):
                release.validate_release_signing([target])
            target.update(timestampVerified=True, notarized=True, pkgStapled=True, teamID='ABCDE12345',
                          archiveSHA256='a' * 64, archiveBinarySHA256='b' * 64,
                          notarization={'archive': {'id': '12345678-1234-1234-1234-123456789abc', 'status': 'Accepted', 'sha256': 'a' * 64},
                                        'installer': {'id': '12345678-1234-1234-1234-123456789abc', 'status': 'Accepted', 'sha256': 'c' * 64}})
            release.validate_release_signing([target])
            target['signed'] = 'true'
            with self.assertRaises(ValueError):
                release.validate_release_signing([target])

    def test_missing_or_wrong_team_configuration_fails_before_any_command(self):
        args = argparse.Namespace(arch='arm64', version='v1.2.3', out='unused')
        with mock.patch.object(MAC, 'command') as command:
            with self.assertRaisesRegex(ValueError, 'missing signing configuration'):
                MAC.sign(args, {})
            command.assert_not_called()
        env = apple_config()
        env['APPLE_INSTALLER_IDENTITY'] = 'Developer ID Installer: Other (ABCDE99999)'
        with self.assertRaisesRegex(ValueError, 'does not match'):
            MAC.configuration(env)

    def test_sensitive_command_failure_never_echoes_password_or_output(self):
        result = subprocess.CompletedProcess([], 1, stdout='private-key', stderr='private-password')
        with mock.patch.object(MAC.subprocess, 'run', return_value=result), mock.patch('sys.stderr') as stderr:
            with self.assertRaisesRegex(ValueError, 'security import failed') as error:
                MAC.command(['security', 'import', '-P', 'private-password'], sensitive=True)
            self.assertNotIn('private-password', str(error.exception))
            stderr.write.assert_not_called()

    def test_notarization_requires_accepted_and_submission_id(self):
        env = apple_config()
        submission_id = '12345678-1234-1234-1234-123456789abc'
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / 'archive.zip'; archive.write_bytes(b'signed-cli-zip')
            for value in ({'status': 'Invalid'}, {'status': 'In Progress'}, {}):
                replies = [json.dumps({'id': submission_id}), json.dumps(value)]
                with mock.patch.object(MAC, 'command', side_effect=replies) as command:
                    with self.assertRaisesRegex(ValueError, 'not Accepted'):
                        MAC.notarize(archive, Path('key.p8'), env)
                self.assertEqual(command.call_args_list[0].args[0][:3], ['xcrun', 'notarytool', 'submit'])
                self.assertNotIn('--wait', command.call_args_list[0].args[0])
                self.assertEqual(command.call_args_list[1].args[0][:4], ['xcrun', 'notarytool', 'wait', submission_id])
            with mock.patch.object(MAC, 'command', return_value='{"status":"Accepted"}') as command:
                with self.assertRaisesRegex(ValueError, 'valid ID'):
                    MAC.notarize(archive, Path('key.p8'), env)
                command.assert_called_once()

    def test_notary_wait_failure_preserves_submission_without_resubmitting(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / 'archive.zip'; archive.write_bytes(b'signed-cli-zip')
            receipt_path = Path(temp) / 'notarization/archive.json'
            submission_id = '12345678-1234-1234-1234-123456789abc'
            calls = []
            def command(argv, **kwargs):
                calls.append(argv)
                if argv[2] == 'submit':
                    return json.dumps({'id': submission_id})
                stored = json.loads(receipt_path.read_text())
                self.assertEqual(stored, {'id': submission_id, 'status': 'Submitted', 'sha256': release.sha256(archive)})
                self.assertTrue(any(submission_id in str(call) and call.kwargs.get('flush') for call in output.call_args_list))
                raise ValueError('wait timed out')
            with mock.patch.object(MAC, 'command', side_effect=command), mock.patch('builtins.print') as output:
                with self.assertRaisesRegex(ValueError, 'wait timed out'):
                    MAC.notarize(archive, Path('key.p8'), apple_config(), receipt_path)
            self.assertEqual([call[2] for call in calls], ['submit', 'wait'])
            stored = json.loads(receipt_path.read_text())
            self.assertEqual(stored, {'id': submission_id, 'status': 'WaitFailed', 'sha256': release.sha256(archive)})

    def test_notary_accepted_wait_returns_original_submission_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / 'archive.zip'; archive.write_bytes(b'signed-cli-zip')
            receipt_path = Path(temp) / 'notarization/archive.json'
            submission_id = '12345678-1234-1234-1234-123456789abc'
            replies = [json.dumps({'id': submission_id}), json.dumps({'id': submission_id, 'status': 'Accepted'})]
            with mock.patch.object(MAC, 'command', side_effect=replies):
                receipt = MAC.notarize(archive, Path('key.p8'), apple_config(), receipt_path)
            self.assertEqual(receipt, {'id': submission_id, 'status': 'Accepted', 'sha256': release.sha256(archive)})
            self.assertEqual(json.loads(receipt_path.read_text()), receipt)

    def test_failed_build_restores_keychain_and_removes_private_material(self):
        with tempfile.TemporaryDirectory() as temp:
            env = apple_config()
            env['RUNNER_TEMP'] = temp
            args = argparse.Namespace(arch='arm64', version='v1.2.3', out=str(Path(temp) / 'dist'))
            calls = []
            def command(argv, **kwargs):
                calls.append([str(a) for a in argv])
                if argv == ['security', 'list-keychains', '-d', 'user']:
                    return '"/original/login.keychain-db"\n"/original/other.keychain-db"'
                return ''
            with mock.patch.object(MAC.sys, 'platform', 'darwin'), mock.patch.object(MAC, 'command', side_effect=command), \
                    mock.patch.object(release, 'build', side_effect=ValueError('failed compilation')):
                with self.assertRaisesRegex(ValueError, 'failed compilation'):
                    MAC.sign(args, env)
            self.assertEqual(calls[-2], ['security', 'list-keychains', '-d', 'user', '-s',
                                         '/original/login.keychain-db', '/original/other.keychain-db'])
            self.assertEqual(calls[-1][:2], ['security', 'delete-keychain'])
            self.assertEqual(list(Path(temp).glob('agentd-signing-*')), [])
            self.assertFalse((Path(args.out) / 'SHA256SUMS').exists())

    def test_notary_failure_has_no_checksum_and_cleans_private_material(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            env = apple_config()
            env['RUNNER_TEMP'] = temp
            args, built = fake_signed_build(root)
            out = built[2]
            with mock.patch.object(MAC.sys, 'platform', 'darwin'), mock.patch.object(MAC, 'command', side_effect=fake_mac_command), \
                    mock.patch.object(release, 'build', return_value=built), mock.patch.object(release, 'package_mac_universal'), \
                    mock.patch.object(MAC, 'notarize', side_effect=ValueError('not Accepted')):
                with self.assertRaisesRegex(ValueError, 'not Accepted'):
                    MAC.sign(args, env)
            self.assertFalse((out / 'SHA256SUMS').exists())
            self.assertEqual(list(root.glob('agentd-signing-*')), [])

    def test_wrapper_build_environment_is_isolated_and_final_bytes_are_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            args, built = fake_signed_build(root)
            target, _, out, payload = built
            env = dict(apple_config(), RUNNER_TEMP=temp, PATH='/safe/path')
            archive = out / release.names(target, built[1])[0]
            before = archive.read_bytes(), (payload / 'agentd').read_bytes(), (payload / 'BUILDINFO.json').read_bytes()
            receipt = {'id': 'fake-submission', 'status': 'Accepted', 'sha256': 'fake-hash'}
            with mock.patch.dict(os.environ, {'UNCHANGED_SENTINEL': 'original'}, clear=True), \
                    mock.patch.object(MAC.sys, 'platform', 'darwin'), mock.patch.object(MAC, 'command', side_effect=fake_mac_command) as command, \
                    mock.patch.object(release, 'build', return_value=built) as build, mock.patch.object(release, 'package_mac_universal') as package, \
                    mock.patch.object(MAC, 'notarize', return_value=receipt):
                MAC.sign(args, env)
                self.assertEqual(dict(os.environ), {'UNCHANGED_SENTINEL': 'original'})
            build.assert_called_once()
            child = build.call_args.kwargs['build_env']
            self.assertEqual(child['AGENTD_SIGN_ARTIFACTS'], 'true')
            self.assertEqual(child['APPLE_TEAM_ID'], 'ABCDE12345')
            self.assertIn('AGENTD_MACOS_KEYCHAIN', child)
            self.assertFalse(any(name.endswith(('_BASE64', '_PASSWORD')) for name in child))
            package.assert_not_called()
            self.assertEqual(before, (archive.read_bytes(), (payload / 'agentd').read_bytes(), (payload / 'BUILDINFO.json').read_bytes()))
            metadata = json.loads((out / '_metadata/darwin-arm64.json').read_text())
            self.assertTrue(metadata['notarized'])
            self.assertNotIn('pkgStapled', metadata)
            self.assertEqual(metadata['teamID'], 'ABCDE12345')
            self.assertEqual(metadata['archiveSHA256'], release.sha256(archive))
            self.assertEqual(set(metadata['notarization']), {'archive'})
            release.verify_manifest(out)
            self.assertEqual(list(root.glob('agentd-signing-*')), [])
            calls = [call.args[0] for call in command.call_args_list]
            self.assertEqual(calls[-2], ['security', 'list-keychains', '-d', 'user', '-s', '/original/login.keychain-db'])
            self.assertEqual(calls[-1][:2], ['security', 'delete-keychain'])

    def test_notary_cannot_mutate_signed_archive_or_binary(self):
        for target in ('archive', 'binary'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temp:
                args, built = fake_signed_build(Path(temp))
                env = dict(apple_config(), RUNNER_TEMP=temp)
                def mutate(*args, **kwargs):
                    path = built[3] / 'agentd' if target == 'binary' else built[2] / release.names(built[0], built[1])[0]
                    path.write_bytes(b'changed-after-signing')
                    return {'id': 'submission', 'status': 'Accepted'}
                with mock.patch.object(MAC.sys, 'platform', 'darwin'), mock.patch.object(MAC, 'command', side_effect=fake_mac_command), \
                        mock.patch.object(release, 'build', return_value=built), mock.patch.object(MAC, 'notarize', side_effect=mutate):
                    with self.assertRaisesRegex(ValueError, 'changed during notarization'):
                        MAC.sign(args, env)
                self.assertFalse((built[2] / 'SHA256SUMS').exists())
                self.assertEqual(list(Path(temp).glob('agentd-signing-*')), [])

    def test_per_architecture_stage_does_not_require_installer_private_key(self):
        with tempfile.TemporaryDirectory() as temp:
            args, built = fake_signed_build(Path(temp))
            env = {key: value for key, value in apple_config().items() if not key.startswith('APPLE_INSTALLER_')}
            env['RUNNER_TEMP'] = temp
            with mock.patch.object(MAC.sys, 'platform', 'darwin'), mock.patch.object(MAC, 'command', side_effect=fake_mac_command) as command, \
                    mock.patch.object(release, 'build', return_value=built), mock.patch.object(MAC, 'notarize', return_value={'id': 'submission', 'status': 'Accepted'}):
                MAC.sign(args, env)
            imports = [call.args[0] for call in command.call_args_list if call.args[0][:2] == ['security', 'import']]
            self.assertEqual(len(imports), 1)
            self.assertEqual(Path(imports[0][2]).name, 'application.p12')


def universal_sources(root):
    inputs = {}
    for arch in ('amd64', 'arm64'):
        _, built = fake_signed_build(root, arch, 'target-darwin-' + arch)
        target, version, out, payload = built
        archive = out / release.names(target, version)[0]
        metadata_path = out / ('_metadata/darwin-' + arch + '.json')
        metadata = json.loads(metadata_path.read_text())
        metadata.update(signed=True, binarySigned=True, notarized=True, teamID='ABCDE12345',
                        archiveSHA256=release.sha256(archive), archiveBinarySHA256=release.sha256(payload / 'agentd'),
                        notarization={'archive': {'id': '12345678-1234-1234-1234-123456789abc',
                                                   'status': 'Accepted', 'sha256': release.sha256(archive)}})
        metadata_path.write_text(json.dumps(metadata))
        release.manifest(out)
        inputs[arch] = out
    args = argparse.Namespace(amd64_input=str(inputs['amd64']), arm64_input=str(inputs['arm64']),
                              out=str(root / 'universal'), version=None)
    return args, inputs


def fake_universal_package(target, version, out, payload, **kwargs):
    metadata = json.loads((payload / 'BUILDINFO.json').read_text())
    if not metadata['binarySigned'] or metadata['binarySHA256'] != release.sha256(payload / 'agentd'):
        raise ValueError('fixture package received an unsigned or changed universal binary')
    (out / release.names(target, version)[0]).write_bytes(b'signed-universal-pkg:' + (payload / 'agentd').read_bytes())


def fake_notary_receipt(path, *args, **kwargs):
    return {'id': '12345678-1234-1234-1234-123456789abc', 'status': 'Accepted', 'sha256': release.sha256(path)}


class MacUniversalSigningTest(unittest.TestCase):
    def test_universal_assembles_and_resigns_only_new_binary_without_rebuilding_or_changing_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            args, inputs = universal_sources(root)
            before = {path: path.read_bytes() for directory in inputs.values() for path in directory.rglob('*') if path.is_file()}
            env = dict(apple_config(), RUNNER_TEMP=temp)
            with mock.patch.object(MAC.sys, 'platform', 'darwin'), mock.patch.object(MAC, 'command', side_effect=fake_mac_command) as command, \
                    mock.patch.object(release, 'build') as build, \
                    mock.patch.object(release, 'package_mac_universal', side_effect=fake_universal_package) as package, \
                    mock.patch.object(MAC, 'notarize', side_effect=fake_notary_receipt) as notary:
                MAC.sign_universal(args, env)
            build.assert_not_called()
            package.assert_called_once()
            notary.assert_called_once()
            self.assertTrue(Path(notary.call_args.args[0]).name.endswith('_macOS_universal.pkg'))
            self.assertTrue(all(path.read_bytes() == contents for path, contents in before.items()))
            out = Path(args.out).resolve()
            metadata = json.loads((out / '_metadata/darwin-universal.json').read_text())
            binary = out / '.staging/darwin-universal/payload/agentd'
            self.assertTrue(binary.read_bytes().startswith(b'universal-fat-cli:'))
            self.assertTrue(binary.read_bytes().endswith(b'-resigned'))
            self.assertEqual(metadata['binarySHA256'], release.sha256(binary))
            self.assertEqual(metadata['version'], 'v1.2.3')
            self.assertTrue(metadata['signed'] and metadata['notarized'] and metadata['pkgStapled'])
            self.assertEqual(len(metadata['components']), 2)
            calls = [call.args[0] for call in command.call_args_list]
            signed = [call for call in calls if call[:2] == ['codesign', '--force']]
            self.assertEqual(len(signed), 1)
            self.assertEqual(signed[0][-1], binary)
            for arch in ('x86_64', 'arm64'):
                self.assertTrue(any(call[:2] == ['codesign', '--display'] and '--architecture' in call and arch in call and call[-1] == binary for call in calls))
            release.verify_manifest(out)
            self.assertEqual(list(root.glob('agentd-signing-*')), [])

    def test_universal_rejects_untrusted_inputs_before_importing_credentials(self):
        for scenario in ('zip-bytes', 'version', 'team', 'notary-status', 'notary-hash'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                args, inputs = universal_sources(root)
                source = inputs['arm64']
                metadata_path = source / '_metadata/darwin-arm64.json'
                metadata = json.loads(metadata_path.read_text())
                if scenario == 'zip-bytes':
                    archive = source / release.names(release.target('darwin', 'arm64'), 'v1.2.3')[0]
                    archive.write_bytes(archive.read_bytes() + b'tampered')
                else:
                    if scenario == 'version': metadata['version'] = 'v1.2.4'
                    if scenario == 'team': metadata['teamID'] = 'WRONG12345'
                    if scenario == 'notary-status': metadata['notarization']['archive']['status'] = 'In Progress'
                    if scenario == 'notary-hash': metadata['notarization']['archive']['sha256'] = '0' * 64
                    metadata_path.write_text(json.dumps(metadata)); release.manifest(source)
                with mock.patch.object(MAC.sys, 'platform', 'darwin'), mock.patch.object(MAC, 'command') as command:
                    with self.assertRaises(ValueError):
                        MAC.sign_universal(args, dict(apple_config(), RUNNER_TEMP=temp))
                    command.assert_not_called()
                self.assertFalse((Path(args.out) / 'SHA256SUMS').exists())

    def test_universal_checks_non_native_slice_team_and_cleans_credentials_on_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            args, _ = universal_sources(root)
            def wrong_team(argv, **kwargs):
                if argv[:2] == ['codesign', '--display'] and '--architecture' in argv and 'arm64' in argv and Path(argv[-1]).parent.name == 'payload':
                    return SIGNED_DETAILS.replace('TeamIdentifier=ABCDE12345', 'TeamIdentifier=WRONG12345')
                return fake_mac_command(argv, **kwargs)
            with mock.patch.object(MAC.sys, 'platform', 'darwin'), mock.patch.object(MAC, 'command', side_effect=wrong_team), \
                    mock.patch.object(release, 'package_mac_universal') as package:
                with self.assertRaisesRegex(ValueError, 'TeamIdentifier'):
                    MAC.sign_universal(args, dict(apple_config(), RUNNER_TEMP=temp))
                package.assert_not_called()
            self.assertFalse((Path(args.out) / 'SHA256SUMS').exists())
            self.assertEqual(list(root.glob('agentd-signing-*')), [])

    def test_universal_detects_source_archive_mutation_and_emits_no_checksum(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            args, inputs = universal_sources(root)
            def mutate_input(*values, **kwargs):
                fake_universal_package(*values, **kwargs)
                archive = inputs['amd64'] / release.names(release.target('darwin', 'amd64'), 'v1.2.3')[0]
                archive.write_bytes(archive.read_bytes() + b'changed')
            with mock.patch.object(MAC.sys, 'platform', 'darwin'), mock.patch.object(MAC, 'command', side_effect=fake_mac_command), \
                    mock.patch.object(release, 'package_mac_universal', side_effect=mutate_input), \
                    mock.patch.object(MAC, 'notarize', side_effect=fake_notary_receipt):
                with self.assertRaisesRegex(ValueError, 'original architecture ZIP changed'):
                    MAC.sign_universal(args, dict(apple_config(), RUNNER_TEMP=temp))
            self.assertFalse((Path(args.out) / 'SHA256SUMS').exists())
            self.assertEqual(list(root.glob('agentd-signing-*')), [])


class AzureSubjectTest(unittest.TestCase):
    REPOSITORY = {'full_name': 'Bit-Precise/agentd', 'id': 1423467115,
                  'owner': {'login': 'Bit-Precise', 'id': 295183371}}
    OLD_SUBJECT = 'repository_owner_id:295183371:job_workflow_ref:Bit-Precise/actions/.github/workflows/sign-windows.yml@refs/tags/v1'
    SUBJECT = 'repository_owner_id:295183371:repository_id:1423467115:environment:release-signing'

    def args(self, **overrides):
        values = dict(repository='Bit-Precise/agentd', tenant_id='11111111-1111-1111-1111-111111111111',
            subscription_id='22222222-2222-2222-2222-222222222222', resource_group='signing', account='account',
            profile='profile', environment='release-signing', application_id='33333333-3333-3333-3333-333333333333',
            credential_name='credential-github', replace_subject='', endpoint='https://wus2.codesigning.azure.net/')
        return argparse.Namespace(**(values | overrides))

    def plan(self):
        with mock.patch.object(AZURE, 'github', side_effect=[self.REPOSITORY, {'use_default': True}]):
            return AZURE.plan(self.args())

    def test_read_only_plan_binds_owner_repository_and_environment_without_workflow_ref(self):
        with mock.patch.object(AZURE, 'github', side_effect=[self.REPOSITORY,
                {'use_default': False, 'include_claim_keys': ['repository_owner_id', 'job_workflow_ref']}]) as gh:
            plan = AZURE.plan(self.args())
        self.assertEqual(plan['federatedCredential']['subject'], self.SUBJECT)
        self.assertEqual(plan['repositoryOIDC'], {'use_default': False,
                         'include_claim_keys': ['repository_owner_id', 'repository_id', 'context']})
        self.assertTrue(plan['profileScope'].endswith('/certificateProfiles/profile'))
        self.assertTrue(all(call.args[0] == 'GET' for call in gh.call_args_list))
        self.assertEqual(plan['organizationVariablesAction'], 'unchanged; configure in organization settings')
        self.assertNotIn('client-secret', json.dumps(plan))

    def test_identity_requires_positive_numeric_ids_and_safe_environment(self):
        for repo in (self.REPOSITORY | {'id': '1423467115'}, self.REPOSITORY | {'id': 0},
                     self.REPOSITORY | {'owner': {'id': True}}):
            with self.assertRaises(ValueError): AZURE.exact_subject(repo, 'release-signing')
        with self.assertRaises(ValueError): AZURE.exact_subject(self.REPOSITORY, 'production:other')
        with mock.patch.object(AZURE, 'github', return_value=self.REPOSITORY | {'full_name': 'other/repo'}):
            with self.assertRaisesRegex(ValueError, 'canonical'): AZURE.plan(self.args())

    def test_named_credential_update_requires_exact_explicit_old_subject(self):
        desired = self.plan()['federatedCredential']
        old = desired | {'subject': self.OLD_SUBJECT, 'id': 'credential-id'}
        with self.assertRaisesRegex(ValueError, 'replace-subject'):
            AZURE.credential_operation([old], desired, '')
        with self.assertRaisesRegex(ValueError, 'replace-subject'):
            AZURE.credential_operation([old], desired, 'another-subject')
        self.assertEqual(AZURE.credential_operation([old], desired, self.OLD_SUBJECT), ('update', 'credential-id'))
        self.assertEqual(AZURE.credential_operation([desired | {'id': 'credential-id'}], desired, ''), ('unchanged', 'credential-id'))
        self.assertEqual(AZURE.credential_operation([old | {'name': 'unrelated'}], desired, ''), ('create', None))
        with self.assertRaisesRegex(ValueError, 'issuer/audience'):
            AZURE.credential_operation([old | {'issuer': 'https://other.invalid'}], desired, self.OLD_SUBJECT)

    def test_apply_checks_identity_and_old_credential_before_any_mutation(self):
        args, plan = self.args(), self.plan()
        responses = [
            {'tenantId': args.tenant_id, 'id': args.subscription_id},
            {'appId': args.application_id, 'id': 'application-object'},
            [{'id': 'service-principal', 'appOwnerOrganizationId': args.tenant_id, 'accountEnabled': True}],
            {'properties': {'status': 'Active', 'profileType': 'PublicTrust'}},
            [plan['federatedCredential'] | {'id': 'credential-id', 'subject': self.OLD_SUBJECT}],
        ]
        with mock.patch.object(AZURE, 'plan', return_value=plan), mock.patch.object(AZURE, 'run', side_effect=responses) as run, \
                mock.patch.object(AZURE, 'github') as gh, mock.patch.object(AZURE, 'ensure_environment') as environment:
            with self.assertRaisesRegex(ValueError, 'replace-subject'): AZURE.apply(args, plan)
            gh.assert_not_called();environment.assert_not_called()
            self.assertTrue(all(call.args[0][1:4] != ['ad', 'app', 'create'] for call in run.call_args_list))

    def test_environment_policy_allows_only_main_branch_and_v_tags(self):
        rules = [{'id': 1, 'type': 'branch', 'name': 'main'}, {'id': 2, 'type': 'branch', 'name': 'feature/*'}]
        replies = [{'environments': [{'name': 'release-signing', 'deployment_branch_policy':
                    {'protected_branches': False, 'custom_branch_policies': True}}]}, {'branch_policies': rules}, {}, None]
        with mock.patch.object(AZURE, 'github', side_effect=replies) as gh:
            AZURE.ensure_environment('Bit-Precise/agentd', 'release-signing')
        writes = [call.args for call in gh.call_args_list if call.args[0] != 'GET']
        self.assertEqual(writes[0][-1], {'type': 'tag', 'name': 'v*'})
        self.assertEqual(writes[1][0], 'DELETE')
        self.assertTrue(writes[1][1].endswith('/2'))
        self.assertFalse(any('orgs/' in call.args[1] for call in gh.call_args_list))


if __name__ == '__main__':
    unittest.main()
