"""Exercise fail-closed release gating and private-key cleanup without real keys."""
import argparse
import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
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


class ReleaseSigningTest(unittest.TestCase):
    def test_tag_release_rejects_unsigned_missing_notary_and_missing_timestamp(self):
        for target in release.all_targets():
            if target['os'] == 'linux':
                release.validate_release_signing([target])
                continue
            with self.assertRaisesRegex(ValueError, 'signed installer'):
                release.validate_release_signing([target])
            target.update(signed=True, binarySigned=True)
            with self.assertRaises(ValueError):
                release.validate_release_signing([target])
            target.update(timestampVerified=True, notarized=True, pkgStapled=True)
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
        for value in ({'status': 'Invalid', 'id': 'id'}, {'status': 'In Progress', 'id': 'id'}, {'status': 'Accepted'}):
            with mock.patch.object(MAC, 'command', return_value=json.dumps(value)):
                with self.assertRaisesRegex(ValueError, 'not Accepted'):
                    MAC.notarize(Path('archive.zip'), Path('key.p8'), env)

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
            out = root / 'dist'
            payload = out / '.staging/darwin-arm64/payload'
            payload.mkdir(parents=True)
            (payload / 'agentd').write_bytes(b'signed-test-binary')
            args = argparse.Namespace(arch='arm64', version='v1.2.3', out=str(out))
            built = (release.target('darwin', 'arm64'), release.versions('v1.2.3'), out, payload)
            with mock.patch.object(MAC.sys, 'platform', 'darwin'), mock.patch.object(MAC, 'command', return_value=''), \
                    mock.patch.object(release, 'build', return_value=built), mock.patch.object(release, 'package_mac'), \
                    mock.patch.object(MAC, 'notarize', side_effect=ValueError('not Accepted')):
                with self.assertRaisesRegex(ValueError, 'not Accepted'):
                    MAC.sign(args, env)
            self.assertFalse((out / 'SHA256SUMS').exists())
            self.assertEqual(list(root.glob('agentd-signing-*')), [])

    def test_bootstrap_plan_has_profile_scope_exact_subject_and_no_client_secret(self):
        args = argparse.Namespace(repository='Bit-Precise/agentd', tenant_id='11111111-1111-1111-1111-111111111111',
            subscription_id='22222222-2222-2222-2222-222222222222', resource_group='signing', account='account',
            profile='profile', environment='release-signing', application_name='agentd-release-signing',
            application_id='', endpoint='https://wus2.codesigning.azure.net/')
        with mock.patch.object(AZURE.subprocess, 'run') as run:
            plan = AZURE.plan(args)
            run.assert_not_called()
        self.assertTrue(plan['scope'].endswith('/certificateProfiles/profile'))
        self.assertEqual(plan['federatedCredential']['subject'], 'repo:Bit-Precise/agentd:environment:release-signing')
        self.assertEqual(plan['federatedCredential']['audiences'], ['api://AzureADTokenExchange'])
        self.assertNotIn('client-secret', json.dumps(plan))


if __name__ == '__main__':
    unittest.main()
