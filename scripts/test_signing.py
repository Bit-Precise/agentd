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
            application_id='', endpoint='https://wus2.codesigning.azure.net/',
            discover_subject=False, subject_prefix='repo:Bit-Precise@295183371/agentd@1423467115')
        with mock.patch.object(AZURE.subprocess, 'run') as run:
            plan = AZURE.plan(args)
            run.assert_not_called()
        self.assertTrue(plan['scope'].endswith('/certificateProfiles/profile'))
        self.assertEqual(plan['federatedCredential']['subject'], 'repo:Bit-Precise@295183371/agentd@1423467115:environment:release-signing')
        self.assertEqual(plan['federatedCredential']['audiences'], ['api://AzureADTokenExchange'])
        self.assertNotIn('client-secret', json.dumps(plan))


class AzureSubjectTest(unittest.TestCase):
    REPOSITORY = {'full_name': 'Bit-Precise/agentd', 'id': 1423467115,
                  'owner': {'login': 'Bit-Precise', 'id': 295183371}}
    IMMUTABLE = {'use_default': True, 'use_immutable_subject': True,
                 'sub_claim_prefix': 'repo:Bit-Precise@295183371/agentd@1423467115'}
    LEGACY = {'use_default': True, 'use_immutable_subject': False,
              'sub_claim_prefix': 'repo:Bit-Precise/agentd'}

    def args(self, **overrides):
        values = dict(repository='Bit-Precise/agentd', tenant_id='11111111-1111-1111-1111-111111111111',
            subscription_id='22222222-2222-2222-2222-222222222222', resource_group='signing', account='account',
            profile='profile', environment='release-signing', application_name='agentd-release-signing',
            application_id='', endpoint='https://wus2.codesigning.azure.net/',
            discover_subject=False, subject_prefix=self.IMMUTABLE['sub_claim_prefix'])
        return argparse.Namespace(**(values | overrides))

    def test_offline_plans_require_explicit_legacy_or_immutable_prefix_without_any_reads(self):
        with mock.patch.object(AZURE, 'run') as run:
            for source in (self.LEGACY, self.IMMUTABLE):
                plan = AZURE.plan(self.args(subject_prefix=source['sub_claim_prefix']))
                self.assertEqual(plan['federatedCredential']['subject'], source['sub_claim_prefix'] + ':environment:release-signing')
            with self.assertRaisesRegex(ValueError, 'supply --subject-prefix'):
                AZURE.plan(self.args(subject_prefix=''))
            run.assert_not_called()

    def test_discovery_reads_explicit_default_settings_and_cross_checks_repository_ids(self):
        for source in (self.LEGACY, self.IMMUTABLE):
            with self.subTest(source=source), mock.patch.object(AZURE, 'run', side_effect=[source, self.REPOSITORY]) as run:
                plan = AZURE.plan(self.args(discover_subject=True, subject_prefix=None))
                self.assertEqual(plan['githubSubjectPrefix'], source['sub_claim_prefix'])
                self.assertEqual(run.call_count, 2)
                self.assertTrue(all(call.args[0][:2] == ['gh', 'api'] for call in run.call_args_list))

    def test_discovery_rejects_custom_or_ambiguous_templates(self):
        for source in ({'use_default': False, 'include_claim_keys': ['repository_owner_id', 'job_workflow_ref']},
                       {'use_default': True}, {'use_default': True, 'sub_claim_prefix': self.LEGACY['sub_claim_prefix']}):
            with self.subTest(source=source), mock.patch.object(AZURE, 'run', return_value=source) as run:
                with self.assertRaises(ValueError):
                    AZURE.discover_subject_prefix('Bit-Precise/agentd')
                self.assertEqual(run.call_count, 1)

    def test_discovery_rejects_prefix_mismatching_mode_ids_or_canonical_name(self):
        cases = [
            (self.IMMUTABLE | {'sub_claim_prefix': self.LEGACY['sub_claim_prefix']}, self.REPOSITORY),
            (self.LEGACY | {'sub_claim_prefix': self.IMMUTABLE['sub_claim_prefix']}, self.REPOSITORY),
            (self.IMMUTABLE, self.REPOSITORY | {'id': 1}),
            (self.IMMUTABLE, self.REPOSITORY | {'owner': {'id': 1}}),
            (self.IMMUTABLE, self.REPOSITORY | {'full_name': 'other/agentd'}),
        ]
        for source, repo in cases:
            with self.subTest(source=source, repo=repo), mock.patch.object(AZURE, 'run', side_effect=[source, repo]):
                with self.assertRaises(ValueError):
                    AZURE.discover_subject_prefix('Bit-Precise/agentd')

    def test_offline_prefix_rejects_other_repositories_wildcards_context_or_partial_ids(self):
        for prefix in ('repo:other/agentd', 'repo:Bit-Precise/agentd:*',
                       'repo:Bit-Precise/agentd:environment:release-signing',
                       'repo:Bit-Precise@295183371/agentd', 'repo:Bit-Precise/agentd@1423467115',
                       'repository_owner_id:295183371:job_workflow_ref:any'):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                AZURE.plan(self.args(subject_prefix=prefix))

    def test_apply_rejects_obsolete_offline_prefix_before_any_azure_or_github_write(self):
        args = self.args(subject_prefix=self.LEGACY['sub_claim_prefix'])
        plan = AZURE.plan(args)
        with mock.patch.object(AZURE, 'run', side_effect=[self.IMMUTABLE, self.REPOSITORY]) as run, \
                mock.patch.object(AZURE.subprocess, 'run') as process:
            with self.assertRaisesRegex(ValueError, 'does not match current'):
                AZURE.apply(args, plan)
            process.assert_not_called()
            self.assertEqual(run.call_count, 2)
            self.assertTrue(all(call.args[0][:2] == ['gh', 'api'] for call in run.call_args_list))

    def test_apply_rechecks_even_discovered_plan_and_refuses_custom_template_change(self):
        args = self.args(discover_subject=True, subject_prefix=None)
        with mock.patch.object(AZURE, 'run', side_effect=[self.IMMUTABLE, self.REPOSITORY,
                {'use_default': False, 'include_claim_keys': ['repository_owner_id', 'job_workflow_ref']}]) as run, \
                mock.patch.object(AZURE.subprocess, 'run') as process:
            plan = AZURE.plan(args)
            with self.assertRaisesRegex(ValueError, 'custom OIDC subject template'):
                AZURE.apply(args, plan)
            process.assert_not_called()
            self.assertEqual(run.call_count, 3)
            self.assertTrue(all(call.args[0][:2] == ['gh', 'api'] for call in run.call_args_list))


if __name__ == '__main__':
    unittest.main()
