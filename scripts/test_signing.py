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
