"""Publish the selected tag even when an annotated RC names the same commit."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import test_build_release as fixtures


R = fixtures.R


class PublishTagTest(unittest.TestCase):
    def git(self, repository, *args):
        env = dict(os.environ, GIT_AUTHOR_NAME='Release fixture', GIT_AUTHOR_EMAIL='release@example.invalid',
                   GIT_COMMITTER_NAME='Release fixture', GIT_COMMITTER_EMAIL='release@example.invalid')
        return subprocess.check_output(['git', '-C', str(repository), '-c', 'commit.gpgsign=false',
                                        '-c', 'tag.gpgsign=false', *args], env=env, text=True,
                                       stderr=subprocess.DEVNULL).strip()

    def fixture(self, root):
        repository = root / 'repository'
        repository.mkdir()
        self.git(repository, 'init', '-q')
        self.git(repository, 'commit', '--allow-empty', '-m', 'Release fixture')
        commit = self.git(repository, 'rev-parse', 'HEAD')
        self.git(repository, 'tag', '-a', 'v1.2.3-rc.1', '-m', 'Release candidate')
        self.git(repository, 'tag', 'v1.2.3')
        self.git(repository, 'checkout', '--detach', 'v1.2.3')
        # Reproduce the old failure rather than merely mocking tag discovery.
        self.assertEqual(self.git(repository, 'describe', '--tags', '--exact-match', 'HEAD'), 'v1.2.3-rc.1')
        (repository / '.goreleaser.publish.json').write_bytes((R.ROOT / '.goreleaser.publish.json').read_bytes())
        incoming, out = root / 'incoming', root / 'release'
        fixtures.ReleaseContractTest().fixture_targets(incoming)
        R.collect(incoming, out)
        metadata_path = out / '_metadata/BUILDINFO.json'
        metadata = json.loads(metadata_path.read_text())
        for item in metadata['targets']:
            item.update(commit=commit, signed=True, binarySigned=True, timestampVerified=True,
                        notarized=True, pkgStapled=True)
            if item['os'] == 'darwin' and item['arch'] != 'universal':
                item.update(teamID='ABCDE12345', notarization={'archive': {
                    'id': 'accepted-test-receipt', 'status': 'Accepted', 'sha256': item['archiveSHA256']}})
        metadata_path.write_text(json.dumps(metadata))
        R.manifest(out)
        return repository, out

    def environment(self, **updates):
        # Keep runner tooling available but do not inherit the test workflow's
        # branch/PR ref, signing mode or a caller's GoReleaser tag override.
        env = {name: value for name, value in os.environ.items()
               if not name.startswith('GITHUB_') and name not in ('GORELEASER_CURRENT_TAG', 'AGENTD_SIGN_ARTIFACTS')}
        return dict(env, **updates)

    def fake_goreleaser(self, calls, expected_tag):
        def run(command, **kwargs):
            self.assertEqual(kwargs['env']['GORELEASER_CURRENT_TAG'], expected_tag)
            calls.append(command)
            config = json.loads(Path(command[command.index('--config') + 1]).read_text())
            paths = [Path(item['glob']) for item in config['checksum']['extra_files']]
            generated = Path(config['dist'])
            generated.mkdir(parents=True, exist_ok=True)
            # No executable or network request: emulate only GoReleaser's final
            # checksum output, while exercising the real repository/ref checks.
            (generated / R.checksum_name(expected_tag)).write_bytes(
                ''.join(f'{R.sha256(path)}  {path.name}\n' for path in paths).encode())
        return run

    def test_local_formal_release_selects_metadata_tag_and_overrides_stale_goreleaser_tag(self):
        with tempfile.TemporaryDirectory() as temp:
            repository, out = self.fixture(Path(temp))
            calls = []
            with mock.patch.dict(os.environ, self.environment(GORELEASER_CURRENT_TAG='v1.2.3-rc.1'), clear=True), \
                    mock.patch.object(R, 'ROOT', repository), \
                    mock.patch.object(R, 'goreleaser_command', return_value='goreleaser'), \
                    mock.patch.object(R, 'run', side_effect=self.fake_goreleaser(calls, 'v1.2.3')):
                R.publish(out)
            self.assertEqual(len(calls), 2)
            self.assertIn('--snapshot', calls[0])
            self.assertNotIn('--snapshot', calls[1])

    def test_github_formal_release_uses_the_event_tag(self):
        with tempfile.TemporaryDirectory() as temp:
            repository, out = self.fixture(Path(temp))
            calls = []
            env = self.environment(GITHUB_ACTIONS='true', GITHUB_REF_TYPE='tag',
                                   GITHUB_REF_NAME='v1.2.3', GITHUB_REF='refs/tags/v1.2.3')
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(R, 'ROOT', repository), \
                    mock.patch.object(R, 'goreleaser_command', return_value='goreleaser'), \
                    mock.patch.object(R, 'run', side_effect=self.fake_goreleaser(calls, 'v1.2.3')):
                R.publish(out)
            self.assertEqual(len(calls), 2)

    def test_github_nonmatching_or_missing_event_ref_fails_before_goreleaser(self):
        for changes in ({'GITHUB_REF_TYPE': 'branch'}, {'GITHUB_REF_NAME': 'v1.2.3-rc.1'},
                        {'GITHUB_REF': 'refs/heads/main'}, {'GITHUB_REF': ''}, {'GITHUB_REF_NAME': ''}):
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as temp:
                repository, out = self.fixture(Path(temp))
                env = self.environment(GITHUB_ACTIONS='true', GITHUB_REF_TYPE='tag',
                                       GITHUB_REF_NAME='v1.2.3', GITHUB_REF='refs/tags/v1.2.3')
                env.update(changes)
                with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(R, 'ROOT', repository), \
                        mock.patch.object(R, 'goreleaser_command') as executable, mock.patch.object(R, 'run') as run:
                    with self.assertRaisesRegex(ValueError, 'GitHub release ref must match'):
                        R.publish(out)
                    executable.assert_not_called()
                    run.assert_not_called()

    def test_tag_on_a_different_commit_fails_before_goreleaser(self):
        with tempfile.TemporaryDirectory() as temp:
            repository, out = self.fixture(Path(temp))
            self.git(repository, 'commit', '--allow-empty', '-m', 'Another commit')
            metadata_path = out / '_metadata/BUILDINFO.json'
            metadata = json.loads(metadata_path.read_text())
            for item in metadata['targets']:
                item['commit'] = self.git(repository, 'rev-parse', 'HEAD')
            metadata_path.write_text(json.dumps(metadata))
            R.manifest(out)
            with mock.patch.dict(os.environ, self.environment(), clear=True), mock.patch.object(R, 'ROOT', repository), \
                    mock.patch.object(R, 'goreleaser_command') as executable, mock.patch.object(R, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'exact source tag'):
                    R.publish(out)
                executable.assert_not_called()
                run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
