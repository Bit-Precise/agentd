"""Verify package preconditions and cleanup without invoking sudo or installing."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import release

spec = importlib.util.spec_from_file_location('verify_macos_package', SCRIPTS / 'verify-macos-package.py')
VERIFY = importlib.util.module_from_spec(spec)
spec.loader.exec_module(VERIFY)


class MacPackageVerificationTest(unittest.TestCase):
    def fixture(self, root, signed=False):
        out = (root / 'artifact').resolve()
        (out / '_metadata').mkdir(parents=True)
        version = 'v1.2.3'
        target = release.target('darwin', 'universal')
        pkg = out / release.names(target, release.versions(version))[0]
        pkg.write_bytes(b'fixture-package-not-a-real-installer')
        binary = b'fixture-universal-binary'
        metadata = {**target, **release.versions(version), 'sourceVersion': version,
                    'binarySHA256': hashlib.sha256(binary).hexdigest(), 'signed': signed,
                    'binarySigned': signed, 'notarized': signed, 'pkgStapled': signed}
        metadata_path = out / '_metadata/darwin-universal.json'
        metadata_path.write_text(json.dumps(metadata))
        release.manifest(out)
        return out, version, pkg, metadata_path, binary

    def test_missing_manifest_coverage_is_rejected_before_any_native_command(self):
        for included in ((), ('metadata',), ('pkg',)):
            with self.subTest(included=included), tempfile.TemporaryDirectory() as temp:
                out, version, pkg, metadata, _ = self.fixture(Path(temp))
                paths = {'metadata': metadata, 'pkg': pkg}
                (out / 'SHA256SUMS').write_text(''.join(
                    f'{release.sha256(paths[name])}  {paths[name].relative_to(out).as_posix()}\n'
                    for name in included))
                with mock.patch.object(VERIFY.sys, 'platform', 'darwin'), mock.patch.object(VERIFY, 'run') as run:
                    with self.assertRaisesRegex(ValueError, 'manifest must cover'):
                        VERIFY.verify(out, version)
                    run.assert_not_called()

    def test_wrong_target_version_or_binary_hash_is_rejected_before_install(self):
        for change in ({'arch': 'arm64'}, {'key': 'darwin-arm64'}, {'version': 'v1.2.4'}, {'binarySHA256': 'not-a-hash'}):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                out, version, _, metadata_path, _ = self.fixture(Path(temp))
                metadata = json.loads(metadata_path.read_text())
                metadata.update(change)
                metadata_path.write_text(json.dumps(metadata))
                release.manifest(out)
                with mock.patch.object(VERIFY.sys, 'platform', 'darwin'), mock.patch.object(VERIFY, 'run') as run:
                    with self.assertRaises(ValueError):
                        VERIFY.verify(out, version)
                    run.assert_not_called()

    def test_changed_package_bytes_are_rejected_before_install(self):
        with tempfile.TemporaryDirectory() as temp:
            out, version, pkg, _, _ = self.fixture(Path(temp))
            pkg.write_bytes(b'changed-after-checksum')
            with mock.patch.object(VERIFY.sys, 'platform', 'darwin'), mock.patch.object(VERIFY, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'invalid checksum'):
                    VERIFY.verify(out, version)
                run.assert_not_called()

    def fake_installation(self, root, version, binary, architecture_output='x86_64 arm64', installed_version=None):
        installed = root / 'mock-install/bin/agentd'
        documentation = root / 'mock-install/doc/agentd'
        calls = []

        def path(value):
            requested = Path(value)
            if requested == Path('/usr/local/bin/agentd'):
                return installed
            if requested == Path('/usr/local/share/doc/agentd'):
                return documentation
            return requested

        def run(args, capture=False):
            calls.append(args)
            if args[:3] == ['sudo', '-n', 'installer']:
                installed.parent.mkdir(parents=True)
                installed.write_bytes(binary)
                for relative in ('README.md', 'config.example.yaml', 'THIRD_PARTY_NOTICES.md', 'licenses/go/LICENSE'):
                    file = documentation / relative
                    file.parent.mkdir(parents=True, exist_ok=True)
                    file.write_text('fixture documentation')
            elif args[:2] == [installed, 'version']:
                return (installed_version or version) + '\n'
            elif args[:2] == ['lipo', '-archs']:
                return architecture_output + '\n'
            elif args[:3] == ['sudo', '-n', 'rm']:
                destination = Path(args[-1])
                if destination.is_dir(): shutil.rmtree(destination)
                else: destination.unlink()
            return ''

        return path, run, calls, installed, documentation

    def test_signed_success_verifies_installation_and_cleans_all_installed_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            out, version, pkg, _, binary = self.fixture(root, signed=True)
            path, run, calls, installed, documentation = self.fake_installation(root, version, binary)
            with mock.patch.object(VERIFY.sys, 'platform', 'darwin'), mock.patch.object(VERIFY, 'Path', side_effect=path), \
                    mock.patch.object(VERIFY, 'run', side_effect=run):
                VERIFY.verify(out, version, require_signed=True)
            self.assertEqual(calls[0], ['pkgutil', '--check-signature', pkg])
            self.assertIn(['xcrun', 'stapler', 'validate', pkg], calls)
            self.assertIn(['codesign', '--verify', '--strict', '--all-architectures', installed], calls)
            self.assertEqual(calls[-1], ['sudo', '-n', 'pkgutil', '--forget', 'com.bit-precise.agentd'])
            self.assertFalse(installed.exists())
            self.assertFalse(documentation.exists())

    def test_post_install_integrity_failures_still_clean_up(self):
        for failure in ('hash', 'version', 'architectures'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                out, version, _, _, binary = self.fixture(root)
                path, run, calls, installed, documentation = self.fake_installation(
                    root, version, b'wrong-binary' if failure == 'hash' else binary,
                    architecture_output='arm64' if failure == 'architectures' else 'x86_64 arm64',
                    installed_version='v9.9.9' if failure == 'version' else None)
                with mock.patch.object(VERIFY.sys, 'platform', 'darwin'), mock.patch.object(VERIFY, 'Path', side_effect=path), \
                        mock.patch.object(VERIFY, 'run', side_effect=run):
                    with self.assertRaises(ValueError):
                        VERIFY.verify(out, version)
                self.assertTrue(any(call[:3] == ['sudo', '-n', 'installer'] for call in calls))
                self.assertEqual(calls[-1], ['sudo', '-n', 'pkgutil', '--forget', 'com.bit-precise.agentd'])
                self.assertFalse(installed.exists())
                self.assertFalse(documentation.exists())


if __name__ == '__main__':
    unittest.main()
