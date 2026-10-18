"""Artifact handoff tests; native signature checks and installers run in CI."""
import argparse
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import release

SPEC = importlib.util.spec_from_file_location('shared_signing', SCRIPTS / 'shared-signing.py')
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)


def signed_artifact(root, stage, filename, data=b'signed-file'):
    root.mkdir()
    (root / filename).write_bytes(data)
    record = {'name': filename, 'sha256': release.sha256(root / filename)}
    info = {'provider': 'Azure Artifact Signing' if stage in ('exe', 'msi') else 'Apple Developer ID',
            'stage': stage, 'signed': True, 'files': [record]}
    if stage in ('exe', 'msi'):
        record['timestampVerified'] = True
    else:
        info['notarized'] = True
        record.update(stapled=stage == 'pkg', notarization={'id': 'submission-id', 'status': 'Accepted', 'submittedSHA256': 'a' * 64})
    (root / 'SIGNINGINFO.json').write_text(json.dumps(info))
    release.manifest(root)
    return info


def build_state(root, target):
    root.mkdir()
    payload = root / '.staging' / target['key'] / 'payload'
    payload.mkdir(parents=True)
    (payload / ('agentd.exe' if target['os'] == 'windows' else 'agentd')).write_bytes(b'unsigned-cli')
    (payload / 'BUILDINFO.json').write_text('{}')
    metadata = dict(target, version='v1.2.3', signed=False, commit=os.environ.get('GITHUB_SHA', 'commit'))
    (root / '_metadata').mkdir()
    S.write_metadata(root, target, metadata)
    license_path = root / '_licenses' / target['key'] / 'go/LICENSE'
    license_path.parent.mkdir(parents=True)
    license_path.write_text('Go license')
    if target['os'] == 'windows':
        (root / release.names(target)[0]).write_bytes(b'unsigned-cli')
    else:
        release.archive_tree(payload, root / release.names(target)[0])
    return payload, metadata


class StateBundleTest(unittest.TestCase):
    def test_state_whitelist_excludes_tools_keys_and_unrelated_targets(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = release.target('windows', 'amd64')
            out = root / 'dist'
            build_state(out, target)
            for relative in ('.tools/wix.exe', '.staging/windows-amd64/notary-key.p8',
                             'admin.token', '_metadata/darwin-arm64.json'):
                path = out / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'must-not-transfer')
            bundle = root / 'state.tgz'
            S.save_state(out, target, bundle)
            with tarfile.open(bundle) as archive:
                names = archive.getnames()
                self.assertTrue(all(S.state_path_allowed(name, target) for name in names))
                self.assertFalse(any(name.endswith(('wix.exe', '.p8', 'admin.token', 'darwin-arm64.json')) for name in names))
            restored = root / 'restored'
            S.restore_state(bundle, restored, target)
            self.assertEqual((restored / 'agentd-windows-amd64.exe').read_bytes(), b'unsigned-cli')
            self.assertEqual(S.load_metadata(restored, target, 'v1.2.3')['key'], target['key'])
            with self.assertRaisesRegex(ValueError, 'version mismatch'):
                S.load_metadata(restored, target, 'v9.0.0')

    def test_restore_rejects_path_traversal_links_and_tools(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = release.target('darwin', 'arm64')
            for index, name in enumerate(('../escape', '/escape', '.tools/key', '.staging/darwin-arm64/payload/link')):
                bundle = root / f'{index}.tgz'
                with tarfile.open(bundle, 'w:gz') as archive:
                    entry = tarfile.TarInfo(name)
                    if name.endswith('/link'):
                        entry.type, entry.linkname = tarfile.SYMTYPE, '/secret'
                        archive.addfile(entry)
                    else:
                        entry.size = 4
                        archive.addfile(entry, io.BytesIO(b'data'))
                with self.subTest(name=name), self.assertRaises(ValueError):
                    S.restore_state(bundle, root / f'out-{index}', target)
            self.assertFalse((root / 'escape').exists())


class SharedReceiptTest(unittest.TestCase):
    def test_each_stage_requires_exact_file_manifest_provider_and_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for stage, filename in (('exe', 'agentd.exe'), ('msi', 'agentd.msi'), ('cli', 'agentd'), ('pkg', 'agentd.pkg')):
                directory = root / stage
                info = signed_artifact(directory, stage, filename)
                path, found = S.shared_product(directory, stage, filename)
                self.assertEqual(found, info)
                self.assertEqual(path.name, filename)
                (directory / filename).write_bytes(b'tampered')
                with self.assertRaisesRegex(ValueError, 'checksum'):
                    S.shared_product(directory, stage, filename)

    def test_apple_receipts_cannot_claim_pending_unstapled_or_wrong_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / 'pkg'
            info = signed_artifact(directory, 'pkg', 'agentd.pkg')
            modifications = (
                lambda item: item.update(stage='cli'),
                lambda item: item.update(provider='other'),
                lambda item: item.update(signed='true'),
                lambda item: item['files'][0].update(stapled=False),
                lambda item: item['files'][0].update(sha256='0' * 64),
                lambda item: item['files'][0]['notarization'].update(status='In Progress'),
                lambda item: item['files'][0]['notarization'].update(submittedSHA256=[]),
            )
            for change in modifications:
                bad = copy.deepcopy(info)
                change(bad)
                (directory / 'SIGNINGINFO.json').write_text(json.dumps(bad))
                release.manifest(directory)
                with self.assertRaises(ValueError): S.shared_product(directory, 'pkg', 'agentd.pkg')
            (directory / 'extra-key.p8').write_text('must reject')
            with self.assertRaisesRegex(ValueError, 'unexpected files'):
                S.shared_product(directory, 'pkg', 'agentd.pkg')


class HandoffTest(unittest.TestCase):
    def test_windows_assembles_from_signed_exe_and_finalizes_signed_msi_without_rebuild(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = release.target('windows', 'amd64')
            original = root / 'original'
            build_state(original, target)
            S.save_state(original, target, root / 'built.tgz')
            signed_artifact(root / 'signed-exe', 'exe', release.names(target)[0], b'externally-signed-exe')
            args = argparse.Namespace(os='windows', arch='amd64', version='v1.2.3', out=str(root / 'assembled'),
                state_input=str(root / 'built.tgz'), signed_input=str(root / 'signed-exe'),
                signing_output=str(root / 'msi-input'), state_output=str(root / 'packaged.tgz'))
            def package(command):
                self.assertIn('-RequireSigned', command)
                self.assertIn('Package', command)
                (Path(args.out) / release.names(target)[1]).write_bytes(b'unsigned-msi-with-signed-exe')
            with mock.patch.object(release, 'run', side_effect=package), mock.patch.object(release, 'build') as rebuild:
                S.assemble(args)
                rebuild.assert_not_called()
            self.assertEqual((Path(args.out) / '.staging/windows-amd64/payload/agentd.exe').read_bytes(), b'externally-signed-exe')
            signed_artifact(root / 'signed-msi', 'msi', release.names(target)[1], b'externally-signed-msi')
            final = argparse.Namespace(os='windows', arch='amd64', version='v1.2.3', out=str(root / 'final'),
                state_input=str(root / 'packaged.tgz'), signed_input=str(root / 'signed-msi'))
            def finalize(command):
                self.assertIn('Finalize', command)
                self.assertIn('-SmokeTest', command)
                self.assertIn('-RequireSigned', command)
                out = Path(final.out)
                metadata = S.load_metadata(out, target, final.version)
                metadata.update(signed=True, binarySigned=True, timestampVerified=True)
                S.write_metadata(out, target, metadata)
                release.manifest(out)
            with mock.patch.object(release, 'run', side_effect=finalize), mock.patch.object(release, 'build') as rebuild:
                S.finalize(final)
                rebuild.assert_not_called()
            self.assertEqual(set(S.load_metadata(Path(final.out), target, final.version)['signingReceipts']), {'exe', 'msi'})

    def test_mac_finalization_binds_archive_cli_and_final_stapled_pkg_to_receipts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = release.target('darwin', 'arm64')
            assembled = root / 'assembled'
            payload, metadata = build_state(assembled, target)
            cli_info = signed_artifact(root / 'signed-cli', 'cli', 'agentd', b'signed-notarized-cli')
            (payload / 'agentd').write_bytes(b'signed-notarized-cli')
            release.archive_tree(payload, assembled / release.names(target)[0])
            (assembled / release.names(target)[1]).write_bytes(b'unsigned-pkg')
            metadata['signingReceipts'] = {'cli': cli_info}
            S.write_metadata(assembled, target, metadata)
            S.save_state(assembled, target, root / 'packaged.tgz')
            signed_artifact(root / 'signed-pkg', 'pkg', release.names(target)[1], b'signed-stapled-pkg')
            args = argparse.Namespace(os='darwin', arch='arm64', version='v1.2.3', out=str(root / 'final'),
                state_input=str(root / 'packaged.tgz'), signed_input=str(root / 'signed-pkg'))
            with mock.patch.object(release, 'run') as run:
                S.finalize(args)
            commands = [call.args[0] for call in run.call_args_list]
            self.assertTrue(any(command[:3] == ['xcrun', 'stapler', 'validate'] for command in commands))
            self.assertTrue(any(command[:3] == ['spctl', '--assess', '--type'] for command in commands))
            info = S.load_metadata(Path(args.out), target, args.version)
            self.assertTrue(info['notarized'] and info['pkgStapled'])
            self.assertEqual(info['archiveBinarySHA256'], cli_info['files'][0]['sha256'])
            self.assertIn(release.names(target)[1], release.verify_manifest(args.out))
            other_payload = root / 'other-payload'
            other_payload.mkdir()
            (other_payload / 'agentd').write_bytes(b'different-cli')
            release.archive_tree(other_payload, assembled / release.names(target)[0])
            S.save_state(assembled, target, root / 'bad-archive-state.tgz')
            args.out, args.state_input = str(root / 'bad-final'), str(root / 'bad-archive-state.tgz')
            with mock.patch.object(release, 'run'), self.assertRaisesRegex(ValueError, 'TGZ differs'):
                S.finalize(args)
            self.assertFalse((Path(args.out) / 'SHA256SUMS').exists())


if __name__ == '__main__':
    unittest.main()
