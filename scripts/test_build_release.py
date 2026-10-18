"""Portable release-contract tests; real installers are exercised in native CI."""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

SPEC=importlib.util.spec_from_file_location('release',Path(__file__).with_name('release.py'))
R=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(R)

class ReleaseContractTest(unittest.TestCase):
    def test_exact_twenty_six_products(self):
        actual=R.expected_assets()
        self.assertEqual(len(actual),26);self.assertEqual(len(set(actual)),26)
        self.assertEqual(sum(name.endswith('.deb') for name in actual),6)
        self.assertEqual(sum(name.endswith('.rpm') for name in actual),6)
        self.assertEqual(sum(name.endswith('.pkg') for name in actual),2)
        self.assertEqual(sum(name.endswith('.msi') for name in actual),2)
        self.assertEqual(sum(name.endswith('.tgz') for name in actual),2)
        self.assertIn('agentd-fips-linux-x86_64.rpm',actual)
        self.assertIn('agentd-linux-aarch64.rpm',actual)
        self.assertIn('agentd-linux-armhf',actual)
        self.assertEqual(R.names(R.target('linux','arm','7')),['agentd-linux-armhf','agentd-linux-armhf.deb','agentd-linux-armhf.rpm'])

    def test_versions_and_invalid_arguments(self):
        self.assertEqual(R.versions('v1.2.3')['msiVersion'],'1.2.3')
        self.assertEqual(R.versions('v2026.10.1')['msiVersion'],'26.10.1')
        self.assertEqual(R.versions('dev-deadbeef')['msiVersion'],'0.0.0')
        self.assertEqual(R.versions('v1.2.3-rc.1')['packageVersion'],'1.2.3-rc.1')
        for value in ['$(touch injected)','v1/escape','v300.1.1','v1.2.65536','v1.2']:
            with self.subTest(value=value),self.assertRaises(ValueError):R.versions(value)
        for args in [('windows','arm64'),('darwin','386'),('linux','mips'),('linux','arm','6')]:
            with self.assertRaises(ValueError):R.target(*args)
        with self.assertRaises(ValueError):R.target('linux','arm64',fips=True)

    def test_fips_requires_pinned_module_and_runtime_default(self):
        for line in ['DefaultGODEBUG=fips140=on','DefaultGODEBUG=foo=1,fips140=on,bar=2']:
            with mock.patch('subprocess.check_output',return_value='build GOFIPS140='+R.FIPS_VERSION+'\nbuild '+line+'\n'):
                R.check_fips('binary',{})
        with mock.patch('subprocess.check_output',return_value='build GOFIPS140=off\n'):
            with self.assertRaises(ValueError):R.check_fips('binary',{})

    def test_manifest_excludes_tools_and_detects_tampering(self):
        with tempfile.TemporaryDirectory() as temp:
            out=Path(temp);(out/'agentd-linux-amd64').write_bytes(b'binary')
            (out/'.tools').mkdir();(out/'.tools/tool').write_text('not a release asset')
            (out/'.staging').mkdir();(out/'.staging/token').write_text('must not publish')
            R.manifest(out);self.assertEqual(R.verify_manifest(out),{'agentd-linux-amd64'})
            (out/'agentd-linux-amd64').write_bytes(b'changed')
            with self.assertRaises(ValueError):R.verify_manifest(out)
            (out/'SHA256SUMS').write_text('0'*64+'  ../escape\n')
            with self.assertRaises(ValueError):R.verify_manifest(out)

    def fixture_targets(self, incoming):
        for t in R.all_targets():
            group=incoming/('target-'+t['key']);group.mkdir(parents=True)
            for name in R.names(t):(group/name).write_text('built '+name)
            metadata=group/'_metadata'/ (t['key']+'.json');metadata.parent.mkdir()
            metadata.write_text(json.dumps({**t,**R.versions('v1.2.3'),'commit':'abc','goVersion':R.GO_VERSION,'goFIPS140':R.FIPS_VERSION if t['fips'] else 'off'}))
            license=group/'_licenses'/t['key']/'go/LICENSE';license.parent.mkdir(parents=True);license.write_text('Go license')
            R.manifest(group)

    def test_collect_checks_complete_set_and_every_input_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);incoming=root/'incoming';self.fixture_targets(incoming)
            R.collect(incoming,root/'release')
            names=R.verify_manifest(root/'release')
            self.assertEqual(names,set(R.expected_assets())|{'agentd-licenses.tgz','BUILDINFO.json'})
            self.assertEqual(len((root/'release/SHA256SUMS').read_text().splitlines()),28)
            (incoming/'target-windows-386/agentd-windows-386.msi').write_text('tampered')
            with self.assertRaises(ValueError):R.collect(incoming,root/'bad')

    def test_collect_rejects_missing_product_and_different_versions(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);incoming=root/'incoming';self.fixture_targets(incoming)
            group=incoming/'target-darwin-amd64';(group/'agentd-amd64.pkg').unlink();R.manifest(group)
            with self.assertRaisesRegex(ValueError,'missing'):R.collect(incoming,root/'missing')
            (group/'agentd-amd64.pkg').write_text('pkg')
            metadata=group/'_metadata/darwin-amd64.json';info=json.loads(metadata.read_text());info['version']='v9.0.0';metadata.write_text(json.dumps(info));R.manifest(group)
            with self.assertRaisesRegex(ValueError,'disagree'):R.collect(incoming,root/'different')

    def test_archive_is_deterministic(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);payload=root/'payload';payload.mkdir();(payload/'agentd').write_text('binary')
            R.archive_tree(payload,root/'one.tgz');R.archive_tree(payload,root/'two.tgz')
            self.assertEqual((root/'one.tgz').read_bytes(),(root/'two.tgz').read_bytes())
            with tarfile.open(root/'one.tgz') as archive:self.assertEqual(archive.getmember('agentd').mode,0o755)

    def test_nfpm_architectures_conflicts_and_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            out=Path(temp);payload=out/'payload';payload.mkdir();(payload/'agentd').write_text('binary');(payload/'README.md').write_text('docs')
            for arch in R.LINUX:
                t=R.target('linux',arch)
                config=R.goreleaser_config(t,R.versions('v1.2.3'),out,payload,packages=True)
                build,package=config['builds'][0],config['nfpms'][0]
                self.assertEqual(build['goos'],['linux']);self.assertEqual(build['goarch'],[t['goarch']])
                if t['goarm']:self.assertEqual(build['goarm'],[t['goarm']])
                self.assertEqual(package['conflicts'],['agentd-fips'])
                self.assertEqual(package['bindir'],'/usr/bin')
                self.assertEqual(package['contents'][0]['dst'],'/usr/share/doc/agentd/README.md')
                self.assertEqual(set(package['formats']),{'deb','rpm'})
                self.assertEqual([package['overrides'][fmt]['file_name_template']+'.'+fmt for fmt in ('deb','rpm')],R.names(t)[1:])
            config=R.goreleaser_config(R.target('linux','amd64',fips=True),R.versions('v1.2.3'),out,payload,packages=True)
            package=config['nfpms'][0];self.assertEqual(package['package_name'],'agentd-fips');self.assertEqual(package['conflicts'],['agentd'])

    def test_publish_rejects_extra_files_and_unsigned_release_before_invocation(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);incoming=root/'incoming';self.fixture_targets(incoming)
            R.collect(incoming,root/'release')
            with mock.patch.object(R,'run') as run:
                with self.assertRaisesRegex(ValueError,'signed installer'):R.publish(root/'release')
                run.assert_not_called()
            (root/'release/private-key.p8').write_text('do not publish')
            with mock.patch.object(R,'run') as run:
                with self.assertRaisesRegex(ValueError,'exactly 29'):R.publish(root/'release',dry_run=True)
                run.assert_not_called()

class BuildPayloadTest(unittest.TestCase):
    def test_client_only_build_and_platform_payload(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);payload_sources=['README.md','THIRD_PARTY_NOTICES.md','go.mod','go.sum','examples/agentd/config.yaml','docs/agentd-config.md','docs/build-and-release.md','connection/README.md','transport/xhttp/README.md','transport/xhttp/LICENSE','transport/xhttp/NOTICE']
            for name in payload_sources:
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(name)
            (root/'.goreleaser.json').write_bytes((R.ROOT/'.goreleaser.json').read_bytes())
            goroot=root/'toolchain';goroot.mkdir();(goroot/'LICENSE').write_text('Go license')
            def fake_run(command,**kwargs):
                if command[:2]==['goreleaser','build']:
                    config=json.loads(Path(command[command.index('--config')+1]).read_text())
                    self.assertEqual(config['builds'][0]['main'],'./cmd/agentd');self.assertEqual(kwargs['env']['CGO_ENABLED'],'0')
                    self.assertEqual(kwargs['env']['AGENTD_SOURCE_VERSION'],'v1.2.3')
                    Path(command[command.index('--output')+1]).write_text('fake client')
                return subprocess.CompletedProcess(command,0,stdout='abc')
            def output(command,**kwargs):
                if command[:2]==['go','list']:return json.dumps({'Module':{'Main':True,'Path':'client'}})
                return json.dumps({'GOROOT':str(goroot),'GOVERSION':R.GO_VERSION})
            for os_name,arch in [('linux','amd64'),('darwin','arm64'),('windows','386')]:
                args=argparse.Namespace(os=os_name,arch=arch,goarm='',fips=False,version='v1.2.3',out=str(root/'out'))
                with mock.patch.object(R,'ROOT',root),mock.patch.object(R,'goreleaser_command',return_value='goreleaser'),mock.patch.object(R,'run',side_effect=fake_run),mock.patch('subprocess.check_output',side_effect=output),mock.patch('subprocess.run',return_value=subprocess.CompletedProcess([],0,stdout='abc')):
                    t,v,out,payload=R.build(args)
                self.assertFalse((payload/'agents').exists());self.assertFalse((payload/'agents.exe').exists())
                self.assertFalse((payload/'agents.example.yaml').exists())
                self.assertTrue((payload/'licenses/go/LICENSE').is_file())
                self.assertTrue((out/R.names(t)[0]).exists())

if __name__=='__main__':unittest.main()
