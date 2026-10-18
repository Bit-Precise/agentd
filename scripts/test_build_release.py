"""Portable release-contract tests; real installers are exercised in native CI."""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile
import zipfile
import hashlib
import unittest
from unittest import mock

SPEC=importlib.util.spec_from_file_location('release',Path(__file__).with_name('release.py'))
R=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(R)

class ReleaseContractTest(unittest.TestCase):
    def test_exact_twenty_one_products_match_github_cli_matrix(self):
        actual=R.expected_assets('v1.2.3')
        self.assertEqual(len(actual),21);self.assertEqual(len(set(actual)),21)
        self.assertEqual(sum(name.endswith('.deb') for name in actual),4)
        self.assertEqual(sum(name.endswith('.rpm') for name in actual),4)
        self.assertEqual(sum(name.endswith('.pkg') for name in actual),1)
        self.assertEqual(sum(name.endswith('.msi') for name in actual),3)
        self.assertEqual(sum(name.endswith('.zip') for name in actual),5)
        self.assertEqual(sum(name.endswith('.tar.gz') for name in actual),4)
        self.assertFalse(any('fips' in name for name in actual))
        self.assertIn('agentd_1.2.3_windows_arm64.msi',actual)
        self.assertIn('agentd_1.2.3_macOS_universal.pkg',actual)
        self.assertEqual(R.names(R.target('linux','arm','6'),'v1.2.3'),['agentd_1.2.3_linux_armv6.tar.gz','agentd_1.2.3_linux_armv6.deb','agentd_1.2.3_linux_armv6.rpm'])

    def test_versions_and_invalid_arguments(self):
        self.assertEqual(R.versions('v1.2.3')['msiVersion'],'1.2.3')
        self.assertEqual(R.versions('v2026.10.1')['msiVersion'],'26.10.1')
        self.assertEqual(R.versions('dev-deadbeef')['msiVersion'],'0.0.0')
        self.assertEqual(R.versions('v1.2.3-rc.1')['packageVersion'],'1.2.3-rc.1')
        for value in ['$(touch injected)','v1/escape','v300.1.1','v1.2.65536','v1.2']:
            with self.subTest(value=value),self.assertRaises(ValueError):R.versions(value)
        for args in [('darwin','386'),('linux','mips'),('linux','arm','7')]:
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
        v=R.versions('v1.2.3')
        for t in R.all_targets():
            group=incoming/('target-'+t['key']);group.mkdir(parents=True)
            for name in R.names(t,'v1.2.3'):(group/name).write_text('built '+name)
            metadata=group/'_metadata'/ (t['key']+'.json');metadata.parent.mkdir()
            info={**t,**v,'commit':'abc','goVersion':R.GO_VERSION,'goFIPS140':'off'}
            if t['arch']!='universal':
                binary=b'compiled '+t['key'].encode()
                info['archiveBinarySHA256']=hashlib.sha256(binary).hexdigest()
                archive=group/R.names(t,v)[0]
                prefix='' if t['os']=='windows' else R.product_stem(t,v)+'/'
                files={R.archive_binary(t,v):binary,prefix+'BUILDINFO.json':json.dumps(info).encode(),
                       prefix+'licenses/go/LICENSE':b'Go license',prefix+'README.md':b'docs'}
                if archive.suffix=='.zip':
                    with zipfile.ZipFile(archive,'w') as z:
                        for name,data in files.items():z.writestr(name,data)
                else:
                    with tarfile.open(archive,'w:gz') as tar:
                        for name,data in files.items():
                            entry=tarfile.TarInfo(name);entry.size=len(data);tar.addfile(entry,io.BytesIO(data))
                info['archiveSHA256']=R.sha256(archive)
            metadata.write_text(json.dumps(info))
            license=group/'_licenses'/t['key']/'go/LICENSE';license.parent.mkdir(parents=True);license.write_text('Go license')
            R.manifest(group)
        group=incoming/'target-darwin-universal';path=group/'_metadata/darwin-universal.json'
        info=json.loads(path.read_text());info['components']=[]
        for arch in ('amd64','arm64'):
            item=json.loads((incoming/f'target-darwin-{arch}/_metadata/darwin-{arch}.json').read_text())
            info['components'].append({'target':item['key'],'archive':R.names(item,v)[0],
                                       'archiveSHA256':item['archiveSHA256'],'binarySHA256':item['archiveBinarySHA256']})
        path.write_text(json.dumps(info));R.manifest(group)

    def test_collect_checks_complete_set_and_every_input_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);incoming=root/'incoming';self.fixture_targets(incoming)
            R.collect(incoming,root/'release')
            names=R.verify_manifest(root/'release')
            self.assertEqual(names,set(R.expected_assets('v1.2.3'))|{'_metadata/BUILDINFO.json'})
            self.assertEqual(len((root/'release/SHA256SUMS').read_text().splitlines()),22)
            (incoming/'target-windows-386/agentd_1.2.3_windows_386.msi').write_text('tampered')
            with self.assertRaises(ValueError):R.collect(incoming,root/'bad')

    def test_collect_rejects_missing_product_and_different_versions(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);incoming=root/'incoming';self.fixture_targets(incoming)
            group=incoming/'target-darwin-amd64';(group/'agentd_1.2.3_macOS_amd64.zip').unlink();R.manifest(group)
            with self.assertRaisesRegex(ValueError,'missing'):R.collect(incoming,root/'missing')
            (group/'agentd_1.2.3_macOS_amd64.zip').write_text('zip')
            metadata=group/'_metadata/darwin-amd64.json';info=json.loads(metadata.read_text());info['version']='v9.0.0';metadata.write_text(json.dumps(info));R.manifest(group)
            with self.assertRaisesRegex(ValueError,'disagree'):R.collect(incoming,root/'different')

    def test_collect_normalizes_only_crlf_in_merged_license_copy(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);incoming=root/'incoming';self.fixture_targets(incoming)
            originals={}
            for t in R.all_targets():
                group=incoming/('target-'+t['key'])
                path=group/'_licenses'/t['key']/'go/LICENSE'
                path.write_bytes(b'Copyright\r\nPermission.\r\n' if t['os']=='windows' else b'Copyright\nPermission.\n')
                originals[path]=path.read_bytes();R.manifest(group)
            R.collect(incoming,root/'release')
            metadata=json.loads((root/'release/_metadata/BUILDINFO.json').read_text())
            self.assertEqual(metadata['licenses']['go/LICENSE'],hashlib.sha256(b'Copyright\nPermission.\n').hexdigest())
            self.assertFalse((root/'release/agentd-licenses.tgz').exists())
            for path,data in originals.items():self.assertEqual(path.read_bytes(),data)
            self.assertEqual(len(R.verify_manifest(root/'release')),22)

    def test_collect_rejects_real_license_difference(self):
        for changed in (b'Different license\n',b'Copyright \nPermission.\n',b'Copyright\rPermission.\n',b'\xef\xbb\xbfCopyright\nPermission.\n'):
            with self.subTest(changed=changed),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);incoming=root/'incoming';self.fixture_targets(incoming)
                for t in R.all_targets():
                    group=incoming/('target-'+t['key'])
                    path=group/'_licenses'/t['key']/'go/LICENSE'
                    path.write_bytes(changed if t['key']=='windows-amd64' else b'Copyright\nPermission.\n')
                    R.manifest(group)
                with self.assertRaisesRegex(ValueError,'different license contents at same path: go/LICENSE'):
                    R.collect(incoming,root/'release')

    def test_collect_checks_original_license_digest_before_normalizing(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);incoming=root/'incoming';self.fixture_targets(incoming)
            group=incoming/'target-windows-amd64';path=group/'_licenses/windows-amd64/go/LICENSE'
            path.write_bytes(b'Copyright\n');R.manifest(group)
            path.write_bytes(b'Copyright\r\n')
            with self.assertRaisesRegex(ValueError,'invalid checksum for _licenses/windows-amd64/go/LICENSE'):
                R.collect(incoming,root/'release')

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
                self.assertEqual(package['bindir'],'/usr')
                self.assertEqual(package['contents'][0]['dst'],'/usr/share/doc/agentd/README.md')
                self.assertEqual(set(package['formats']),{'deb','rpm'})
                self.assertEqual([package['overrides'][fmt]['file_name_template']+'.'+fmt for fmt in ('deb','rpm')],R.names(t,'v1.2.3')[1:])
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
                with self.assertRaisesRegex(ValueError,'outside the verified release set'):R.publish(root/'release',dry_run=True)
                run.assert_not_called()

    def test_public_checksum_imports_only_products_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);incoming=root/'incoming';self.fixture_targets(incoming)
            out=root/'release';R.collect(incoming,out)
            expected=R.expected_assets('v1.2.3')
            def fake_release(command,**kwargs):
                config=json.loads(Path(command[command.index('--config')+1]).read_text())
                for kind in ('checksum','release'):
                    self.assertEqual([Path(item['glob']).name for item in config[kind]['extra_files']],expected)
                generated=Path(config['dist']);generated.mkdir(parents=True,exist_ok=True)
                (generated/R.checksum_name('v1.2.3')).write_text(''.join(f'{R.sha256(out/name)}  {name}\n' for name in expected))
            with mock.patch.object(R,'goreleaser_command',return_value='goreleaser'),mock.patch.object(R,'run',side_effect=fake_release):
                R.publish(out,dry_run=True)
                first=(out/R.checksum_name('v1.2.3')).read_bytes()
                R.publish(out,dry_run=True)
                self.assertEqual(first,(out/R.checksum_name('v1.2.3')).read_bytes())
            self.assertEqual(len(first.splitlines()),21)
            self.assertEqual(len(list(out.glob('agentd_*'))),22)
            self.assertEqual(R.verify_manifest(out),set(expected)|{'_metadata/BUILDINFO.json',R.checksum_name('v1.2.3')})

    def test_universal_preparation_checks_inputs_and_preserves_archives(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);incoming=root/'incoming';self.fixture_targets(incoming)
            dirs=[incoming/f'target-darwin-{arch}' for arch in ('amd64','arm64')]
            originals={p:p.read_bytes() for directory in dirs for p in directory.glob('*.zip')}
            t,v,out,payload=R.prepare_mac_universal(*dirs,root/'universal')
            self.assertEqual(t['key'],'darwin-universal');self.assertEqual(v['version'],'v1.2.3')
            self.assertEqual((payload.parent/'inputs/amd64/agentd').read_bytes(),b'compiled darwin-amd64')
            self.assertEqual((payload/'licenses/go/LICENSE').read_bytes(),b'Go license')
            self.assertEqual(len(json.loads((payload/'BUILDINFO.json').read_text())['components']),2)
            for path,data in originals.items():self.assertEqual(path.read_bytes(),data)
            with self.assertRaisesRegex(ValueError,'signed installer'):
                R.prepare_mac_universal(*dirs,root/'requires-signed',require_signed=True)

    def test_archive_reader_rejects_traversal_duplicate_entries_and_links(self):
        t=R.target('windows','arm64');v=R.versions('v1.2.3')
        for kind in ('traversal','duplicate','symlink','wrong-layout'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temp:
                path=Path(temp)/'test.zip'
                with zipfile.ZipFile(path,'w') as archive:
                    if kind=='traversal':archive.writestr('../outside',b'x')
                    if kind=='symlink':
                        entry=zipfile.ZipInfo('link');entry.external_attr=(0o120777<<16);archive.writestr(entry,b'outside')
                    if kind=='duplicate':
                        archive.writestr('bin/agentd.exe',b'a');archive.writestr('agentd.exe',b'b')
                    if kind=='wrong-layout':archive.writestr('agentd.exe',b'a')
                    archive.writestr('BUILDINFO.json',b'{}')
                with self.assertRaises(ValueError):R.read_payload_archive(t,v,path)

class BuildPayloadTest(unittest.TestCase):
    def test_build_environment_removes_apple_keys_but_preserves_hook_identity(self):
        source={'PATH':'tools','AGENTD_SIGN_ARTIFACTS':'true','AGENTD_MACOS_KEYCHAIN':'keychain',
                'APPLE_APPLICATION_IDENTITY':'Developer ID Application: Example (TEAM123456)',
                'APPLE_TEAM_ID':'TEAM123456','APPLE_NOTARY_KEY_ID':'public-key-id',
                'APPLE_NOTARY_ISSUER_ID':'public-issuer','APPLE_APPLICATION_P12_BASE64':'private',
                'APPLE_APPLICATION_P12_PASSWORD':'password','APPLE_INSTALLER_P12_BASE64':'private',
                'APPLE_INSTALLER_P12_PASSWORD':'password','APPLE_NOTARY_KEY_P8_BASE64':'private'}
        child=R.build_environment(source)
        self.assertEqual(child['AGENTD_SIGN_ARTIFACTS'],'true')
        self.assertEqual(child['AGENTD_MACOS_KEYCHAIN'],'keychain')
        self.assertEqual(child['APPLE_APPLICATION_IDENTITY'],source['APPLE_APPLICATION_IDENTITY'])
        self.assertEqual(child['APPLE_TEAM_ID'],source['APPLE_TEAM_ID'])
        self.assertEqual(child['APPLE_NOTARY_KEY_ID'],'public-key-id')
        self.assertEqual(child['APPLE_NOTARY_ISSUER_ID'],'public-issuer')
        self.assertFalse(any('P12' in name or name.endswith('_PASSWORD') or name.endswith('_BASE64') for name in child))
        self.assertIn('APPLE_NOTARY_KEY_P8_BASE64',source)
        self.assertEqual(R.build_environment({})['AGENTD_SIGN_ARTIFACTS'],'false')
        with self.assertRaisesRegex(ValueError,'must be true or false'):
            R.build_environment({'AGENTD_SIGN_ARTIFACTS':'yes'})

    def test_client_only_build_and_platform_payload(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);payload_sources=['README.md','THIRD_PARTY_NOTICES.md','go.mod','go.sum','examples/agentd/config.yaml','docs/agentd-config.md','docs/build-and-release.md','connection/README.md','transport/xhttp/README.md','transport/xhttp/LICENSE','transport/xhttp/NOTICE']
            for name in payload_sources:
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(name)
            (root/'.goreleaser.json').write_bytes((R.ROOT/'.goreleaser.json').read_bytes())
            goroot=root/'toolchain';goroot.mkdir();(goroot/'LICENSE').write_text('Go license')
            def fake_run(command,**kwargs):
                if command[:2]==['goreleaser','release']:
                    config=json.loads(Path(command[command.index('--config')+1]).read_text())
                    self.assertEqual(config['builds'][0]['main'],'./cmd/agentd');self.assertEqual(kwargs['env']['CGO_ENABLED'],'0')
                    self.assertEqual(kwargs['env']['AGENTD_SOURCE_VERSION'],'v1.2.3')
                    self.assertEqual(kwargs['env']['AGENTD_SIGN_ARTIFACTS'],'false')
                    self.assertNotIn('APPLE_APPLICATION_P12_PASSWORD',kwargs['env'])
                    self.assertIn('--snapshot',command);self.assertIn('--skip=publish',command)
                    generated=Path(config['dist']);generated.mkdir()
                    windows=config['builds'][0]['goos']==['windows']
                    binary=generated/('agentd.exe' if windows else 'agentd');binary.write_text('fake client')
                    archive=config['archives'][0]
                    prefix=archive['name_template']+'/' if archive.get('wrap_in_directory') else ''
                    extension='.tar.gz' if archive['formats']==['tar.gz'] else '.zip'
                    filename=archive['name_template']+extension;artifact=generated/filename
                    files={prefix+'bin/'+binary.name:binary.read_bytes()}
                    for extra in archive['files']:
                        name=PurePosixPath(extra['dst'])/Path(extra['src']).name
                        files[prefix+name.as_posix()]=Path(extra['src']).read_bytes()
                    if extension=='.tar.gz':
                        with tarfile.open(artifact,'w:gz') as tar:
                            for name,data in files.items():
                                entry=tarfile.TarInfo(name);entry.size=len(data);tar.addfile(entry,io.BytesIO(data))
                    else:
                        with zipfile.ZipFile(artifact,'w') as z:
                            for name,data in files.items():z.writestr(name,data)
                    (generated/'artifacts.json').write_text(json.dumps([
                        {'name':binary.name,'path':str(binary),'type':'Binary','extra':{'ID':config['builds'][0]['id'],'Builder':'go'}},
                        {'name':filename,'path':str(artifact),'type':'Binary' if archive['formats']==['binary'] else 'Archive','extra':{'ID':archive['id']}}
                    ]))
                else:self.fail('compilation must use a single GoReleaser release pipeline')
                return subprocess.CompletedProcess(command,0,stdout='abc')
            def output(command,**kwargs):
                if command[:2]==['go','list']:return json.dumps({'Module':{'Main':True,'Path':'client'}})
                return json.dumps({'GOROOT':str(goroot),'GOVERSION':R.GO_VERSION})
            for os_name,arch in [('linux','amd64'),('darwin','arm64'),('windows','386')]:
                args=argparse.Namespace(os=os_name,arch=arch,goarm='',fips=False,version='v1.2.3',out=str(root/'out'))
                with mock.patch.object(R,'ROOT',root),mock.patch.object(R,'goreleaser_command',return_value='goreleaser'),mock.patch.object(R,'run',side_effect=fake_run),mock.patch('subprocess.check_output',side_effect=output),mock.patch('subprocess.run',return_value=subprocess.CompletedProcess([],0,stdout='abc')),mock.patch.object(R,'archive_tree') as manual_archive:
                    t,v,out,payload=R.build(args,build_env={'APPLE_APPLICATION_P12_PASSWORD':'must-not-be-inherited'})
                    manual_archive.assert_not_called()
                self.assertFalse((payload/'agents').exists());self.assertFalse((payload/'agents.exe').exists())
                self.assertFalse((payload/'agents.example.yaml').exists())
                self.assertTrue((payload/'licenses/go/LICENSE').is_file())
                self.assertTrue((out/R.names(t,'v1.2.3')[0]).exists())
                files=R.read_payload_archive(t,v,out/R.names(t,v)[0])
                self.assertEqual(files[R.payload_binary(t)],(payload/R.payload_binary(t)).read_bytes())
                self.assertEqual(files['BUILDINFO.json'],(payload/'BUILDINFO.json').read_bytes())
                self.assertIn('licenses/go/LICENSE',files)

    def test_pkg_consumes_same_signed_cli_without_rebuilding_or_rearchiving(self):
        with tempfile.TemporaryDirectory() as temp:
            out=Path(temp);payload=out/'.staging/darwin-universal/payload';payload.mkdir(parents=True)
            (payload/'agentd').write_bytes(b'signed-cli')
            (payload/'BUILDINFO.json').write_text(json.dumps({'binarySigned':True,'signed':False,'binarySHA256':R.sha256(payload/'agentd')}))
            (out/'_metadata').mkdir();(out/'_metadata/darwin-universal.json').write_text('{}')
            t=R.target('darwin','universal')
            original={p:p.read_bytes() for p in [payload/'agentd',payload/'BUILDINFO.json']}
            commands=[]
            def native(command,**kwargs):
                commands.append([str(a) for a in command])
                self.assertNotIn('APPLE_INSTALLER_P12_PASSWORD',kwargs['env'])
                if command[0] in ('pkgbuild','productsign'):Path(command[-1]).write_bytes(b'installer')
                if command[:2]==['pkgutil','--expand-full']:
                    expanded=Path(command[-1]);expanded.mkdir();(expanded/'PackageInfo').write_text('component')
            with mock.patch.object(R.sys,'platform','darwin'),mock.patch.object(R,'run',side_effect=native),mock.patch.object(R,'archive_tree') as archive,mock.patch.object(R,'compile_target') as rebuild:
                R.package_mac_universal(t,R.versions('v1.2.3'),out,payload,sign_identity='Developer ID Installer: Example',
                                        build_env={'AGENTD_SIGN_ARTIFACTS':'true','APPLE_INSTALLER_P12_PASSWORD':'private'})
                archive.assert_not_called();rebuild.assert_not_called()
            for path,data in original.items():self.assertEqual(path.read_bytes(),data)
            self.assertTrue(any(command[:3]==['codesign','--verify','--strict'] for command in commands))
            self.assertFalse(any(command[0]=='codesign' and '--sign' in command for command in commands))
            info=json.loads((out/'_metadata/darwin-universal.json').read_text())
            self.assertTrue(info['signed'] and info['binarySigned'])
            (payload/'agentd').write_bytes(b'different-cli')
            with mock.patch.object(R.sys,'platform','darwin'),mock.patch.object(R,'run'),self.assertRaisesRegex(ValueError,'differs from its payload metadata'):
                R.package_mac_universal(t,R.versions('v1.2.3'),out,payload)

if __name__=='__main__':unittest.main()
