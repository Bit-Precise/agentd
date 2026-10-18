#!/usr/bin/env python3
"""Bridge agentd packaging to Bit-Precise/actions without transferring secrets/tools."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile

import release


def state_path_allowed(name, target):
    path = release.checked_relative(name)
    if not path.parts or any(part in ('', '.') for part in path.parts):
        return False
    key = target['key']
    return (name in release.names(target) or name == f'_metadata/{key}.json' or
            name.startswith(f'_licenses/{key}/') or name.startswith(f'.staging/{key}/payload/'))


def save_state(out, target, destination):
    out, destination = Path(out), Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(destination, 'w:gz') as archive:
        for path in sorted(out.rglob('*')):
            name = path.relative_to(out).as_posix()
            if not state_path_allowed(name, target):
                continue
            if path.is_symlink():
                raise ValueError('build state cannot contain symlinks')
            if not path.is_file():
                continue
            data = path.read_bytes()
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            entry.mode = 0o755 if path.name in ('agentd', 'agentd.exe') else 0o644
            archive.addfile(entry, io.BytesIO(data))


def restore_state(source, out, target):
    out = Path(out)
    if out.exists():
        raise ValueError('restore destination must not exist')
    out.mkdir(parents=True)
    total, seen = 0, set()
    with tarfile.open(source, 'r:gz') as archive:
        for entry in archive:
            if (not entry.isfile() or not state_path_allowed(entry.name, target) or
                    entry.name in seen or entry.size < 0 or entry.size > 512 * 1024 * 1024):
                raise ValueError('unexpected or unsafe build-state entry')
            total += entry.size
            seen.add(entry.name)
            if total > 1024 * 1024 * 1024 or len(seen) > 4096:
                raise ValueError('build-state archive exceeds limits')
            path = out.joinpath(*PurePosixPath(entry.name).parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            stream = archive.extractfile(entry)
            if stream is None:
                raise ValueError('missing build-state entry data')
            with stream, path.open('xb') as output:
                shutil.copyfileobj(stream, output)
            path.chmod(0o755 if path.name in ('agentd', 'agentd.exe') else 0o644)


def shared_product(directory, stage, expected_name):
    root = Path(directory)
    expected_files = {expected_name, 'SIGNINGINFO.json', 'SHA256SUMS'}
    if root.is_symlink() or not root.is_dir():
        raise ValueError('signed artifact must be a regular directory')
    entries = list(root.iterdir())
    if {p.name for p in entries} != expected_files or any(p.is_symlink() or not p.is_file() for p in entries):
        raise ValueError('signed artifact has unexpected files')
    if release.verify_manifest(root) != expected_files - {'SHA256SUMS'}:
        raise ValueError('signed artifact manifest is incomplete')
    info = json.loads((root / 'SIGNINGINFO.json').read_text())
    validate_signing_info(info, stage, expected_name, release.sha256(root / expected_name))
    return root / expected_name, info


def validate_signing_info(info, stage, expected_name, expected_digest):
    provider = 'Azure Artifact Signing' if stage in ('exe', 'msi') else 'Apple Developer ID'
    if not isinstance(info, dict) or info.get('stage') != stage or info.get('provider') != provider or info.get('signed') is not True:
        raise ValueError('signed artifact provider or stage does not match')
    records = info.get('files')
    if not isinstance(records, list) or len(records) != 1:
        raise ValueError('expected exactly one signed product')
    record = records[0]
    if not isinstance(record, dict) or record.get('name') != expected_name or record.get('sha256') != expected_digest:
        raise ValueError('signed product record does not match bytes')
    if stage in ('exe', 'msi'):
        if record.get('timestampVerified') is not True:
            raise ValueError('shared Windows output has no verified timestamp')
    else:
        receipt = record.get('notarization', {})
        if (not isinstance(receipt, dict) or info.get('notarized') is not True or receipt.get('status') != 'Accepted' or
                not isinstance(receipt.get('id'), str) or not receipt['id'] or
                not isinstance(receipt.get('submittedSHA256'), str) or
                not re.fullmatch(r'[0-9a-f]{64}', receipt.get('submittedSHA256', ''))):
            raise ValueError('shared Apple output has no Accepted notarization receipt')
        if record.get('stapled') is not (stage == 'pkg'):
            raise ValueError('shared Apple staple state does not match product type')


def write_metadata(out, target, metadata):
    path = out / '_metadata' / (target['key'] + '.json')
    path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n')


def load_metadata(out, target, version):
    metadata = json.loads((out / '_metadata' / (target['key'] + '.json')).read_text())
    if metadata.get('key') != target['key'] or metadata.get('version') != version:
        raise ValueError('build-state target/version mismatch')
    if os.environ.get('GITHUB_SHA') and metadata.get('commit') != os.environ['GITHUB_SHA']:
        raise ValueError('build-state source commit differs from this workflow run')
    return metadata


def export_file(source, directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    if any(directory.iterdir()):
        raise ValueError('signing input directory must be empty')
    release.copy_file(source, directory / source.name)


def prepare(args):
    if Path(args.out).exists():
        raise ValueError('prepare output directory must not exist')
    args.goarm, args.fips = '', False
    target, _, out, payload = release.build(args)
    binary = out / release.names(target)[0] if args.os == 'windows' else payload / 'agentd'
    export_file(binary, args.signing_output)
    save_state(out, target, args.state_output)


def assemble(args):
    target = release.target(args.os, args.arch)
    out = Path(args.out).resolve()
    restore_state(args.state_input, out, target)
    metadata = load_metadata(out, target, args.version)
    payload = out / '.staging' / target['key'] / 'payload'
    stage = 'exe' if args.os == 'windows' else 'cli'
    filename = release.names(target)[0] if args.os == 'windows' else 'agentd'
    signed, receipt = shared_product(args.signed_input, stage, filename)
    release.copy_file(signed, payload / ('agentd.exe' if args.os == 'windows' else 'agentd'))
    (payload / ('agentd.exe' if args.os == 'windows' else 'agentd')).chmod(0o755)
    metadata['signingReceipts'] = {stage: receipt}
    metadata['binarySigned'] = True
    write_metadata(out, target, metadata)
    if args.os == 'windows':
        release.copy_file(signed, out / filename)
        release.run(['pwsh', '-NoProfile', '-File', release.ROOT / 'scripts/build-windows.ps1',
                     '-Architecture', args.arch, '-Version', args.version, '-OutDir', out,
                     '-Stage', 'Package', '-RequireSigned'])
    else:
        release.run(['codesign', '--verify', '--strict', payload / 'agentd'])
        release.package_mac(target, release.versions(args.version), out, payload, binary_presigned=True)
    export_file(out / release.names(target)[1], args.signing_output)
    save_state(out, target, args.state_output)


def finalize(args):
    target = release.target(args.os, args.arch)
    out = Path(args.out).resolve()
    restore_state(args.state_input, out, target)
    metadata = load_metadata(out, target, args.version)
    stage = 'msi' if args.os == 'windows' else 'pkg'
    filename = release.names(target)[1]
    signed, receipt = shared_product(args.signed_input, stage, filename)
    release.copy_file(signed, out / filename)
    metadata.setdefault('signingReceipts', {})[stage] = receipt
    binary_stage = 'exe' if args.os == 'windows' else 'cli'
    binary_name = release.names(target)[0] if args.os == 'windows' else 'agentd'
    payload = out / '.staging' / target['key'] / 'payload'
    binary_path = out / binary_name if args.os == 'windows' else payload / 'agentd'
    validate_signing_info(metadata['signingReceipts'].get(binary_stage), binary_stage,
                          binary_name, release.sha256(binary_path))
    write_metadata(out, target, metadata)
    if args.os == 'windows':
        release.run(['pwsh', '-NoProfile', '-File', release.ROOT / 'scripts/build-windows.ps1',
                     '-Architecture', args.arch, '-Version', args.version, '-OutDir', out,
                     '-Stage', 'Finalize', '-RequireSigned', '-SmokeTest'])
    else:
        binary_hash = release.sha256(payload / 'agentd')
        release.run(['codesign', '--verify', '--strict', payload / 'agentd'])
        release.run(['pkgutil', '--check-signature', out / filename])
        release.run(['xcrun', 'stapler', 'validate', out / filename])
        release.run(['spctl', '--assess', '--type', 'install', '--verbose=2', out / filename])
        with tarfile.open(out / release.names(target)[0], 'r:gz') as archive:
            binary = archive.extractfile('agentd')
            if binary is None or hashlib.sha256(binary.read()).hexdigest() != binary_hash:
                raise ValueError('TGZ differs from the notarized CLI')
        metadata.update(signed=True, binarySigned=True, notarized=True, pkgStapled=True,
                        archiveBinarySHA256=binary_hash, archiveStapled=False,
                        signingProvider='Apple Developer ID')
        write_metadata(out, target, metadata)
        release.manifest(out)
    release.validate_release_signing([load_metadata(out, target, args.version)])
    release.verify_manifest(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('prepare', 'assemble', 'finalize'))
    parser.add_argument('--os', required=True, choices=('darwin', 'windows'))
    parser.add_argument('--arch', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--state-input')
    parser.add_argument('--state-output')
    parser.add_argument('--signed-input')
    parser.add_argument('--signing-output')
    args = parser.parse_args()
    try:
        release.target(args.os, args.arch)
        release.versions(args.version)
        required = {'prepare': ('state_output', 'signing_output'),
                    'assemble': ('state_input', 'state_output', 'signed_input', 'signing_output'),
                    'finalize': ('state_input', 'signed_input')}
        if any(not getattr(args, name) for name in required[args.phase]):
            raise ValueError('phase requires its state/signing artifact paths')
        globals()[args.phase](args)
    except (ValueError, OSError, KeyError, tarfile.TarError, subprocess.SubprocessError) as error:
        parser.exit(1, f'shared signing: {error}\n')


if __name__ == '__main__':
    main()
