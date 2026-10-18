#!/usr/bin/env python3
"""Install a SHA256-pinned official nfpm release without changing go.mod."""
import argparse
import hashlib
import io
from pathlib import Path
import platform
import subprocess
import tarfile
import urllib.request

VERSION='2.48.0'
ASSETS={
 ('Linux','x86_64'):('Linux_x86_64','6d7f9a28b2f397934403950fcbba83f598b08d02edbe79a0815b3b4897341750'),
 ('Darwin','arm64'):('Darwin_arm64','ae23377895437b18d4727b362e7ec4c2d38295eb9adf96008e0cbc813038df81'),
 ('Darwin','x86_64'):('Darwin_x86_64','be3bdff94bae08638da0f7a3cc4b4ea3f381fa3f10560fcf81ec2e8fea625b49'),
}

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--destination',required=True);args=p.parse_args()
 key=(platform.system(),platform.machine())
 if key not in ASSETS:p.error('unsupported nfpm host; use official nfpm '+VERSION)
 name,expected=ASSETS[key]
 url=f'https://github.com/goreleaser/nfpm/releases/download/v{VERSION}/nfpm_{VERSION}_{name}.tar.gz'
 request=urllib.request.Request(url,headers={'User-Agent':'agentd-release-builder'})
 with urllib.request.urlopen(request,timeout=120) as response:data=response.read(64<<20)
 if hashlib.sha256(data).hexdigest()!=expected:raise SystemExit('nfpm archive SHA256 mismatch')
 dest=Path(args.destination).resolve();dest.mkdir(parents=True,exist_ok=True)
 with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
  member=archive.getmember('nfpm')
  if not member.isfile():raise SystemExit('nfpm executable not found')
  (dest/'nfpm').write_bytes(archive.extractfile(member).read())
 (dest/'nfpm').chmod(0o755)
 subprocess.run([str(dest/'nfpm'),'--version'],check=True)
 print(dest/'nfpm')

if __name__=='__main__':main()
