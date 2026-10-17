#!/usr/bin/env python3
"""Generate disposable TLS material and portable configs for the historical PoC."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def prepare(output: Path) -> None:
    source = Path(__file__).resolve().parent / "configs"
    output.mkdir(parents=True, exist_ok=True)
    certs = output / "certs"
    certs.mkdir(mode=0o700, exist_ok=True)
    key = certs / "server.key"
    cert = certs / "server.crt"
    if key.exists() or cert.exists():
        raise SystemExit("refusing to replace existing TLS material; use a fresh output directory")
    old_mask = os.umask(0o077)
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key), "-out", str(cert), "-days", "7",
             "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    finally:
        os.umask(old_mask)
    der = subprocess.check_output(["openssl", "x509", "-in", str(cert), "-outform", "DER"])
    fingerprint = hashlib.sha256(der).hexdigest()

    def rewrite(value):
        if isinstance(value, list):
            return [rewrite(item) for item in value]
        if isinstance(value, dict):
            result = {name: rewrite(item) for name, item in value.items()}
            if "certificateFile" in result:
                result["certificateFile"] = str(cert.resolve())
            if "keyFile" in result:
                result["keyFile"] = str(key.resolve())
            if "pinnedPeerCertSha256" in result:
                result["pinnedPeerCertSha256"] = fingerprint
            return result
        return value

    for path in sorted(source.glob("*.json")):
        (output / path.name).write_text(json.dumps(rewrite(json.loads(path.read_text())), indent=2) + "\n")
    print(f"Generated {len(list(source.glob('*.json')))} configs in {output.resolve()}")
    print("TLS material is disposable and must not be committed or used in production.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent / ".generated")
    prepare(parser.parse_args().output)
