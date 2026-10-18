#!/usr/bin/env python3
"""Generate a WiX fragment from release.py's explicit staged payload."""

import argparse
import hashlib
import json
from pathlib import Path
import uuid
import xml.etree.ElementTree as ET


WIX_NAMESPACE = "http://wixtoolset.org/schemas/v4/wxs"
# Architecture identities/namespaces must remain stable across upgrades.
ARCHITECTURES = json.loads(Path(__file__).with_name("architectures.json").read_text())
ET.register_namespace("", WIX_NAMESPACE)


def identifier(kind, relative):
    return kind + hashlib.sha256(relative.encode("utf-8")).hexdigest()[:32]


def element(parent, tag, **attributes):
    return ET.SubElement(parent, f"{{{WIX_NAMESPACE}}}{tag}", attributes)


def generate(payload, arch, output):
    if arch not in ARCHITECTURES:
        raise ValueError(f"unsupported Windows architecture: {arch}")
    namespace = uuid.UUID(ARCHITECTURES[arch]["componentNamespace"])
    payload = Path(payload)
    if payload.is_symlink() or not payload.is_dir():
        raise ValueError("payload must be a real directory")
    payload = payload.resolve()
    paths = sorted(payload.rglob("*"))
    if any(path.is_symlink() for path in paths):
        raise ValueError("Windows installer payload must not contain symlinks")
    files = [path for path in paths if path.is_file()]
    if not (payload / "agentd.exe").is_file():
        raise ValueError("Windows installer payload is missing agentd.exe")
    # Case-sensitive filesystems can stage paths that collide on Windows.
    folded = set()
    for path in paths:
        relative = path.relative_to(payload).as_posix()
        if relative.casefold() in folded:
            raise ValueError(f"Windows payload contains a case-insensitive collision: {relative}")
        folded.add(relative.casefold())
        if any(ch in path.name for ch in '<>:"\\|?*') or path.name.endswith((" ", ".")):
            raise ValueError(f"invalid Windows payload filename: {relative}")

    root = ET.Element(f"{{{WIX_NAMESPACE}}}Wix")
    fragment = element(root, "Fragment")
    base = element(fragment, "DirectoryRef", Id="INSTALLFOLDER")
    directories = {".": base}
    for path in sorted((path for path in paths if path.is_dir()), key=lambda path: (len(path.parts), path.as_posix())):
        relative = path.relative_to(payload)
        directories[relative.as_posix()] = element(
            directories[relative.parent.as_posix()], "Directory",
            Id=identifier("D", relative.as_posix()), Name=path.name,
        )
    group = element(fragment, "ComponentGroup", Id="AgentdPayload")
    for path in files:
        relative = path.relative_to(payload)
        name = relative.as_posix()
        component_id = identifier("C", name)
        component = element(
            directories[relative.parent.as_posix()], "Component",
            Id=component_id,
            Guid=str(uuid.uuid5(namespace, arch + "/" + name)),
        )
        # Do not put arbitrary source paths through the WiX preprocessor.
        # BindPath is expanded by the binder after preprocessing has finished.
        # WiX trims only a leading backslash; a forward slash becomes a rooted
        # Windows path and discards the named bind directory (WIX0103).
        element(component, "File", Id=identifier("F", name),
                Source="!(bindpath.Payload)\\" + name.replace("/", "\\"), Name=path.name, KeyPath="yes")
        element(group, "ComponentRef", Id=component_id)
    ET.indent(root, space="  ")
    ET.ElementTree(root).write(output, encoding="utf-8", xml_declaration=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--arch", required=True, choices=tuple(ARCHITECTURES))
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    generate(args.payload, args.arch, args.out)


if __name__ == "__main__":
    main()
