#!/usr/bin/env python3
"""Generate a WiX fragment from release.py's explicit staged payload."""

import argparse
import hashlib
from pathlib import Path
import uuid
import xml.etree.ElementTree as ET


WIX_NAMESPACE = "http://wixtoolset.org/schemas/v4/wxs"
# Project-specific namespace. Keep this stable across releases and upgrades.
COMPONENT_NAMESPACE = uuid.UUID("a0a2c761-823e-45a9-91bf-7f9cdd68e90e")
ET.register_namespace("", WIX_NAMESPACE)


def identifier(kind, relative):
    return kind + hashlib.sha256(relative.encode("utf-8")).hexdigest()[:32]


def element(parent, tag, **attributes):
    return ET.SubElement(parent, f"{{{WIX_NAMESPACE}}}{tag}", attributes)


def generate(payload, arch, output):
    if arch not in ("386", "amd64"):
        raise ValueError(f"unsupported Windows architecture: {arch}")
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
            Guid=str(uuid.uuid5(COMPONENT_NAMESPACE, arch + "/" + name)),
        )
        # Do not put arbitrary source paths through the WiX preprocessor.
        # BindPath is expanded by the binder after preprocessing has finished.
        element(component, "File", Id=identifier("F", name),
                Source="!(bindpath.Payload)/" + name, Name=path.name, KeyPath="yes")
        element(group, "ComponentRef", Id=component_id)
    ET.indent(root, space="  ")
    ET.ElementTree(root).write(output, encoding="utf-8", xml_declaration=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--arch", required=True, choices=("386", "amd64"))
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    generate(args.payload, args.arch, args.out)


if __name__ == "__main__":
    main()
