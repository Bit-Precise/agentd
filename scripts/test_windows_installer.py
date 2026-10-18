"""Portable payload tests; native MSI installation is exercised by -SmokeTest."""

import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import uuid
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("windows_payload", ROOT / "installer/windows/generate_payload.py")
PAYLOAD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PAYLOAD)
NS = {"w": PAYLOAD.WIX_NAMESPACE}


class WindowsPayloadTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.payload = self.root / "payload with spaces"
        self.payload.mkdir()
        for relative in ("agentd.exe", "README.md", "docs/config & options.md", "licenses/go/LICENSE", "licenses/module/LICENSE"):
            path = self.payload / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(relative)
        self.fragment = self.root / "payload.wxs"

    def generate(self, arch="amd64"):
        PAYLOAD.generate(self.payload, arch, self.fragment)
        return ET.parse(self.fragment)

    def test_all_payload_files_have_unique_components_and_correct_hierarchy(self):
        root = self.generate()
        files = root.findall(".//w:File", NS)
        self.assertEqual(len(files), 5)
        components = root.findall(".//w:Component", NS)
        self.assertEqual(len({c.attrib["Id"] for c in components}), 5)
        self.assertEqual(len({c.attrib["Guid"] for c in components}), 5)
        self.assertEqual({c.attrib["Id"] for c in components},
                         {c.attrib["Id"] for c in root.findall(".//w:ComponentRef", NS)})
        for component in components:
            self.assertEqual(len(component), 1)
            self.assertEqual(component[0].attrib["KeyPath"], "yes")
        actual = {}

        def visit(directory, relative=Path()):
            for child in directory:
                if child.tag.endswith("}Directory"):
                    visit(child, relative / child.attrib["Name"])
                elif child.tag.endswith("}Component"):
                    f = child[0]
                    actual[(relative / f.attrib["Name"]).as_posix()] = f.attrib["Source"]

        visit(root.find(".//w:DirectoryRef", NS))
        expected = {p.relative_to(self.payload).as_posix() for p in self.payload.rglob("*") if p.is_file()}
        self.assertEqual(set(actual), expected)
        for path, source in actual.items():
            self.assertEqual(source, "!(bindpath.Payload)\\" + path.replace("/", "\\"))

    def test_component_identity_survives_rebuild_and_addition_but_not_architecture_change(self):
        first = {c.attrib["Id"]: c.attrib["Guid"] for c in self.generate().findall(".//w:Component", NS)}
        (self.payload / "README.md").write_text("updated documentation")
        (self.payload / "new.md").write_text("new documentation")
        second = {c.attrib["Id"]: c.attrib["Guid"] for c in self.generate().findall(".//w:Component", NS)}
        self.assertEqual(first, {key: second[key] for key in first})
        other_arch = {c.attrib["Id"]: c.attrib["Guid"] for c in self.generate("386").findall(".//w:Component", NS)}
        self.assertEqual(set(second), set(other_arch))
        self.assertTrue(set(second.values()).isdisjoint(other_arch.values()))
        arm64 = {c.attrib["Id"]: c.attrib["Guid"] for c in self.generate("arm64").findall(".//w:Component", NS)}
        self.assertEqual(set(second), set(arm64))
        self.assertTrue(set(second.values()).isdisjoint(arm64.values()))
        self.assertTrue(set(other_arch.values()).isdisjoint(arm64.values()))

    def test_architecture_identity_and_default_paths_are_independent(self):
        architectures = PAYLOAD.ARCHITECTURES
        self.assertEqual(set(architectures), {"386", "amd64", "arm64"})
        self.assertEqual([architectures[a]["wixArch"] for a in ("386", "amd64", "arm64")], ["x86", "x64", "arm64"])
        for field in ("upgradeCode", "pathComponentGuid"):
            identities = [uuid.UUID(arch[field]) for arch in architectures.values()]
            self.assertEqual(len(set(identities)), 3)
        self.assertEqual(architectures["arm64"]["programFilesFolder"], "ProgramFiles64Folder")
        self.assertNotEqual(architectures["arm64"]["installDirectory"], architectures["amd64"]["installDirectory"])
        # Preserve component identities of existing x86/x64 installations.
        legacy_namespace = uuid.UUID("a0a2c761-823e-45a9-91bf-7f9cdd68e90e")
        for arch in ("386", "amd64"):
            components = self.generate(arch).findall(".//w:Component", NS)
            expected = {str(uuid.uuid5(legacy_namespace, arch + "/" + path.relative_to(self.payload).as_posix()))
                        for path in self.payload.rglob("*") if path.is_file()}
            self.assertEqual({item.attrib["Guid"] for item in components}, expected)

    def test_fragment_deterministic(self):
        self.generate()
        first = self.fragment.read_bytes()
        self.generate()
        self.assertEqual(first, self.fragment.read_bytes())

    def test_missing_binary_and_unsupported_architecture_rejected(self):
        with self.assertRaisesRegex(ValueError, "architecture"):
            self.generate("mips")
        (self.payload / "agentd.exe").unlink()
        with self.assertRaisesRegex(ValueError, "agentd.exe"):
            self.generate()

    def test_symlink_not_followed_or_packaged(self):
        secret = self.root / "private-credentials"
        secret.write_text("must not be packaged")
        try:
            (self.payload / "leak").symlink_to(secret)
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error}")
        with self.assertRaisesRegex(ValueError, "symlinks"):
            self.generate()
        self.assertFalse(self.fragment.exists())

    def test_case_collisions_rejected_on_case_sensitive_host(self):
        upper = self.payload / "README.md"
        lower = self.payload / "readme.md"
        lower.write_text("collision")
        if upper.samefile(lower):
            self.skipTest("host filesystem is case-insensitive")
        with self.assertRaisesRegex(ValueError, "collision"):
            self.generate()

    @unittest.skipUnless(shutil.which('pwsh'), 'PowerShell 7 required; exercised in Windows CI')
    def test_archive_only_verification_helpers_and_architecture_guards(self):
        result = subprocess.run(['pwsh', '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
            str(ROOT / 'scripts/test-windows-installer.ps1')], capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + '\n' + result.stderr)


if __name__ == "__main__":
    unittest.main()
