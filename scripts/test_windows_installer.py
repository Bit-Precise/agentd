"""Portable payload tests; native MSI installation is exercised by -SmokeTest."""

import importlib.util
from pathlib import Path
import tempfile
import unittest
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
            self.assertEqual(source, "!(bindpath.Payload)/" + path)

    def test_component_identity_survives_rebuild_and_addition_but_not_architecture_change(self):
        first = {c.attrib["Id"]: c.attrib["Guid"] for c in self.generate().findall(".//w:Component", NS)}
        (self.payload / "README.md").write_text("updated documentation")
        (self.payload / "new.md").write_text("new documentation")
        second = {c.attrib["Id"]: c.attrib["Guid"] for c in self.generate().findall(".//w:Component", NS)}
        self.assertEqual(first, {key: second[key] for key in first})
        other_arch = {c.attrib["Id"]: c.attrib["Guid"] for c in self.generate("386").findall(".//w:Component", NS)}
        self.assertEqual(set(second), set(other_arch))
        self.assertTrue(set(second.values()).isdisjoint(other_arch.values()))

    def test_fragment_deterministic(self):
        self.generate()
        first = self.fragment.read_bytes()
        self.generate()
        self.assertEqual(first, self.fragment.read_bytes())

    def test_missing_binary_and_unsupported_architecture_rejected(self):
        with self.assertRaisesRegex(ValueError, "architecture"):
            self.generate("arm64")
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


if __name__ == "__main__":
    unittest.main()
