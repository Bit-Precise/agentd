"""Exercise CLI validation, archive layout and the workflow's actual Python steps."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import textwrap
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/build-release.sh"
WORKFLOW = ROOT / ".github/workflows/build.yml"


def embedded_python():
    chunks, current = [], None
    for line in WORKFLOW.read_text().splitlines():
        if line.strip() == "python3 - <<'PY'":
            current = []
        elif current is not None and line.strip() == "PY":
            chunks.append(textwrap.dedent("\n".join(current)))
            current = None
        elif current is not None:
            current.append(line)
    return chunks


class BuildReleaseTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        shutil.copyfile(SCRIPT, self.root / "scripts/build-release.sh")
        for name in ["README.md", "THIRD_PARTY_NOTICES.md", "go.mod", "go.sum", "examples/agentd/config.yaml", "transport/xhttp/LICENSE", "transport/xhttp/NOTICE"]:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name + "\n")
        module = self.root / "fixture-module"
        module.mkdir()
        (module / "LICENSE").write_text("MIT license\nCopyright fixture owner\n")
        (module / "secret.txt").write_text("must not be packaged")
        toolchain = self.root / "fixture-toolchain"
        toolchain.mkdir()
        (toolchain / "LICENSE").write_text("Go license\nCopyright The Go Authors\n")
        tools = self.root / "tools"
        tools.mkdir()
        fake_go = tools / "go"
        fake_go.write_text(textwrap.dedent("""\
            #!/usr/bin/env python3
            import json, os, pathlib, sys
            if os.environ.get('FAIL_GO'):
                raise SystemExit(7)
            if sys.argv[1] == 'env':
                print(json.dumps({'GOROOT':os.environ.get('FAKE_GOROOT', str(pathlib.Path.cwd() / 'fixture-toolchain')), 'GOVERSION':'go1.27.2'}))
                raise SystemExit(0)
            if sys.argv[1] == 'list':
                assert '-deps' in sys.argv and '-json=Module' in sys.argv
                print(json.dumps({'Module': {'Path':'github.com/bit-precise/agentd', 'Main':True}}))
                print(json.dumps({'Module': {'Path':'fixture.example/dependency', 'Version':'v1.0.0', 'Dir':str(pathlib.Path.cwd() / 'fixture-module')}}))
                raise SystemExit(0)
            assert sys.argv[1] == 'build'
            assert '-mod=readonly' in sys.argv and '-trimpath' in sys.argv
            assert os.environ['CGO_ENABLED'] == '0'
            assert os.environ['GOFIPS140'] == 'off'
            output = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])
            output.write_text(json.dumps({
                'os': os.environ['GOOS'], 'arch': os.environ['GOARCH'],
                'arm': os.environ['GOARM'],
                'ldflags': sys.argv[sys.argv.index('-ldflags') + 1],
            }))
            """))
        fake_go.chmod(0o755)
        self.env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"], SOURCE_DATE_EPOCH="1700000000")
        self.output = self.root / "output with spaces"

    def invoke(self, *args, **kwargs):
        return subprocess.run(["bash", str(self.root / "scripts/build-release.sh"), *args],
                              cwd=self.root, env=kwargs.get("env", self.env), text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def build(self, goos, arch, arm=""):
        args = ["--os", goos, "--arch", arch, "--version", "v0.1.0", "--out", str(self.output)]
        if arm:
            args.extend(["--goarm", arm])
        result = self.invoke(*args)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        artifact_arch = "armhf" if arm == "7" else arch
        suffix = ".zip" if goos == "windows" else ".tar.gz"
        return self.output / f"agentd-v0.1.0-{goos}-{artifact_arch}{suffix}"

    def test_all_nine_targets_and_checksum_lines(self):
        matrix = [("linux", "386", ""), ("linux", "amd64", ""),
                  ("linux", "arm", "5"), ("linux", "arm", "7"), ("linux", "arm64", ""),
                  ("darwin", "amd64", ""), ("darwin", "arm64", ""),
                  ("windows", "amd64", ""), ("windows", "386", "")]
        for goos, arch, arm in matrix:
            with self.subTest(goos=goos, arch=arch, arm=arm):
                archive = self.build(goos, arch, arm)
                base = archive.name.removesuffix(".tar.gz").removesuffix(".zip")
                binary = "agentd.exe" if goos == "windows" else "agentd"
                if goos == "windows":
                    with zipfile.ZipFile(archive) as package:
                        read = package.read
                        data = json.loads(read(f"{base}/{binary}"))
                        self.assertEqual(package.testzip(), None)
                        buildinfo = read(f"{base}/BUILDINFO").decode()
                        self.assertTrue(read(f"{base}/licenses/xhttp/LICENSE"))
                        self.assertIn(b"Copyright fixture owner", read(f"{base}/licenses/modules/fixture.example/dependency@v1.0.0/LICENSE"))
                        self.assertTrue(read(f"{base}/go.mod"))
                        self.assertIn(b"The Go Authors", read(f"{base}/licenses/go/LICENSE"))
                        self.assertFalse(any(name.endswith('/secret.txt') for name in package.namelist()))
                else:
                    with tarfile.open(archive) as package:
                        data = json.load(package.extractfile(f"{base}/{binary}"))
                        self.assertEqual(package.getmember(f"{base}/{binary}").mode, 0o755)
                        buildinfo = package.extractfile(f"{base}/BUILDINFO").read().decode()
                        self.assertTrue(package.extractfile(f"{base}/licenses/xhttp/LICENSE").read())
                        self.assertIn(b"Copyright fixture owner", package.extractfile(f"{base}/licenses/modules/fixture.example/dependency@v1.0.0/LICENSE").read())
                        self.assertTrue(package.extractfile(f"{base}/go.sum").read())
                        self.assertIn(b"The Go Authors", package.extractfile(f"{base}/licenses/go/LICENSE").read())
                        self.assertFalse(any(name.endswith('/secret.txt') for name in package.getnames()))
                self.assertEqual((data["os"], data["arch"], data["arm"]), (goos, arch, arm))
                self.assertIn("-X main.Version=v0.1.0", data["ldflags"])
                self.assertEqual(len(buildinfo.splitlines()), 5)
                self.assertIn("go_version=go1.27.2", buildinfo.splitlines())
                self.assertNotIn(r"\n", buildinfo)
        lines = (self.output / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(len(lines), 9)
        for line in lines:
            digest, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256((self.output / name).read_bytes()).hexdigest(), digest)

    def test_invalid_target_and_injectable_version_rejected(self):
        for args in [["--os", "windows", "--arch", "arm64"], ["--os", "linux", "--arch", "arm"],
                     ["--os", "darwin", "--arch", "386"], ["--os", "linux", "--arch", "amd64", "--goarm", "7"]]:
            result = self.invoke(*args, "--version", "v1", "--out", str(self.output))
            self.assertNotEqual(result.returncode, 0)
        result = self.invoke("--os", "linux", "--arch", "amd64", "--version", "$(touch injected)", "--out", str(self.output))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "injected").exists())
        self.assertFalse(self.output.exists())

    def test_build_error_is_not_packaged(self):
        env = dict(self.env, FAIL_GO="1")
        result = self.invoke("--os", "linux", "--arch", "amd64", "--version", "v1", "--out", str(self.output), env=env)
        self.assertEqual(result.returncode, 7)
        self.assertFalse(self.output.exists())

    def test_packaging_reproducible(self):
        for goos in ["linux", "windows"]:
            first = self.build(goos, "amd64").read_bytes()
            second = self.build(goos, "amd64").read_bytes()
            self.assertEqual(first, second)

    def test_homebrew_toolchain_license_layout(self):
        libexec = self.root / "fixture-toolchain/libexec"
        libexec.mkdir()
        self.env["FAKE_GOROOT"] = str(libexec)
        archive = self.build("darwin", "arm64")
        with tarfile.open(archive) as package:
            name = next(name for name in package.getnames() if name.endswith('/licenses/go/LICENSE'))
            self.assertIn(b"The Go Authors", package.extractfile(name).read())


class WorkflowPythonTest(unittest.TestCase):
    def test_nul_separated_formatting_paths(self):
        code = next(chunk for chunk in embedded_python() if "gofmt" in chunk)
        with mock.patch("subprocess.check_output", side_effect=[b"one.go\0two.go\0", ""]) as command:
            exec(compile(code, "workflow-format", "exec"), {})
        self.assertEqual(command.call_args_list[1].args[0], ["gofmt", "-l", "one.go", "two.go"])

    def test_aggregate_manifest_has_real_lines_and_checks_hashes(self):
        code = next(chunk for chunk in embedded_python() if "SHA256SUMS" in chunk)
        with tempfile.TemporaryDirectory() as temp:
            previous = os.getcwd()
            os.chdir(temp)
            try:
                for i in range(9):
                    group = Path("incoming") / f"target-{i}"
                    group.mkdir(parents=True)
                    name, payload = f"agentd-target-{i}.tar.gz", f"archive-{i}".encode()
                    (group / name).write_bytes(payload)
                    (group / "SHA256SUMS").write_text(hashlib.sha256(payload).hexdigest() + "  " + name + "\n")
                exec(compile(code, "workflow-aggregate", "exec"), {})
                lines = Path("release/SHA256SUMS").read_text().splitlines()
                self.assertEqual(len(lines), 9)
                for line in lines:
                    digest, name = line.split("  ", 1)
                    self.assertEqual(hashlib.sha256((Path("release") / name).read_bytes()).hexdigest(), digest)
                shutil.rmtree("release")
                Path("incoming/target-0/agentd-target-0.tar.gz").write_bytes(b"tampered")
                with self.assertRaises(SystemExit):
                    exec(compile(code, "workflow-aggregate", "exec"), {})
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
