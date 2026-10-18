"""Run isolated PowerShell hook tests where PowerShell 7 is available."""
from pathlib import Path
import shutil
import subprocess
import unittest


class WindowsSigningHookTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which('pwsh'), 'PowerShell 7 required; exercised on Windows CI')
    def test_signing_hook_fails_closed_and_preserves_client_dependencies(self):
        result = subprocess.run(['pwsh', '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
            str(Path(__file__).with_name('test-sign-windows.ps1'))], capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + '\n' + result.stderr)
        self.assertIn('All Windows signing hook contract tests passed', result.stdout)


if __name__ == '__main__':
    unittest.main()
