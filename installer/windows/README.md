# Native Windows packages

Build from a Windows PowerShell 7 session with Python 3, the repository's Go
toolchain, and the .NET 8 SDK installed:

```powershell
./scripts/build-windows.ps1 -Architecture amd64 -Version v1.2.3 -OutDir artifacts
./scripts/build-windows.ps1 -Architecture 386 -Version v1.2.3 -OutDir artifacts
```

The script installs the pinned `wix` 5.0.2 .NET tool under
`artifacts/.tools/wix-5.0.2`. It produces the same Windows artifact names as the
cloudflared release matrix, with the project prefix replaced:

- `agentd-windows-amd64.exe` and `agentd-windows-amd64.msi`
- `agentd-windows-386.exe` and `agentd-windows-386.msi`

`scripts/release.py` builds the executable and explicit payload, maps the original
version to MSI's numeric version, and writes the final SHA256 manifest. The CLI
retains the original version string. MSI supports major/minor fields up to 255
and build fields up to 65535; its version must come from `release.py version`
(`msiVersion`), rather than being inferred in this script.

The MSI installs per machine. The 64-bit package defaults to
`%ProgramFiles%\agentd`; the 32-bit package defaults to
`%ProgramFiles(x86)%\agentd` on 64-bit Windows (or `%ProgramFiles%\agentd` on
32-bit Windows). Both include `agentd.exe`, README, documentation, licenses, and
example configuration. They do not enroll an agent, install a Windows service,
or create runtime credentials/configuration. Copy an example to a writable
location and configure it before enrollment.

Use an elevated session for installation:

```powershell
msiexec.exe /i agentd-windows-amd64.msi /qn /norestart /l*v install.log
& "$env:ProgramFiles\agentd\agentd.exe" version
msiexec.exe /x agentd-windows-amd64.msi /qn /norestart /l*v uninstall.log
```

The default `Core` feature does not alter PATH. To opt in to the optional machine
PATH component, pass `ADDLOCAL=Core,Path` at installation. Open a new terminal
afterward. Uninstall removes only the component's added PATH entry. The two
architectures have independent, stable upgrade identities and can coexist; if
both are added to PATH, Windows uses the first matching entry. Newer packages
upgrade the same architecture, older numeric versions are rejected, and
same-version rebuilds can replace an existing installation. Development versions
that map to the same MSI version therefore follow rebuild replacement semantics.

For an actual installer test on a **disposable, clean Windows machine**, run the
following from an elevated PowerShell session:

```powershell
./scripts/build-windows.ps1 -Architecture amd64 -Version v1.2.3 -OutDir artifacts -SmokeTest
```

The test installs into a unique directory, executes `agentd version`, compares
the installed EXE's SHA256 to the release EXE, checks documentation/license/example
files, and uninstalls in `finally`. It verifies that the executable was removed.
It uses `ADDLOCAL=Core` so PATH is unchanged. The installer can still replace any
registered agentd package of the same architecture, hence the clean-machine
requirement. Install/uninstall exit codes `0` and `3010` (success, reboot required)
are accepted; all other codes and subprocess failures fail the script. Logs are
kept under `artifacts/.staging/windows-ARCH/`. A failed build or smoke test must
not be published, even if an old artifact is already present in the output.

Packages are unsigned by default. To sign using an already provisioned Windows
certificate store and Windows SDK SignTool:

```powershell
./scripts/build-windows.ps1 -Architecture amd64 -Version v1.2.3 `
  -SignThumbprint '<40-hex-character-certificate-thumbprint>' `
  -SignTool 'C:\Path\To\signtool.exe' `
  -SignStoreLocation CurrentUser -TimestampUrl 'https://timestamp.digicert.com'
```

Signing uses SHA256, an RFC 3161 HTTPS timestamp, and `signtool verify /pa /all`.
The EXE is signed before inclusion in the MSI; the final MSI is then signed.
No certificate is imported or exported, and no remote credential/account setup
is performed. Timestamp or verification failures stop the build.

WiX references: [5.0.2 NuGet package](https://www.nuget.org/packages/wix/5.0.2),
[WiX 5.0.2 package compiler](https://github.com/wixtoolset/wix/blob/v5.0.2/src/wix/WixToolset.Core/Compiler_Package.cs),
and [component/feature/environment compiler](https://github.com/wixtoolset/wix/blob/v5.0.2/src/wix/WixToolset.Core/Compiler.cs).
WiX 5 retains the `http://wixtoolset.org/schemas/v4/wxs` XML namespace.
