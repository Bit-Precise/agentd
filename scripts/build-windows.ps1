#Requires -Version 7.0
<#
.SYNOPSIS
Build versioned Windows ZIP/MSI products or verify them on a native host.
.EXAMPLE
./scripts/build-windows.ps1 -Architecture amd64 -Version v1.2.3 -OutDir artifacts -SmokeTest
.EXAMPLE
./scripts/build-windows.ps1 -Architecture arm64 -Version v1.2.3 -OutDir downloaded -Stage Verify -RequireSigned
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [ValidateSet('386', 'amd64', 'arm64')] [string] $Architecture,
    [Parameter(Mandatory = $true)] [string] $Version,
    [string] $OutDir = 'artifacts',
    [string] $Python = 'python',
    [switch] $SmokeTest,
    # Package/Finalize preserve the GoReleaser ZIP and its signed EXE. Verify
    # installs final ZIP/MSI products without build staging, Go, .NET or WiX.
    [ValidateSet('All', 'Package', 'Finalize', 'Verify')] [string] $Stage = 'All',
    [switch] $RequireSigned,
    [ValidatePattern('^$|^[A-Fa-f0-9]{40}$')] [string] $SignThumbprint = '',
    [ValidateSet('CurrentUser', 'LocalMachine')] [string] $SignStoreLocation = 'CurrentUser',
    [string] $SignTool = 'signtool.exe',
    [string] $TimestampUrl = 'https://timestamp.digicert.com'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
# Failures can occur before output paths are initialized (including on a
# non-Windows host). Keep diagnostics safe under StrictMode in those cases.
$staging = $null
$verifyTemporary = $null

function Invoke-Native {
    param([string] $File, [string[]] $Arguments)
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$File failed with exit code $LASTEXITCODE."
    }
}

function Invoke-Msi {
    param([string[]] $Arguments)
    # msiexec parses its raw command line: switches must remain unquoted,
    # and a property quotes its value (INSTALLFOLDER="C:\Program Files\...").
    # Quoting every token can open installer UI instead of honoring /qn and /l*v.
    $quoted = $Arguments | ForEach-Object {
        if ($_ -match '"') { throw 'An MSI argument contains an unsupported double quote.' }
        if ($_ -match '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
            $Matches[1] + '="' + $Matches[2] + '"'
        } elseif ($_ -match '\s') {
            '"' + $_ + '"'
        } else {
            $_
        }
    }
    Write-Host "Starting MSI operation $($Arguments[0]); waiting for the client process only."
    # Start-Process -Wait also waits for descendants. Windows Installer can
    # retain a service process after the requesting msiexec client has finished.
    $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList ($quoted -join ' ') -PassThru
    if (-not $process.WaitForExit(300000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        throw 'msiexec client exceeded five minutes. Inspect its log in the output staging directory.'
    }
    $process.Refresh()
    Write-Host "MSI operation $($Arguments[0]) completed with exit code $($process.ExitCode)."
    if ($process.ExitCode -notin @(0, 3010)) {
        throw "msiexec failed with exit code $($process.ExitCode). See the MSI log in the output staging directory."
    }
    if ($process.ExitCode -eq 3010) { Write-Host 'MSI succeeded; Windows reports a reboot is required (3010).' }
}

function Assert-SignedArtifact {
    param([string] $Path)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or $null -eq $signature.TimeStamperCertificate) {
        throw "Artifact must have a valid Authenticode signature and RFC3161 timestamp: $Path"
    }
    Invoke-Native $SignTool @('verify', '/pa', '/all', '/tw', $Path)
}

function Find-VerificationTool {
    $sdkRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits/10/bin'
    $native = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    $toolArchitectures = if ($native -eq 'Arm64') { @('arm64', 'x64') } else { @('x64', 'x86') }
    foreach ($toolArchitecture in $toolArchitectures) {
        $tool = Get-ChildItem -Path (Join-Path $sdkRoot "*/$toolArchitecture/signtool.exe") -ErrorAction SilentlyContinue |
            Where-Object { $_.Directory.Parent.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
            Sort-Object { [version] $_.Directory.Parent.Name } -Descending | Select-Object -First 1
        if ($null -ne $tool) { return $tool.FullName }
    }
    throw 'Windows SDK SignTool is required for signature verification.'
}

function Assert-CompatibleArchitecture {
    param([string] $Target, [string] $HostArchitecture)
    if (($Target -eq 'arm64' -and $HostArchitecture -ne 'Arm64') -or
        ($Target -eq 'amd64' -and $HostArchitecture -ne 'X64') -or
        ($Target -eq '386' -and $HostArchitecture -notin @('X86', 'X64')) -or
        $Target -notin @('386', 'amd64', 'arm64')) {
        throw "Architecture $Target requires a compatible native Windows host for installation; current OS is $HostArchitecture."
    }
}

function Assert-SmokeHost {
    Assert-CompatibleArchitecture -Target $Architecture -HostArchitecture ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString())
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Installer verification requires an elevated PowerShell session on a disposable clean machine.'
    }
}

function Read-ArchiveBinary {
    param([string] $ArchivePath, [string] $Destination)
    Add-Type -AssemblyName System.IO.Compression.ZipFile
    $archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        $entries = @($archive.Entries | Where-Object { $_.FullName -ceq 'bin/agentd.exe' })
        if ($entries.Count -ne 1 -or $entries[0].Length -lt 1 -or $entries[0].Length -gt 512MB) {
            throw 'Release ZIP must contain exactly one nonempty bin/agentd.exe (at most 512 MiB).'
        }
        # Extract this one fixed file only, never arbitrary ZIP entry paths.
        $source = $entries[0].Open()
        try {
            $destinationStream = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew)
            try { $source.CopyTo($destinationStream) } finally { $destinationStream.Dispose() }
        } finally { $source.Dispose() }
    } finally { $archive.Dispose() }
    return (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-ArchivePayload {
    param([string] $ReleaseScript, [string] $OutputDirectory, [string] $Executable, [string] $ArchiveName)
    $result = Invoke-Native $Python @($ReleaseScript, 'verify-archive', '--os', 'windows', '--arch', $Architecture,
        '--version', $Version, '--out', $OutputDirectory)
    $info = ($result -join "`n") | ConvertFrom-Json
    if ($info.archive -cne $ArchiveName -or $info.binary -cne 'bin/agentd.exe' -or
        $info.sha256 -cne (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw 'GoReleaser ZIP payload does not match the MSI source executable.'
    }
    return [string] $info.sha256
}

function Invoke-InstallerSmoke {
    param([string] $Installer, [string] $ExpectedSHA256, [string] $ExpectedVersion, [string] $Logs)
    Assert-SmokeHost
    $programFiles = $env:ProgramFiles
    if ($Architecture -eq '386' -and ${env:ProgramFiles(x86)}) { $programFiles = ${env:ProgramFiles(x86)} }
    $installDir = Join-Path $programFiles ('agentd-msi-smoke-' + [Guid]::NewGuid().ToString('N'))
    $installed = $false
    try {
        Invoke-Msi @('/i', $Installer, '/qn', '/norestart', "INSTALLFOLDER=$installDir", 'ADDLOCAL=Core',
            '/l*v', (Join-Path $Logs 'install.log'))
        $installed = $true
        $installedExe = Join-Path $installDir 'agentd.exe'
        # Check exact ZIP/MSI byte identity before executing the installed CLI.
        if ((Get-FileHash -LiteralPath $installedExe -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedSHA256) {
            throw 'Installed executable differs from bin/agentd.exe in the release ZIP.'
        }
        $actualVersion = (Invoke-Native $installedExe @('version')) -join "`n"
        if ($actualVersion.Trim() -cne $ExpectedVersion) {
            throw "Installed version '$actualVersion' differs from '$ExpectedVersion'."
        }
        foreach ($relative in @('README.md', 'config.example.yaml', 'THIRD_PARTY_NOTICES.md', 'licenses/go/LICENSE')) {
            if (-not (Test-Path -LiteralPath (Join-Path $installDir $relative) -PathType Leaf)) {
                throw "Installed payload is missing $relative."
            }
        }
    } finally {
        if ($installed) {
            Invoke-Msi @('/x', $Installer, '/qn', '/norestart', '/l*v', (Join-Path $Logs 'uninstall.log'))
            if (Test-Path -LiteralPath (Join-Path $installDir 'agentd.exe')) { throw 'MSI uninstall left agentd.exe installed.' }
        }
    }
}

function Invoke-WindowsBuild {
    if (-not $IsWindows) { throw 'Windows MSI operations require Windows with PowerShell 7 or newer.' }
    if ($SignThumbprint) {
        throw '-SignThumbprint cannot modify an EXE after ZIP creation; sign in the GoReleaser binary hook and sign the MSI separately.'
    }
    if ($SmokeTest -or $Stage -eq 'Verify') { Assert-SmokeHost }
    if ($RequireSigned) {
        if ($SignTool -eq 'signtool.exe' -and -not (Get-Command $SignTool -ErrorAction SilentlyContinue)) {
            $script:SignTool = Find-VerificationTool
        }
        $null = Get-Command $SignTool -ErrorAction Stop
    }
    $null = Get-Command $Python -ErrorAction Stop
    $repo = Split-Path $PSScriptRoot -Parent
    $release = Join-Path $PSScriptRoot 'release.py'
    $output = [IO.Path]::GetFullPath($OutDir)
    $productJson = Invoke-Native $Python @($release, 'products', '--os', 'windows', '--arch', $Architecture, '--version', $Version)
    $products = ($productJson -join "`n") | ConvertFrom-Json
    $versionInfo = $products.version
    $packageVersion = [string] $versionInfo.msiVersion
    if ($packageVersion -notmatch '^\d+\.\d+\.\d+$' -or $products.target.arch -cne $Architecture -or
        $products.target.os -cne 'windows' -or $products.assets.Count -ne 2 -or $products.payloadBinary -cne 'agentd.exe') {
        throw 'Invalid target/version data from release.py products.'
    }
    $archiveName, $msiName = [string] $products.assets[0], [string] $products.assets[1]
    if ([IO.Path]::GetFileName($archiveName) -cne $archiveName -or [IO.Path]::GetExtension($archiveName) -cne '.zip' -or
        [IO.Path]::GetFileName($msiName) -cne $msiName -or [IO.Path]::GetExtension($msiName) -cne '.msi') {
        throw 'Expected versioned ZIP and MSI basenames from release.py products.'
    }
    if ($Stage -eq 'All') {
        Invoke-Native $Python @($release, 'build', '--os', 'windows', '--arch', $Architecture,
            '--version', $Version, '--out', $output, '--no-manifest')
    }
    $archivePath = Join-Path $output $archiveName
    $msi = Join-Path $output $msiName
    if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) { throw "Missing GoReleaser ZIP: $archivePath" }
    if ($Stage -eq 'Verify') {
        if (-not (Test-Path -LiteralPath $msi -PathType Leaf)) { throw "Missing release MSI: $msi" }
        $script:verifyTemporary = Join-Path ([IO.Path]::GetTempPath()) ('agentd-msi-verify-' + [Guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $script:verifyTemporary
        $script:staging = $script:verifyTemporary
        $exe = Join-Path $staging 'agentd.exe'
        $expectedHash = Read-ArchiveBinary -ArchivePath $archivePath -Destination $exe
        if ($RequireSigned) {
            Assert-SignedArtifact $exe
            Assert-SignedArtifact $msi
        }
        Invoke-InstallerSmoke -Installer $msi -ExpectedSHA256 $expectedHash -ExpectedVersion $versionInfo.version -Logs $staging
        Write-Host "Verified $archiveName and $msiName on native $Architecture Windows; input products were not modified."
        return
    }
    Remove-Item -LiteralPath (Join-Path $output 'SHA256SUMS') -Force -ErrorAction SilentlyContinue
    $script:staging = Join-Path $output ".staging/windows-$Architecture"
    $payload = Join-Path $staging 'payload'
    $exe = Join-Path $payload 'agentd.exe'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'Missing staged GoReleaser agentd.exe; use -Stage Verify for final products only.' }
    $expectedHash = Assert-ArchivePayload -ReleaseScript $release -OutputDirectory $output -Executable $exe -ArchiveName $archiveName
    if ($RequireSigned) { Assert-SignedArtifact $exe }
    if ($Stage -ne 'Finalize') {
        $null = Get-Command 'dotnet' -ErrorAction Stop
        $toolPath = Join-Path $output '.tools/wix-5.0.2'
        $wix = Join-Path $toolPath 'wix.exe'
        if (-not (Test-Path -LiteralPath $wix -PathType Leaf)) {
            Invoke-Native 'dotnet' @('tool', 'install', 'wix', '--version', '5.0.2', '--tool-path', $toolPath)
        }
        $wixVersion = (Invoke-Native $wix @('--version')) -join "`n"
        if ($wixVersion.Trim() -notmatch '^5\.0\.2(?:[+.\s]|$)') { throw "Expected WiX 5.0.2, got: $wixVersion" }
        $architectureTable = Get-Content -LiteralPath (Join-Path $repo 'installer/windows/architectures.json') -Raw | ConvertFrom-Json -AsHashtable
        $architectureInfo = $architectureTable[$Architecture]
        $fragment = Join-Path $staging 'payload.wxs'
        Invoke-Native $Python @((Join-Path $repo 'installer/windows/generate_payload.py'), '--payload', $payload, '--arch', $Architecture, '--out', $fragment)
        $stagedMsi = Join-Path $staging $msiName
        Invoke-Native $wix @(
            'build', (Join-Path $repo 'installer/windows/Product.wxs'), $fragment,
            '-arch', $architectureInfo.wixArch, '-d', "Architecture=$Architecture", '-d', "PackageVersion=$packageVersion",
            '-d', "UpgradeCode=$($architectureInfo.upgradeCode)", '-d', "PathComponentGuid=$($architectureInfo.pathComponentGuid)",
            '-d', "ProgramFilesFolder=$($architectureInfo.programFilesFolder)", '-d', "InstallDirectoryName=$($architectureInfo.installDirectory)",
            '-bindpath', "Payload=$payload", '-intermediatefolder', (Join-Path $staging 'wix-obj'), '-o', $stagedMsi
        )
        Copy-Item -LiteralPath $stagedMsi -Destination $msi -Force
    }
    if ($Stage -eq 'Package') {
        Write-Host 'MSI assembled from the unchanged GoReleaser ZIP binary; sign MSI then run -Stage Finalize.'
        return
    }
    if ($RequireSigned) { Assert-SignedArtifact $msi }
    if ($SmokeTest) {
        Invoke-InstallerSmoke -Installer $msi -ExpectedSHA256 $expectedHash -ExpectedVersion $versionInfo.version -Logs $staging
    }
    $metadataPath = Join-Path $output "_metadata/windows-$Architecture.json"
    $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
    $metadata.signed = [bool] $RequireSigned
    $metadata | Add-Member -NotePropertyName binarySigned -NotePropertyValue ([bool] $RequireSigned) -Force
    $metadata | Add-Member -NotePropertyName timestampVerified -NotePropertyValue ([bool] $RequireSigned) -Force
    $metadata | Add-Member -NotePropertyName archiveBinarySHA256 -NotePropertyValue $expectedHash -Force
    if ($RequireSigned) { $metadata | Add-Member -NotePropertyName signingProvider -NotePropertyValue 'Azure Artifact Signing' -Force }
    $metadata | Add-Member -NotePropertyName wixVersion -NotePropertyValue '5.0.2' -Force
    $metadata | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $metadataPath -Encoding utf8
    Invoke-Native $Python @($release, 'manifest', '--out', $output)
    Write-Host "Built $archivePath and $msi (MSI version $packageVersion)."
}

# Dot-sourcing exposes the archive/host helpers to isolated tests without builds.
if ($MyInvocation.InvocationName -ne '.') {
    try {
        Invoke-WindowsBuild
    } catch {
        $buildError = $_
        Write-Error $buildError -ErrorAction Continue
        if ($null -ne $staging) {
            # Inspect only this build's fixed MSI transaction logs.
            foreach ($logName in @('install.log', 'uninstall.log')) {
                $logPath = Join-Path $staging $logName
                if (Test-Path -LiteralPath $logPath -PathType Leaf -ErrorAction SilentlyContinue) {
                    Write-Host "MSI diagnostic: $logName (last 100 lines)"
                    try { Get-Content -LiteralPath $logPath -Tail 100 -ErrorAction Stop | ForEach-Object { Write-Host $_ } }
                    catch { Write-Warning "Could not read MSI diagnostic log $logName." }
                }
            }
        }
        exit 1
    } finally {
        if ($null -ne $verifyTemporary) { Remove-Item -LiteralPath $verifyTemporary -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
