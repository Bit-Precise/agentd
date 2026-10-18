#Requires -Version 7.0
<#
.SYNOPSIS
Build agentd's Windows EXE and MSI with the pinned WiX .NET tool.
.EXAMPLE
./scripts/build-windows.ps1 -Architecture amd64 -Version v1.2.3 -OutDir artifacts -SmokeTest
.EXAMPLE
./scripts/build-windows.ps1 -Architecture 386 -Version v1.2.3 -SignThumbprint 0123456789012345678901234567890123456789
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [ValidateSet('386', 'amd64')] [string] $Architecture,
    [Parameter(Mandatory = $true)] [string] $Version,
    [string] $OutDir = 'artifacts',
    [string] $Python = 'python',
    [switch] $SmokeTest,
    [ValidatePattern('^$|^[A-Fa-f0-9]{40}$')] [string] $SignThumbprint = '',
    [ValidateSet('CurrentUser', 'LocalMachine')] [string] $SignStoreLocation = 'CurrentUser',
    [string] $SignTool = 'signtool.exe',
    [string] $TimestampUrl = 'https://timestamp.digicert.com'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

function Invoke-Native {
    param([string] $File, [string[]] $Arguments)
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$File failed with exit code $LASTEXITCODE."
    }
}

function Invoke-Msi {
    param([string[]] $Arguments)
    # Start-Process requires its own quoting when a path contains spaces.
    $quoted = $Arguments | ForEach-Object {
        if ($_ -match '"') { throw 'An MSI argument contains an unsupported double quote.' }
        '"' + $_ + '"'
    }
    $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList ($quoted -join ' ') -Wait -PassThru
    if ($process.ExitCode -notin @(0, 3010)) {
        throw "msiexec failed with exit code $($process.ExitCode). See the MSI log in the output staging directory."
    }
    if ($process.ExitCode -eq 3010) { Write-Host 'MSI succeeded; Windows reports a reboot is required (3010).' }
}

function Sign-Artifact {
    param([string] $Path)
    if (-not $SignThumbprint) { return }
    $signArguments = @('sign', '/sha1', $SignThumbprint, '/s', 'My', '/fd', 'SHA256', '/tr', $TimestampUrl, '/td', 'SHA256')
    if ($SignStoreLocation -eq 'LocalMachine') { $signArguments += '/sm' }
    Invoke-Native $SignTool ($signArguments + $Path)
    Invoke-Native $SignTool @('verify', '/pa', '/all', $Path)
}

try {
    if (-not $IsWindows) { throw 'Windows MSI packages must be built on Windows with PowerShell 7 or newer.' }
    if ($SmokeTest) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw '-SmokeTest requires an elevated PowerShell session for per-machine MSI installation.'
        }
    }
    if ($SignThumbprint) {
        $timestamp = [Uri] $TimestampUrl
        if (-not $timestamp.IsAbsoluteUri -or $timestamp.Scheme -ne 'https') { throw 'TimestampUrl must be an absolute HTTPS URL.' }
        $null = Get-Command $SignTool -ErrorAction Stop
    }
    $null = Get-Command $Python -ErrorAction Stop
    $null = Get-Command 'dotnet' -ErrorAction Stop
    $repo = Split-Path $PSScriptRoot -Parent
    $release = Join-Path $PSScriptRoot 'release.py'
    $output = [IO.Path]::GetFullPath($OutDir)
    $versionJson = Invoke-Native $Python @($release, 'version', '--version', $Version)
    $versionInfo = ($versionJson -join "`n") | ConvertFrom-Json
    $packageVersion = [string] $versionInfo.msiVersion
    if ($packageVersion -notmatch '^\d+\.\d+\.\d+$') { throw "Invalid MSI version: $packageVersion" }
    Invoke-Native $Python @($release, 'build', '--os', 'windows', '--arch', $Architecture, '--version', $Version, '--out', $output)
    $staging = Join-Path $output ".staging/windows-$Architecture"
    $payload = Join-Path $staging 'payload'
    $exe = Join-Path $output "agentd-windows-$Architecture.exe"
    $msi = Join-Path $output "agentd-windows-$Architecture.msi"
    $stagedMsi = Join-Path $staging "agentd-windows-$Architecture.msi"
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Missing release executable: $exe" }
    if (-not (Test-Path -LiteralPath (Join-Path $payload 'agentd.exe') -PathType Leaf)) { throw 'Missing staged agentd.exe.' }
    Sign-Artifact $exe
    Copy-Item -LiteralPath $exe -Destination (Join-Path $payload 'agentd.exe') -Force

    $toolPath = Join-Path $output '.tools/wix-5.0.2'
    $wix = Join-Path $toolPath 'wix.exe'
    if (-not (Test-Path -LiteralPath $wix -PathType Leaf)) {
        Invoke-Native 'dotnet' @('tool', 'install', 'wix', '--version', '5.0.2', '--tool-path', $toolPath)
    }
    $wixVersion = (Invoke-Native $wix @('--version')) -join "`n"
    if ($wixVersion.Trim() -notmatch '^5\.0\.2(?:[+.\s]|$)') { throw "Expected WiX 5.0.2, got: $wixVersion" }
    if ($Architecture -eq 'amd64') {
        $wixArch = 'x64'
        $programFilesFolder = 'ProgramFiles64Folder'
        $upgradeCode = '29773e61-3d95-4baa-9cd7-c3a815de4dfa'
        $pathComponentGuid = '6225b3fb-212c-485e-a0fe-4b374732f569'
    } else {
        $wixArch = 'x86'
        $programFilesFolder = 'ProgramFilesFolder'
        $upgradeCode = '67207472-250a-4699-8b8e-b96589fd6c70'
        $pathComponentGuid = '122f3d4c-31bc-4d10-9598-d5eb6b8905fe'
    }
    $fragment = Join-Path $staging 'payload.wxs'
    Invoke-Native $Python @((Join-Path $repo 'installer/windows/generate_payload.py'), '--payload', $payload, '--arch', $Architecture, '--out', $fragment)
    Invoke-Native $wix @(
        'build', (Join-Path $repo 'installer/windows/Product.wxs'), $fragment,
        '-arch', $wixArch, '-d', "Architecture=$Architecture", '-d', "PackageVersion=$packageVersion",
        '-d', "UpgradeCode=$upgradeCode", '-d', "PathComponentGuid=$pathComponentGuid",
        '-d', "ProgramFilesFolder=$programFilesFolder", '-bindpath', "Payload=$payload",
        '-intermediatefolder', (Join-Path $staging 'wix-obj'), '-o', $stagedMsi
    )
    Sign-Artifact $stagedMsi

    if ($SmokeTest) {
        # An isolated install path avoids touching an existing default install.
        # Major upgrades can still replace a registered product of this architecture,
        # so the documented smoke-test prerequisite is a disposable clean machine.
        $installDir = Join-Path $env:ProgramFiles ("agentd-msi-smoke-" + [Guid]::NewGuid().ToString('N'))
        if ($Architecture -eq '386' -and ${env:ProgramFiles(x86)}) {
            $installDir = Join-Path ${env:ProgramFiles(x86)} (Split-Path $installDir -Leaf)
        }
        $installed = $false
        try {
            Invoke-Msi @('/i', $stagedMsi, '/qn', '/norestart', "INSTALLFOLDER=$installDir", 'ADDLOCAL=Core', '/l*v', (Join-Path $staging 'install.log'))
            $installed = $true
            $installedExe = Join-Path $installDir 'agentd.exe'
            $actualVersion = (Invoke-Native $installedExe @('version')) -join "`n"
            if ($actualVersion.Trim() -cne [string] $versionInfo.version) {
                throw "Installed version '$actualVersion' differs from '$($versionInfo.version)'."
            }
            $expectedHash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
            if ((Get-FileHash -LiteralPath $installedExe -Algorithm SHA256).Hash -ne $expectedHash) {
                throw 'Installed executable differs from the release executable.'
            }
            foreach ($relative in @('README.md', 'config.example.yaml', 'THIRD_PARTY_NOTICES.md', 'licenses/go/LICENSE')) {
                if (-not (Test-Path -LiteralPath (Join-Path $installDir $relative) -PathType Leaf)) {
                    throw "Installed payload is missing $relative."
                }
            }
        } finally {
            if ($installed) {
                Invoke-Msi @('/x', $stagedMsi, '/qn', '/norestart', '/l*v', (Join-Path $staging 'uninstall.log'))
                if (Test-Path -LiteralPath (Join-Path $installDir 'agentd.exe')) { throw 'MSI uninstall left agentd.exe installed.' }
            }
        }
    }
    Copy-Item -LiteralPath $stagedMsi -Destination $msi -Force
    $metadataPath = Join-Path $output "_metadata/windows-$Architecture.json"
    $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
    $metadata.signed = [bool] $SignThumbprint
    $metadata | Add-Member -NotePropertyName binarySigned -NotePropertyValue ([bool] $SignThumbprint) -Force
    $metadata | Add-Member -NotePropertyName wixVersion -NotePropertyValue '5.0.2' -Force
    $metadata | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $metadataPath -Encoding utf8
    Invoke-Native $Python @($release, 'manifest', '--out', $output)
    Write-Host "Built $exe and $msi (MSI version $packageVersion)."
} catch {
    Write-Error $_ -ErrorAction Continue
    exit 1
}
