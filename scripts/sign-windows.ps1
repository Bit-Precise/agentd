#Requires -Version 7.0
<#
.SYNOPSIS
Prepare Azure Artifact Signing, or sign one GoReleaser EXE / WiX MSI.
.DESCRIPTION
AGENTD_SIGN_ARTIFACTS must be exactly true or false. False is an explicit
unsigned build; true fails closed on missing configuration or failed checks.
The workflow authenticates with azure/login OIDC before -Prepare and build.
The hook never imports a certificate/private key or reads an Azure token.
.EXAMPLE
./scripts/sign-windows.ps1 -Prepare
.EXAMPLE
./scripts/sign-windows.ps1 -Path ./dist/agentd_1.2.3_windows_amd64.msi
#>
[CmdletBinding()]
param(
    [switch] $Prepare,
    [Parameter(Position = 0)] [string] $Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

# Official Microsoft package, also pinned by Azure/artifact-signing-action v2.
# Downloaded from NuGet's official flat-container endpoint and inspected at this
# exact version. SHA256 covers the complete NuGet package, including all DLLs.
$script:ClientVersion = '1.0.128'
$script:ClientSHA256 = '74bd7d27e6ce1051409c38d9b46bc8df0400ecd643d51ffbf2ac00869061e40b'
$script:ClientURL = "https://api.nuget.org/v3-flatcontainer/microsoft.artifactsigning.client/$script:ClientVersion/microsoft.artifactsigning.client.$script:ClientVersion.nupkg"
$script:TimestampURL = 'http://timestamp.acs.microsoft.com'

function Get-SigningMode {
    switch -CaseSensitive ($env:AGENTD_SIGN_ARTIFACTS) {
        'true' { return $true }
        'false' { return $false }
        default { throw 'Set AGENTD_SIGN_ARTIFACTS explicitly to true or false.' }
    }
}

function Get-SigningMetadata {
    foreach ($name in @('AZURE_SIGNING_ENDPOINT', 'AZURE_SIGNING_ACCOUNT', 'AZURE_SIGNING_PROFILE')) {
        if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
            throw "Missing signing configuration: $name"
        }
    }
    if ($env:AZURE_SIGNING_ENDPOINT -cnotmatch '^https://[a-z0-9]+\.codesigning\.azure\.net/?$') {
        throw 'AZURE_SIGNING_ENDPOINT must be the official regional HTTPS endpoint.'
    }
    foreach ($name in @('AZURE_SIGNING_ACCOUNT', 'AZURE_SIGNING_PROFILE')) {
        if ([Environment]::GetEnvironmentVariable($name) -cnotmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,127}$') {
            throw "Invalid signing resource name: $name"
        }
    }
    # Restrict DefaultAzureCredential to the Azure CLI session established by
    # azure/login. These are the credential names documented by Microsoft.
    return [ordered]@{
        Endpoint = $env:AZURE_SIGNING_ENDPOINT
        CodeSigningAccountName = $env:AZURE_SIGNING_ACCOUNT
        CertificateProfileName = $env:AZURE_SIGNING_PROFILE
        ExcludeCredentials = @(
            'EnvironmentCredential', 'WorkloadIdentityCredential', 'ManagedIdentityCredential',
            'SharedTokenCacheCredential', 'VisualStudioCredential', 'VisualStudioCodeCredential',
            'AzurePowerShellCredential', 'AzureDeveloperCliCredential', 'InteractiveBrowserCredential'
        )
    }
}

function Invoke-CheckedNative {
    param([string] $File, [string[]] $Arguments)
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$File failed with exit code $LASTEXITCODE." }
}

function Assert-MicrosoftSignTool {
    param([string] $File)
    $signature = Get-AuthenticodeSignature -LiteralPath $File
    # Microsoft changes certificate common names over time; require the trusted
    # publisher organization, not a particular CN or expiring thumbprint.
    if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch '(^|,\s*)O="?Microsoft Corporation"?(,|$)') {
        throw 'SignTool must have a valid Microsoft Authenticode signature.'
    }
}

function Find-SignTool {
    if (-not ${env:ProgramFiles(x86)}) { throw 'The x64 Windows SDK is required.' }
    $sdkRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits/10/bin'
    $candidates = @(Get-ChildItem -Path (Join-Path $sdkRoot '*/x64/signtool.exe') -ErrorAction SilentlyContinue |
        Where-Object { $_.Directory.Parent.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
        Sort-Object { [version] $_.Directory.Parent.Name } -Descending)
    foreach ($candidate in $candidates) {
        # The 20348 SDK is unsupported by Azure's DLib; use a modern SDK.
        if ([version] $candidate.Directory.Parent.Name -lt [version] '10.0.22621.0') { continue }
        Assert-MicrosoftSignTool $candidate.FullName
        return $candidate.FullName
    }
    throw 'A Microsoft-signed x64 SignTool from Windows SDK 10.0.22621 or later is required.'
}

function Assert-DotNetRuntime {
    if (-not $env:ProgramFiles) { throw 'The x64 .NET 8 runtime is required.' }
    $dotnet = Join-Path $env:ProgramFiles 'dotnet/dotnet.exe'
    if (-not (Test-Path -LiteralPath $dotnet -PathType Leaf)) { throw 'The x64 .NET 8 runtime is required.' }
    $runtimes = (Invoke-CheckedNative $dotnet @('--list-runtimes')) -join "`n"
    if ($runtimes -notmatch '(?m)^Microsoft\.NETCore\.App 8\.0\.\d+\s') {
        throw 'Azure CodeSigning DLib requires the x64 .NET 8 runtime; install it before signing.'
    }
}

function Assert-PackageHash {
    param([string] $File)
    $actual = (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash
    if ($actual -ine $script:ClientSHA256) {
        throw "Microsoft.ArtifactSigning.Client $script:ClientVersion SHA256 mismatch; refusing to extract or execute it."
    }
}

function Export-SigningPaths {
    param([string] $Dlib, [string] $Metadata, [string] $SignTool)
    $paths = [ordered]@{DLIB_PATH = $Dlib; METADATA_PATH = $Metadata; SIGNTOOL_PATH = $SignTool}
    foreach ($item in $paths.GetEnumerator()) {
        if ($item.Value -match '[\r\n]') { throw 'Signing paths cannot contain newlines.' }
    }
    foreach ($item in $paths.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($item.Key, $item.Value, 'Process')
        if ($env:GITHUB_ENV) {
            "$($item.Key)=$($item.Value)" | Out-File -LiteralPath $env:GITHUB_ENV -Encoding utf8NoBOM -Append
        }
    }
}

function Initialize-Signing {
    $metadata = Get-SigningMetadata
    Assert-DotNetRuntime
    $signTool = Find-SignTool
    if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) { throw '-Prepare requires a temporary RUNNER_TEMP directory.' }
    $directory = Join-Path $env:RUNNER_TEMP ('agentd-artifact-signing-' + [Guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $directory
    $ready = $false
    try {
        $package = Join-Path $directory 'client.nupkg'
        Invoke-WebRequest -Uri $script:ClientURL -OutFile $package -MaximumRedirection 3 -TimeoutSec 120
        Assert-PackageHash $package
        $client = Join-Path $directory 'client'
        # Keep the entire package dependency layout; a lone copied DLib cannot
        # load its adjacent managed/native DLLs and runtimeconfig.json.
        Add-Type -AssemblyName System.IO.Compression.ZipFile
        [IO.Compression.ZipFile]::ExtractToDirectory($package, $client)
        $dlib = Join-Path $client 'bin/x64/Azure.CodeSigning.Dlib.dll'
        $runtimeConfig = Join-Path $client 'bin/x64/Azure.CodeSigning.Dlib.runtimeconfig.json'
        if (-not (Test-Path -LiteralPath $dlib -PathType Leaf) -or
            -not (Test-Path -LiteralPath $runtimeConfig -PathType Leaf)) {
            throw 'Pinned Artifact Signing package has an unexpected DLib layout.'
        }
        $metadataPath = Join-Path $directory 'metadata.json'
        $metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $metadataPath -Encoding utf8NoBOM
        Export-SigningPaths -Dlib $dlib -Metadata $metadataPath -SignTool $signTool
        $ready = $true
        Write-Host "Prepared Microsoft.ArtifactSigning.Client $script:ClientVersion (verified package SHA256)."
    } finally {
        if (-not $ready) { Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Assert-PreparedSigning {
    foreach ($name in @('DLIB_PATH', 'METADATA_PATH', 'SIGNTOOL_PATH')) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if ([string]::IsNullOrWhiteSpace($value) -or -not (Test-Path -LiteralPath $value -PathType Leaf)) {
            throw "Missing prepared signing path $name; run sign-windows.ps1 -Prepare first."
        }
    }
    Assert-MicrosoftSignTool $env:SIGNTOOL_PATH
    $expected = Get-SigningMetadata
    $actual = Get-Content -LiteralPath $env:METADATA_PATH -Raw | ConvertFrom-Json -AsHashtable
    if (@($actual.Keys).Count -ne $expected.Count) { throw 'Signing metadata differs from the prepared Azure CLI-only configuration.' }
    foreach ($name in $expected.Keys) {
        if (-not $actual.ContainsKey($name) -or
            (ConvertTo-Json -InputObject $actual[$name] -Compress) -cne (ConvertTo-Json -InputObject $expected[$name] -Compress)) {
            throw 'Signing metadata differs from the prepared Azure CLI-only configuration.'
        }
    }
}

function Sign-WindowsArtifact {
    param([string] $File)
    if ([string]::IsNullOrWhiteSpace($File)) { throw 'Provide -Path with an EXE or MSI.' }
    $artifact = Get-Item -LiteralPath $File
    if ($artifact.PSIsContainer -or ($artifact.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $artifact.Extension.ToLowerInvariant() -notin @('.exe', '.msi')) {
        throw 'Signing accepts only a regular EXE or MSI file, not a directory or link.'
    }
    Assert-PreparedSigning
    Invoke-CheckedNative $env:SIGNTOOL_PATH @('sign', '/fd', 'SHA256', '/tr', $script:TimestampURL,
        '/td', 'SHA256', '/d', 'agentd', '/dlib', $env:DLIB_PATH, '/dmdf', $env:METADATA_PATH, $artifact.FullName)
    $signature = Get-AuthenticodeSignature -LiteralPath $artifact.FullName
    if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or $null -eq $signature.TimeStamperCertificate) {
        throw 'Signed artifact must have a valid Authenticode signature and timestamp certificate.'
    }
    Invoke-CheckedNative $env:SIGNTOOL_PATH @('verify', '/pa', '/all', '/tw', $artifact.FullName)
    Write-Host "Signed and verified $($artifact.Name), including its timestamp."
}

function Invoke-SigningMain {
    param([bool] $PrepareRequested, [string] $ArtifactPath)
    if (-not (Get-SigningMode)) {
        Write-Host 'Skipping Windows signing: AGENTD_SIGN_ARTIFACTS=false (explicit unsigned build).'
        return
    }
    if (-not $IsWindows -or [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString() -ne 'X64') {
        throw 'Signing requires Windows with x64 PowerShell 7.'
    }
    if ($PrepareRequested) {
        if ($ArtifactPath) { throw 'Use -Prepare or -Path, not both.' }
        Initialize-Signing
    } else {
        Sign-WindowsArtifact $ArtifactPath
    }
}

# Dot-sourcing defines functions for isolated tests without signing or downloads.
if ($MyInvocation.InvocationName -ne '.') {
    try {
        Invoke-SigningMain -PrepareRequested ([bool] $Prepare) -ArtifactPath $Path
    } catch {
        Write-Error $_ -ErrorAction Continue
        exit 1
    }
}
