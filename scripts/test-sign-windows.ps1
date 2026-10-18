#Requires -Version 7.0
# Isolated hook tests: fake package/certificates, no Azure requests or credentials.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'sign-windows.ps1')

function Assert {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

function Assert-Throws {
    param([scriptblock] $Action, [string] $Message)
    $caught = $false
    try { & $Action } catch {
        $caught = $true
        if (-not $_.Exception.Message.Contains($Message)) { throw "Unexpected failure: $($_.Exception.Message)" }
    }
    if (-not $caught) { throw "Expected failure containing: $Message" }
}

$temp = Join-Path ([IO.Path]::GetTempPath()) ('agentd-sign-hook-test-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $temp
try {
    $env:AGENTD_SIGN_ARTIFACTS = ''
    Assert-Throws { Get-SigningMode } 'explicitly to true or false'
    $env:AGENTD_SIGN_ARTIFACTS = 'TRUE'
    Assert-Throws { Get-SigningMode } 'explicitly to true or false'
    $env:AGENTD_SIGN_ARTIFACTS = 'false'
    Assert (-not (Get-SigningMode)) 'false must be the only unsigned mode'
    $initialize = (Get-Item Function:\Initialize-Signing).ScriptBlock
    function Initialize-Signing { throw 'Unsigned mode attempted a download' }
    Invoke-SigningMain -PrepareRequested $true -ArtifactPath ''
    Set-Item Function:\Initialize-Signing -Value $initialize
    $env:AGENTD_SIGN_ARTIFACTS = 'true'
    Assert (Get-SigningMode) 'true must require signing'

    $env:AZURE_SIGNING_ENDPOINT = ''
    Assert-Throws { Get-SigningMetadata } 'Missing signing configuration'
    $env:AZURE_SIGNING_ENDPOINT = 'https://attacker.invalid/'
    $env:AZURE_SIGNING_ACCOUNT = 'test-account'
    $env:AZURE_SIGNING_PROFILE = 'test-profile'
    Assert-Throws { Get-SigningMetadata } 'official regional HTTPS endpoint'
    $env:AZURE_SIGNING_ENDPOINT = 'https://wus2.codesigning.azure.net/'
    $metadata = Get-SigningMetadata
    Assert ($metadata.ExcludeCredentials -contains 'EnvironmentCredential') 'environment credentials must be excluded'
    Assert ($metadata.ExcludeCredentials -contains 'InteractiveBrowserCredential') 'interactive credentials must be excluded'
    Assert ($metadata.ExcludeCredentials -notcontains 'AzureCliCredential') 'OIDC-established Azure CLI must remain enabled'

    $script:Signature = [pscustomobject]@{
        Status = 'Valid'
        SignerCertificate = [pscustomobject]@{Subject = 'CN=Microsoft SDK Publisher, O=Microsoft Corporation, C=US'}
        TimeStamperCertificate = $null
    }
    function Get-AuthenticodeSignature {
        param([string] $LiteralPath)
        return $script:Signature
    }
    Assert-MicrosoftSignTool 'fake-signtool.exe'
    $script:Signature.SignerCertificate.Subject = 'CN=Different Microsoft Tool Name, O=Microsoft Corporation, C=US'
    Assert-MicrosoftSignTool 'fake-signtool.exe'
    $script:Signature.SignerCertificate.Subject = 'CN=Microsoft SDK Publisher, O=Other Vendor, C=US'
    Assert-Throws { Assert-MicrosoftSignTool 'fake-signtool.exe' } 'valid Microsoft Authenticode signature'
    $script:Signature.SignerCertificate.Subject = 'CN=Microsoft SDK Publisher, O=Microsoft Corporation, C=US'
    $script:Signature.Status = 'HashMismatch'
    Assert-Throws { Assert-MicrosoftSignTool 'fake-signtool.exe' } 'valid Microsoft Authenticode signature'
    $script:Signature.Status = 'Valid'

    $badPackage = Join-Path $temp 'untrusted.nupkg'
    [IO.File]::WriteAllText($badPackage, 'untrusted-package')
    Assert-Throws { Assert-PackageHash $badPackage } 'SHA256 mismatch'

    # Prepare refuses a bad package before extraction and cleans its temp files.
    function Assert-DotNetRuntime {}
    $script:TestSignTool = Join-Path $temp 'signtool.exe'
    [IO.File]::WriteAllText($script:TestSignTool, 'fake-signtool')
    function Find-SignTool { return $script:TestSignTool }
    $script:DownloadFixture = $badPackage
    function Invoke-WebRequest {
        param([string] $Uri, [string] $OutFile, [int] $MaximumRedirection, [int] $TimeoutSec)
        Copy-Item -LiteralPath $script:DownloadFixture -Destination $OutFile
    }
    $env:RUNNER_TEMP = $temp
    $env:GITHUB_ENV = Join-Path $temp 'github-env'
    Assert-Throws { Initialize-Signing } 'SHA256 mismatch'
    Assert (@(Get-ChildItem -LiteralPath $temp -Directory -Filter 'agentd-artifact-signing-*').Count -eq 0) 'failed package must be removed'
    Assert (-not (Test-Path -LiteralPath $env:GITHUB_ENV)) 'failed prepare must not export any paths'

    # A fake ZIP tests directory preservation and exports; its digest is changed
    # only in this dot-sourced test scope, never through a production input.
    $fixture = Join-Path $temp 'package-fixture'
    $bin = Join-Path $fixture 'bin/x64'
    $null = New-Item -ItemType Directory -Path $bin -Force
    [IO.File]::WriteAllText((Join-Path $bin 'Azure.CodeSigning.Dlib.dll'), 'fake-dlib')
    [IO.File]::WriteAllText((Join-Path $bin 'Azure.CodeSigning.Dlib.runtimeconfig.json'), '{}')
    [IO.File]::WriteAllText((Join-Path $bin 'Azure.Identity.dll'), 'fake-adjacent-dependency')
    $script:DownloadFixture = Join-Path $temp 'valid-fixture.nupkg'
    Add-Type -AssemblyName System.IO.Compression.ZipFile
    [IO.Compression.ZipFile]::CreateFromDirectory($fixture, $script:DownloadFixture)
    $script:ClientSHA256 = (Get-FileHash -LiteralPath $script:DownloadFixture -Algorithm SHA256).Hash
    Initialize-Signing
    Assert (Test-Path -LiteralPath (Join-Path (Split-Path $env:DLIB_PATH -Parent) 'Azure.Identity.dll')) 'DLib dependencies must stay adjacent'
    $exports = Get-Content -LiteralPath $env:GITHUB_ENV
    Assert ($exports.Count -eq 3) 'only three public path variables are exported'
    Assert ($exports[0].StartsWith('DLIB_PATH=')) 'DLib path export'
    Assert ($exports[1].StartsWith('METADATA_PATH=')) 'metadata path export'
    Assert ($exports[2].StartsWith('SIGNTOOL_PATH=')) 'SignTool path export'
    Assert-PreparedSigning
    $savedDlib = $env:DLIB_PATH
    $env:DLIB_PATH = ''
    Assert-Throws { Assert-PreparedSigning } 'Missing prepared signing path DLIB_PATH'
    $env:DLIB_PATH = $savedDlib
    $changed = Get-Content -LiteralPath $env:METADATA_PATH -Raw | ConvertFrom-Json -AsHashtable
    $changed.ExcludeCredentials = @('EnvironmentCredential')
    $changed | ConvertTo-Json | Set-Content -LiteralPath $env:METADATA_PATH -Encoding utf8NoBOM
    Assert-Throws { Assert-PreparedSigning } 'Azure CLI-only configuration'
    $metadata | ConvertTo-Json | Set-Content -LiteralPath $env:METADATA_PATH -Encoding utf8NoBOM

    # Exercise both artifact types and timestamp fail-closed behavior without
    # executing a downloaded DLL, invoking real SignTool, or contacting Azure.
    $script:Calls = [Collections.Generic.List[object]]::new()
    function Invoke-CheckedNative {
        param([string] $File, [string[]] $Arguments)
        $script:Calls.Add([pscustomobject]@{File = $File; Arguments = $Arguments})
    }
    foreach ($extension in @('exe', 'msi')) {
        $artifact = Join-Path $temp "artifact.$extension"
        [IO.File]::WriteAllText($artifact, 'fake-artifact')
        $script:Calls.Clear()
        $script:Signature.TimeStamperCertificate = [pscustomobject]@{Subject = 'Fake Timestamp'}
        Sign-WindowsArtifact $artifact
        Assert ($script:Calls.Count -eq 2) 'one signing call followed by verification'
        Assert ($script:Calls[0].Arguments[0] -eq 'sign') 'sign first'
        Assert ($script:Calls[0].Arguments -contains '/dlib') 'Azure DLib used for signing'
        Assert ($script:Calls[0].Arguments -contains '/dmdf') 'metadata passed as a file'
        Assert ($script:Calls[0].Arguments -contains 'http://timestamp.acs.microsoft.com') 'Microsoft timestamp service is required'
        Assert ($script:Calls[1].Arguments[0] -eq 'verify') 'verify after signing'
        Assert ($script:Calls[1].Arguments -contains '/tw') 'verify timestamp'
        $script:Calls.Clear()
        $script:Signature.TimeStamperCertificate = $null
        Assert-Throws { Sign-WindowsArtifact $artifact } 'timestamp certificate'
        Assert ($script:Calls.Count -eq 1) 'missing timestamp must stop verification/release'
    }
    $other = Join-Path $temp 'artifact.cmd'
    [IO.File]::WriteAllText($other, 'fake-script')
    Assert-Throws { Sign-WindowsArtifact $other } 'regular EXE or MSI'
    Assert-Throws { Sign-WindowsArtifact $temp } 'regular EXE or MSI'
    Write-Host 'All Windows signing hook contract tests passed (no real signing requests).'
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
