#Requires -Version 7.0
# Pure archive/host checks: no MSI installation, signing service, Go or WiX.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'build-windows.ps1') -Architecture amd64 -Version v1.2.3

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
    if (-not $caught) { throw "Expected failure containing $Message" }
}
function New-TestZip {
    param([string] $File, [string[]] $Names)
    $archive = [IO.Compression.ZipFile]::Open($File, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in $Names) {
            $entry = $archive.CreateEntry($name)
            $stream = $entry.Open()
            try {
                $bytes = [Text.Encoding]::UTF8.GetBytes('known-binary-bytes')
                $stream.Write($bytes, 0, $bytes.Length)
            } finally { $stream.Dispose() }
        }
    } finally { $archive.Dispose() }
}

$temp = Join-Path ([IO.Path]::GetTempPath()) ('agentd-installer-test-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $temp
try {
    Assert-CompatibleArchitecture -Target arm64 -HostArchitecture Arm64
    Assert-CompatibleArchitecture -Target amd64 -HostArchitecture X64
    Assert-CompatibleArchitecture -Target 386 -HostArchitecture X64
    Assert-CompatibleArchitecture -Target 386 -HostArchitecture X86
    Assert-Throws { Assert-CompatibleArchitecture -Target arm64 -HostArchitecture X64 } 'compatible native Windows host'
    Assert-Throws { Assert-CompatibleArchitecture -Target amd64 -HostArchitecture Arm64 } 'compatible native Windows host'
    Add-Type -AssemblyName System.IO.Compression.ZipFile
    $archive = Join-Path $temp 'release.zip'
    New-TestZip -File $archive -Names @('bin/agentd.exe', '../escape.txt', 'docs/readme.txt')
    $destination = Join-Path $temp 'agentd.exe'
    $hash = Read-ArchiveBinary -ArchivePath $archive -Destination $destination
    Assert (([IO.File]::ReadAllText($destination)) -ceq 'known-binary-bytes') 'extract the exact binary bytes'
    Assert ($hash -ceq (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()) 'archive binary digest'
    Assert (-not (Test-Path -LiteralPath (Join-Path $temp 'docs'))) 'do not extract unrelated entries'
    Assert (-not (Test-Path -LiteralPath (Join-Path (Split-Path $temp -Parent) 'escape.txt'))) 'do not follow ZIP paths'
    Assert-Throws { Read-ArchiveBinary -ArchivePath $archive -Destination $destination } 'already exists'
    Assert (([IO.File]::ReadAllText($destination)) -ceq 'known-binary-bytes') 'do not overwrite an existing destination'
    foreach ($kind in @('missing', 'duplicate')) {
        $bad = Join-Path $temp "$kind.zip"
        $names = if ($kind -eq 'missing') { @('agentd.exe') } else { @('bin/agentd.exe', 'bin/agentd.exe') }
        New-TestZip -File $bad -Names $names
        Assert-Throws { Read-ArchiveBinary -ArchivePath $bad -Destination (Join-Path $temp "$kind.exe") } 'exactly one nonempty bin/agentd.exe'
    }
    Write-Host 'Windows archive-only verification helpers passed.'
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
