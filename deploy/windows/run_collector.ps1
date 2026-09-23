param(
    [Parameter(Mandatory = $true)]
    [string]$CollectorExe,

    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    [Parameter(Mandatory = $true)]
    [string]$WorkingDirectory
)

$ErrorActionPreference = "Stop"

$CollectorExe = (
    Resolve-Path $CollectorExe
).Path

$ConfigPath = (
    Resolve-Path $ConfigPath
).Path

$WorkingDirectory = (
    [System.IO.Path]::GetFullPath(
        $WorkingDirectory
    )
)

New-Item `
    -ItemType Directory `
    -Force `
    -Path $WorkingDirectory |
    Out-Null

$env:AEGISGUARD_COLLECTOR_CONFIG = (
    $ConfigPath
)

Set-Location $WorkingDirectory

& $CollectorExe

exit $LASTEXITCODE
