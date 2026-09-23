# Packaged entrypoint: backend.analyzer.mtls_server
# This runner launches the PyInstaller executable built from that
# existing production mTLS listener; it does not implement TLS itself.

param(
    [Parameter(Mandatory = $true)]
    [string]$AnalyzerExe,

    [Parameter(Mandatory = $true)]
    [string]$DataDirectory,

    [Parameter(Mandatory = $true)]
    [string]$ServerCertificate,

    [Parameter(Mandatory = $true)]
    [string]$ServerPrivateKey,

    [Parameter(Mandatory = $true)]
    [string]$ClientCa,

    [string]$BindHost = "0.0.0.0",

    [ValidateRange(1, 65535)]
    [int]$Port = 5443
)

$ErrorActionPreference = "Stop"

$AnalyzerExe = (
    Resolve-Path $AnalyzerExe
).Path

$ServerCertificate = (
    Resolve-Path $ServerCertificate
).Path

$ServerPrivateKey = (
    Resolve-Path $ServerPrivateKey
).Path

$ClientCa = (
    Resolve-Path $ClientCa
).Path

$DataDirectory = (
    [System.IO.Path]::GetFullPath(
        $DataDirectory
    )
)

New-Item `
    -ItemType Directory `
    -Force `
    -Path $DataDirectory |
    Out-Null

$env:AEGISGUARD_DATA_DIR = $DataDirectory

$env:AEGISGUARD_TLS_CERT_FILE = (
    $ServerCertificate
)

$env:AEGISGUARD_TLS_KEY_FILE = (
    $ServerPrivateKey
)

$env:AEGISGUARD_TLS_CLIENT_CA_FILE = (
    $ClientCa
)

$env:AEGISGUARD_TLS_BIND_HOST = (
    $BindHost
)

$env:AEGISGUARD_TLS_PORT = (
    [string]$Port
)

$env:AEGISGUARD_COLLECTOR_MTLS_REQUIRED = (
    "true"
)

& $AnalyzerExe

exit $LASTEXITCODE
