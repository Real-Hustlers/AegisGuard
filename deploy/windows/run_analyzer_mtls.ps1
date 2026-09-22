param(
    [Parameter(Mandatory = $true)]
    [string]$PythonExe,

    [Parameter(Mandatory = $true)]
    [string]$RepoRoot,

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

$PythonExe = (Resolve-Path $PythonExe).Path
$RepoRoot = (Resolve-Path $RepoRoot).Path
$ServerCertificate = (Resolve-Path $ServerCertificate).Path
$ServerPrivateKey = (Resolve-Path $ServerPrivateKey).Path
$ClientCa = (Resolve-Path $ClientCa).Path

$env:PYTHONPATH = $RepoRoot
$env:AEGISGUARD_TLS_CERT_FILE = $ServerCertificate
$env:AEGISGUARD_TLS_KEY_FILE = $ServerPrivateKey
$env:AEGISGUARD_TLS_CLIENT_CA_FILE = $ClientCa
$env:AEGISGUARD_TLS_BIND_HOST = $BindHost
$env:AEGISGUARD_TLS_PORT = [string]$Port
$env:AEGISGUARD_COLLECTOR_MTLS_REQUIRED = "true"

Set-Location $RepoRoot

& $PythonExe -m backend.analyzer.mtls_server
exit $LASTEXITCODE
