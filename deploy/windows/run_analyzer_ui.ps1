param(
    [Parameter(Mandatory = $true)]
    [string]$AnalyzerExe,

    [Parameter(Mandatory = $true)]
    [string]$DataDirectory,

    [string]$BindHost = "127.0.0.1",

    [ValidateRange(1, 65535)]
    [int]$Port = 5000
)

$ErrorActionPreference = "Stop"

$AnalyzerExe = (
    Resolve-Path -LiteralPath $AnalyzerExe
).Path

$DataDirectory = (
    [System.IO.Path]::GetFullPath(
        $DataDirectory
    )
)

if (
    $BindHost -notin @(
        "127.0.0.1",
        "localhost",
        "::1"
    )
) {
    throw "Analyzer UI BindHost must be loopback-only."
}

New-Item `
    -ItemType Directory `
    -Force `
    -Path $DataDirectory |
    Out-Null

$env:AEGISGUARD_DATA_DIR = $DataDirectory
$env:AEGISGUARD_UI_BIND_HOST = $BindHost
$env:AEGISGUARD_UI_PORT = [string]$Port

# This listener is intentionally HTTP and loopback-only.
# Secure cookies are not returned over this HTTP deployment path.
# Keep the application default secure for every other deployment;
# only this local loopback runner opts out.
$env:AEGISGUARD_SESSION_COOKIE_SECURE = "false"

# The human UI listener is never an alternate Collector ingress path.
# Collector endpoints loaded by the shared Flask application remain
# fail-closed unless a verified mTLS client certificate is present.
$env:AEGISGUARD_COLLECTOR_MTLS_REQUIRED = "true"

& $AnalyzerExe

exit $LASTEXITCODE
