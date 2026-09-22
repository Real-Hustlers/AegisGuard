param(
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    [Parameter(Mandatory = $true)]
    [string]$AnalyzerBaseUrl,

    [Parameter(Mandatory = $true)]
    [string]$CaBundle,

    [Parameter(Mandatory = $true)]
    [string]$ClientCertificate,

    [Parameter(Mandatory = $true)]
    [string]$ClientKey
)

$ErrorActionPreference = "Stop"

$ConfigPath = (Resolve-Path $ConfigPath).Path
$CaBundle = (Resolve-Path $CaBundle).Path
$ClientCertificate = (Resolve-Path $ClientCertificate).Path
$ClientKey = (Resolve-Path $ClientKey).Path

try {
    $uri = [Uri]$AnalyzerBaseUrl
}
catch {
    throw "AnalyzerBaseUrl must be an absolute HTTPS URL."
}

if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne "https") {
    throw "AnalyzerBaseUrl must use HTTPS."
}

if ($uri.Query -or $uri.Fragment) {
    throw "AnalyzerBaseUrl must not contain a query string or fragment."
}

$base = $uri.AbsoluteUri.TrimEnd("/")

$config = Get-Content `
    -Path $ConfigPath `
    -Raw `
    -Encoding UTF8 |
    ConvertFrom-Json

function Set-ConfigValue(
    [object]$Object,
    [string]$Name,
    $Value
) {
    $Object |
        Add-Member `
            -NotePropertyName $Name `
            -NotePropertyValue $Value `
            -Force
}

Set-ConfigValue $config "analyzer_url" `
    "$base/api/upload_logs"
Set-ConfigValue $config "collector_ingest_url" `
    "$base/api/collector/v1/batches"
Set-ConfigValue $config "collector_enrollment_url" `
    "$base/api/collector/v1/enroll"
Set-ConfigValue $config "collector_rotation_url" `
    "$base/api/collector/v1/rotate"
Set-ConfigValue $config "collector_recovery_url" `
    "$base/api/collector/v1/recover"
Set-ConfigValue $config "collector_certificate_rotation_url" `
    "$base/api/collector/v1/certificate/rotate"
Set-ConfigValue $config "collector_auth_required" $true
Set-ConfigValue $config "collector_mtls_required" $true
Set-ConfigValue $config "ca_bundle" $CaBundle
Set-ConfigValue $config "collector_client_certificate" `
    $ClientCertificate
Set-ConfigValue $config "collector_client_key" $ClientKey

$temp = "$ConfigPath.tmp"

$config |
    ConvertTo-Json -Depth 20 |
    Set-Content `
        -Path $temp `
        -Encoding UTF8

Move-Item `
    -Path $temp `
    -Destination $ConfigPath `
    -Force

Write-Host "Collector mTLS configuration updated."
Write-Host "Config: $ConfigPath"
Write-Host "Analyzer: $base"
Write-Host "mTLS required: true"
Write-Host ""
Write-Host "No enrollment token, recovery token, device credential,"
Write-Host "certificate, or private-key content was written to config.json."
