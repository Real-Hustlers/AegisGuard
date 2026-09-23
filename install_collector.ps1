param(
    [Parameter(Mandatory = $true)]
    [string]$CollectorExe,

    [Parameter(Mandatory = $true)]
    [string]$AnalyzerBaseUrl,

    [Parameter(Mandatory = $true)]
    [string]$CaBundle,

    [Parameter(Mandatory = $true)]
    [string]$ClientCertificate,

    [Parameter(Mandatory = $true)]
    [string]$ClientKey,

    [string]$InstallDirectory = (
        Join-Path $env:ProgramFiles "AegisGuard\Collector"
    ),

    [string]$DataDirectory = (
        Join-Path $env:ProgramData "AegisGuard\Collector"
    ),

    [ValidateRange(1, 8760)]
    [int]$HistoricalHours = 10,

    [ValidateRange(1, 100000)]
    [int]$MaxEvents = 500,

    [string]$TaskName = "AegisGuard Collector",

    [switch]$EnableStartup,

    [switch]$StartNow
)

$ErrorActionPreference = "Stop"

if ($StartNow -and -not $EnableStartup) {
    throw "-StartNow requires -EnableStartup."
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()

$principal = (
    [Security.Principal.WindowsPrincipal]::new(
        $identity
    )
)

$isAdmin = $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $isAdmin) {
    throw "Administrator privileges are required."
}

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

$CollectorExe = (
    Resolve-Path -LiteralPath $CollectorExe
).Path

$CaBundle = (
    Resolve-Path -LiteralPath $CaBundle
).Path

$ClientCertificate = (
    Resolve-Path -LiteralPath $ClientCertificate
).Path

$ClientKey = (
    Resolve-Path -LiteralPath $ClientKey
).Path

$InstallDirectory = (
    [System.IO.Path]::GetFullPath(
        $InstallDirectory
    )
)

$DataDirectory = (
    [System.IO.Path]::GetFullPath(
        $DataDirectory
    )
)

New-Item `
    -ItemType Directory `
    -Force `
    -Path $InstallDirectory |
    Out-Null

New-Item `
    -ItemType Directory `
    -Force `
    -Path $DataDirectory |
    Out-Null

$InstalledExe = Join-Path `
    $InstallDirectory `
    "AegisGuardCollector.exe"

Copy-Item `
    -LiteralPath $CollectorExe `
    -Destination $InstalledExe `
    -Force

$RunnerSource = Join-Path `
    $PSScriptRoot `
    "deploy\windows\run_collector.ps1"

if (-not (Test-Path -LiteralPath $RunnerSource -PathType Leaf)) {
    throw "Collector runner was not found: $RunnerSource"
}

$InstalledRunner = Join-Path `
    $InstallDirectory `
    "run_collector.ps1"

Copy-Item `
    -LiteralPath $RunnerSource `
    -Destination $InstalledRunner `
    -Force

$ConfigPath = Join-Path `
    $DataDirectory `
    "config.json"

$config = @{
    log_name = "Security"

    analyzer_url = (
        "$base/api/upload_logs"
    )

    collector_ingest_url = (
        "$base/api/collector/v1/batches"
    )

    collector_enrollment_url = (
        "$base/api/collector/v1/enroll"
    )

    collector_heartbeat_url = (
        "$base/api/collector/v1/heartbeat"
    )

    collector_heartbeat_interval_seconds = 30

    collector_rotation_url = (
        "$base/api/collector/v1/rotate"
    )

    collector_recovery_url = (
        "$base/api/collector/v1/recover"
    )

    collector_certificate_rotation_url = (
        "$base/api/collector/v1/certificate/rotate"
    )

    collector_mtls_required = $true

    collector_client_certificate = (
        $ClientCertificate
    )

    collector_client_key = (
        $ClientKey
    )

    collector_auth_required = $true

    collector_version = "0.1.0"

    collector_state_file = "collector_state.db"

    ca_bundle = $CaBundle

    collector_retry_base_seconds = 2

    collector_retry_max_seconds = 60

    collector_retry_jitter_ratio = 0.2

    event_ids = @(
        4624,
        4625,
        4663,
        4688,
        4720,
        4722,
        4723,
        4724,
        4725,
        4726,
        4732,
        4733,
        4798,
        5156,
        5158
    )

    max_events = $MaxEvents

    hours = $HistoricalHours

    raw_output_enabled = $false

    raw_output_file = (
        "output/raw_security_logs.json"
    )
}

$json = (
    $config |
    ConvertTo-Json -Depth 20
)

$utf8NoBom = (
    [System.Text.UTF8Encoding]::new($false)
)

[System.IO.File]::WriteAllText(
    $ConfigPath,
    $json,
    $utf8NoBom
)

function Quote-Argument {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    return ('"' + ($Value -replace '"', '\"') + '"')
}

$arguments = @(
    "-NoProfile"
    "-ExecutionPolicy"
    "Bypass"
    "-File"
    (Quote-Argument $InstalledRunner)
    "-CollectorExe"
    (Quote-Argument $InstalledExe)
    "-ConfigPath"
    (Quote-Argument $ConfigPath)
    "-WorkingDirectory"
    (Quote-Argument $DataDirectory)
) -join " "

$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument $arguments `
    -WorkingDirectory $DataDirectory

$trigger = New-ScheduledTaskTrigger `
    -AtStartup

$taskPrincipal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -RestartCount 5 `
    -RestartInterval (
        New-TimeSpan -Minutes 1
    ) `
    -StartWhenAvailable

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $taskPrincipal `
    -Settings $settings `
    -Force |
    Out-Null

if ($EnableStartup) {
    Enable-ScheduledTask `
        -TaskName $TaskName |
        Out-Null
}
else {
    Disable-ScheduledTask `
        -TaskName $TaskName |
        Out-Null
}

if ($StartNow) {
    Start-ScheduledTask `
        -TaskName $TaskName
}

Write-Host ""
Write-Host "AegisGuard Collector installation completed."
Write-Host "Executable: $InstalledExe"
Write-Host "Config: $ConfigPath"
Write-Host "Runtime data: $DataDirectory"
Write-Host "Task: $TaskName"
Write-Host "Authenticated collector transport: enabled"
Write-Host "mTLS: required"
Write-Host "Local raw-log persistence: disabled"
Write-Host ""

if (-not $EnableStartup) {
    Write-Host "Startup task is installed but disabled."
}

Write-Host "Enrollment and recovery bootstrap secrets are not stored by this installer."

Write-Host "Provision the existing one-time bootstrap secret through the approved runtime deployment process before first enrollment."
