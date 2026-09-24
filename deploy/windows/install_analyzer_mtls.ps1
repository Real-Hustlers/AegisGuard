param(
    [Parameter(Mandatory = $true)]
    [string]$AnalyzerExe,

    [string]$InstallDirectory = (
        Join-Path $env:ProgramFiles "AegisGuard\Analyzer"
    ),

    [string]$DataDirectory = (
        Join-Path $env:ProgramData "AegisGuard\Analyzer"
    ),

    [Parameter(Mandatory = $true)]
    [string]$ServerCertificate,

    [Parameter(Mandatory = $true)]
    [string]$ServerPrivateKey,

    [Parameter(Mandatory = $true)]
    [string]$ClientCa,

    [string]$BindHost = "0.0.0.0",

    [ValidateRange(1, 65535)]
    [int]$Port = 5443,

    [string]$TaskName = (
        "AegisGuard Analyzer mTLS"
    ),

    [switch]$OpenFirewall
)

$ErrorActionPreference = "Stop"

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
    "AegisGuardAnalyzerMTLS.exe"

Copy-Item `
    -LiteralPath $AnalyzerExe `
    -Destination $InstalledExe `
    -Force

$RunnerSource = Join-Path `
    $PSScriptRoot `
    "run_analyzer_mtls.ps1"

if (-not (
    Test-Path -LiteralPath $RunnerSource -PathType Leaf
)) {
    throw "mTLS runner was not found: $RunnerSource"
}

$InstalledRunner = Join-Path `
    $InstallDirectory `
    "run_analyzer_mtls.ps1"

Copy-Item `
    -LiteralPath $RunnerSource `
    -Destination $InstalledRunner `
    -Force

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
    "-AnalyzerExe"
    (Quote-Argument $InstalledExe)
    "-DataDirectory"
    (Quote-Argument $DataDirectory)
    "-ServerCertificate"
    (Quote-Argument $ServerCertificate)
    "-ServerPrivateKey"
    (Quote-Argument $ServerPrivateKey)
    "-ClientCa"
    (Quote-Argument $ClientCa)
    "-BindHost"
    (Quote-Argument $BindHost)
    "-Port"
    ([string]$Port)
) -join " "

$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument $arguments `
    -WorkingDirectory (
        Split-Path `
            -Parent `
            $InstalledExe
    )

$trigger = (
    New-ScheduledTaskTrigger `
        -AtStartup
)

$taskPrincipal = (
    New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest
)

$settings = (
    New-ScheduledTaskSettingsSet `
        -RestartCount 5 `
        -RestartInterval (
            New-TimeSpan -Minutes 1
        ) `
        -StartWhenAvailable
)

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $taskPrincipal `
    -Settings $settings `
    -Force |
    Out-Null

if ($OpenFirewall) {
    $ruleName = "AegisGuard Analyzer mTLS $Port"

    $existing = Get-NetFirewallRule `
        -DisplayName $ruleName `
        -ErrorAction SilentlyContinue

    if ($null -eq $existing) {
        New-NetFirewallRule `
            -DisplayName $ruleName `
            -Direction Inbound `
            -Action Allow `
            -Protocol TCP `
            -LocalPort $Port |
            Out-Null
    }
}

Start-ScheduledTask `
    -TaskName $TaskName

Write-Host "AegisGuard packaged Analyzer mTLS startup task installed."

Write-Host "Task: $TaskName"
Write-Host "Executable: $InstalledExe"
Write-Host "Data directory: $DataDirectory"
Write-Host "Port: $Port"
Write-Host (
    "Client certificate verification: REQUIRED"
)

Write-Host ""
Write-Host "Enrollment/recovery bootstrap secrets are intentionally not stored"
Write-Host "in the scheduled task command line or repository."
