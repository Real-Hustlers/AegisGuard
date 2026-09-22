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
    [int]$Port = 5443,

    [string]$TaskName = "AegisGuard Analyzer mTLS",

    [switch]$OpenFirewall
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $isAdmin) {
    throw "Administrator privileges are required."
}

$PythonExe = (Resolve-Path $PythonExe).Path
$RepoRoot = (Resolve-Path $RepoRoot).Path
$ServerCertificate = (Resolve-Path $ServerCertificate).Path
$ServerPrivateKey = (Resolve-Path $ServerPrivateKey).Path
$ClientCa = (Resolve-Path $ClientCa).Path

$Runner = Join-Path $RepoRoot "deploy\windows\run_analyzer_mtls.ps1"
if (-not (Test-Path $Runner -PathType Leaf)) {
    throw "mTLS runner was not found: $Runner"
}

function Quote-Argument([string]$Value) {
    return '"' + ($Value -replace '"', '\"') + '"'
}

$arguments = @(
    "-NoProfile"
    "-ExecutionPolicy"
    "Bypass"
    "-File"
    (Quote-Argument $Runner)
    "-PythonExe"
    (Quote-Argument $PythonExe)
    "-RepoRoot"
    (Quote-Argument $RepoRoot)
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
    -WorkingDirectory $RepoRoot

$trigger = New-ScheduledTaskTrigger -AtStartup

$taskPrincipal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -RestartCount 5 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $taskPrincipal `
    -Settings $settings `
    -Force | Out-Null

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
            -LocalPort $Port | Out-Null
    }
}

Start-ScheduledTask -TaskName $TaskName

Write-Host "AegisGuard Analyzer mTLS startup task installed."
Write-Host "Task: $TaskName"
Write-Host "Port: $Port"
Write-Host "Client certificate verification: REQUIRED"
Write-Host ""
Write-Host "Enrollment/recovery bootstrap secrets are intentionally not stored"
Write-Host "in the scheduled task command line or repository."
