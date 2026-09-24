param(
    [Parameter(Mandatory = $true)]
    [string]$AnalyzerExe,

    [string]$InstallDirectory = (
        Join-Path $env:ProgramFiles "AegisGuard\Analyzer"
    ),

    [string]$DataDirectory = (
        Join-Path $env:ProgramData "AegisGuard\Analyzer"
    ),

    [string]$BindHost = "127.0.0.1",

    [ValidateRange(1, 65535)]
    [int]$Port = 5000,

    [string]$TaskName = (
        "AegisGuard Analyzer UI"
    )
)

$ErrorActionPreference = "Stop"

$identity = (
    [Security.Principal.WindowsIdentity]::GetCurrent()
)

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

if (
    $BindHost -notin @(
        "127.0.0.1",
        "localhost",
        "::1"
    )
) {
    throw "Analyzer UI BindHost must be loopback-only."
}

$AnalyzerExe = (
    Resolve-Path -LiteralPath $AnalyzerExe
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
    "AegisGuardAnalyzer.exe"

Copy-Item `
    -LiteralPath $AnalyzerExe `
    -Destination $InstalledExe `
    -Force

$RunnerSource = Join-Path `
    $PSScriptRoot `
    "run_analyzer_ui.ps1"

if (-not (
    Test-Path `
        -LiteralPath $RunnerSource `
        -PathType Leaf
)) {
    throw "Analyzer UI runner was not found: $RunnerSource"
}

$InstalledRunner = Join-Path `
    $InstallDirectory `
    "run_analyzer_ui.ps1"

Copy-Item `
    -LiteralPath $RunnerSource `
    -Destination $InstalledRunner `
    -Force

function Quote-Argument {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    return (
        '"' +
        ($Value -replace '"', '\"') +
        '"'
    )
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
    "-BindHost"
    (Quote-Argument $BindHost)
    "-Port"
    ([string]$Port)
) -join " "

$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument $arguments `
    -WorkingDirectory $InstallDirectory

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

Start-ScheduledTask `
    -TaskName $TaskName

Write-Host ""
Write-Host "AegisGuard Analyzer UI installation completed."
Write-Host "Executable: $InstalledExe"
Write-Host "Runtime data: $DataDirectory"
Write-Host "Task: $TaskName"
Write-Host "UI: http://$BindHost`:$Port"
Write-Host "Network exposure: loopback only"
Write-Host ""
