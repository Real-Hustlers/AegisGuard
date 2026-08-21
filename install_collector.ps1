Write-Host "============================================"
Write-Host "      AEGISGUARD COLLECTOR INSTALLER"
Write-Host "============================================"
Write-Host ""

$AnalyzerUrl = Read-Host "Enter Analyzer URL"
$Hours = Read-Host "Enter historical collection hours"
$MaxEvents = Read-Host "Enter maximum historical events"

$CollectorDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ExePath = Join-Path $CollectorDir "AegisGuardCollector.exe"
$ConfigPath = Join-Path $CollectorDir "config.json"

if (-not (Test-Path $ExePath)) {
    Write-Host "ERROR: AegisGuardCollector.exe was not found."
    Write-Host $ExePath
    exit 1
}

$config = @{
    log_name = "Security"
    analyzer_url = $AnalyzerUrl
    event_ids = @(
        4624, 4625, 4663, 4688,
        4720, 4722, 4723, 4724,
        4725, 4726, 4732, 4733,
        4798, 5156, 5158
    )
    max_events = [int]$MaxEvents
    hours = [int]$Hours
    raw_output_file = "raw_security_logs.json"
}

$config |
    ConvertTo-Json -Depth 5 |
    Set-Content -Path $ConfigPath -Encoding UTF8

Write-Host ""
Write-Host "Configuration saved:"
Write-Host $ConfigPath

$TaskName = "AegisGuard Collector"

$Action = New-ScheduledTaskAction `
    -Execute $ExePath `
    -WorkingDirectory $CollectorDir

$Trigger = New-ScheduledTaskTrigger -AtStartup

$Principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

$Settings = New-ScheduledTaskSettingsSet `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Settings $Settings `
    -Force

Write-Host ""
Write-Host "Scheduled task created."
Write-Host "Starting Collector..."

Start-ScheduledTask -TaskName $TaskName

Write-Host ""
Write-Host "Collector installation completed."