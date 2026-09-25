param(
    [Parameter(Mandatory = $true)]
    [string]$TransactionId,

    [string]$InstallRoot = (Join-Path $env:ProgramFiles "AegisGuard"),

    [string]$BackupRoot = (Join-Path $env:ProgramData "AegisGuard\UpgradeBackups"),

    [string[]]$TaskNames = @(
        "AegisGuard Collector",
        "AegisGuard Analyzer UI",
        "AegisGuard Analyzer mTLS"
    ),

    [switch]$Apply
)

$ErrorActionPreference = "Stop"

$ApprovedArtifacts = @(
    "Analyzer\AegisGuardAnalyzer.exe",
    "Analyzer\AegisGuardAnalyzerMTLS.exe",
    "Analyzer\run_analyzer_ui.ps1",
    "Analyzer\run_analyzer_mtls.ps1",
    "Collector\AegisGuardCollector.exe",
    "Collector\run_collector.ps1"
)


function Get-NormalizedFullPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    return [System.IO.Path]::GetFullPath($Value).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
}


function Get-RelativeChildPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $rootFull = Get-NormalizedFullPath $Root
    $pathFull = [System.IO.Path]::GetFullPath($Path)
    $prefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar

    if (-not $pathFull.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escapes approved root: $Path"
    }

    return $pathFull.Substring($prefix.Length)
}


function Assert-ExactPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Actual,

        [Parameter(Mandatory = $true)]
        [string]$Expected,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $actualFull = [System.IO.Path]::GetFullPath($Actual)
    $expectedFull = [System.IO.Path]::GetFullPath($Expected)

    if (-not $actualFull.Equals($expectedFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label path does not match the approved transaction layout."
    }
}


function Get-TaskSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    $snapshot = @()

    foreach ($name in $Names) {
        $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue

        if ($null -ne $task) {
            $snapshot += @{
                Name = $name
                WasRunning = ([string]$task.State -eq "Running")
            }
        }
    }

    return $snapshot
}


function Restore-RunningTasks {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Snapshot
    )

    foreach ($state in $Snapshot) {
        if ($state.WasRunning) {
            Start-ScheduledTask -TaskName $state.Name -ErrorAction SilentlyContinue
        }
    }
}


if ($TransactionId -notmatch "^[0-9A-Fa-f]{12}-[0-9]{8}T[0-9]{6}Z$") {
    throw "TransactionId does not match the S11-C transaction format."
}

$InstallRoot = Get-NormalizedFullPath $InstallRoot
$BackupRoot = Get-NormalizedFullPath $BackupRoot

$transactionRoot = Join-Path $BackupRoot $TransactionId
$transactionRoot = Get-NormalizedFullPath $transactionRoot

$transactionParent = Split-Path -Parent $transactionRoot

if (-not $transactionParent.Equals($BackupRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Transaction directory is outside BackupRoot."
}

if (-not (Test-Path -LiteralPath $transactionRoot -PathType Container)) {
    throw "Upgrade transaction was not found: $TransactionId"
}

$recordPath = Join-Path $transactionRoot "transaction.json"

if (-not (Test-Path -LiteralPath $recordPath -PathType Leaf)) {
    throw "Upgrade transaction metadata is missing."
}

$recordText = Get-Content -LiteralPath $recordPath -Raw -Encoding UTF8
$record = $recordText | ConvertFrom-Json

if ($record.schema_version -ne 1) {
    throw "Unsupported upgrade transaction schema."
}

if ([string]$record.transaction_id -ne $TransactionId) {
    throw "Transaction metadata ID does not match the requested transaction."
}

if ([string]$record.source_commit -notmatch "^[0-9A-Fa-f]{40}$") {
    throw "Transaction source_commit is invalid."
}

if ([string]$record.runtime_state_policy -ne "preserve_programdata") {
    throw "Rollback requires the preserve_programdata transaction policy."
}

$files = @($record.files)

if ($files.Count -ne $ApprovedArtifacts.Count) {
    throw "Transaction artifact count does not match the approved rollback set."
}

$validated = @{}
$rollbackItems = @()

foreach ($entry in $files) {
    $target = [string]$entry.Target
    $backup = [string]$entry.Backup
    $previousHash = [string]$entry.PreviousSha256
    $releaseHash = [string]$entry.ReleaseSha256

    if ($previousHash -notmatch "^[0-9A-Fa-f]{64}$") {
        throw "Transaction PreviousSha256 is invalid."
    }

    if ($releaseHash -notmatch "^[0-9A-Fa-f]{64}$") {
        throw "Transaction ReleaseSha256 is invalid."
    }

    $relative = Get-RelativeChildPath -Root $InstallRoot -Path $target

    if ($ApprovedArtifacts -notcontains $relative) {
        throw "Transaction target is not an approved AegisGuard artifact: $relative"
    }

    if ($validated.ContainsKey($relative)) {
        throw "Transaction contains a duplicate artifact: $relative"
    }

    $expectedTarget = Join-Path $InstallRoot $relative
    $expectedBackup = Join-Path $transactionRoot $relative

    Assert-ExactPath -Actual $target -Expected $expectedTarget -Label "Target"
    Assert-ExactPath -Actual $backup -Expected $expectedBackup -Label "Backup"

    if (-not (Test-Path -LiteralPath $backup -PathType Leaf)) {
        throw "Rollback backup is missing: $relative"
    }

    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
        throw "Installed release artifact is missing: $relative"
    }

    $backupHash = (
        Get-FileHash -LiteralPath $backup -Algorithm SHA256
    ).Hash.ToUpperInvariant()

    if ($backupHash -ne $previousHash.ToUpperInvariant()) {
        throw "Rollback backup hash mismatch: $relative"
    }

    $currentHash = (
        Get-FileHash -LiteralPath $target -Algorithm SHA256
    ).Hash.ToUpperInvariant()

    if ($currentHash -ne $releaseHash.ToUpperInvariant()) {
        throw "Installed artifact no longer matches this upgrade transaction: $relative"
    }

    $validated[$relative] = $true

    $rollbackItems += @{
        Relative = $relative
        Target = $expectedTarget
        Backup = $expectedBackup
        PreviousSha256 = $previousHash.ToUpperInvariant()
        ReleaseSha256 = $releaseHash.ToUpperInvariant()
    }
}

foreach ($relative in $ApprovedArtifacts) {
    if (-not $validated.ContainsKey($relative)) {
        throw "Transaction is missing approved artifact: $relative"
    }
}

Write-Host "ROLLBACK_PREFLIGHT = PASS"
Write-Host ("TRANSACTION_ID = " + $TransactionId)
Write-Host ("ROLLBACK_FILE_COUNT = " + $rollbackItems.Count)
Write-Host "RUNTIME_STATE_POLICY = PRESERVE_PROGRAMDATA"

if (-not $Apply) {
    Write-Host "MODE = PLAN_ONLY"
    Write-Host "No installed files or scheduled tasks were changed."
    exit 0
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)

$isAdmin = $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $isAdmin) {
    throw "Administrator privileges are required for -Apply."
}

$rollbackTimestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$recoveryRoot = Join-Path $transactionRoot ("rollback-recovery-" + $rollbackTimestamp)

New-Item -ItemType Directory -Path $recoveryRoot -Force | Out-Null

$taskSnapshot = Get-TaskSnapshot $TaskNames

try {
    foreach ($state in $taskSnapshot) {
        if ($state.WasRunning) {
            Stop-ScheduledTask -TaskName $state.Name -ErrorAction Stop
        }
    }

    $recoveryFiles = @()

    foreach ($item in $rollbackItems) {
        $recoveryPath = Join-Path $recoveryRoot $item.Relative
        $recoveryParent = Split-Path -Parent $recoveryPath

        New-Item -ItemType Directory -Path $recoveryParent -Force | Out-Null

        Copy-Item `
            -LiteralPath $item.Target `
            -Destination $recoveryPath `
            -Force

        $recoveryHash = (
            Get-FileHash -LiteralPath $recoveryPath -Algorithm SHA256
        ).Hash.ToUpperInvariant()

        if ($recoveryHash -ne $item.ReleaseSha256) {
            throw "Rollback recovery backup verification failed: $($item.Relative)"
        }

        $recoveryFiles += @{
            Relative = $item.Relative
            Recovery = $recoveryPath
            Sha256 = $recoveryHash
        }
    }

    $attempt = @{
        schema_version = 1
        transaction_id = $TransactionId
        attempted_at_utc = $rollbackTimestamp
        source_commit = [string]$record.source_commit
        runtime_state_policy = "preserve_programdata"
        recovery_files = $recoveryFiles
    }

    $attemptPath = Join-Path $recoveryRoot "rollback-attempt.json"

    $attempt |
        ConvertTo-Json -Depth 10 |
        Set-Content -LiteralPath $attemptPath -Encoding UTF8

    foreach ($item in $rollbackItems) {
        Copy-Item `
            -LiteralPath $item.Backup `
            -Destination $item.Target `
            -Force

        $restoredHash = (
            Get-FileHash -LiteralPath $item.Target -Algorithm SHA256
        ).Hash.ToUpperInvariant()

        if ($restoredHash -ne $item.PreviousSha256) {
            throw "Restored artifact verification failed: $($item.Relative)"
        }
    }

    Restore-RunningTasks $taskSnapshot

    Write-Host "ROLLBACK_RESULT = SUCCESS"
    Write-Host ("TRANSACTION_ID = " + $TransactionId)
    Write-Host ("RECOVERY_DIRECTORY = " + $recoveryRoot)
}
catch {
    $rollbackError = $_

    foreach ($item in $rollbackItems) {
        $recoveryPath = Join-Path $recoveryRoot $item.Relative

        if (Test-Path -LiteralPath $recoveryPath -PathType Leaf) {
            Copy-Item `
                -LiteralPath $recoveryPath `
                -Destination $item.Target `
                -Force
        }
    }

    Restore-RunningTasks $taskSnapshot

    Write-Host "ROLLBACK_RESULT = RECOVERED_CURRENT_RELEASE"
    Write-Host ("TRANSACTION_ID = " + $TransactionId)
    Write-Host ("RECOVERY_DIRECTORY = " + $recoveryRoot)

    throw $rollbackError
}
