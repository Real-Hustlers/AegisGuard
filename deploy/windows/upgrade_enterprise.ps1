param(
    [Parameter(Mandatory = $true)]
    [string]$BundleDirectory,

    [string]$InstallRoot = (Join-Path $env:ProgramFiles "AegisGuard"),

    [string]$BackupRoot = (Join-Path $env:ProgramData "AegisGuard\UpgradeBackups"),

    [string]$ExpectedSourceCommit,

    [string[]]$TaskNames = @(
        "AegisGuard Collector",
        "AegisGuard Analyzer UI",
        "AegisGuard Analyzer mTLS"
    ),

    [switch]$Apply
)

$ErrorActionPreference = "Stop"
$BundleName = "AegisGuard-Windows-Enterprise"


function Resolve-BundleRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputPath
    )

    $resolved = (Resolve-Path -LiteralPath $InputPath).Path

    if ((Split-Path -Leaf $resolved) -eq $BundleName) {
        return $resolved
    }

    $candidate = Join-Path $resolved $BundleName

    if (Test-Path -LiteralPath $candidate -PathType Container) {
        return (Resolve-Path -LiteralPath $candidate).Path
    }

    throw "Bundle root '$BundleName' was not found."
}


function Assert-SafeRelativePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "Bundle metadata contains an empty path."
    }

    if ($Value.Contains("\")) {
        throw "Bundle path must use POSIX separators: $Value"
    }

    if ($Value.StartsWith("/")) {
        throw "Unsafe bundle path: $Value"
    }

    $parts = $Value.Split("/")

    if ($parts -contains "..") {
        throw "Unsafe bundle path: $Value"
    }

    if ($parts -contains ".") {
        throw "Unsafe bundle path: $Value"
    }

    return $Value
}


function Get-BundleRelativePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $rootFull = [System.IO.Path]::GetFullPath($Root)
    $pathFull = [System.IO.Path]::GetFullPath($Path)

    $rootFull = $rootFull.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )

    $prefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar

    if (-not $pathFull.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escapes bundle root: $Path"
    }

    $relative = $pathFull.Substring($prefix.Length)
    return ($relative -replace "\\", "/")
}


function Invoke-BundleVerification {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,

        [string]$TrustedSourceCommit
    )

    $manifestPath = Join-Path $Root "manifest.json"
    $checksumPath = Join-Path $Root "SHA256SUMS.txt"

    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Bundle manifest.json is missing."
    }

    if (-not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) {
        throw "Bundle SHA256SUMS.txt is missing."
    }

    $manifestText = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8
    $manifest = $manifestText | ConvertFrom-Json

    if ($manifest.schema_version -ne 1) {
        throw "Unsupported manifest schema version."
    }

    if ($manifest.product -ne "AegisGuard Enterprise") {
        throw "Unexpected manifest product."
    }

    if ($manifest.platform -ne "Windows x86_64") {
        throw "Unexpected manifest platform."
    }

    if ($manifest.bundle -ne $BundleName) {
        throw "Unexpected manifest bundle name."
    }

    $sourceCommit = [string]$manifest.source_commit

    if ($sourceCommit -notmatch "^[0-9A-Fa-f]{40}$") {
        throw "Manifest source_commit is invalid."
    }

    if ($manifest.source_dirty -ne $false) {
        throw "Production upgrade rejects dirty-source bundles."
    }

    if (-not [string]::IsNullOrWhiteSpace($TrustedSourceCommit)) {
        if ($TrustedSourceCommit -notmatch "^[0-9A-Fa-f]{40}$") {
            throw "ExpectedSourceCommit must be a 40-character Git SHA."
        }

        if ($sourceCommit.ToLowerInvariant() -ne $TrustedSourceCommit.ToLowerInvariant()) {
            throw "Manifest source commit does not match trusted release pin."
        }
    }

    $securityFlags = @(
        "contains_runtime_database",
        "contains_private_keys",
        "contains_certificates",
        "contains_customer_logs",
        "contains_python_source"
    )

    foreach ($flag in $securityFlags) {
        if ($manifest.security.$flag -ne $false) {
            throw "Unsafe manifest security flag: $flag"
        }
    }

    $checksums = @{}

    foreach ($line in (Get-Content -LiteralPath $checksumPath -Encoding UTF8)) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        if ($line -notmatch "^([0-9A-Fa-f]{64})  (.+)$") {
            throw "Invalid SHA256SUMS.txt entry."
        }

        $digest = $Matches[1].ToUpperInvariant()
        $relative = Assert-SafeRelativePath $Matches[2]

        if ($relative -eq "SHA256SUMS.txt") {
            throw "Checksum file must not checksum itself."
        }

        if ($checksums.ContainsKey($relative)) {
            throw "Duplicate checksum path: $relative"
        }

        $checksums[$relative] = $digest
    }

    if ($checksums.Count -eq 0) {
        throw "Checksum file contains no entries."
    }

    $actualFiles = @{}

    foreach ($file in (Get-ChildItem -LiteralPath $Root -Recurse -File)) {
        $relative = Get-BundleRelativePath -Root $Root -Path $file.FullName

        if ($relative -ne "SHA256SUMS.txt") {
            $actualFiles[$relative] = $file.FullName
        }
    }

    if ($checksums.Count -ne $actualFiles.Count) {
        throw "Checksum coverage does not match bundle files."
    }

    foreach ($relative in $checksums.Keys) {
        if (-not $actualFiles.ContainsKey($relative)) {
            throw "Checksum coverage does not match bundle files."
        }

        $actualHash = (
            Get-FileHash -LiteralPath $actualFiles[$relative] -Algorithm SHA256
        ).Hash.ToUpperInvariant()

        if ($actualHash -ne $checksums[$relative]) {
            throw "Checksum mismatch: $relative"
        }
    }

    $payloadPaths = @{}

    foreach ($entry in @($manifest.payload_files)) {
        $relative = Assert-SafeRelativePath ([string]$entry.path)

        if ($payloadPaths.ContainsKey($relative)) {
            throw "Duplicate manifest payload path: $relative"
        }

        if (($relative -eq "manifest.json") -or ($relative -eq "SHA256SUMS.txt")) {
            throw "Reserved file cannot be payload: $relative"
        }

        $nativeRelative = $relative -replace "/", "\"
        $fullPath = Join-Path $Root $nativeRelative

        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            throw "Manifest payload file is missing: $relative"
        }

        $item = Get-Item -LiteralPath $fullPath

        if ([int64]$entry.size -ne [int64]$item.Length) {
            throw "Manifest size mismatch: $relative"
        }

        $expectedHash = [string]$entry.sha256

        if ($expectedHash -notmatch "^[0-9A-Fa-f]{64}$") {
            throw "Invalid manifest SHA-256: $relative"
        }

        $actualHash = (
            Get-FileHash -LiteralPath $fullPath -Algorithm SHA256
        ).Hash.ToUpperInvariant()

        if ($actualHash -ne $expectedHash.ToUpperInvariant()) {
            throw "Manifest SHA-256 mismatch: $relative"
        }

        $payloadPaths[$relative] = $true
    }

    $expectedPayloadCount = $actualFiles.Count - 1

    if ($payloadPaths.Count -ne $expectedPayloadCount) {
        throw "Manifest payload coverage does not match bundle files."
    }

    foreach ($relative in $actualFiles.Keys) {
        if ($relative -eq "manifest.json") {
            continue
        }

        if (-not $payloadPaths.ContainsKey($relative)) {
            throw "Manifest payload coverage does not match bundle files."
        }
    }

    return @{
        SourceCommit = $sourceCommit.ToLowerInvariant()
        PayloadCount = $payloadPaths.Count
    }
}


function Get-UpgradeMappings {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,

        [Parameter(Mandatory = $true)]
        [string]$TargetRoot
    )

    return @(
        @{
            Source = Join-Path $Root "bin\AegisGuardAnalyzer.exe"
            Target = Join-Path $TargetRoot "Analyzer\AegisGuardAnalyzer.exe"
            Backup = "Analyzer\AegisGuardAnalyzer.exe"
        },
        @{
            Source = Join-Path $Root "bin\AegisGuardAnalyzerMTLS.exe"
            Target = Join-Path $TargetRoot "Analyzer\AegisGuardAnalyzerMTLS.exe"
            Backup = "Analyzer\AegisGuardAnalyzerMTLS.exe"
        },
        @{
            Source = Join-Path $Root "deploy\windows\run_analyzer_ui.ps1"
            Target = Join-Path $TargetRoot "Analyzer\run_analyzer_ui.ps1"
            Backup = "Analyzer\run_analyzer_ui.ps1"
        },
        @{
            Source = Join-Path $Root "deploy\windows\run_analyzer_mtls.ps1"
            Target = Join-Path $TargetRoot "Analyzer\run_analyzer_mtls.ps1"
            Backup = "Analyzer\run_analyzer_mtls.ps1"
        },
        @{
            Source = Join-Path $Root "bin\AegisGuardCollector.exe"
            Target = Join-Path $TargetRoot "Collector\AegisGuardCollector.exe"
            Backup = "Collector\AegisGuardCollector.exe"
        },
        @{
            Source = Join-Path $Root "deploy\windows\run_collector.ps1"
            Target = Join-Path $TargetRoot "Collector\run_collector.ps1"
            Backup = "Collector\run_collector.ps1"
        }
    )
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


$bundleRoot = Resolve-BundleRoot $BundleDirectory

$verification = Invoke-BundleVerification `
    -Root $bundleRoot `
    -TrustedSourceCommit $ExpectedSourceCommit

$InstallRoot = [System.IO.Path]::GetFullPath($InstallRoot)
$BackupRoot = [System.IO.Path]::GetFullPath($BackupRoot)

$mappings = Get-UpgradeMappings -Root $bundleRoot -TargetRoot $InstallRoot

foreach ($mapping in $mappings) {
    if (-not (Test-Path -LiteralPath $mapping.Source -PathType Leaf)) {
        throw ("Required release file missing: " + $mapping.Source)
    }

    if (-not (Test-Path -LiteralPath $mapping.Target -PathType Leaf)) {
        throw (
            "Installed target is missing. S11-C upgrades existing enterprise installations only: " +
            $mapping.Target
        )
    }
}

Write-Host "UPGRADE_PREFLIGHT = PASS"
Write-Host ("SOURCE_COMMIT = " + $verification.SourceCommit)
Write-Host ("UPGRADE_FILE_COUNT = " + $mappings.Count)
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

$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$transactionId = $verification.SourceCommit.Substring(0, 12) + "-" + $timestamp
$transactionRoot = Join-Path $BackupRoot $transactionId

New-Item -ItemType Directory -Path $transactionRoot -Force | Out-Null

$taskSnapshot = Get-TaskSnapshot $TaskNames

try {
    foreach ($state in $taskSnapshot) {
        if ($state.WasRunning) {
            Stop-ScheduledTask -TaskName $state.Name -ErrorAction Stop
        }
    }

    $transactionFiles = @()

    foreach ($mapping in $mappings) {
        $backupPath = Join-Path $transactionRoot $mapping.Backup
        $backupParent = Split-Path -Parent $backupPath

        New-Item -ItemType Directory -Path $backupParent -Force | Out-Null

        Copy-Item `
            -LiteralPath $mapping.Target `
            -Destination $backupPath `
            -Force

        $previousHash = (
            Get-FileHash -LiteralPath $backupPath -Algorithm SHA256
        ).Hash.ToUpperInvariant()

        $releaseHash = (
            Get-FileHash -LiteralPath $mapping.Source -Algorithm SHA256
        ).Hash.ToUpperInvariant()

        $transactionFiles += @{
            Target = $mapping.Target
            Backup = $backupPath
            PreviousSha256 = $previousHash
            ReleaseSha256 = $releaseHash
        }
    }

    $record = @{
        schema_version = 1
        transaction_id = $transactionId
        source_commit = $verification.SourceCommit
        created_at_utc = $timestamp
        runtime_state_policy = "preserve_programdata"
        files = $transactionFiles
    }

    $recordPath = Join-Path $transactionRoot "transaction.json"

    $record |
        ConvertTo-Json -Depth 10 |
        Set-Content -LiteralPath $recordPath -Encoding UTF8

    foreach ($mapping in $mappings) {
        Copy-Item `
            -LiteralPath $mapping.Source `
            -Destination $mapping.Target `
            -Force

        $sourceHash = (
            Get-FileHash -LiteralPath $mapping.Source -Algorithm SHA256
        ).Hash.ToUpperInvariant()

        $targetHash = (
            Get-FileHash -LiteralPath $mapping.Target -Algorithm SHA256
        ).Hash.ToUpperInvariant()

        if ($sourceHash -ne $targetHash) {
            throw ("Installed file verification failed: " + $mapping.Target)
        }
    }

    Restore-RunningTasks $taskSnapshot

    Write-Host "UPGRADE_RESULT = SUCCESS"
    Write-Host ("TRANSACTION_ID = " + $transactionId)
    Write-Host ("BACKUP_DIRECTORY = " + $transactionRoot)
}
catch {
    $upgradeError = $_

    foreach ($mapping in $mappings) {
        $backupPath = Join-Path $transactionRoot $mapping.Backup

        if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
            Copy-Item `
                -LiteralPath $backupPath `
                -Destination $mapping.Target `
                -Force
        }
    }

    Restore-RunningTasks $taskSnapshot

    Write-Host "UPGRADE_RESULT = ROLLED_BACK"
    Write-Host ("BACKUP_DIRECTORY = " + $transactionRoot)

    throw $upgradeError
}
