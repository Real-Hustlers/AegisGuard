import importlib.util
import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]

ROLLBACK = (
    ROOT
    / "deploy"
    / "windows"
    / "rollback_enterprise.ps1"
)


def _load_builder():
    path = (
        ROOT
        / "scripts"
        / "build_windows_offline_bundle.py"
    )

    spec = importlib.util.spec_from_file_location(
        "s11d_bundle_builder",
        path,
    )

    module = importlib.util.module_from_spec(spec)

    assert spec.loader is not None
    spec.loader.exec_module(module)

    return module


def test_s11d_rollback_is_registered_in_deployment_contract():
    from backend.deployment.windows_contract import (
        DEPLOYMENT_TEXT_FILES,
        REQUIRED_DEPLOYMENT_FILES,
    )

    relative = "deploy/windows/rollback_enterprise.ps1"

    assert relative in REQUIRED_DEPLOYMENT_FILES
    assert relative in DEPLOYMENT_TEXT_FILES
    assert ROLLBACK.is_file()


def test_s11d_rollback_is_in_source_free_bundle():
    builder = _load_builder()

    destinations = {
        destination
        for destination, _source
        in builder.BUNDLE_PAYLOAD
    }

    assert (
        "deploy/windows/rollback_enterprise.ps1"
        in destinations
    )


def test_s11d_defaults_to_plan_only_and_requires_explicit_apply():
    source = ROLLBACK.read_text(
        encoding="utf-8-sig"
    )

    assert "[switch]$Apply" in source
    assert "if (-not $Apply)" in source
    assert "MODE = PLAN_ONLY" in source
    assert (
        "No installed files or scheduled tasks were changed."
        in source
    )


def test_s11d_uses_only_the_approved_program_files_artifact_set():
    source = ROLLBACK.read_text(
        encoding="utf-8-sig"
    )

    for relative in (
        r"Analyzer\AegisGuardAnalyzer.exe",
        r"Analyzer\AegisGuardAnalyzerMTLS.exe",
        r"Analyzer\run_analyzer_ui.ps1",
        r"Analyzer\run_analyzer_mtls.ps1",
        r"Collector\AegisGuardCollector.exe",
        r"Collector\run_collector.ps1",
    ):
        assert relative in source

    assert "Transaction target is not an approved AegisGuard artifact" in source


def test_s11d_verifies_backup_and_current_release_hashes_before_apply():
    source = ROLLBACK.read_text(
        encoding="utf-8-sig"
    )

    assert "Rollback backup hash mismatch" in source
    assert (
        "Installed artifact no longer matches this upgrade transaction"
        in source
    )

    preflight = source.index("ROLLBACK_PREFLIGHT = PASS")
    apply_gate = source.index("if (-not $Apply)")
    stop_task = source.index("Stop-ScheduledTask")

    assert preflight < apply_gate < stop_task


def test_s11d_preserves_programdata_runtime_state():
    source = ROLLBACK.read_text(
        encoding="utf-8-sig"
    ).lower()

    assert "preserve_programdata" in source

    for forbidden in (
        "aegisguard.db",
        "collector_state.db",
        "config.json",
        "serverprivatekey",
        "clientkey",
    ):
        assert forbidden not in source


def test_s11d_rollback_is_itself_transactional():
    source = ROLLBACK.read_text(
        encoding="utf-8-sig"
    )

    assert "rollback-recovery-" in source
    assert "rollback-attempt.json" in source
    assert "ROLLBACK_RESULT = SUCCESS" in source
    assert (
        "ROLLBACK_RESULT = RECOVERED_CURRENT_RELEASE"
        in source
    )
    assert "throw $rollbackError" in source


def test_s11d_rollback_powershell_parses():
    powershell = (
        shutil.which("powershell")
        or shutil.which("pwsh")
    )

    if powershell is None:
        pytest.skip(
            "PowerShell is not available on this host"
        )

    command = (
        "$tokens=$null;"
        "$errors=$null;"
        "$target=$env:AEGISGUARD_PS_PARSE_TARGET;"
        "[System.Management.Automation.Language.Parser]"
        "::ParseFile("
        "$target,"
        "[ref]$tokens,"
        "[ref]$errors"
        ")|Out-Null;"
        "if($errors.Count -gt 0){"
        "$errors|ForEach-Object{"
        "Write-Output ($_.ErrorId + ': ' + $_.Message)"
        "};"
        "exit 1"
        "};"
        "exit 0"
    )

    environment = os.environ.copy()
    environment[
        "AEGISGUARD_PS_PARSE_TARGET"
    ] = str(ROLLBACK.resolve())

    result = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )

    assert result.returncode == 0, (
        result.stdout + "\n" + result.stderr
    )
