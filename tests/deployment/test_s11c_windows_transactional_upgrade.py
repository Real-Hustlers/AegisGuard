import importlib.util
import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]

UPGRADE = (
    ROOT
    / "deploy"
    / "windows"
    / "upgrade_enterprise.ps1"
)


def _load_builder():
    path = (
        ROOT
        / "scripts"
        / "build_windows_offline_bundle.py"
    )

    spec = importlib.util.spec_from_file_location(
        "s11c_bundle_builder",
        path,
    )

    module = importlib.util.module_from_spec(spec)

    assert spec.loader is not None
    spec.loader.exec_module(module)

    return module


def test_s11c_upgrade_script_is_registered_in_deployment_contract():
    from backend.deployment.windows_contract import (
        DEPLOYMENT_TEXT_FILES,
        REQUIRED_DEPLOYMENT_FILES,
    )

    relative = "deploy/windows/upgrade_enterprise.ps1"

    assert relative in REQUIRED_DEPLOYMENT_FILES
    assert relative in DEPLOYMENT_TEXT_FILES
    assert UPGRADE.is_file()


def test_s11c_upgrade_script_is_in_source_free_bundle():
    builder = _load_builder()

    destinations = {
        destination
        for destination, _source
        in builder.BUNDLE_PAYLOAD
    }

    assert (
        "deploy/windows/upgrade_enterprise.ps1"
        in destinations
    )


def test_s11c_verifies_release_before_mutation():
    source = UPGRADE.read_text(
        encoding="utf-8-sig"
    )

    verification = source.index(
        "$verification = Invoke-BundleVerification"
    )

    task_stop = source.index(
        "Stop-ScheduledTask"
    )

    installed_copy = source.index(
        "-LiteralPath $mapping.Source",
        task_stop,
    )

    assert verification < task_stop
    assert verification < installed_copy


def test_s11c_defaults_to_plan_only_and_requires_explicit_apply():
    source = UPGRADE.read_text(
        encoding="utf-8-sig"
    )

    assert "[switch]$Apply" in source
    assert "if (-not $Apply)" in source
    assert "MODE = PLAN_ONLY" in source
    assert (
        "No installed files or scheduled tasks were changed."
        in source
    )


def test_s11c_preserves_runtime_state_and_secrets():
    source = UPGRADE.read_text(
        encoding="utf-8-sig"
    ).lower()

    assert "preserve_programdata" in source

    for forbidden_target in (
        "aegisguard.db",
        "collector_state.db",
        "config.json",
        r"\tls",
        "serverprivatekey",
        "clientkey",
    ):
        assert forbidden_target not in source


def test_s11c_has_automatic_failure_rollback():
    source = UPGRADE.read_text(
        encoding="utf-8-sig"
    )

    assert "transaction.json" in source
    assert "UPGRADE_RESULT = SUCCESS" in source
    assert "UPGRADE_RESULT = ROLLED_BACK" in source
    assert "throw $upgradeError" in source

    catch_index = source.index("catch {")
    restore_index = source.index(
        "-LiteralPath $backupPath",
        catch_index,
    )

    assert restore_index > catch_index


def test_s11c_upgrade_powershell_parses():
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
    ] = str(UPGRADE.resolve())

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
