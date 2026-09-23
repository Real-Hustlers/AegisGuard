from pathlib import Path

from backend.deployment.windows_contract import (
    REQUIRED_DEPLOYMENT_FILES,
    deployment_layout,
    find_developer_paths_in_text,
    find_forbidden_packaging_literals,
    validate_repository,
)


ROOT = Path(__file__).resolve().parents[2]


def test_layout_separates_binaries_runtime_data_and_secrets():
    layout = deployment_layout()

    analyzer = layout["analyzer"]
    collector = layout["collector"]

    assert analyzer["binary"].startswith(
        "%ProgramFiles%"
    )
    assert analyzer["database"].startswith(
        "%ProgramData%"
    )
    assert analyzer["tls_directory"].startswith(
        "%ProgramData%"
    )

    assert collector["binary"].startswith(
        "%ProgramFiles%"
    )
    assert collector["config"].startswith(
        "%ProgramData%"
    )
    assert collector["state"].startswith(
        "%ProgramData%"
    )
    assert collector["tls_directory"].startswith(
        "%ProgramData%"
    )

    assert (
        Path(analyzer["binary"]).parent
        != Path(analyzer["database"]).parent
    )
    assert (
        Path(collector["binary"]).parent
        != Path(collector["state"]).parent
    )


def test_contract_lists_existing_deployment_sources():
    for relative in REQUIRED_DEPLOYMENT_FILES:
        assert (ROOT / relative).is_file(), relative


def test_developer_absolute_paths_are_detected():
    findings = find_developer_paths_in_text(
        r"""
        C:\Users\developer\AegisGuard\dist
        /home/builduser/AegisGuard
        /Users/macosuser/AegisGuard
        """
    )

    assert len(findings) == 3


def test_portable_paths_do_not_trigger_developer_path_guard():
    findings = find_developer_paths_in_text(
        r"""
        %ProgramFiles%\AegisGuard
        %ProgramData%\AegisGuard
        .\dist\AegisGuardCollector
        deploy\windows
        """
    )

    assert findings == []


def test_packaging_guard_rejects_runtime_and_secret_material():
    findings = find_forbidden_packaging_literals(
        r'''
        datas=[
            ("config.json", "."),
            ("collector_state.db", "."),
            ("server-private.key", "tls"),
            ("server-cert.pem", "tls"),
        ]
        '''
    )

    names = {
        item["literal"]
        for item in findings
    }

    assert "config.json" in names
    assert "collector_state.db" in names
    assert "server-private.key" in names
    assert "server-cert.pem" in names


def test_current_pyinstaller_specs_do_not_bundle_sensitive_runtime_state():
    for relative in (
        "app.spec",
        "backend/collector/AegisGuardCollector.spec",
    ):
        source = (
            ROOT / relative
        ).read_text(
            encoding="utf-8-sig"
        )

        assert (
            find_forbidden_packaging_literals(
                source
            )
            == []
        ), relative


def test_repository_deployment_preflight_is_clean():
    report = validate_repository(
        ROOT
    )

    assert report["ok"] is True
    assert report["issues"] == []

def test_frozen_analyzer_defaults_to_programdata(tmp_path):
    from backend.deployment.runtime_paths import (
        resolve_analyzer_data_dir,
    )

    result = resolve_analyzer_data_dir(
        environ={
            "ProgramData": str(tmp_path),
        },
        frozen=True,
    )

    assert result == (
        tmp_path
        / "AegisGuard"
        / "Analyzer"
    )


def test_explicit_analyzer_data_directory_wins(tmp_path):
    from backend.deployment.runtime_paths import (
        resolve_analyzer_data_dir,
    )

    explicit = tmp_path / "enterprise-data"

    result = resolve_analyzer_data_dir(
        environ={
            "AEGISGUARD_DATA_DIR": str(explicit),
            "ProgramData": str(
                tmp_path / "ignored"
            ),
        },
        frozen=True,
    )

    assert result == explicit.resolve()


def test_frozen_analyzer_without_programdata_fails_closed():
    import pytest

    from backend.deployment.runtime_paths import (
        resolve_analyzer_data_dir,
    )

    with pytest.raises(
        RuntimeError,
        match="ProgramData",
    ):
        resolve_analyzer_data_dir(
            environ={},
            frozen=True,
        )


def test_source_analyzer_retains_project_runtime_root(tmp_path):
    from backend.deployment.runtime_paths import (
        resolve_analyzer_data_dir,
    )

    result = resolve_analyzer_data_dir(
        environ={},
        frozen=False,
        source_root=tmp_path,
    )

    assert result == tmp_path.resolve()


def test_packaged_mtls_spec_is_part_of_deployment_contract():
    assert (
        ROOT
        / "backend/analyzer/AegisGuardAnalyzerMTLS.spec"
    ).is_file()


def test_packaged_mtls_launcher_has_no_python_source_dependency():
    source = (
        ROOT
        / "deploy/windows/run_analyzer_mtls.ps1"
    ).read_text(
        encoding="utf-8-sig"
    )

    assert "AnalyzerExe" in source
    assert "AEGISGUARD_DATA_DIR" in source

    assert "PythonExe" not in source
    assert "RepoRoot" not in source
    assert "-m backend.analyzer.mtls_server" not in source


def test_packaged_mtls_installer_uses_analyzer_executable():
    source = (
        ROOT
        / "deploy/windows/install_analyzer_mtls.ps1"
    ).read_text(
        encoding="utf-8-sig"
    )

    assert "AnalyzerExe" in source
    assert "DataDirectory" in source

    assert "PythonExe" not in source
    assert "RepoRoot" not in source


def test_analyzer_runtime_paths_are_externalized():
    database_source = (
        ROOT
        / "backend/analyzer/database.py"
    ).read_text(
        encoding="utf-8-sig"
    )

    app_source = (
        ROOT
        / "backend/analyzer/app.py"
    ).read_text(
        encoding="utf-8-sig"
    )

    assert (
        "resolve_analyzer_data_dir"
        in database_source
    )

    assert (
        "resolve_analyzer_data_dir"
        in app_source
    )

def test_frozen_collector_config_defaults_to_programdata(tmp_path):
    from backend.deployment.runtime_paths import (
        resolve_collector_config_path,
    )

    result = resolve_collector_config_path(
        environ={
            "ProgramData": str(tmp_path),
        },
        frozen=True,
    )

    assert result == (
        tmp_path
        / "AegisGuard"
        / "Collector"
        / "config.json"
    )


def test_explicit_collector_config_path_wins(tmp_path):
    from backend.deployment.runtime_paths import (
        resolve_collector_config_path,
    )

    explicit = (
        tmp_path
        / "custom"
        / "collector.json"
    ).resolve()

    result = resolve_collector_config_path(
        environ={
            "AEGISGUARD_COLLECTOR_CONFIG": str(
                explicit
            ),
            "ProgramData": str(
                tmp_path / "ignored"
            ),
        },
        frozen=True,
    )

    assert result == explicit


def test_frozen_collector_without_programdata_fails_closed():
    import pytest

    from backend.deployment.runtime_paths import (
        resolve_collector_config_path,
    )

    with pytest.raises(
        RuntimeError,
        match="ProgramData",
    ):
        resolve_collector_config_path(
            environ={},
            frozen=True,
        )


def test_source_collector_config_path_is_preserved(tmp_path):
    from backend.deployment.runtime_paths import (
        resolve_collector_config_path,
    )

    source = (
        tmp_path
        / "config.json"
    )

    result = resolve_collector_config_path(
        environ={},
        frozen=False,
        source_path=source,
    )

    assert result == source.resolve()


def test_collector_installer_uses_enterprise_external_layout():
    source = (
        ROOT
        / "install_collector.ps1"
    ).read_text(
        encoding="utf-8-sig"
    )

    assert "ProgramFiles" in source
    assert "ProgramData" in source
    assert "AEGISGUARD_COLLECTOR_CONFIG" not in source

    assert (
        'raw_output_enabled = $false'
        in source
    )

    assert (
        'collector_auth_required = $true'
        in source
    )

    assert (
        'collector_mtls_required = $true'
        in source
    )


def test_collector_installer_writes_all_durable_endpoints():
    source = (
        ROOT
        / "install_collector.ps1"
    ).read_text(
        encoding="utf-8-sig"
    )

    for endpoint in (
        "/api/collector/v1/batches",
        "/api/collector/v1/enroll",
        "/api/collector/v1/heartbeat",
        "/api/collector/v1/rotate",
        "/api/collector/v1/recover",
        "/api/collector/v1/certificate/rotate",
    ):
        assert endpoint in source

    assert "must use HTTPS" in source


def test_collector_installer_does_not_persist_bootstrap_tokens():
    source = (
        ROOT
        / "install_collector.ps1"
    ).read_text(
        encoding="utf-8-sig"
    )

    assert (
        "AEGISGUARD_COLLECTOR_ENROLLMENT_TOKEN"
        not in source
    )

    assert (
        "AEGISGUARD_COLLECTOR_RECOVERY_TOKEN"
        not in source
    )


def test_collector_runner_uses_external_config():
    source = (
        ROOT
        / "deploy/windows/run_collector.ps1"
    ).read_text(
        encoding="utf-8-sig"
    )

    assert (
        "AEGISGUARD_COLLECTOR_CONFIG"
        in source
    )

    assert "CollectorExe" in source
    assert "ConfigPath" in source


def test_collector_spec_contains_enterprise_runtime_modules():
    source = (
        ROOT
        / "backend/collector/AegisGuardCollector.spec"
    ).read_text(
        encoding="utf-8-sig"
    )

    for module in (
        "backend.collector.durable_runtime",
        "backend.collector.state",
        "backend.collector.transport",
        "backend.collector.credential_store",
    ):
        assert module in source



def test_collector_spec_does_not_shadow_stdlib_platform():
    source = (
        ROOT
        / "backend/collector/AegisGuardCollector.spec"
    ).read_text(
        encoding="utf-8-sig"
    )

    # Adding PROJECT_ROOT/backend as a top-level search path makes
    # backend/platform shadow Python's standard-library platform module
    # in the frozen Collector.
    assert (
        'str(PROJECT_ROOT / "backend")'
        not in source
    )


def test_windows_deployment_powershell_scripts_parse():
    import os
    import shutil
    import subprocess

    import pytest

    powershell = (
        shutil.which("powershell")
        or shutil.which("pwsh")
    )

    if powershell is None:
        pytest.skip(
            "PowerShell is not available on this host"
        )

    scripts = (
        "install_collector.ps1",
        "deploy/windows/run_collector.ps1",
        "deploy/windows/install_analyzer_mtls.ps1",
        "deploy/windows/run_analyzer_mtls.ps1",
        "deploy/windows/configure_collector_mtls.ps1",
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

    for relative in scripts:
        target = str(
            (ROOT / relative).resolve()
        )

        environment = os.environ.copy()
        environment[
            "AEGISGUARD_PS_PARSE_TARGET"
        ] = target

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
            relative
            + "\nSTDOUT:\n"
            + result.stdout
            + "\nSTDERR:\n"
            + result.stderr
        )
