from pathlib import Path

from backend.deployment.windows_contract import (
    DEPLOYMENT_TEXT_FILES,
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

    assert analyzer["ml_registry"] == (
        r"%ProgramData%\AegisGuard\Analyzer"
        r"\data\ml_registry"
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


def test_deployment_contract_file_lists_are_unique():
    assert len(
        REQUIRED_DEPLOYMENT_FILES
    ) == len(
        set(REQUIRED_DEPLOYMENT_FILES)
    )

    assert len(
        DEPLOYMENT_TEXT_FILES
    ) == len(
        set(DEPLOYMENT_TEXT_FILES)
    )


def test_analyzer_ui_deployment_files_are_registered_once():
    for relative in (
        "deploy/windows/install_analyzer_ui.ps1",
        "deploy/windows/run_analyzer_ui.ps1",
    ):
        assert (
            REQUIRED_DEPLOYMENT_FILES.count(
                relative
            )
            == 1
        )

        assert (
            DEPLOYMENT_TEXT_FILES.count(
                relative
            )
            == 1
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
        "backend/analyzer/AegisGuardAnalyzerMTLS.spec",
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


def test_analyzer_specs_use_project_root_only():
    import re

    for relative in (
        "app.spec",
        "backend/analyzer/AegisGuardAnalyzerMTLS.spec",
    ):
        source = (
            ROOT / relative
        ).read_text(
            encoding="utf-8-sig"
        )

        match = re.search(
            r"pathex=\[(.*?)\],",
            source,
            flags=re.DOTALL,
        )

        assert match is not None, relative

        pathex = match.group(1)

        assert "str(PROJECT_ROOT)" in pathex
        assert '"backend"' not in pathex
        assert "COLLECTOR_DIR" not in pathex


def test_human_analyzer_spec_contains_enterprise_runtime_modules():
    source = (
        ROOT
        / "app.spec"
    ).read_text(
        encoding="utf-8-sig"
    )

    for module in (
        "backend.analyzer.ingest_worker",
        "backend.analyzer.ingest_pipeline",
        "backend.analyzer.collector_api",
        "backend.analyzer.auth_api",
        "backend.analyzer.app_authorization",
        "backend.analyzer.audit_context",
        "backend.analyzer.audit_api",
        "backend.analyzer.incident_api",
        "backend.analyzer.incident_service",
        "backend.analyzer.asset_api",
        "backend.analyzer.privacy_projection",
        "backend.analyzer.sensitive_audit",
        "backend.analyzer.browser_security",
        "backend.analyzer.intelligence.api",
        "backend.analyzer.intelligence.ml_runtime",
        "backend.analyzer.ml",
        "backend.deployment.runtime_paths",
        "backend.platform.data_privacy",
        "backend.platform.sqlite_security",
    ):
        assert module in source


def test_mtls_analyzer_spec_contains_enterprise_runtime_modules():
    source = (
        ROOT
        / "backend/analyzer/AegisGuardAnalyzerMTLS.spec"
    ).read_text(
        encoding="utf-8-sig"
    )

    for module in (
        "backend.analyzer.mtls_server",
        "backend.analyzer.ingest_worker",
        "backend.analyzer.collector_api",
        "backend.analyzer.auth_api",
        "backend.analyzer.audit_context",
        "backend.analyzer.incident_service",
        "backend.analyzer.intelligence.ml_runtime",
        "backend.deployment.runtime_paths",
        "backend.platform.data_privacy",
        "backend.platform.sqlite_security",
    ):
        assert module in source


def test_governed_ml_registry_contract_matches_runtime():
    layout = deployment_layout()

    assert layout["analyzer"]["ml_registry"] == (
        r"%ProgramData%\AegisGuard\Analyzer"
        r"\data\ml_registry"
    )

    app_source = (
        ROOT
        / "backend/analyzer/app.py"
    ).read_text(
        encoding="utf-8-sig"
    )

    readme = (
        ROOT
        / "BUILD-README.txt"
    ).read_text(
        encoding="utf-8-sig"
    )

    assert '"data/ml_registry"' in app_source
    assert r"Analyzer\data\ml_registry" in readme


def test_packaged_ui_analyzer_uses_loopback_non_debug_server():
    spec_source = (
        ROOT
        / "app.spec"
    ).read_text(
        encoding="utf-8-sig"
    )

    server_source = (
        ROOT
        / "backend/analyzer/ui_server.py"
    ).read_text(
        encoding="utf-8-sig"
    )

    assert "ui_server.py" in spec_source
    assert "backend.analyzer.ui_server" in spec_source

    assert "make_server" in server_source
    assert '"127.0.0.1"' in server_source

    assert "app.run(" not in server_source
    assert "debug=True" not in server_source


def test_packaged_ui_server_rejects_non_loopback_binding():
    import pytest

    from backend.analyzer.ui_server import (
        load_ui_server_config,
    )

    default = load_ui_server_config(
        {},
    )

    assert default == {
        "host": "127.0.0.1",
        "port": 5000,
    }

    with pytest.raises(
        ValueError,
        match="loopback",
    ):
        load_ui_server_config({
            "AEGISGUARD_UI_BIND_HOST": "0.0.0.0",
        })


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


def test_analyzer_installer_copies_packaged_runtime_to_program_files():
    source = (
        ROOT
        / "deploy/windows/install_analyzer_mtls.ps1"
    ).read_text(
        encoding="utf-8-sig"
    )

    assert "InstallDirectory" in source
    assert "ProgramFiles" in source

    assert (
        '"AegisGuardAnalyzerMTLS.exe"'
        in source
    )

    assert (
        '"run_analyzer_mtls.ps1"'
        in source
    )

    assert "Copy-Item" in source

    assert "$InstalledExe" in source
    assert "$InstalledRunner" in source


def test_analyzer_scheduled_task_uses_installed_paths():
    source = (
        ROOT
        / "deploy/windows/install_analyzer_mtls.ps1"
    ).read_text(
        encoding="utf-8-sig"
    )

    assert (
        "(Quote-Argument $InstalledRunner)"
        in source
    )

    assert (
        "(Quote-Argument $InstalledExe)"
        in source
    )

    assert (
        "-WorkingDirectory ("
        in source
    )

    assert (
        "$InstalledExe"
        in source
    )


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


def test_analyzer_ui_installer_uses_enterprise_layout():
    source = (
        ROOT
        / "deploy/windows/install_analyzer_ui.ps1"
    ).read_text(
        encoding="utf-8-sig"
    )

    assert "ProgramFiles" in source
    assert "ProgramData" in source

    assert '"AegisGuardAnalyzer.exe"' in source
    assert '"run_analyzer_ui.ps1"' in source

    assert "$InstalledExe" in source
    assert "$InstalledRunner" in source

    assert "Copy-Item" in source


def test_analyzer_ui_deployment_is_loopback_only():
    installer = (
        ROOT
        / "deploy/windows/install_analyzer_ui.ps1"
    ).read_text(
        encoding="utf-8-sig"
    )

    runner = (
        ROOT
        / "deploy/windows/run_analyzer_ui.ps1"
    ).read_text(
        encoding="utf-8-sig"
    )

    combined = installer + "\n" + runner

    assert '"127.0.0.1"' in combined

    assert (
        "Analyzer UI BindHost must be loopback-only."
        in combined
    )


def test_analyzer_ui_listener_keeps_collector_mtls_fail_closed():
    source = (
        ROOT
        / "deploy/windows/run_analyzer_ui.ps1"
    ).read_text(
        encoding="utf-8-sig"
    )

    assert (
        'AEGISGUARD_COLLECTOR_MTLS_REQUIRED'
        in source
    )

    assert (
        '"true"'
        in source
    )


def test_analyzer_ui_task_uses_system_identity():
    source = (
        ROOT
        / "deploy/windows/install_analyzer_ui.ps1"
    ).read_text(
        encoding="utf-8-sig"
    )

    assert '-UserId "SYSTEM"' in source
    assert "-LogonType ServiceAccount" in source
    assert "-RunLevel Highest" in source


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
        "deploy/windows/install_analyzer_ui.ps1",
        "deploy/windows/run_analyzer_ui.ps1",
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
