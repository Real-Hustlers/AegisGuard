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
