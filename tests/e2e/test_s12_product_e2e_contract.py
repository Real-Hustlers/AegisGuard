from pathlib import Path
import importlib.util


ROOT = Path(__file__).resolve().parents[2]

DASHBOARD = ROOT / "static" / "js" / "dashboard.js"
INTELLIGENCE = ROOT / "static" / "js" / "intelligence_ui.js"
TEMPLATE = ROOT / "templates" / "index.html"
ENTERPRISE_CSS = ROOT / "static" / "css" / "aegisguard-enterprise.css"
BUNDLE_BUILDER = ROOT / "scripts" / "build_windows_offline_bundle.py"
UPGRADE = ROOT / "deploy" / "windows" / "upgrade_enterprise.ps1"
ROLLBACK = ROOT / "deploy" / "windows" / "rollback_enterprise.ps1"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


def load_bundle_builder():
    spec = importlib.util.spec_from_file_location(
        "s12_bundle_builder",
        BUNDLE_BUILDER,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_source_free_bundle_contains_complete_installed_runtime_path():
    builder = load_bundle_builder()

    destinations = {
        destination
        for destination, _source
        in builder.BUNDLE_PAYLOAD
    }

    required = {
        "bin/AegisGuardAnalyzer.exe",
        "bin/AegisGuardAnalyzerMTLS.exe",
        "bin/AegisGuardCollector.exe",
        "bin/AegisGuardRecovery.exe",
        "bin/AegisGuardUserAdmin.exe",
        "install_collector.ps1",
        "deploy/windows/install_analyzer_ui.ps1",
        "deploy/windows/run_analyzer_ui.ps1",
        "deploy/windows/install_analyzer_mtls.ps1",
        "deploy/windows/run_analyzer_mtls.ps1",
        "deploy/windows/run_collector.ps1",
        "deploy/windows/configure_collector_mtls.ps1",
        "deploy/windows/upgrade_enterprise.ps1",
        "deploy/windows/rollback_enterprise.ps1",
    }

    assert required.issubset(destinations)

    assert not any(
        Path(destination).suffix.lower() == ".py"
        for destination in destinations
    )


def test_windows_product_layout_separates_program_files_and_program_data():
    from backend.deployment.windows_contract import deployment_layout

    layout = deployment_layout()

    assert "%ProgramFiles%\\AegisGuard\\Analyzer" in layout["analyzer"]["binary"]
    assert "%ProgramData%\\AegisGuard\\Analyzer" in layout["analyzer"]["data_directory"]
    assert "%ProgramFiles%\\AegisGuard\\Collector" in layout["collector"]["binary"]
    assert "%ProgramData%\\AegisGuard\\Collector" in layout["collector"]["data_directory"]

    assert layout["analyzer"]["database"].endswith(
        r"Analyzer\aegisguard.db"
    )
    assert layout["collector"]["state"].endswith(
        r"Collector\collector_state.db"
    )


def test_installed_launch_contract_does_not_require_python_source_runtime():
    install_and_launch_files = (
        ROOT / "deploy" / "windows" / "install_analyzer_ui.ps1",
        ROOT / "deploy" / "windows" / "install_analyzer_mtls.ps1",
        ROOT / "install_collector.ps1",
        ROOT / "deploy" / "windows" / "run_analyzer_ui.ps1",
        ROOT / "deploy" / "windows" / "run_analyzer_mtls.ps1",
        ROOT / "deploy" / "windows" / "run_collector.ps1",
    )

    combined = "\n".join(
        read(path)
        for path in install_and_launch_files
    ).lower()

    assert "python.exe" not in combined
    assert "python " not in combined
    assert "aegisguardanalyzer.exe" in combined
    assert "aegisguardanalyzermtls.exe" in combined
    assert "aegisguardcollector.exe" in combined


def test_soc_dashboard_is_wired_to_real_product_api_contracts():
    source = read(DASHBOARD)

    for endpoint in (
        "fetch('/api/dashboard')",
        "fetch('/api/alerts')",
        "fetch('/api/events')",
        "fetch('/api/collectors')",
        "fetch('/api/intelligence?event_limit=500')",
        "fetch('/api/incidents')",
        "fetch('/api/response-actions')",
    ):
        assert endpoint in source


def test_soc_workflow_surfaces_mitre_ml_and_governed_response_state():
    dashboard = read(DASHBOARD)
    intelligence = read(INTELLIGENCE)

    assert "MITRE ATT&CK" in dashboard
    assert "mitre.technique_name || mitre.technique || 'Unknown'" in dashboard

    assert "Governed ML Runtime" in intelligence
    assert "Model Version" in intelligence
    assert "Feature Schema" in intelligence
    assert "Threat Prediction" in intelligence
    assert "Confidence" in intelligence

    assert "SIMULATED" in dashboard
    assert "EXECUTED" in dashboard


def test_simulated_and_executed_response_states_are_visually_distinct():
    source = read(DASHBOARD)

    simulated = "if (s === 'SIMULATED')"
    executed = "if (s === 'EXECUTED')"

    assert simulated in source
    assert executed in source
    assert source.index(simulated) != source.index(executed)

    simulated_line = next(
        line for line in source.splitlines()
        if simulated in line
    )
    executed_line = next(
        line for line in source.splitlines()
        if executed in line
    )

    assert "var(--orange)" in simulated_line
    assert "var(--green)" in executed_line


def test_loading_empty_and_error_states_do_not_fake_success():
    template = read(TEMPLATE)
    dashboard = read(DASHBOARD)
    intelligence = read(INTELLIGENCE)

    assert "WAITING FOR DATA" in template
    assert "No enterprise collectors are registered." in dashboard
    assert "AegisIntelligenceUI.renderError(error)" in dashboard
    assert "SNAPSHOT STALE" in intelligence
    assert "SNAPSHOT DEGRADED" in intelligence
    assert (
        "No structured MITRE ATT&amp;CK mapping is present"
        in intelligence
    )


def test_frontend_does_not_render_sensitive_collector_fingerprints():
    source = read(DASHBOARD)

    assert "credential_fingerprint" not in source
    assert "certificate_fingerprint" not in source


def test_bundle_security_contract_excludes_runtime_and_secret_material():
    builder = load_bundle_builder()

    for suffix in (
        ".key",
        ".pem",
        ".pfx",
        ".p12",
        ".crt",
        ".cer",
        ".db",
        ".sqlite",
        ".sqlite3",
        ".py",
        ".pyc",
        ".spec",
    ):
        assert suffix in builder.FORBIDDEN_SUFFIXES

    for name in (
        "config.json",
        "collector_state.db",
        "aegisguard.db",
    ):
        assert name in builder.FORBIDDEN_NAMES

    source = read(BUNDLE_BUILDER)

    for expected in (
        '"contains_runtime_database": False',
        '"contains_private_keys": False',
        '"contains_certificates": False',
        '"contains_customer_logs": False',
        '"contains_python_source": False',
    ):
        assert expected in source


def test_upgrade_and_rollback_preserve_programdata_runtime_state():
    upgrade = read(UPGRADE).lower()
    rollback = read(ROLLBACK).lower()

    assert "preserve_programdata" in upgrade
    assert "preserve_programdata" in rollback

    assert "runtimE_state_policy".lower() in upgrade
    assert "runtime_state_policy" in rollback


def test_supported_widths_and_keyboard_accessibility_are_present():
    source = read(ENTERPRISE_CSS)

    assert "@media (max-width: 900px)" in source
    assert "@media (max-width: 620px)" in source
    assert ":focus-visible" in source
    assert "@media (prefers-reduced-motion: reduce)" in source
