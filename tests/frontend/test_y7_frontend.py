from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INDEX = ROOT / "templates" / "index.html"
DASHBOARD = ROOT / "static" / "js" / "dashboard.js"
SHELL = ROOT / "static" / "js" / "frontend_shell.js"
ENTERPRISE_CSS = ROOT / "static" / "css" / "aegisguard-enterprise.css"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_enterprise_assets_are_loaded_by_dashboard_template():
    html = read(INDEX)
    assert "css/aegisguard-enterprise.css" in html
    assert "js/frontend_shell.js" in html


def test_sidebar_and_main_have_stable_accessibility_targets():
    html = read(INDEX)
    assert 'id="primarySidebar"' in html
    assert 'aria-label="AegisGuard primary navigation"' in html
    assert 'id="mainContent"' in html


def test_shell_adds_keyboard_navigation_and_aria_state():
    shell = read(SHELL)
    assert "ArrowDown" in shell
    assert "ArrowUp" in shell
    assert "aria-current" in shell
    assert "aria-controls" in shell
    assert "aria-hidden" in shell


def test_shell_is_idempotent():
    assert "__aegisEnterpriseShellInitialized" in read(SHELL)


def test_dashboard_has_exactly_one_dom_ready_handler():
    dashboard = read(DASHBOARD)
    assert dashboard.count("window.addEventListener('DOMContentLoaded'") == 1


def test_dashboard_initialization_is_idempotent():
    assert "__aegisDashboardInitialized" in read(DASHBOARD)


def test_dashboard_polling_is_not_aggressive_for_large_event_payload():
    dashboard = read(DASHBOARD)
    assert "setInterval(loadDashboardData, 15000)" in dashboard
    assert "setInterval(loadDeviceData, 30000)" in dashboard
    assert "setInterval(loadIncidentResponseData, 10000)" in dashboard
    assert "setInterval(loadDashboardData, 5000)" not in dashboard
    assert "setInterval(loadIncidentResponseData, 3000)" not in dashboard


def test_enterprise_css_supports_responsive_sidebar():
    css = read(ENTERPRISE_CSS)
    assert "@media (max-width: 900px)" in css
    assert "body.sidebar-open .sidebar" in css
    assert ".y7-sidebar-toggle" in css


def test_enterprise_css_supports_small_screens():
    css = read(ENTERPRISE_CSS)
    assert "@media (max-width: 620px)" in css
    assert "grid-template-columns: 1fr" in css


def test_enterprise_css_has_visible_keyboard_focus():
    css = read(ENTERPRISE_CSS)
    assert ":focus-visible" in css
    assert "outline: 2px solid var(--ag-focus)" in css


def test_enterprise_css_respects_reduced_motion():
    assert "@media (prefers-reduced-motion: reduce)" in read(ENTERPRISE_CSS)


def test_shell_does_not_make_security_api_calls():
    shell = read(SHELL)
    assert "fetch(" not in shell
    assert "XMLHttpRequest" not in shell


def test_y7_new_files_are_frontend_scoped():
    assert ENTERPRISE_CSS.parts[-3:] == ("static", "css", "aegisguard-enterprise.css")
    assert SHELL.parts[-3:] == ("static", "js", "frontend_shell.js")