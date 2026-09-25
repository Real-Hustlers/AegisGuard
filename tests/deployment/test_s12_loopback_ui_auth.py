from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


def test_loopback_http_runner_allows_session_cookie_over_local_http():
    source = read(
        ROOT / "deploy/windows/run_analyzer_ui.ps1"
    )

    assert (
        '$env:AEGISGUARD_SESSION_COOKIE_SECURE = "false"'
        in source
    )

    assert '"127.0.0.1"' in source
    assert '"localhost"' in source
    assert '"::1"' in source

    assert (
        "Analyzer UI BindHost must be loopback-only."
        in source
    )


def test_authentication_default_remains_secure():
    source = read(
        ROOT / "backend/analyzer/auth_api.py"
    )

    assert "cookie_secure=True" in source
    assert "secure=bool(cookie_secure)" in source


def test_shared_app_default_remains_secure():
    source = read(
        ROOT / "backend/analyzer/app.py"
    )

    assert '"AEGISGUARD_SESSION_COOKIE_SECURE"' in source
    assert '"true"' in source
