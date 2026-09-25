from pathlib import Path

from backend.deployment.windows_contract import (
    PACKAGING_SPEC_FILES,
    REQUIRED_DEPLOYMENT_FILES,
    deployment_layout,
    find_forbidden_packaging_literals,
)

ROOT = Path(__file__).resolve().parents[2]

def read(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")

def test_source_free_user_admin_spec_is_registered():
    relative = "backend/deployment/AegisGuardUserAdmin.spec"
    assert relative in REQUIRED_DEPLOYMENT_FILES
    assert relative in PACKAGING_SPEC_FILES
    assert (ROOT / relative).is_file()

def test_source_free_user_admin_spec_preserves_security_boundaries():
    source = read(ROOT / "backend/deployment/AegisGuardUserAdmin.spec")
    assert "backend.analyzer.user_admin" in source
    assert "backend.storage.user_auth" in source
    assert "backend.analyzer.database" in source
    assert "str(PROJECT_ROOT)" in source
    assert "uac_admin=True" in source
    assert find_forbidden_packaging_literals(source) == []

def test_bundle_contains_source_free_user_admin_executable():
    import importlib.util
    path = ROOT / "scripts/build_windows_offline_bundle.py"
    spec = importlib.util.spec_from_file_location("s12_bundle_builder", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    destinations = {
        destination for destination, _source in module.BUNDLE_PAYLOAD
    }
    assert "bin/AegisGuardUserAdmin.exe" in destinations

def test_analyzer_ui_installer_can_install_user_admin_cli():
    source = read(ROOT / "deploy/windows/install_analyzer_ui.ps1")
    assert "UserAdminExe" in source
    assert '"AegisGuardUserAdmin.exe"' in source
    assert "$InstalledUserAdmin" in source
    assert "Copy-Item" in source

def test_user_admin_keeps_password_off_command_line():
    source = read(ROOT / "backend/analyzer/user_admin.py")
    assert 'parser.add_argument("username")' in source
    assert '"--role"' in source
    assert "getpass.getpass" in source
    assert "--password" not in source

def test_deployment_layout_registers_source_free_user_admin():
    layout = deployment_layout()
    assert layout["analyzer"]["user_admin_binary"] == (
        r"%ProgramFiles%\AegisGuard\Analyzer"
        r"\AegisGuardUserAdmin.exe"
    )
