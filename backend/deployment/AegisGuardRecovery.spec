# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path


PROJECT_ROOT = Path.cwd()

ENTRY_POINT = (
    PROJECT_ROOT
    / "backend"
    / "deployment"
    / "recovery_cli.py"
)


a = Analysis(
    [str(ENTRY_POINT)],
    pathex=[
        str(PROJECT_ROOT),
    ],
    binaries=[],
    datas=[],
    hiddenimports=[
        "backend.deployment.enterprise_recovery",
        "backend.deployment.runtime_paths",
        "backend.storage.audit_integrity",
        "sqlite3",
        "json",
        "hashlib",
        "zipfile",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)


pyz = PYZ(
    a.pure
)


exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="AegisGuardRecovery",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
