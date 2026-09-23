# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path.cwd()

COLLECTOR_DIR = (
    PROJECT_ROOT
    / "backend"
    / "collector"
)

ENTRY_POINT = (
    COLLECTOR_DIR
    / "live_monitoring.py"
)


# ============================================================
# TZDATA
# ============================================================

tzdata_files = collect_data_files(
    "tzdata"
)


# ============================================================
# ANALYSIS
# ============================================================

a = Analysis(
    [
        str(ENTRY_POINT)
    ],

    pathex=[
        str(PROJECT_ROOT),
        str(PROJECT_ROOT / "backend"),
        str(COLLECTOR_DIR),
    ],

    binaries=[],

    # config.json is intentionally NOT bundled.
    # Frozen enterprise deployments load it from the external
    # ProgramData runtime directory or AEGISGUARD_COLLECTOR_CONFIG.
    datas=[
        *tzdata_files,
    ],

    hiddenimports=[
        # Collector modules
        "backend.collector",
        "backend.collector.live_monitoring",
        "backend.collector.parser",
        "backend.collector.detector",
        "backend.collector.config_loader",
        "backend.collector.durable_runtime",
        "backend.collector.state",
        "backend.collector.transport",
        "backend.collector.credential_store",
        "backend.deployment.runtime_paths",

        # Networking
        "requests",
        "urllib3",

        # Windows / system
        "platform",
        "subprocess",

        # Timezone support
        "zoneinfo",
        "tzdata",
    ],

    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)


# ============================================================
# PYZ
# ============================================================

pyz = PYZ(
    a.pure
)


# ============================================================
# SINGLE EXE
# ============================================================

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],

    name="AegisGuardCollector",

    # Required to read Windows Security Event Log.
    uac_admin=True,

    debug=False,
    bootloader_ignore_signals=False,
    strip=False,

    # Keep disabled for first stable build.
    upx=False,
    upx_exclude=[],

    runtime_tmpdir=None,

    # Keep console visible during testing.
    console=True,

    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)