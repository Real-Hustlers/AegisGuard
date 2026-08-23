# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

PROJECT_ROOT = Path.cwd()

ANALYZER_APP = PROJECT_ROOT / "backend" / "analyzer" / "app.py"

TEMPLATES_DIR = PROJECT_ROOT / "templates"
STATIC_DIR = PROJECT_ROOT / "static"

MITRE_FILE = (
    PROJECT_ROOT
    / "backend"
    / "analyzer"
    / "ingestion"
    / "mitre"
    / "mitre_mapping.json"
)

RESPONSE_PLAYBOOKS = (
    PROJECT_ROOT
    / "backend"
    / "analyzer"
    / "response"
    / "response_playbooks.json"
)

MODEL_FILE = (
    PROJECT_ROOT
    / "backend"
    / "ML Aegis"
    / "ml"
    / "model.pkl"
)

ENCODER_FILE = (
    PROJECT_ROOT
    / "backend"
    / "ML Aegis"
    / "ml"
    / "label_encoder.pkl"
)


a = Analysis(
    [str(ANALYZER_APP)],

    pathex=[
        str(PROJECT_ROOT),
        str(PROJECT_ROOT / "backend" / "analyzer"),
        str(PROJECT_ROOT / "backend"),
    ],

    binaries=[],

    datas=[
        # ====================================================
        # FLASK FRONTEND
        # ====================================================

        (
            str(TEMPLATES_DIR),
            "templates"
        ),

        (
            str(STATIC_DIR),
            "static"
        ),

        # ====================================================
        # MITRE DATA
        # ====================================================

        (
            str(MITRE_FILE),
            r"backend\analyzer\ingestion\mitre"
        ),

        # ====================================================
        # RESPONSE PLAYBOOKS
        # ====================================================

        (
            str(RESPONSE_PLAYBOOKS),
            r"backend\analyzer\response"
        ),

        # ====================================================
        # ML MODEL
        # ====================================================

        (
            str(MODEL_FILE),
            r"backend\ML Aegis\ml"
        ),

        (
            str(ENCODER_FILE),
            r"backend\ML Aegis\ml"
        ),
    ],

    hiddenimports=[
        # ====================================================
        # ANALYZER
        # ====================================================

        "backend.analyzer.app",
        "backend.analyzer.database",
        "backend.analyzer.service",
        "backend.analyzer.incident_response",
        "backend.analyzer.incident_enricher",
        "backend.analyzer.soar",
        "backend.analyzer.soar.engine",
        "backend.analyzer.soar.policies",
        "backend.analyzer.soar.firewall",

        # ====================================================
        # INGESTION
        # ====================================================

        "backend.analyzer.ingestion",
        "backend.analyzer.ingestion.classifier",
        "backend.analyzer.ingestion.import_merge",
        "backend.analyzer.ingestion.correlation_engine",
        "backend.analyzer.ingestion.mitre_mapper",

        # ====================================================
        # DATABASE IMPORTER
        # ====================================================

        "mysql.merge_log_sql",

        # ====================================================
        # ML / DATA
        # ====================================================

        "joblib",
        "pandas",
        "sklearn",
        "sklearn.ensemble",
        "sklearn.preprocessing",

        # ====================================================
        # FLASK
        # ====================================================

        "flask",
        "jinja2",

        # ====================================================
        # SQLITE
        # ====================================================

        "sqlite3",
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

    name="AegisGuardAnalyzer",

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
