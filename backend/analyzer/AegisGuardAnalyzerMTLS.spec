# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path


PROJECT_ROOT = Path.cwd()

ENTRY_POINT = (
    PROJECT_ROOT
    / "backend"
    / "analyzer"
    / "mtls_server.py"
)

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

# The legacy incremental classifier still uses these bundled
# artifacts. They are separate from the governed promoted-model
# registry, which remains external writable runtime state.
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
    [str(ENTRY_POINT)],

    pathex=[
        str(PROJECT_ROOT),
    ],

    binaries=[],

    datas=[
        (
            str(TEMPLATES_DIR),
            "templates",
        ),
        (
            str(STATIC_DIR),
            "static",
        ),
        (
            str(MITRE_FILE),
            r"backend\analyzer\ingestion\mitre",
        ),
        (
            str(RESPONSE_PLAYBOOKS),
            r"backend\analyzer\response",
        ),
        (
            str(MODEL_FILE),
            r"backend\ML Aegis\ml",
        ),
        (
            str(ENCODER_FILE),
            r"backend\ML Aegis\ml",
        ),
    ],

    hiddenimports=[
        "backend.analyzer.app",
        "backend.analyzer.mtls_server",
        "backend.analyzer.database",
        "backend.analyzer.service",
        "backend.analyzer.incident_response",
        "backend.analyzer.incident_enricher",
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
        "backend.analyzer.ingestion",
        "backend.analyzer.ingestion.classifier",
        "backend.analyzer.ingestion.import_merge",
        "backend.analyzer.ingestion.correlation_engine",
        "backend.analyzer.ingestion.mitre_mapper",
        "backend.analyzer.soar",
        "backend.analyzer.soar.engine",
        "backend.analyzer.soar.policies",
        "backend.analyzer.soar.firewall",
        "backend.deployment.runtime_paths",
        "backend.platform.data_privacy",
        "backend.platform.sqlite_security",
        "mysql.merge_log_sql",
        "joblib",
        "pandas",
        "sklearn",
        "sklearn.ensemble",
        "sklearn.preprocessing",
        "flask",
        "jinja2",
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

    name="AegisGuardAnalyzerMTLS",

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
