# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['backend\\analyzer\\app.py'],

    pathex=[
        '.',
        'backend\\analyzer'
    ],

    binaries=[],

    datas=[
        # ====================================================
        # FLASK FRONTEND
        # ====================================================

        (
            r'C:\Users\saran\makethon\templates',
            'templates'
        ),

        (
            r'C:\Users\saran\makethon\static',
            'static'
        ),

        # ====================================================
        # DATABASE
        # ====================================================

        (
            r'C:\Users\saran\makethon\mysql\aegisguard.db',
            'mysql'
        ),

        # ====================================================
        # MITRE
        # ====================================================

        (
            r'C:\Users\saran\makethon\backend\analyzer\ingestion\mitre\mitre_mapping.json',
            r'backend\analyzer\ingestion\mitre'
        ),

        # ====================================================
        # RESPONSE PLAYBOOKS
        # ====================================================

        (
            r'C:\Users\saran\makethon\backend\analyzer\response\response_playbooks.json',
            'response'
        ),
    ],

    hiddenimports=[
        # Response
        'response',
        'response.playbook_loader',

        # Backend
        'backend.analyzer.incident_response',
        'backend.analyzer.incident_enricher',
        'backend.analyzer.service',
        'backend.analyzer.database',

        # Ingestion
        'backend.analyzer.ingestion.classifier',
        'backend.analyzer.ingestion.import_merge',
        'backend.analyzer.ingestion.correlation_engine',
        'backend.analyzer.ingestion.mitre_mapper',

        # MySQL folder / SQLite importer
        'backend.analyzer.mysql.merge_log_sql',
    ],

    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],

    name='app',

    debug=False,

    bootloader_ignore_signals=False,
    strip=False,

    # For debugging, I recommend disabling UPX first
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