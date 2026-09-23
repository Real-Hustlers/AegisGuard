AegisGuard Enterprise Windows build notes
==========================================

Run all build commands from the repository root.

Analyzer
--------

Build with:

    python -m PyInstaller app.spec

Collector
---------

Build with:

    python -m PyInstaller backend/collector/AegisGuardCollector.spec

The Collector configuration is intentionally external to the executable.

Enterprise deployment layout
----------------------------

Program binaries belong under:

    %ProgramFiles%\AegisGuard\

Writable runtime data belongs under:

    %ProgramData%\AegisGuard\

Analyzer runtime data includes:

    Analyzer\aegisguard.db
    Analyzer\ml_registry\

Collector runtime data includes:

    Collector\config.json
    Collector\collector_state.db

TLS certificates, CA material, and private-key references remain external
runtime configuration under the protected ProgramData deployment area.

Do not bundle or commit:

- collector credentials
- enrollment tokens
- recovery tokens
- private keys
- production certificates
- runtime SQLite databases
- customer log data

Current deployment helpers
--------------------------

Existing Windows deployment helpers are under:

    deploy\windows\

The repository currently contains:

    configure_collector_mtls.ps1
    install_analyzer_mtls.ps1
    run_analyzer_mtls.ps1

S10 hardens these existing deployment paths rather than introducing a
parallel security or trust implementation.

Validation
----------

Run:

    python scripts/run_s13a_benchmark.py --help

for the existing performance harness, and:

    python scripts/validate_windows_deployment.py

for the S10 Windows deployment-source preflight.

The preflight is static. It does not install services, open firewall rules,
generate credentials, or execute response functionality.

Packaged Analyzer mTLS listener
-------------------------------

Build the dedicated collector-facing listener with:

    python -m PyInstaller backend/analyzer/AegisGuardAnalyzerMTLS.spec

This produces:

    dist\AegisGuardAnalyzerMTLS.exe

The packaged listener uses the existing AegisGuard production mTLS server.
It does not implement a second TLS or certificate-validation path.

Writable Analyzer state must live outside Program Files.

Default frozen location:

    %ProgramData%\AegisGuard\Analyzer

Optional explicit override:

    AEGISGUARD_DATA_DIR

The mTLS Windows startup scripts now execute the packaged Analyzer listener
directly and do not require Python or a source checkout on the deployed host.
