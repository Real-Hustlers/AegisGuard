AegisGuard Enterprise Windows build notes
==========================================

Run all build commands from the repository root.

Analyzer
--------

Build with:

    python -m PyInstaller app.spec

Source-free user administration
-------------------------------

Build the existing local application-user provisioning CLI with:

    python -m PyInstaller backend/deployment/AegisGuardUserAdmin.spec

This produces:

    dist\AegisGuardUserAdmin.exe

The CLI reuses the existing AegisGuard user-authentication storage and
validation implementation. It prompts for the password securely and does not
accept the password as a command-line argument.

For the default installed Analyzer data location, run from an elevated
operator shell:

    AegisGuardUserAdmin.exe <username> --role ADMINISTRATOR

The Analyzer UI installer accepts -UserAdminExe to copy this source-free
operator CLI alongside AegisGuardAnalyzer.exe under Program Files.

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
    Analyzer\data\ml_registry\

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

Packaged Collector deployment
-----------------------------

Build:

    python -m PyInstaller backend/collector/AegisGuardCollector.spec

The Collector executable is installed under:

    %ProgramFiles%\AegisGuard\Collector

Writable configuration and durable Collector state live under:

    %ProgramData%\AegisGuard\Collector

The supported frozen configuration path can be overridden with:

    AEGISGUARD_COLLECTOR_CONFIG

The enterprise Collector installer requires an HTTPS Analyzer base URL and
configures the existing authenticated durable Collector endpoints with mTLS.

The installer deliberately does not persist enrollment or recovery bootstrap
tokens.

A fresh Collector installation therefore remains disabled by default until
the deployment operator provisions the existing one-time bootstrap trust
through the approved runtime mechanism.

S7-D local raw-output policy is preserved:

    raw_output_enabled = false

Optional local raw-log copies remain disabled unless explicitly enabled later
through the governed Collector configuration.
