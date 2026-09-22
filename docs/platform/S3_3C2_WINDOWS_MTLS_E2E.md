# S3-3C2 — Windows mTLS deployment and real E2E proof

S3-3C2 completes the production mTLS transport gate started by S3-3C1.

## Windows analyzer startup

The repository now includes:

- `deploy/windows/run_analyzer_mtls.ps1`
- `deploy/windows/install_analyzer_mtls.ps1`

The installer registers an elevated startup scheduled task that launches:

```text
python -m backend.analyzer.mtls_server
```

The task runs as `SYSTEM`, matching the existing Windows startup-task model.
Certificate/key **paths** are passed to the runner. Certificate or private-key
contents and bootstrap secrets are not embedded in the task command.

The installer can optionally create an inbound Windows Firewall rule for the
configured TLS port with `-OpenFirewall`.

## Collector configuration

Use:

```text
deploy/windows/configure_collector_mtls.ps1
```

The script requires an HTTPS analyzer base URL and writes all durable collector
endpoints:

- `/api/collector/v1/enroll`
- `/api/collector/v1/batches`
- `/api/collector/v1/rotate`
- `/api/collector/v1/recover`
- `/api/collector/v1/certificate/rotate`

It also enables authenticated mode and mTLS and stores only filesystem paths to:

- analyzer CA bundle
- collector client certificate
- collector client private key

It does **not** write enrollment/recovery tokens, device credentials,
certificate bytes, or private-key bytes into `config.json`.

## Bootstrap-secret boundary

Enrollment and recovery bootstrap secrets remain runtime deployment secrets.
They are deliberately not persisted by these scripts or placed on a scheduled
task command line. A production deployment must inject them into the analyzer
or collector service identity only for the operation that needs them.

## Real mTLS E2E

`tests/platform/test_production_mtls_e2e.py` creates an ephemeral test PKI in a
temporary directory using OpenSSL and starts the real Werkzeug TLS listener
plus the real collector blueprint.

The test proves:

1. a client certificate signed by the trusted CA can enroll;
2. the enrolled certificate can receive a durable HTTP 202 batch ACK;
3. a different certificate signed by the same trusted CA completes TLS but is
   rejected by AegisGuard certificate identity binding;
4. a client with no certificate is rejected during the TLS handshake;
5. a client certificate signed by a rogue CA is rejected during the TLS
   handshake.

All generated test keys and certificates exist only in a temporary directory
and are deleted when the test completes.

## Certificate material

The repository `.gitignore` blocks common certificate/private-key extensions:

- `*.pem`
- `*.key`
- `*.crt`
- `*.cer`
- `*.pfx`
- `*.p12`

Do not override these protections to commit deployment keys or certificates.
