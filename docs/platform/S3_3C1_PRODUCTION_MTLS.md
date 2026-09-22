# S3-3C1 — Production mTLS boundary

Use the dedicated analyzer listener:

```powershell
python -m backend.analyzer.mtls_server
```

Required environment variables:

- `AEGISGUARD_TLS_CERT_FILE`
- `AEGISGUARD_TLS_KEY_FILE`
- `AEGISGUARD_TLS_CLIENT_CA_FILE`

Optional:

- `AEGISGUARD_TLS_BIND_HOST` (default `0.0.0.0`)
- `AEGISGUARD_TLS_PORT` (default `5443`)

Security properties:

- TLS minimum: TLS 1.2
- Client certificate required with `ssl.CERT_REQUIRED`
- Client certificate must chain to the configured client CA
- WSGI certificate identity comes only from the verified TLS socket
- Direct Flask startup refuses mTLS mode

S3-3C2 still covers Windows service/deployment wiring and real certificate
E2E validation. Do not commit private keys, certificates, enrollment tokens,
runtime databases, or other deployment secrets.
