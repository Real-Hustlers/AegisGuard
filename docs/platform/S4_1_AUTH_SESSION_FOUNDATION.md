# S4-1 — Application Authentication and Session Foundation

S4-1 introduces human-user authentication without changing collector/device
authentication and without yet protecting the existing dashboard or
intelligence routes.

## Trust boundary

Collector endpoints continue to use the S3 device trust path:

```text
/api/collector/v1/*
```

Human users use a separate application-session path:

```text
POST /api/auth/login
GET  /api/auth/me
POST /api/auth/logout
```

A collector credential or client certificate is never accepted as an
application-user session.

## User provisioning

There is deliberately no unauthenticated HTTP endpoint for creating the first
administrator.

Operators provision users locally:

```powershell
python -m backend.analyzer.user_admin <username> --role ADMINISTRATOR
```

The password is read with `getpass` and never appears in process arguments.

There is no default username/password in the repository.

## Password storage

Passwords use Python's standard-library `hashlib.scrypt` with:

- random 128-bit salt;
- N = 16384;
- r = 8;
- p = 1;
- 256-bit derived key.

The database stores only the encoded scrypt verifier.

## Sessions

Login creates a cryptographically random opaque session token.

The browser receives the raw token only in an HttpOnly cookie. SQLite stores
only the SHA-256 token fingerprint.

Session records are persistent and contain:

- session ID;
- user ID;
- token fingerprint;
- creation time;
- last-seen time;
- absolute expiry;
- revocation time;
- peer IP;
- user agent.

Inactive users invalidate existing sessions.

## Cookie controls

The session cookie is:

- HttpOnly;
- SameSite=Strict;
- Path=/;
- Secure by default in the production application.

For explicit local HTTP development only, operators may set:

```text
AEGISGUARD_SESSION_COOKIE_SECURE=false
```

The default session lifetime is eight hours and can be configured using:

```text
AEGISGUARD_SESSION_TTL_SECONDS
```

## Scope boundary

S4-1 does **not** yet place authorization requirements on dashboard,
intelligence, incident, or SOAR routes. That is S4-2.

This sequencing avoids breaking the existing frontend before user-session
awareness and RBAC rules are introduced.

S4-3 will add the remaining browser/session hardening required before the
state-changing application APIs are considered fully protected.
