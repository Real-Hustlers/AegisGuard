# S4-3 — Session Hardening and Final Application Security Closure

S4-3 completes the human application-security phase. It does not change the
S3 collector/device trust model and does not implement S5 audit logging.

## CSRF protection

Human state-changing application APIs require:

```text
X-AegisGuard-CSRF: <per-session token>
```

The CSRF token is deterministically derived from the high-entropy opaque
session token using HMAC-SHA-256 and a fixed domain-separation string.

The session token remains in an HttpOnly cookie. The application returns the
derived CSRF token from login and `/api/auth/me`.

No second reusable session secret is stored in SQLite.

Authorization order is:

1. authenticate session;
2. enforce role;
3. enforce CSRF for authorized state-changing human requests.

`POST /api/auth/logout` also requires the CSRF token when a session cookie is
present.

Collector/device endpoints remain outside human CSRF and RBAC.

## Idle timeout

The existing absolute session lifetime remains eight hours by default.

S4-3 adds a default 30-minute idle timeout using the existing persistent
`sessions.last_seen_at` field.

Configuration:

```text
AEGISGUARD_SESSION_IDLE_TIMEOUT_SECONDS
```

## Persistent login throttling

Platform schema v8 adds:

```text
auth_login_throttle
```

The throttle bucket is keyed by normalized username + direct peer IP.

Defaults:

- 5 failed attempts;
- 5-minute failure window;
- 5-minute block.

Configuration:

```text
AEGISGUARD_LOGIN_FAILURE_LIMIT
AEGISGUARD_LOGIN_WINDOW_SECONDS
AEGISGUARD_LOGIN_BLOCK_SECONDS
```

Throttle state is SQLite-backed, so application restart does not reset an
active block. A successful login clears the matching bucket.

## Browser security headers

AegisGuard emits:

```text
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=()
Content-Security-Policy: frame-ancestors 'none'; object-src 'none'; base-uri 'self'
```

HSTS is emitted only for requests Flask considers secure.

The CSP deliberately avoids restrictive `script-src` / `style-src` directives
until the existing offline frontend removes or nonces inline code.

## Completion

S4 is complete only after focused tests, full regression, maintainer review,
merge to `product/integration`, and contributor-branch synchronization.

S5 owns immutable application audit events and is intentionally not folded
into this gate.
