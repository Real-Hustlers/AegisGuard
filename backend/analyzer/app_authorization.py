"""Application-session authorization and role-based access control."""

from __future__ import annotations

from flask import g, jsonify, request

from backend.analyzer.auth_api import AUTH_SESSION_COOKIE
from backend.storage.user_auth import (
    SessionAuthenticationError,
    authenticate_session,
)


ROLE_ADMINISTRATOR = "ADMINISTRATOR"
ROLE_ANALYST = "ANALYST"
ROLE_VIEWER = "VIEWER"

ALL_APPLICATION_ROLES = frozenset({
    ROLE_ADMINISTRATOR,
    ROLE_ANALYST,
    ROLE_VIEWER,
})

# Human application RBAC must never be layered onto the independent S3
# collector/device trust path.
_DEVICE_API_PREFIX = "/api/collector/v1/"
_LEGACY_DEVICE_UPLOAD_PATH = "/api/upload_logs"
_AUTH_API_PREFIX = "/api/auth/"

# The existing endpoint is simulation-only: app.py rejects enforce=True and
# directs live response actions through the constrained SOAR endpoints.
_ANALYST_MUTATION_PATHS = frozenset({
    "/api/incidents/execute",
})


def _json_error(error, message, status_code):
    response = jsonify({
        "status": "error",
        "error": error,
        "message": message,
    })
    response.status_code = int(status_code)
    return response


def required_roles_for_request(path: str, method: str):
    """Return allowed application roles, or None when S4 RBAC does not apply.

    Policy:
      * auth APIs manage their own authentication lifecycle;
      * collector/device APIs remain on the separate S3 trust boundary;
      * the legacy upload path is retained as a device-ingestion compatibility
        surface and is not reclassified as a human API by S4;
      * application reads are available to all authenticated roles;
      * incident simulation is available to analysts and administrators;
      * all other application mutations default to administrator-only.
    """

    path_value = str(path or "")
    method_value = str(method or "GET").upper()

    if method_value == "OPTIONS":
        return None

    if path_value.startswith(_AUTH_API_PREFIX):
        return None

    if path_value.startswith(_DEVICE_API_PREFIX):
        return None

    if path_value == _LEGACY_DEVICE_UPLOAD_PATH:
        return None

    if not path_value.startswith("/api/"):
        return None

    if method_value in {"GET", "HEAD"}:
        return ALL_APPLICATION_ROLES

    if path_value in _ANALYST_MUTATION_PATHS:
        return frozenset({
            ROLE_ADMINISTRATOR,
            ROLE_ANALYST,
        })

    return frozenset({ROLE_ADMINISTRATOR})


def install_application_authorization(app, connection_factory):
    """Install fail-closed application-session RBAC on a Flask app."""

    @app.before_request
    def enforce_application_authorization():
        # Preserve Flask's normal 404 behavior for unmatched paths.
        if request.url_rule is None:
            return None

        allowed_roles = required_roles_for_request(
            request.path,
            request.method,
        )
        if allowed_roles is None:
            return None

        token = request.cookies.get(AUTH_SESSION_COOKIE)
        if not token:
            return _json_error(
                "authentication_required",
                "authentication required",
                401,
            )

        conn = connection_factory()
        try:
            try:
                session = authenticate_session(conn, token)
            except SessionAuthenticationError:
                return _json_error(
                    "authentication_required",
                    "authentication required",
                    401,
                )
        finally:
            conn.close()

        role = str(session.get("role") or "").upper()
        if role not in allowed_roles:
            return _json_error(
                "forbidden",
                "insufficient role",
                403,
            )

        # Downstream application handlers may use this identity in later gates
        # (audit, incident ownership, response governance) without trusting
        # client-supplied identity fields.
        g.aegisguard_user = {
            "user_id": session["user_id"],
            "username": session["username"],
            "role": role,
            "session_id": session["session_id"],
        }
        return None

    return enforce_application_authorization
