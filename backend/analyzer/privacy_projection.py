"""Role-aware privacy projection for human-facing AegisGuard APIs."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from flask import g, request

from backend.platform.data_privacy import redact_sensitive_mapping


_PROTECTED_READ_PREFIXES = (
    "/api/events",
    "/api/alerts",
    "/api/devices",
    "/api/incidents",
    "/api/response-actions",
    "/api/soar",
    "/api/collectors",
    "/api/intelligence",
)

_FULL_TELEMETRY_ROLES = frozenset({
    "ADMINISTRATOR",
    "ANALYST",
})


def _project_value(value: Any, *, redact_security_sensitive: bool) -> Any:
    if isinstance(value, Mapping):
        return redact_sensitive_mapping(
            value,
            redact_security_sensitive=redact_security_sensitive,
        )
    if isinstance(value, (list, tuple)):
        return [
            _project_value(
                item,
                redact_security_sensitive=redact_security_sensitive,
            )
            for item in value
        ]
    return value


def _should_project(path: str, method: str) -> bool:
    path_value = str(path or "")
    method_value = str(method or "GET").upper()
    return (
        method_value in {"GET", "HEAD"}
        and any(
            path_value.startswith(prefix)
            for prefix in _PROTECTED_READ_PREFIXES
        )
    )


def install_application_privacy_projection(app):
    """Redact lower-trust SOC API responses without changing stored data."""

    @app.after_request
    def project_application_response(response):
        if not _should_project(request.path, request.method):
            return response
        if not response.is_json:
            return response

        user = getattr(g, "aegisguard_user", None) or {}
        role = str(user.get("role") or "").upper()
        if not role:
            return response

        payload = response.get_json(silent=True)
        if payload is None:
            return response

        projected = _project_value(
            payload,
            redact_security_sensitive=(
                role not in _FULL_TELEMETRY_ROLES
            ),
        )

        response.set_data(app.json.dumps(projected))
        response.mimetype = "application/json"
        return response

    return project_application_response
