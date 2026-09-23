"""Server-generated request correlation context for audit events."""

from __future__ import annotations

import uuid

from flask import g, request


AUDIT_CORRELATION_HEADER = "X-AegisGuard-Correlation-ID"


def new_correlation_id() -> str:
    return "req-" + uuid.uuid4().hex


def install_request_correlation(app, *, correlation_id_factory=None):
    """Attach a server-generated correlation ID to every Flask request.

    Incoming correlation headers are deliberately not trusted as the canonical
    audit identity. The server creates the value and returns it to the caller.
    """

    factory = correlation_id_factory or new_correlation_id

    @app.before_request
    def assign_audit_correlation_id():
        correlation_id = str(factory() or "").strip()
        if not correlation_id:
            raise RuntimeError("correlation ID factory returned an empty value")
        g.aegisguard_correlation_id = correlation_id

    @app.after_request
    def expose_audit_correlation_id(response):
        correlation_id = getattr(
            g,
            "aegisguard_correlation_id",
            None,
        )
        if correlation_id:
            response.headers[
                AUDIT_CORRELATION_HEADER
            ] = correlation_id
        return response

    return assign_audit_correlation_id


def current_request_audit_context() -> dict[str, str | None]:
    """Return trusted request metadata for later S5 audit hooks."""

    return {
        "peer_ip": request.remote_addr,
        "correlation_id": getattr(
            g,
            "aegisguard_correlation_id",
            None,
        ),
    }
