"""Administrator-only audit evidence API."""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from backend.storage.audit_integrity import (
    DEFAULT_AUDIT_RETENTION_DAYS,
    validate_retention_days,
    verify_audit_chain,
)
from backend.storage.audit_query import (
    AuditQueryError,
    query_audit_events,
)


def create_audit_blueprint(
    connection_factory,
    *,
    retention_days=DEFAULT_AUDIT_RETENTION_DAYS,
):
    blueprint = Blueprint("aegisguard_audit", __name__)
    retention = validate_retention_days(retention_days)

    @blueprint.get("/api/audit/events")
    def audit_events():
        try:
            limit = int(request.args.get("limit", "100"))
        except ValueError:
            return jsonify({
                "status": "error",
                "message": "limit must be an integer",
            }), 400

        conn = connection_factory()
        try:
            try:
                events = query_audit_events(
                    conn,
                    limit=limit,
                    action=request.args.get("action"),
                    outcome=request.args.get("outcome"),
                    actor_type=request.args.get("actor_type"),
                    correlation_id=request.args.get("correlation_id"),
                    target_id=request.args.get("target_id"),
                )
            except AuditQueryError as exc:
                return jsonify({
                    "status": "error",
                    "message": str(exc),
                }), 400
        finally:
            conn.close()

        return jsonify({
            "events": events,
            "count": len(events),
            "limit": limit,
        }), 200

    @blueprint.get("/api/audit/integrity")
    def audit_integrity():
        conn = connection_factory()
        try:
            result = verify_audit_chain(conn)
        finally:
            conn.close()

        result["retention_days"] = retention
        return jsonify(result), 200

    return blueprint
