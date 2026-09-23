"""Authenticated API for the AegisGuard unified incident platform."""

from __future__ import annotations

from flask import Blueprint, g, jsonify, request

from backend.analyzer.incident_service import (
    IncidentConflictError,
    IncidentNotFoundError,
    IncidentTransitionError,
    IncidentValidationError,
    add_incident_evidence,
    add_incident_note,
    assign_incident,
    get_incident,
    override_incident_status,
    transition_incident,
)


def _actor_user_id() -> str:
    user = getattr(g, "aegisguard_user", None) or {}
    return str(user.get("user_id") or "")


def _json_error(error, message, status_code):
    response = jsonify({
        "status": "error",
        "error": error,
        "message": message,
    })
    response.status_code = int(status_code)
    return response


def _service_error(exc):
    if isinstance(exc, IncidentNotFoundError):
        return _json_error(
            "incident_not_found",
            str(exc),
            404,
        )
    if isinstance(
        exc,
        (IncidentConflictError, IncidentTransitionError),
    ):
        return _json_error(
            "incident_conflict",
            str(exc),
            409,
        )
    return _json_error(
        "invalid_incident_request",
        str(exc),
        400,
    )


def create_incident_blueprint(connection_factory):
    blueprint = Blueprint(
        "aegisguard_incident_platform",
        __name__,
    )

    @blueprint.get("/api/incidents/<incident_id>")
    def incident_detail(incident_id):
        conn = connection_factory()
        try:
            try:
                incident = get_incident(
                    conn,
                    incident_id,
                )
            except IncidentNotFoundError as exc:
                return _service_error(exc)
        finally:
            conn.close()
        return jsonify({"incident": incident}), 200

    @blueprint.post("/api/incidents/<incident_id>/transition")
    def incident_transition(incident_id):
        payload = request.get_json(silent=True) or {}
        conn = connection_factory()
        try:
            try:
                incident = transition_incident(
                    conn,
                    incident_id=incident_id,
                    to_status=payload.get("to_status"),
                    actor_user_id=_actor_user_id(),
                    resolution_summary=payload.get(
                        "resolution_summary"
                    ),
                )
            except (
                IncidentValidationError,
                IncidentNotFoundError,
                IncidentConflictError,
                IncidentTransitionError,
            ) as exc:
                return _service_error(exc)
        finally:
            conn.close()
        return jsonify({"incident": incident}), 200

    @blueprint.post("/api/incidents/<incident_id>/assign")
    def incident_assign(incident_id):
        payload = request.get_json(silent=True) or {}
        conn = connection_factory()
        try:
            try:
                incident = assign_incident(
                    conn,
                    incident_id=incident_id,
                    assigned_user_id=payload.get(
                        "assigned_user_id"
                    ),
                    actor_user_id=_actor_user_id(),
                )
            except (
                IncidentValidationError,
                IncidentNotFoundError,
                IncidentConflictError,
            ) as exc:
                return _service_error(exc)
        finally:
            conn.close()
        return jsonify({"incident": incident}), 200

    @blueprint.post("/api/incidents/<incident_id>/notes")
    def incident_note(incident_id):
        payload = request.get_json(silent=True) or {}
        conn = connection_factory()
        try:
            try:
                note = add_incident_note(
                    conn,
                    incident_id=incident_id,
                    actor_user_id=_actor_user_id(),
                    note=payload.get("note"),
                )
            except (
                IncidentValidationError,
                IncidentNotFoundError,
            ) as exc:
                return _service_error(exc)
        finally:
            conn.close()
        return jsonify({"note": note}), 201

    @blueprint.post("/api/incidents/<incident_id>/evidence")
    def incident_evidence(incident_id):
        payload = request.get_json(silent=True) or {}
        conn = connection_factory()
        try:
            try:
                evidence = add_incident_evidence(
                    conn,
                    incident_id=incident_id,
                    actor_user_id=_actor_user_id(),
                    reference_type=payload.get(
                        "reference_type"
                    ),
                    reference_id=payload.get(
                        "reference_id"
                    ),
                    description=payload.get(
                        "description"
                    ),
                )
            except (
                IncidentValidationError,
                IncidentNotFoundError,
            ) as exc:
                return _service_error(exc)
        finally:
            conn.close()
        return jsonify({"evidence": evidence}), (
            200 if evidence.get("duplicate") else 201
        )

    @blueprint.post("/api/incidents/<incident_id>/override")
    def incident_override(incident_id):
        payload = request.get_json(silent=True) or {}
        conn = connection_factory()
        try:
            try:
                incident = override_incident_status(
                    conn,
                    incident_id=incident_id,
                    to_status=payload.get("to_status"),
                    actor_user_id=_actor_user_id(),
                    reason=payload.get("reason"),
                )
            except (
                IncidentValidationError,
                IncidentNotFoundError,
                IncidentConflictError,
                IncidentTransitionError,
            ) as exc:
                return _service_error(exc)
        finally:
            conn.close()
        return jsonify({"incident": incident}), 200

    return blueprint
