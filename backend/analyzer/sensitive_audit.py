"""Audit instrumentation for sensitive human application operations."""

from __future__ import annotations

import re
from typing import Any, Optional

from flask import g, request

from backend.analyzer.audit_context import current_request_audit_context
from backend.storage.audit_integrity import (
    DEFAULT_AUDIT_RETENTION_DAYS,
    validate_retention_days,
)
from backend.storage.audit_log import record_audit_event


_RESPONSE_APPROVAL_RE = re.compile(
    r"^/api/response-actions/(?P<action_id>\d+)/approve$"
)
_INCIDENT_WORKFLOW_RE = re.compile(
    r"^/api/incidents/(?P<incident_id>[^/]+)/"
    r"(?P<operation>transition|assign|notes|evidence|override)$"
)


def _response_json(response) -> dict[str, Any]:
    try:
        value = response.get_json(silent=True)
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _request_json() -> dict[str, Any]:
    value = request.get_json(silent=True)
    return value if isinstance(value, dict) else {}


def _trusted_user() -> Optional[dict[str, Any]]:
    for attribute in (
        "aegisguard_user",
        "aegisguard_authenticated_user",
        "aegisguard_audit_user",
    ):
        value = getattr(g, attribute, None)
        if isinstance(value, dict) and value.get("user_id"):
            return value
    return None


def _outcome_for_status(status_code: int) -> str:
    code = int(status_code)
    if 200 <= code < 300:
        return "SUCCESS"
    if code in {401, 403, 429}:
        return "DENIED"
    return "FAILURE"


def _base_details(response) -> dict[str, Any]:
    user = _trusted_user()
    details = {
        "method": request.method.upper(),
        "path": request.path,
        "endpoint": request.endpoint,
        "status_code": int(response.status_code),
    }
    if user:
        details["role"] = str(user.get("role") or "").upper() or None
    return details


def _audit_spec(response) -> Optional[dict[str, Any]]:
    path = request.path
    method = request.method.upper()
    status = int(response.status_code)
    payload = _request_json()
    response_json = _response_json(response)
    user = _trusted_user()
    outcome = _outcome_for_status(status)
    details = _base_details(response)

    # Authentication lifecycle owns its own trust boundary and therefore must
    # be classified before generic authorization-denial handling.
    if path == "/api/auth/login" and method == "POST":
        username = str(payload.get("username") or "").strip().lower()
        details["username"] = username or None
        if user and outcome == "SUCCESS":
            return {
                "actor_type": "USER",
                "actor_user_id": user["user_id"],
                "action": "AUTH.LOGIN",
                "outcome": outcome,
                "target_type": "USER",
                "target_id": user["user_id"],
                "details": details,
            }
        return {
            "actor_type": "SYSTEM",
            "action": "AUTH.LOGIN",
            "outcome": outcome,
            "target_type": "USERNAME",
            "target_id": username or None,
            "details": details,
        }

    if path == "/api/auth/logout" and method == "POST":
        return {
            "actor_type": "USER" if user else "SYSTEM",
            "actor_user_id": user["user_id"] if user else None,
            "action": "AUTH.LOGOUT",
            "outcome": outcome,
            "target_type": "SESSION",
            "target_id": (
                str(user.get("session_id") or "").strip() or None
                if user
                else None
            ),
            "details": details,
        }

    # RBAC/CSRF failures happen before the route handler. The actor is a USER
    # only when the persistent session was successfully authenticated.
    error_code = str(response_json.get("error") or "")
    if error_code in {
        "authentication_required",
        "forbidden",
        "csrf_required",
    }:
        details["reason"] = error_code
        return {
            "actor_type": "USER" if user else "SYSTEM",
            "actor_user_id": user["user_id"] if user else None,
            "action": "AUTHORIZATION.DENIED",
            "outcome": "DENIED",
            "target_type": "API_PATH",
            "target_id": path,
            "details": details,
        }

    if method == "GET" and path == "/api/audit/events":
        return {
            "actor_type": "USER",
            "actor_user_id": user["user_id"],
            "action": "AUDIT.READ",
            "outcome": outcome,
            "target_type": "AUDIT_LOG",
            "target_id": "events",
            "details": details,
        }

    if method == "GET" and path == "/api/audit/integrity":
        return {
            "actor_type": "USER",
            "actor_user_id": user["user_id"],
            "action": "AUDIT.VERIFY",
            "outcome": outcome,
            "target_type": "AUDIT_LOG",
            "target_id": "integrity",
            "details": details,
        }

    if method != "POST":
        return None

    incident_workflow = _INCIDENT_WORKFLOW_RE.fullmatch(path)
    if incident_workflow:
        incident_id = incident_workflow.group("incident_id")
        operation = incident_workflow.group("operation")
        action_map = {
            "transition": "INCIDENT.TRANSITION",
            "assign": "INCIDENT.ASSIGN",
            "notes": "INCIDENT.NOTE_ADD",
            "evidence": "INCIDENT.EVIDENCE_ADD",
            "override": "INCIDENT.OVERRIDE",
        }
        if operation in {"transition", "override"}:
            details["to_status"] = str(
                payload.get("to_status") or ""
            ).upper() or None
        elif operation == "assign":
            details["assigned_user_id"] = (
                str(payload.get("assigned_user_id") or "").strip()
                or None
            )
        elif operation == "evidence":
            details["reference_type"] = (
                str(payload.get("reference_type") or "").upper()
                or None
            )

        return {
            "actor_type": "USER",
            "actor_user_id": user["user_id"],
            "action": action_map[operation],
            "outcome": outcome,
            "target_type": "INCIDENT",
            "target_id": incident_id,
            "details": details,
        }

    if path == "/api/incidents/settings":
        changed_keys = sorted(
            str(key)
            for key in payload.keys()
            if key in {
                "auto_response_enabled",
                "simulation_mode",
                "soar_dry_run",
                "soar_allow_private_ip_blocking",
                "soar_mode",
                "soar_auto_min_score",
                "soar_allowlist",
            }
        )
        details["changed_keys"] = changed_keys
        return {
            "actor_type": "USER",
            "actor_user_id": user["user_id"],
            "action": "SETTINGS.UPDATE",
            "outcome": outcome,
            "target_type": "SETTINGS",
            "target_id": "response-security",
            "details": details,
        }

    approval = _RESPONSE_APPROVAL_RE.fullmatch(path)
    if approval:
        action_id = approval.group("action_id")
        denial_reason = str(
            response_json.get("error") or ""
        ).strip()
        if denial_reason:
            details["reason"] = denial_reason
        return {
            "actor_type": "USER",
            "actor_user_id": user["user_id"],
            "action": "RESPONSE.APPROVE",
            "outcome": outcome,
            "target_type": "RESPONSE_ACTION",
            "target_id": action_id,
            "details": details,
        }

    if path == "/api/soar/block-ip":
        ip_value = str(payload.get("ip") or "").strip() or None
        incident_id = str(payload.get("incident_id") or "").strip() or None
        details["incident_id"] = incident_id
        return {
            "actor_type": "USER",
            "actor_user_id": user["user_id"],
            "action": "SOAR.BLOCK_IP",
            "outcome": outcome,
            "target_type": "IP_ADDRESS",
            "target_id": ip_value,
            "details": details,
        }

    if path == "/api/soar/unblock-ip":
        ip_value = str(payload.get("ip") or "").strip() or None
        details["response_action_id"] = response_json.get("id")
        details["rollback_status"] = response_json.get(
            "rollback_status"
        )
        return {
            "actor_type": "USER",
            "actor_user_id": user["user_id"],
            "action": "SOAR.UNBLOCK_IP",
            "outcome": outcome,
            "target_type": "IP_ADDRESS",
            "target_id": ip_value,
            "details": details,
        }

    if path == "/api/incidents/execute":
        incident_id = str(payload.get("incident_id") or "").strip() or None
        enforce = bool(payload.get("enforce", False))
        details["requested_live_execution"] = enforce
        return {
            "actor_type": "USER",
            "actor_user_id": user["user_id"],
            "action": (
                "INCIDENT.LIVE_EXECUTION_DENIED"
                if enforce and outcome == "DENIED"
                else "INCIDENT.SIMULATE"
            ),
            "outcome": outcome,
            "target_type": "INCIDENT",
            "target_id": incident_id,
            "details": details,
        }

    if path == "/api/incidents/reset":
        return {
            "actor_type": "USER",
            "actor_user_id": user["user_id"],
            "action": "INCIDENT.RESET",
            "outcome": outcome,
            "target_type": "INCIDENT_SET",
            "target_id": "all",
            "details": details,
        }

    return None


def install_sensitive_operation_auditing(
    app,
    connection_factory,
    *,
    retention_days=DEFAULT_AUDIT_RETENTION_DAYS,
):
    """Persist one audit event for each classified sensitive operation.

    Audit writer failures are intentionally not swallowed. A security-sensitive
    request must not appear successful to the caller when its audit record
    could not be persisted.
    """

    retention = validate_retention_days(retention_days)

    @app.after_request
    def audit_sensitive_operation(response):
        spec = _audit_spec(response)
        if spec is None:
            return response

        context = current_request_audit_context()
        conn = connection_factory()
        try:
            record_audit_event(
                conn,
                actor_type=spec["actor_type"],
                actor_user_id=spec.get("actor_user_id"),
                action=spec["action"],
                outcome=spec["outcome"],
                target_type=spec.get("target_type"),
                target_id=spec.get("target_id"),
                peer_ip=context["peer_ip"],
                correlation_id=context["correlation_id"],
                details=spec.get("details"),
                retention_days=retention,
            )
        finally:
            conn.close()

        return response

    return audit_sensitive_operation
