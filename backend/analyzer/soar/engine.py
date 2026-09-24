"""SQLite-audited SOAR decision engine for safe Analyzer-side IP blocking."""

import json
import logging
from datetime import datetime, timezone

from .firewall import FirewallError, WindowsFirewall, rule_name_for_ip
from .policies import ResponsePolicy


LOG = logging.getLogger(__name__)


class ApprovalDeniedError(PermissionError):
    """Raised when a response approval violates governance policy."""

    def __init__(self, code, message):
        self.code = str(code)
        super().__init__(str(message))


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class SoarEngine:
    def __init__(self, conn, firewall=None, policy=None):
        self.conn = conn
        self.policy = policy or ResponsePolicy(self._settings())
        # Upload-peer addresses identify actual Collectors. They are protected
        # just like the Analyzer itself, without assuming event source_ip is a
        # Collector address.
        try:
            self.policy.self_ips.update(
                row["ip"] for row in conn.execute("SELECT DISTINCT ip FROM collector_endpoints")
            )
        except Exception:
            # Old read-only databases are handled by ensure_schema on normal
            # connections; never make a response decision fail on lookup.
            pass
        self.firewall = firewall or WindowsFirewall()

    def _settings(self):
        return {row["key"]: row["value"] for row in self.conn.execute("SELECT key, value FROM settings")}

    @staticmethod
    def _row_to_dict(row):
        if not row:
            return None
        item = dict(row)
        try:
            item["metadata"] = json.loads(item["metadata"] or "{}")
        except (TypeError, json.JSONDecodeError):
            item["metadata"] = {}
        return item

    def list_actions(self, limit=50):
        rows = self.conn.execute(
            "SELECT * FROM response_actions ORDER BY id DESC LIMIT ?", (min(max(int(limit), 1), 200),)
        ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_action(self, action_id):
        return self._row_to_dict(self.conn.execute("SELECT * FROM response_actions WHERE id = ?", (action_id,)).fetchone())

    def _create(
        self,
        action_key,
        incident,
        target,
        mode,
        status,
        reason,
        action_type="BLOCK_IP",
        metadata=None,
        requested_by_user_id=None,
        approval_required=False,
    ):
        requested_at = _utc_now()
        values = (
            action_key, incident.get("incident_id"), incident.get("log_id"),
            incident.get("hostname"), action_type, target, "ANALYZER", mode,
            status, reason, requested_at, None, None, None,
            json.dumps(metadata or {}, sort_keys=True), requested_by_user_id,
            None, 1 if approval_required else 0, None, requested_at,
        )
        self.conn.execute("BEGIN IMMEDIATE")
        self.conn.execute("""
            INSERT OR IGNORE INTO response_actions (
                action_key, incident_id, log_id, hostname, action_type, target,
                execution_scope, mode, status, reason, requested_at, executed_at,
                error, rollback_status, metadata, requested_by_user_id,
                approved_by_user_id, approval_required, simulation_result,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, values)
        row = self.conn.execute(
            "SELECT * FROM response_actions WHERE action_key = ?",
            (action_key,),
        ).fetchone()
        self.conn.commit()
        return self._row_to_dict(row)

    def _update(
        self,
        action_id,
        status,
        error=None,
        rollback_status=None,
        metadata=None,
        approved_by_user_id=None,
        simulation_result=None,
    ):
        existing = self.get_action(action_id)
        merged_metadata = dict(existing.get("metadata") or {})
        if metadata:
            merged_metadata.update(metadata)
        updated_at = _utc_now()
        executed_at = (
            updated_at
            if status in {"EXECUTED", "DRY_RUN", "FAILED", "ROLLED_BACK"}
            else None
        )
        self.conn.execute("""
            UPDATE response_actions
            SET status=?, executed_at=COALESCE(?, executed_at), error=?,
                rollback_status=COALESCE(?, rollback_status), metadata=?,
                approved_by_user_id=COALESCE(?, approved_by_user_id),
                simulation_result=COALESCE(?, simulation_result), updated_at=?
            WHERE id=?
        """, (
            status, executed_at, error, rollback_status,
            json.dumps(merged_metadata, sort_keys=True),
            approved_by_user_id, simulation_result, updated_at, action_id,
        ))
        self.conn.commit()
        return self.get_action(action_id)

    def request_block(
        self,
        incident,
        ip=None,
        reason=None,
        approved=False,
        requested_by_user_id=None,
    ):
        target = ip if ip is not None else incident.get("source_ip")
        valid, target, validation_reason = self.policy.validate_ip(target)
        incident_id = incident.get("incident_id") or "manual"
        action_key = "block:%s:%s:%s" % (
            incident_id, "ANALYZER", target or str(ip or ""),
        )
        if not valid:
            return self._create(
                action_key, incident, target or str(ip or ""), self.policy.mode,
                "BLOCKED_BY_POLICY", validation_reason,
                metadata={"validation": validation_reason},
                requested_by_user_id=requested_by_user_id,
                approval_required=False,
            )

        existing = self.conn.execute(
            "SELECT * FROM response_actions WHERE action_key = ?",
            (action_key,),
        ).fetchone()
        if existing:
            return self._row_to_dict(existing)

        mode = self.policy.mode
        auto_qualification = self.policy.auto_qualification(
            incident
        )
        LOG.info(
            "[SOAR] Incident: %s Action: BLOCK_IP Target: %s Mode: %s",
            incident_id,
            target,
            mode,
        )

        if approved:
            # Retained only for compatibility with older internal callers.
            # Request-side approval is not an authorization boundary.
            LOG.warning(
                "[SOAR] Ignoring request-side approved flag for %s",
                action_key,
            )

        if mode == "OFF":
            return self._create(
                action_key, incident, target, mode, "SKIPPED",
                reason or "response mode OFF",
                requested_by_user_id=requested_by_user_id,
                approval_required=False,
            )

        if mode == "AUTO":
            if not auto_qualification["qualified"]:
                return self._create(
                    action_key,
                    incident,
                    target,
                    mode,
                    "BLOCKED_BY_POLICY",
                    "automatic threshold not met",
                    metadata={
                        "auto_qualification": auto_qualification,
                    },
                    requested_by_user_id=requested_by_user_id,
                    approval_required=False,
                )

            return self._create(
                action_key,
                incident,
                target,
                mode,
                "PENDING_APPROVAL",
                (
                    reason
                    or (
                        "automatic qualification met; "
                        "administrator approval required"
                    )
                ),
                metadata={
                    "auto_qualification": auto_qualification,
                },
                requested_by_user_id=requested_by_user_id,
                approval_required=True,
            )

        return self._create(
            action_key,
            incident,
            target,
            mode,
            "PENDING_APPROVAL",
            reason or "operator approval required",
            requested_by_user_id=requested_by_user_id,
            approval_required=True,
        )

    def approve(self, action_id, approved_by_user_id=None):
        action = self.get_action(action_id)
        if not action or action["action_type"] != "BLOCK_IP":
            return None
        if action["status"] != "PENDING_APPROVAL":
            return action

        approver_id = (
            str(approved_by_user_id or "").strip()
            or None
        )
        if not approver_id:
            raise ApprovalDeniedError(
                "approval_identity_required",
                "trusted approver identity is required",
            )

        requester_id = (
            str(action.get("requested_by_user_id") or "").strip()
            or None
        )
        if requester_id and requester_id == approver_id:
            raise ApprovalDeniedError(
                "self_approval_forbidden",
                "response requester cannot approve their own action",
            )

        valid, _target, validation_reason = self.policy.validate_ip(
            action["target"]
        )
        if not valid:
            return self._update(
                action_id, "BLOCKED_BY_POLICY", validation_reason
            )
        action = self._update(
            action_id,
            "APPROVED",
            approved_by_user_id=approver_id,
        )
        return self._execute_block(action)

    def _execute_block(self, action):
        if self.policy.dry_run:
            LOG.info("[SOAR] Execution: DRY_RUN target=%s", action["target"])
            intended_rule = "AegisGuard-owned inbound Windows Firewall rule"
            return self._update(
                action["id"],
                "DRY_RUN",
                metadata={"intended_rule": intended_rule},
                simulation_result=(
                    "DRY_RUN: " + intended_rule + " would be created"
                ),
            )
        try:
            result, rule_name = self.firewall.block_ip(action["target"])
            LOG.info("[SOAR] Execution: %s target=%s", result, action["target"])
            return self._update(action["id"], "EXECUTED", metadata={"firewall_rule": rule_name, "result": result})
        except FirewallError as exc:
            LOG.warning("[SOAR] Execution: FAILED target=%s error=%s", action["target"], exc)
            return self._update(action["id"], "FAILED", str(exc))

    def _rollback_candidate(self, target):
        expected_rule = rule_name_for_ip(target)
        rows = self.conn.execute("""
            SELECT *
            FROM response_actions
            WHERE action_type='BLOCK_IP'
              AND target=?
              AND execution_scope='ANALYZER'
              AND status='EXECUTED'
            ORDER BY id DESC
        """, (target,)).fetchall()
        for row in rows:
            action = self._row_to_dict(row)
            metadata = action.get("metadata") or {}
            if str(metadata.get("result") or "").upper() != "EXECUTED":
                continue
            if str(metadata.get("firewall_rule") or "") != expected_rule:
                continue
            if str(action.get("rollback_status") or "").upper() == "ROLLED_BACK":
                continue
            return action
        return None

    def _record_rollback(
        self,
        action,
        rollback_status,
        *,
        reason,
        rollback_by_user_id=None,
        error=None,
        completed=False,
        metadata=None,
    ):
        merged_metadata = dict(action.get("metadata") or {})
        merged_metadata["rollback_reason"] = reason
        if rollback_by_user_id:
            merged_metadata["rollback_requested_by_user_id"] = (
                rollback_by_user_id
            )
        if metadata:
            merged_metadata.update(metadata)

        status = "ROLLED_BACK" if completed else action["status"]
        stored_error = (
            None
            if completed
            else (
                str(error)
                if error is not None
                else action.get("error")
            )
        )
        self.conn.execute("""
            UPDATE response_actions
            SET status=?,
                rollback_status=?,
                error=?,
                metadata=?,
                updated_at=?
            WHERE id=?
        """, (
            status,
            rollback_status,
            stored_error,
            json.dumps(merged_metadata, sort_keys=True),
            _utc_now(),
            action["id"],
        ))
        self.conn.commit()
        return self.get_action(action["id"])

    def unblock(
        self,
        ip,
        reason="operator requested rollback",
        rollback_by_user_id=None,
    ):
        valid, target, validation_reason = self.policy.canonicalize_ip(ip)
        if not valid:
            return {
                "status": "BLOCKED_BY_POLICY",
                "target": target or str(ip or ""),
                "error": validation_reason,
            }

        block = self._rollback_candidate(target)
        if not block:
            return {
                "status": "SKIPPED",
                "target": target,
                "error": (
                    "no active executed AegisGuard-owned "
                    "block action found"
                ),
            }

        if self.policy.dry_run:
            rule_name = rule_name_for_ip(target)
            return self._record_rollback(
                block,
                "DRY_RUN",
                reason=reason,
                rollback_by_user_id=rollback_by_user_id,
                metadata={
                    "rollback_simulation_result": (
                        "DRY_RUN: would remove AegisGuard-owned "
                        f"firewall rule {rule_name}"
                    ),
                },
            )

        try:
            _, rule_name = self.firewall.unblock_ip(target)
            return self._record_rollback(
                block,
                "ROLLED_BACK",
                reason=reason,
                rollback_by_user_id=rollback_by_user_id,
                completed=True,
                metadata={"firewall_rule": rule_name},
            )
        except FirewallError as exc:
            return self._record_rollback(
                block,
                "FAILED",
                reason=reason,
                rollback_by_user_id=rollback_by_user_id,
                error=exc,
            )
