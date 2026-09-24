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


class RecoveryDeniedError(PermissionError):
    """Raised when interrupted-response reconciliation is not permitted."""

    def __init__(self, code, message):
        self.code = str(code)
        super().__init__(str(message))


class RejectionDeniedError(PermissionError):
    """Raised when response rejection violates governance policy."""

    def __init__(self, code, message):
        self.code = str(code)
        super().__init__(str(message))


class RetryDeniedError(PermissionError):
    """Raised when failed response execution cannot be retried."""

    def __init__(self, code, message):
        self.code = str(code)
        super().__init__(str(message))


RECOVERY_STALE_SECONDS = 60


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
        approval_context = self.policy.approval_context()
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
                    "approval_context": approval_context,
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
            metadata={
                "approval_context": approval_context,
            },
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

        if self.policy.mode == "OFF":
            raise ApprovalDeniedError(
                "response_mode_off",
                "response mode OFF forbids approval execution",
            )

        metadata = action.get("metadata") or {}
        expected_context = metadata.get("approval_context")
        if not isinstance(expected_context, dict):
            raise ApprovalDeniedError(
                "approval_context_missing",
                "pending action has no trusted approval context",
            )

        current_context = self.policy.approval_context()
        if expected_context != current_context:
            raise ApprovalDeniedError(
                "response_policy_changed",
                "response policy changed after the action was requested",
            )

        valid, _target, validation_reason = self.policy.validate_ip(
            action["target"]
        )
        if not valid:
            return self._update(
                action_id, "BLOCKED_BY_POLICY", validation_reason
            )
        action, claimed = self._claim_approval(
            action_id,
            approver_id,
        )
        if not claimed:
            return action
        return self._execute_block(action)

    def _claim_approval(self, action_id, approved_by_user_id):
        """Atomically claim one pending action for controlled execution."""
        updated_at = _utc_now()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            cursor = self.conn.execute("""
                UPDATE response_actions
                SET status='APPROVED',
                    approved_by_user_id=?,
                    updated_at=?
                WHERE id=?
                  AND status='PENDING_APPROVAL'
            """, (
                approved_by_user_id,
                updated_at,
                action_id,
            ))
            claimed = cursor.rowcount == 1
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

        return self.get_action(action_id), claimed

    def _claim_retry(
        self,
        action_id,
        *,
        retried_by_user_id,
        reason,
    ):
        """Atomically reclaim one failed approved action for execution."""
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            action = self.get_action(action_id)
            if not action or action["status"] != "FAILED":
                self.conn.commit()
                return action, False

            metadata = dict(action.get("metadata") or {})
            history = metadata.get("retry_history")
            if not isinstance(history, list):
                history = []
            history = list(history)
            history.append({
                "by_user_id": retried_by_user_id,
                "reason": reason,
                "at": _utc_now(),
                "previous_error": action.get("error"),
            })
            metadata["retry_history"] = history
            metadata["retry_count"] = len(history)

            updated_at = _utc_now()
            cursor = self.conn.execute("""
                UPDATE response_actions
                SET status='APPROVED',
                    error=NULL,
                    metadata=?,
                    updated_at=?
                WHERE id=?
                  AND status='FAILED'
                  AND approved_by_user_id IS NOT NULL
                  AND approved_by_user_id != ''
            """, (
                json.dumps(metadata, sort_keys=True),
                updated_at,
                action_id,
            ))
            claimed = cursor.rowcount == 1
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

        return self.get_action(action_id), claimed

    def retry(
        self,
        action_id,
        retried_by_user_id=None,
        reason=None,
    ):
        """Retry one previously approved failed firewall execution."""
        action = self.get_action(action_id)
        if not action or action["action_type"] != "BLOCK_IP":
            return None
        if action["status"] != "FAILED":
            raise RetryDeniedError(
                "retry_not_available",
                "only failed response actions can be retried",
            )

        actor = (
            str(retried_by_user_id or "").strip()
            or None
        )
        if not actor:
            raise RetryDeniedError(
                "retry_identity_required",
                "trusted retry identity is required",
            )

        retry_reason = str(reason or "").strip()
        if not retry_reason:
            raise RetryDeniedError(
                "retry_reason_required",
                "retry reason is required",
            )
        if len(retry_reason) > 500:
            raise RetryDeniedError(
                "retry_reason_too_long",
                "retry reason must be 500 characters or fewer",
            )

        original_approver = (
            str(action.get("approved_by_user_id") or "").strip()
            or None
        )
        if not original_approver:
            raise RetryDeniedError(
                "retry_approval_missing",
                "failed action has no trusted original approval",
            )

        if self.policy.mode == "OFF":
            raise RetryDeniedError(
                "response_mode_off",
                "response mode OFF forbids retry execution",
            )

        metadata = action.get("metadata") or {}
        expected_context = metadata.get("approval_context")
        if not isinstance(expected_context, dict):
            raise RetryDeniedError(
                "approval_context_missing",
                "failed action has no trusted approval context",
            )

        current_context = self.policy.approval_context()
        if expected_context != current_context:
            raise RetryDeniedError(
                "response_policy_changed",
                "response policy changed after the action was approved",
            )

        valid, _target, validation_reason = self.policy.validate_ip(
            action["target"]
        )
        if not valid:
            raise RetryDeniedError(
                "retry_target_blocked",
                validation_reason,
            )

        claimed_action, claimed = self._claim_retry(
            action_id,
            retried_by_user_id=actor,
            reason=retry_reason,
        )
        if not claimed:
            return claimed_action
        return self._execute_block(claimed_action)

    def reject(
        self,
        action_id,
        rejected_by_user_id=None,
        reason=None,
    ):
        """Atomically reject one still-pending response action."""
        action = self.get_action(action_id)
        if not action or action["action_type"] != "BLOCK_IP":
            return None
        if action["status"] != "PENDING_APPROVAL":
            return action

        actor = (
            str(rejected_by_user_id or "").strip()
            or None
        )
        if not actor:
            raise RejectionDeniedError(
                "rejection_identity_required",
                "trusted rejection identity is required",
            )

        rejection_reason = str(reason or "").strip()
        if not rejection_reason:
            raise RejectionDeniedError(
                "rejection_reason_required",
                "rejection reason is required",
            )
        if len(rejection_reason) > 500:
            raise RejectionDeniedError(
                "rejection_reason_too_long",
                "rejection reason must be 500 characters or fewer",
            )

        metadata = dict(action.get("metadata") or {})
        now = _utc_now()
        metadata["rejection"] = {
            "by_user_id": actor,
            "reason": rejection_reason,
            "at": now,
        }

        self.conn.execute("BEGIN IMMEDIATE")
        try:
            cursor = self.conn.execute("""
                UPDATE response_actions
                SET status='REJECTED',
                    error=NULL,
                    metadata=?,
                    updated_at=?
                WHERE id=?
                  AND status='PENDING_APPROVAL'
            """, (
                json.dumps(metadata, sort_keys=True),
                now,
                action_id,
            ))
            rejected = cursor.rowcount == 1
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

        current = self.get_action(action_id)
        if not rejected:
            return current
        return current

    @staticmethod
    def _claim_is_stale(action):
        raw = str(
            action.get("updated_at")
            or action.get("executed_at")
            or action.get("requested_at")
            or ""
        ).strip()
        if not raw:
            return False
        try:
            timestamp = datetime.fromisoformat(
                raw.replace("Z", "+00:00")
            )
        except ValueError:
            return False
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        age = (
            datetime.now(timezone.utc)
            - timestamp.astimezone(timezone.utc)
        ).total_seconds()
        return age >= RECOVERY_STALE_SECONDS

    def _active_owned_rule_action(
        self,
        target,
        *,
        exclude_action_id=None,
    ):
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
            if (
                exclude_action_id is not None
                and action["id"] == exclude_action_id
            ):
                continue
            metadata = action.get("metadata") or {}
            if str(metadata.get("result") or "").upper() != "EXECUTED":
                continue
            if str(metadata.get("firewall_rule") or "") != expected_rule:
                continue
            if str(
                action.get("rollback_status") or ""
            ).upper() == "ROLLED_BACK":
                continue
            return action
        return None

    def _recovery_metadata(self, action, actor, outcome):
        metadata = dict(action.get("metadata") or {})
        metadata["reconciliation"] = {
            "by_user_id": actor,
            "outcome": outcome,
            "at": _utc_now(),
        }
        return metadata

    def _finish_recovered_block(
        self,
        action,
        actor,
        *,
        result,
        rule_name,
    ):
        metadata = self._recovery_metadata(
            action,
            actor,
            "BLOCK_RECONCILED",
        )
        metadata["result"] = result
        metadata["firewall_rule"] = rule_name
        now = _utc_now()
        self.conn.execute("""
            UPDATE response_actions
            SET status='EXECUTED',
                executed_at=COALESCE(executed_at, ?),
                error=NULL,
                metadata=?,
                updated_at=?
            WHERE id=?
        """, (
            now,
            json.dumps(metadata, sort_keys=True),
            now,
            action["id"],
        ))
        return self.get_action(action["id"])

    def _reconcile_approved_locked(self, action, actor):
        metadata = action.get("metadata") or {}
        approval_context = metadata.get("approval_context")
        if (
            isinstance(approval_context, dict)
            and bool(approval_context.get("dry_run"))
        ):
            intended_rule = (
                "AegisGuard-owned inbound Windows Firewall rule"
            )
            merged = self._recovery_metadata(
                action,
                actor,
                "DRY_RUN_RECONCILED",
            )
            merged["intended_rule"] = intended_rule
            now = _utc_now()
            self.conn.execute("""
                UPDATE response_actions
                SET status='DRY_RUN',
                    executed_at=COALESCE(executed_at, ?),
                    error=NULL,
                    simulation_result=?,
                    metadata=?,
                    updated_at=?
                WHERE id=?
            """, (
                now,
                (
                    "DRY_RUN: "
                    + intended_rule
                    + " would be created"
                ),
                json.dumps(merged, sort_keys=True),
                now,
                action["id"],
            ))
            return self.get_action(action["id"])

        try:
            exists = self.firewall.rule_exists(action["target"])
        except FirewallError as exc:
            merged = self._recovery_metadata(
                action,
                actor,
                "PROBE_FAILED",
            )
            self.conn.execute("""
                UPDATE response_actions
                SET error=?,
                    metadata=?,
                    updated_at=?
                WHERE id=?
            """, (
                str(exc),
                json.dumps(merged, sort_keys=True),
                _utc_now(),
                action["id"],
            ))
            return self.get_action(action["id"])

        if exists:
            owner = self._active_owned_rule_action(
                action["target"],
                exclude_action_id=action["id"],
            )
            result = "ALREADY_EXISTS" if owner else "EXECUTED"
            return self._finish_recovered_block(
                action,
                actor,
                result=result,
                rule_name=rule_name_for_ip(action["target"]),
            )

        if self.policy.mode == "OFF":
            raise RecoveryDeniedError(
                "response_mode_off",
                "response mode OFF forbids recovery execution",
            )

        if not isinstance(approval_context, dict):
            raise RecoveryDeniedError(
                "approval_context_missing",
                "approved action has no trusted approval context",
            )

        current_context = self.policy.approval_context()
        if approval_context != current_context:
            raise RecoveryDeniedError(
                "response_policy_changed",
                "response policy changed after the action was approved",
            )

        valid, _target, validation_reason = self.policy.validate_ip(
            action["target"]
        )
        if not valid:
            merged = self._recovery_metadata(
                action,
                actor,
                "BLOCKED_BY_POLICY",
            )
            self.conn.execute("""
                UPDATE response_actions
                SET status='BLOCKED_BY_POLICY',
                    error=?,
                    metadata=?,
                    updated_at=?
                WHERE id=?
            """, (
                validation_reason,
                json.dumps(merged, sort_keys=True),
                _utc_now(),
                action["id"],
            ))
            return self.get_action(action["id"])

        try:
            result, rule_name = self.firewall.block_ip(
                action["target"]
            )
        except FirewallError as exc:
            merged = self._recovery_metadata(
                action,
                actor,
                "EXECUTION_FAILED",
            )
            now = _utc_now()
            self.conn.execute("""
                UPDATE response_actions
                SET status='FAILED',
                    executed_at=COALESCE(executed_at, ?),
                    error=?,
                    metadata=?,
                    updated_at=?
                WHERE id=?
            """, (
                now,
                str(exc),
                json.dumps(merged, sort_keys=True),
                now,
                action["id"],
            ))
            return self.get_action(action["id"])

        return self._finish_recovered_block(
            action,
            actor,
            result=result,
            rule_name=rule_name,
        )

    def _reconcile_rollback_locked(self, action, actor):
        target = action["target"]
        try:
            exists = self.firewall.rule_exists(target)
        except FirewallError as exc:
            merged = self._recovery_metadata(
                action,
                actor,
                "ROLLBACK_PROBE_FAILED",
            )
            self.conn.execute("""
                UPDATE response_actions
                SET rollback_status='FAILED',
                    error=?,
                    metadata=?,
                    updated_at=?
                WHERE id=?
            """, (
                str(exc),
                json.dumps(merged, sort_keys=True),
                _utc_now(),
                action["id"],
            ))
            return self.get_action(action["id"])

        rule_name = rule_name_for_ip(target)
        if exists:
            try:
                _, rule_name = self.firewall.unblock_ip(target)
            except FirewallError as exc:
                merged = self._recovery_metadata(
                    action,
                    actor,
                    "ROLLBACK_FAILED",
                )
                self.conn.execute("""
                    UPDATE response_actions
                    SET rollback_status='FAILED',
                        error=?,
                        metadata=?,
                        updated_at=?
                    WHERE id=?
                """, (
                    str(exc),
                    json.dumps(merged, sort_keys=True),
                    _utc_now(),
                    action["id"],
                ))
                return self.get_action(action["id"])

        merged = self._recovery_metadata(
            action,
            actor,
            (
                "ROLLBACK_REMOVED_RULE"
                if exists
                else "ROLLBACK_ALREADY_ABSENT"
            ),
        )
        merged["firewall_rule"] = rule_name
        self.conn.execute("""
            UPDATE response_actions
            SET status='ROLLED_BACK',
                rollback_status='ROLLED_BACK',
                error=NULL,
                metadata=?,
                updated_at=?
            WHERE id=?
        """, (
            json.dumps(merged, sort_keys=True),
            _utc_now(),
            action["id"],
        ))
        return self.get_action(action["id"])

    def reconcile(
        self,
        action_id,
        reconciled_by_user_id=None,
    ):
        """Reconcile one stale claim without blindly replaying mutation."""
        actor = (
            str(reconciled_by_user_id or "").strip()
            or None
        )
        if not actor:
            raise RecoveryDeniedError(
                "reconciliation_identity_required",
                "trusted reconciliation identity is required",
            )

        self.conn.execute("BEGIN IMMEDIATE")
        try:
            action = self.get_action(action_id)
            if not action or action["action_type"] != "BLOCK_IP":
                self.conn.commit()
                return None

            rollback_status = str(
                action.get("rollback_status") or ""
            ).upper()
            recoverable = (
                action["status"] == "APPROVED"
                or (
                    action["status"] == "EXECUTED"
                    and rollback_status == "IN_PROGRESS"
                )
            )
            if not recoverable:
                self.conn.commit()
                return action

            if not self._claim_is_stale(action):
                raise RecoveryDeniedError(
                    "reconciliation_not_stale",
                    "response claim is still inside the recovery grace period",
                )

            if action["status"] == "APPROVED":
                result = self._reconcile_approved_locked(
                    action,
                    actor,
                )
            else:
                result = self._reconcile_rollback_locked(
                    action,
                    actor,
                )

            self.conn.commit()
            return result
        except Exception:
            self.conn.rollback()
            raise

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
            rollback_status = str(
                action.get("rollback_status") or ""
            ).upper()
            if rollback_status in {"ROLLED_BACK", "IN_PROGRESS"}:
                continue
            return action
        return None

    def _claim_rollback(
        self,
        target,
        *,
        reason,
        rollback_by_user_id=None,
    ):
        """Atomically claim one owned live block for rollback execution."""
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            action = self._rollback_candidate(target)
            if not action:
                self.conn.commit()
                return None

            merged_metadata = dict(action.get("metadata") or {})
            merged_metadata["rollback_reason"] = reason
            if rollback_by_user_id:
                merged_metadata["rollback_requested_by_user_id"] = (
                    rollback_by_user_id
                )

            cursor = self.conn.execute("""
                UPDATE response_actions
                SET rollback_status='IN_PROGRESS',
                    error=NULL,
                    metadata=?,
                    updated_at=?
                WHERE id=?
                  AND status='EXECUTED'
                  AND (
                      rollback_status IS NULL
                      OR rollback_status IN ('', 'FAILED', 'DRY_RUN')
                  )
            """, (
                json.dumps(merged_metadata, sort_keys=True),
                _utc_now(),
                action["id"],
            ))
            claimed = cursor.rowcount == 1
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

        if not claimed:
            return None
        return self.get_action(action["id"])

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

        if self.policy.dry_run:
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

        block = self._claim_rollback(
            target,
            reason=reason,
            rollback_by_user_id=rollback_by_user_id,
        )
        if not block:
            return {
                "status": "SKIPPED",
                "target": target,
                "error": (
                    "no claimable executed AegisGuard-owned "
                    "block action found"
                ),
            }

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
