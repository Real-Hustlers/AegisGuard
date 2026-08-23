"""SQLite-audited SOAR decision engine for safe Analyzer-side IP blocking."""

import json
import logging
from datetime import datetime, timezone

from .firewall import FirewallError, WindowsFirewall
from .policies import ResponsePolicy


LOG = logging.getLogger(__name__)


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

    def _create(self, action_key, incident, target, mode, status, reason, action_type="BLOCK_IP", metadata=None):
        values = (
            action_key, incident.get("incident_id"), incident.get("log_id"), incident.get("hostname"),
            action_type, target, "ANALYZER", mode, status, reason, _utc_now(), None, None, None,
            json.dumps(metadata or {}, sort_keys=True),
        )
        self.conn.execute("BEGIN IMMEDIATE")
        self.conn.execute("""
            INSERT OR IGNORE INTO response_actions (
                action_key, incident_id, log_id, hostname, action_type, target,
                execution_scope, mode, status, reason, requested_at, executed_at,
                error, rollback_status, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, values)
        row = self.conn.execute("SELECT * FROM response_actions WHERE action_key = ?", (action_key,)).fetchone()
        self.conn.commit()
        return self._row_to_dict(row)

    def _update(self, action_id, status, error=None, rollback_status=None, metadata=None):
        existing = self.get_action(action_id)
        merged_metadata = dict(existing.get("metadata") or {})
        if metadata:
            merged_metadata.update(metadata)
        executed_at = _utc_now() if status in {"EXECUTED", "DRY_RUN", "FAILED", "ROLLED_BACK"} else None
        self.conn.execute("""
            UPDATE response_actions
            SET status=?, executed_at=COALESCE(?, executed_at), error=?,
                rollback_status=COALESCE(?, rollback_status), metadata=?
            WHERE id=?
        """, (status, executed_at, error, rollback_status, json.dumps(merged_metadata, sort_keys=True), action_id))
        self.conn.commit()
        return self.get_action(action_id)

    def request_block(self, incident, ip=None, reason=None, approved=False):
        target = ip if ip is not None else incident.get("source_ip")
        valid, target, validation_reason = self.policy.validate_ip(target)
        incident_id = incident.get("incident_id") or "manual"
        action_key = "block:%s:%s:%s" % (incident_id, "ANALYZER", target or str(ip or ""))
        if not valid:
            return self._create(action_key, incident, target or str(ip or ""), self.policy.mode,
                                "BLOCKED_BY_POLICY", validation_reason, metadata={"validation": validation_reason})

        existing = self.conn.execute("SELECT * FROM response_actions WHERE action_key = ?", (action_key,)).fetchone()
        if existing:
            return self._row_to_dict(existing)

        mode = self.policy.mode
        qualifies = self.policy.auto_qualifies(incident)
        LOG.info("[SOAR] Incident: %s Action: BLOCK_IP Target: %s Mode: %s", incident_id, target, mode)
        if mode == "OFF":
            return self._create(action_key, incident, target, mode, "SKIPPED", reason or "response mode OFF")
        if mode == "MANUAL" and not approved:
            return self._create(action_key, incident, target, mode, "PENDING_APPROVAL", reason or "operator approval required")
        if mode == "AUTO" and not qualifies and not approved:
            return self._create(action_key, incident, target, mode, "BLOCKED_BY_POLICY", "automatic threshold not met")

        action = self._create(action_key, incident, target, mode, "PENDING_APPROVAL", reason or "approved block request")
        return self._execute_block(action)

    def approve(self, action_id):
        action = self.get_action(action_id)
        if not action or action["action_type"] != "BLOCK_IP":
            return None
        if action["status"] in {"EXECUTED", "DRY_RUN", "ROLLED_BACK", "FAILED"}:
            return action
        valid, target, validation_reason = self.policy.validate_ip(action["target"])
        if not valid:
            return self._update(action_id, "BLOCKED_BY_POLICY", validation_reason)
        return self._execute_block(action)

    def _execute_block(self, action):
        if self.policy.dry_run:
            LOG.info("[SOAR] Execution: DRY_RUN target=%s", action["target"])
            return self._update(action["id"], "DRY_RUN", metadata={"intended_rule": "AegisGuard-owned inbound Windows Firewall rule"})
        try:
            result, rule_name = self.firewall.block_ip(action["target"])
            LOG.info("[SOAR] Execution: %s target=%s", result, action["target"])
            return self._update(action["id"], "EXECUTED", metadata={"firewall_rule": rule_name, "result": result})
        except FirewallError as exc:
            LOG.warning("[SOAR] Execution: FAILED target=%s error=%s", action["target"], exc)
            return self._update(action["id"], "FAILED", str(exc))

    def unblock(self, ip, reason="operator requested rollback"):
        valid, target, validation_reason = self.policy.validate_ip(ip)
        if not valid:
            return {"status": "BLOCKED_BY_POLICY", "target": target or str(ip or ""), "error": validation_reason}
        block = self.conn.execute("""
            SELECT * FROM response_actions WHERE action_type='BLOCK_IP' AND target=?
            AND execution_scope='ANALYZER' ORDER BY id DESC LIMIT 1
        """, (target,)).fetchone()
        if not block:
            return {"status": "SKIPPED", "target": target, "error": "no AegisGuard block action found"}
        block = self._row_to_dict(block)
        if self.policy.dry_run:
            return self._update(block["id"], "ROLLED_BACK", rollback_status="DRY_RUN", metadata={"rollback_reason": reason})
        try:
            _, rule_name = self.firewall.unblock_ip(target)
            return self._update(block["id"], "ROLLED_BACK", rollback_status="ROLLED_BACK", metadata={"firewall_rule": rule_name, "rollback_reason": reason})
        except FirewallError as exc:
            return self._update(block["id"], "FAILED", str(exc), rollback_status="FAILED")
