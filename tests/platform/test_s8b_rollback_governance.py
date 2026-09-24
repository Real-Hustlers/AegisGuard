import sqlite3
import unittest

from backend.analyzer.database import ensure_schema
from backend.analyzer.soar.engine import SoarEngine
from backend.analyzer.soar.firewall import FirewallError, rule_name_for_ip
from backend.analyzer.soar.policies import ResponsePolicy


class OwnershipAwareFirewall:
    def __init__(self):
        self.blocked = set()
        self.blocks = []
        self.unblocks = []
        self.fail_unblock = False

    def block_ip(self, ip):
        name = rule_name_for_ip(ip)
        if ip in self.blocked:
            return "ALREADY_EXISTS", name
        self.blocked.add(ip)
        self.blocks.append(ip)
        return "EXECUTED", name

    def unblock_ip(self, ip):
        if self.fail_unblock:
            raise FirewallError("mock rollback failure")
        self.unblocks.append(ip)
        self.blocked.discard(ip)
        return "ROLLED_BACK", rule_name_for_ip(ip)


def incident(incident_id="INC-S8B", source_ip="8.8.8.8"):
    return {
        "incident_id": incident_id,
        "log_id": "LOG-S8B",
        "hostname": "HOST-S8B",
        "source_ip": source_ip,
        "severity": "HIGH",
        "threat_score": 80,
        "threat_type": "Brute Force Attack",
    }


class S8BRollbackGovernanceTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        ensure_schema(self.conn)
        self.firewall = OwnershipAwareFirewall()

    def tearDown(self):
        self.conn.close()

    def engine(self, **settings):
        values = {
            "soar_mode": "MANUAL",
            "soar_dry_run": "false",
            "soar_auto_min_score": "90",
            "soar_allow_private_ip_blocking": "false",
            "soar_allowlist": "[]",
        }
        values.update(settings)
        return SoarEngine(
            self.conn,
            self.firewall,
            ResponsePolicy(values, self_ips={"198.51.100.7"}),
        )

    def execute_block(self, incident_id="INC-S8B", ip="8.8.8.8"):
        return self.engine().request_block(
            incident(incident_id=incident_id, source_ip=ip),
            ip,
            approved=True,
            requested_by_user_id="requester",
        )

    def test_pending_policy_blocked_and_dry_run_actions_are_not_rollback_owners(self):
        pending = self.engine().request_block(
            incident("INC-PENDING"),
            requested_by_user_id="requester",
        )
        self.assertEqual(pending["status"], "PENDING_APPROVAL")

        blocked = self.engine().request_block(
            incident("INC-BLOCKED", "10.0.0.5"),
            requested_by_user_id="requester",
        )
        self.assertEqual(blocked["status"], "BLOCKED_BY_POLICY")

        dry = self.engine(soar_dry_run="true").request_block(
            incident("INC-DRY"),
            approved=True,
            requested_by_user_id="requester",
        )
        self.assertEqual(dry["status"], "DRY_RUN")

        result = self.engine().unblock(
            "8.8.8.8",
            rollback_by_user_id="admin-1",
        )
        self.assertEqual(result["status"], "SKIPPED")
        self.assertEqual(self.firewall.unblocks, [])

    def test_only_action_that_created_owned_rule_is_rollback_candidate(self):
        creator = self.execute_block("INC-CREATOR")
        duplicate = self.execute_block("INC-DUPLICATE")

        self.assertEqual(creator["metadata"]["result"], "EXECUTED")
        self.assertEqual(duplicate["metadata"]["result"], "ALREADY_EXISTS")

        result = self.engine().unblock(
            "8.8.8.8",
            reason="containment no longer required",
            rollback_by_user_id="admin-rollback",
        )

        self.assertEqual(result["id"], creator["id"])
        self.assertEqual(result["status"], "ROLLED_BACK")
        self.assertEqual(result["rollback_status"], "ROLLED_BACK")
        self.assertEqual(
            result["metadata"]["rollback_requested_by_user_id"],
            "admin-rollback",
        )
        self.assertEqual(self.firewall.unblocks, ["8.8.8.8"])

    def test_dry_run_rollback_preserves_executed_state_and_original_execution_time(self):
        executed = self.execute_block()
        original_executed_at = executed["executed_at"]

        simulated = self.engine(soar_dry_run="true").unblock(
            "8.8.8.8",
            reason="simulate rollback",
            rollback_by_user_id="admin-sim",
        )

        self.assertEqual(simulated["status"], "EXECUTED")
        self.assertEqual(simulated["rollback_status"], "DRY_RUN")
        self.assertEqual(simulated["executed_at"], original_executed_at)
        self.assertIn(
            "would remove",
            simulated["metadata"]["rollback_simulation_result"],
        )
        self.assertEqual(self.firewall.unblocks, [])

    def test_failed_rollback_preserves_active_execution_and_can_retry(self):
        executed = self.execute_block()
        original_executed_at = executed["executed_at"]
        self.firewall.fail_unblock = True

        failed = self.engine().unblock(
            "8.8.8.8",
            rollback_by_user_id="admin-fail",
        )

        self.assertEqual(failed["status"], "EXECUTED")
        self.assertEqual(failed["rollback_status"], "FAILED")
        self.assertEqual(failed["executed_at"], original_executed_at)
        self.assertIn("mock rollback failure", failed["error"])

        self.firewall.fail_unblock = False
        retried = self.engine().unblock(
            "8.8.8.8",
            rollback_by_user_id="admin-retry",
        )

        self.assertEqual(retried["status"], "ROLLED_BACK")
        self.assertEqual(retried["rollback_status"], "ROLLED_BACK")
        self.assertIsNone(retried["error"])
        self.assertEqual(self.firewall.unblocks, ["8.8.8.8"])

    def test_rollback_is_allowed_after_block_policy_becomes_more_restrictive(self):
        executed = self.engine(
            soar_allow_private_ip_blocking="true"
        ).request_block(
            incident("INC-PRIVATE", "10.0.0.5"),
            "10.0.0.5",
            approved=True,
        )
        self.assertEqual(executed["status"], "EXECUTED")

        restrictive = self.engine(
            soar_allow_private_ip_blocking="false",
            soar_allowlist='["10.0.0.5"]',
        )
        result = restrictive.unblock(
            "10.0.0.5",
            rollback_by_user_id="admin-restorative",
        )

        self.assertEqual(result["status"], "ROLLED_BACK")
        self.assertEqual(self.firewall.unblocks, ["10.0.0.5"])


if __name__ == "__main__":
    unittest.main()
