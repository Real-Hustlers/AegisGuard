import sqlite3
import unittest

from backend.analyzer.database import ensure_schema
from backend.analyzer.soar.engine import SoarEngine
from backend.analyzer.soar.policies import ResponsePolicy


class FakeFirewall:
    def __init__(self):
        self.blocks = []

    def block_ip(self, ip):
        self.blocks.append(ip)
        return "EXECUTED", "AegisGuard-test-rule"

    def unblock_ip(self, ip):
        return "ROLLED_BACK", "AegisGuard-test-rule"


def incident(**overrides):
    value = {
        "incident_id": "INC-S8A",
        "log_id": "LOG-S8A",
        "hostname": "HOST-S8A",
        "source_ip": "8.8.8.8",
        "severity": "HIGH",
        "threat_score": 80,
        "threat_type": "Brute Force Attack",
    }
    value.update(overrides)
    return value


class S8AResponseGovernanceFoundationTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        ensure_schema(self.conn)
        self.firewall = FakeFirewall()

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

    def test_manual_request_waits_for_explicit_approval(self):
        engine = self.engine()
        action = engine.request_block(
            incident(),
            requested_by_user_id="requester",
        )
        self.assertEqual(action["status"], "PENDING_APPROVAL")
        self.assertEqual(action["requested_by_user_id"], "requester")
        self.assertIsNone(action["approved_by_user_id"])
        self.assertEqual(action["approval_required"], 1)
        self.assertEqual(self.firewall.blocks, [])

        approved = engine.approve(
            action["id"],
            approved_by_user_id="approver",
        )
        self.assertEqual(approved["status"], "EXECUTED")
        self.assertEqual(approved["approved_by_user_id"], "approver")
        self.assertEqual(self.firewall.blocks, ["8.8.8.8"])

    def test_off_and_policy_blocked_actions_cannot_be_approved_into_execution(self):
        off = self.engine(soar_mode="OFF")
        skipped = off.request_block(
            incident(),
            requested_by_user_id="requester",
        )
        self.assertEqual(skipped["status"], "SKIPPED")
        self.assertEqual(
            off.approve(skipped["id"], approved_by_user_id="approver")["status"],
            "SKIPPED",
        )

        blocked = self.engine().request_block(
            incident(incident_id="INC-BLOCKED", source_ip="10.0.0.5"),
            requested_by_user_id="requester",
        )
        self.assertEqual(blocked["status"], "BLOCKED_BY_POLICY")
        self.assertEqual(
            self.engine().approve(
                blocked["id"],
                approved_by_user_id="approver",
            )["status"],
            "BLOCKED_BY_POLICY",
        )
        self.assertEqual(self.firewall.blocks, [])

    def test_dry_run_records_approver_and_simulation_result(self):
        engine = self.engine(soar_dry_run="true")
        action = engine.request_block(
            incident(),
            requested_by_user_id="requester",
        )
        approved = engine.approve(
            action["id"],
            approved_by_user_id="approver",
        )
        self.assertEqual(approved["status"], "DRY_RUN")
        self.assertEqual(approved["approved_by_user_id"], "approver")
        self.assertIn(
            "AegisGuard-owned inbound Windows Firewall rule",
            approved["simulation_result"],
        )
        self.assertEqual(self.firewall.blocks, [])


if __name__ == "__main__":
    unittest.main()
