import sqlite3
import unittest

from backend.analyzer.database import ensure_schema
from backend.analyzer.soar import ApprovalDeniedError, SoarEngine
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
        "incident_id": "INC-S8D",
        "log_id": "LOG-S8D",
        "hostname": "HOST-S8D",
        "source_ip": "8.8.8.8",
        "severity": "HIGH",
        "threat_score": 80,
        "threat_type": "Brute Force Attack",
    }
    value.update(overrides)
    return value


class S8DSeparationOfDutiesTests(unittest.TestCase):
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
            ResponsePolicy(
                values,
                self_ips={"198.51.100.7"},
            ),
        )

    def test_approval_requires_actor_identity(self):
        engine = self.engine()
        action = engine.request_block(
            incident(),
            requested_by_user_id="requester-1",
        )

        with self.assertRaises(ApprovalDeniedError) as caught:
            engine.approve(action["id"])

        self.assertEqual(
            caught.exception.code,
            "approval_identity_required",
        )
        unchanged = engine.get_action(action["id"])
        self.assertEqual(unchanged["status"], "PENDING_APPROVAL")
        self.assertIsNone(unchanged["approved_by_user_id"])
        self.assertEqual(self.firewall.blocks, [])

    def test_requester_cannot_approve_own_action(self):
        engine = self.engine()
        action = engine.request_block(
            incident(),
            requested_by_user_id="administrator-1",
        )

        with self.assertRaises(ApprovalDeniedError) as caught:
            engine.approve(
                action["id"],
                approved_by_user_id="administrator-1",
            )

        self.assertEqual(
            caught.exception.code,
            "self_approval_forbidden",
        )
        unchanged = engine.get_action(action["id"])
        self.assertEqual(unchanged["status"], "PENDING_APPROVAL")
        self.assertIsNone(unchanged["approved_by_user_id"])
        self.assertEqual(self.firewall.blocks, [])

    def test_second_administrator_can_approve_human_request(self):
        engine = self.engine()
        action = engine.request_block(
            incident(),
            requested_by_user_id="administrator-1",
        )

        approved = engine.approve(
            action["id"],
            approved_by_user_id="administrator-2",
        )

        self.assertEqual(approved["status"], "EXECUTED")
        self.assertEqual(
            approved["approved_by_user_id"],
            "administrator-2",
        )
        self.assertEqual(self.firewall.blocks, ["8.8.8.8"])

    def test_system_generated_auto_recommendation_can_be_approved(self):
        engine = self.engine(soar_mode="AUTO")
        action = engine.request_block(
            incident(
                incident_id="INC-S8D-AUTO",
                severity="CRITICAL",
            )
        )

        self.assertEqual(action["status"], "PENDING_APPROVAL")
        self.assertIsNone(action["requested_by_user_id"])

        approved = engine.approve(
            action["id"],
            approved_by_user_id="administrator-1",
        )

        self.assertEqual(approved["status"], "EXECUTED")
        self.assertEqual(
            approved["approved_by_user_id"],
            "administrator-1",
        )
        self.assertEqual(self.firewall.blocks, ["8.8.8.8"])


if __name__ == "__main__":
    unittest.main()
