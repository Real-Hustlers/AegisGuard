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
        "incident_id": "INC-S8C",
        "log_id": "LOG-S8C",
        "hostname": "HOST-S8C",
        "source_ip": "8.8.8.8",
        "severity": "HIGH",
        "threat_score": 80,
        "threat_type": "Brute Force Attack",
    }
    value.update(overrides)
    return value


class S8CAutoExecutionGovernanceTests(unittest.TestCase):
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

    def test_request_side_approved_flag_cannot_bypass_manual_approval(self):
        action = self.engine().request_block(
            incident(),
            approved=True,
            requested_by_user_id="requester",
        )

        self.assertEqual(action["status"], "PENDING_APPROVAL")
        self.assertEqual(action["approval_required"], 1)
        self.assertEqual(self.firewall.blocks, [])

    def test_auto_nonqualifying_incident_is_blocked_with_evidence(self):
        action = self.engine(soar_mode="AUTO").request_block(
            incident(),
        )

        self.assertEqual(action["status"], "BLOCKED_BY_POLICY")
        qualification = action["metadata"]["auto_qualification"]
        self.assertFalse(qualification["qualified"])
        self.assertEqual(qualification["severity"], "HIGH")
        self.assertEqual(qualification["score"], 80)
        self.assertEqual(qualification["minimum_score"], 90)
        self.assertEqual(self.firewall.blocks, [])

    def test_auto_qualifying_incident_requires_explicit_approval(self):
        engine = self.engine(soar_mode="AUTO")
        requested = engine.request_block(
            incident(
                incident_id="INC-AUTO-CRITICAL",
                severity="CRITICAL",
            ),
        )

        self.assertEqual(requested["status"], "PENDING_APPROVAL")
        self.assertEqual(requested["approval_required"], 1)
        qualification = requested["metadata"]["auto_qualification"]
        self.assertTrue(qualification["qualified"])
        self.assertIn(
            "critical_severity",
            qualification["reasons"],
        )
        self.assertEqual(self.firewall.blocks, [])

        approved = engine.approve(
            requested["id"],
            approved_by_user_id="administrator-1",
        )

        self.assertEqual(approved["status"], "EXECUTED")
        self.assertEqual(
            approved["approved_by_user_id"],
            "administrator-1",
        )
        self.assertEqual(self.firewall.blocks, ["8.8.8.8"])

    def test_auto_approval_respects_dry_run(self):
        engine = self.engine(
            soar_mode="AUTO",
            soar_dry_run="true",
        )
        requested = engine.request_block(
            incident(
                incident_id="INC-AUTO-SCORE",
                threat_score=95,
            ),
        )

        self.assertEqual(requested["status"], "PENDING_APPROVAL")
        self.assertTrue(
            requested["metadata"]["auto_qualification"]["qualified"]
        )

        approved = engine.approve(
            requested["id"],
            approved_by_user_id="administrator-2",
        )

        self.assertEqual(approved["status"], "DRY_RUN")
        self.assertEqual(self.firewall.blocks, [])


if __name__ == "__main__":
    unittest.main()
