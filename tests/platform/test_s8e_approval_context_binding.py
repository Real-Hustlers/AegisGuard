import json
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
        "incident_id": "INC-S8E",
        "log_id": "LOG-S8E",
        "hostname": "HOST-S8E",
        "source_ip": "8.8.8.8",
        "severity": "HIGH",
        "threat_score": 80,
        "threat_type": "Brute Force Attack",
    }
    value.update(overrides)
    return value


class S8EApprovalContextBindingTests(unittest.TestCase):
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

    def test_pending_action_persists_approval_context(self):
        action = self.engine(
            soar_dry_run="true",
        ).request_block(
            incident(),
            requested_by_user_id="administrator-1",
        )

        self.assertEqual(action["status"], "PENDING_APPROVAL")
        self.assertEqual(
            action["metadata"]["approval_context"],
            {
                "version": 1,
                "mode": "MANUAL",
                "dry_run": True,
            },
        )

    def test_off_mode_is_kill_switch_for_pending_approval(self):
        requested = self.engine().request_block(
            incident(),
            requested_by_user_id="administrator-1",
        )

        with self.assertRaises(ApprovalDeniedError) as caught:
            self.engine(soar_mode="OFF").approve(
                requested["id"],
                approved_by_user_id="administrator-2",
            )

        self.assertEqual(
            caught.exception.code,
            "response_mode_off",
        )
        unchanged = self.engine().get_action(requested["id"])
        self.assertEqual(unchanged["status"], "PENDING_APPROVAL")
        self.assertIsNone(unchanged["approved_by_user_id"])
        self.assertEqual(self.firewall.blocks, [])

    def test_dry_run_change_invalidates_pending_approval(self):
        requested = self.engine(
            soar_dry_run="true",
        ).request_block(
            incident(),
            requested_by_user_id="administrator-1",
        )

        with self.assertRaises(ApprovalDeniedError) as caught:
            self.engine(
                soar_dry_run="false",
            ).approve(
                requested["id"],
                approved_by_user_id="administrator-2",
            )

        self.assertEqual(
            caught.exception.code,
            "response_policy_changed",
        )
        unchanged = self.engine().get_action(requested["id"])
        self.assertEqual(unchanged["status"], "PENDING_APPROVAL")
        self.assertEqual(self.firewall.blocks, [])

    def test_auto_threshold_change_invalidates_pending_approval(self):
        requested = self.engine(
            soar_mode="AUTO",
            soar_auto_min_score="90",
        ).request_block(
            incident(
                incident_id="INC-S8E-AUTO",
                threat_score=95,
            )
        )

        self.assertEqual(requested["status"], "PENDING_APPROVAL")
        self.assertEqual(
            requested["metadata"]["approval_context"]["auto_min_score"],
            90,
        )

        with self.assertRaises(ApprovalDeniedError) as caught:
            self.engine(
                soar_mode="AUTO",
                soar_auto_min_score="99",
            ).approve(
                requested["id"],
                approved_by_user_id="administrator-2",
            )

        self.assertEqual(
            caught.exception.code,
            "response_policy_changed",
        )
        self.assertEqual(self.firewall.blocks, [])

    def test_legacy_pending_action_without_context_fails_closed(self):
        requested = self.engine().request_block(
            incident(),
            requested_by_user_id="administrator-1",
        )

        metadata = dict(requested["metadata"])
        metadata.pop("approval_context", None)
        self.conn.execute(
            """
            UPDATE response_actions
            SET metadata=?
            WHERE id=?
            """,
            (
                json.dumps(metadata, sort_keys=True),
                requested["id"],
            ),
        )
        self.conn.commit()

        with self.assertRaises(ApprovalDeniedError) as caught:
            self.engine().approve(
                requested["id"],
                approved_by_user_id="administrator-2",
            )

        self.assertEqual(
            caught.exception.code,
            "approval_context_missing",
        )
        self.assertEqual(
            self.engine().get_action(requested["id"])["status"],
            "PENDING_APPROVAL",
        )
        self.assertEqual(self.firewall.blocks, [])

    def test_unchanged_context_allows_independent_approval(self):
        requested = self.engine().request_block(
            incident(),
            requested_by_user_id="administrator-1",
        )

        approved = self.engine().approve(
            requested["id"],
            approved_by_user_id="administrator-2",
        )

        self.assertEqual(approved["status"], "EXECUTED")
        self.assertEqual(
            approved["approved_by_user_id"],
            "administrator-2",
        )
        self.assertEqual(self.firewall.blocks, ["8.8.8.8"])


if __name__ == "__main__":
    unittest.main()
