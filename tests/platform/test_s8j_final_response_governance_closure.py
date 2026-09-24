import sqlite3
import unittest
from pathlib import Path

from backend.analyzer.app_authorization import (
    ROLE_ADMINISTRATOR,
    required_roles_for_request,
)
from backend.analyzer.database import ensure_schema
from backend.analyzer.soar import (
    ApprovalDeniedError,
    SoarEngine,
)
from backend.analyzer.soar.firewall import (
    FirewallError,
    rule_name_for_ip,
)
from backend.analyzer.soar.policies import ResponsePolicy


class ClosureFirewall:
    def __init__(self, fail_first_block=False):
        self.blocks = []
        self.unblocks = []
        self.rules = set()
        self.fail_first_block = fail_first_block

    def block_ip(self, ip):
        self.blocks.append(ip)
        if self.fail_first_block:
            self.fail_first_block = False
            raise FirewallError("mock transient firewall failure")
        self.rules.add(ip)
        return "EXECUTED", rule_name_for_ip(ip)

    def unblock_ip(self, ip):
        self.unblocks.append(ip)
        self.rules.discard(ip)
        return "ROLLED_BACK", rule_name_for_ip(ip)

    def rule_exists(self, ip):
        return ip in self.rules


def incident(incident_id="INC-S8J", **overrides):
    value = {
        "incident_id": incident_id,
        "log_id": "LOG-S8J",
        "hostname": "HOST-S8J",
        "source_ip": "8.8.8.8",
        "severity": "HIGH",
        "threat_score": 80,
        "threat_type": "Brute Force Attack",
    }
    value.update(overrides)
    return value


def policy(**overrides):
    values = {
        "soar_mode": "MANUAL",
        "soar_dry_run": "false",
        "soar_auto_min_score": "90",
        "soar_allow_private_ip_blocking": "false",
        "soar_allowlist": "[]",
    }
    values.update(overrides)
    return ResponsePolicy(values, self_ips={"198.51.100.7"})


class S8JFinalResponseGovernanceClosureTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        ensure_schema(self.conn)

    def tearDown(self):
        self.conn.close()

    def engine(self, firewall=None, **settings):
        return SoarEngine(
            self.conn,
            firewall or ClosureFirewall(),
            policy(**settings),
        )

    def test_all_live_response_mutations_remain_administrator_only(self):
        admin_only_paths = (
            "/api/soar/block-ip",
            "/api/soar/unblock-ip",
            "/api/response-actions/1/approve",
            "/api/response-actions/1/reject",
            "/api/response-actions/1/retry",
            "/api/response-actions/1/reconcile",
            "/api/incidents/settings",
        )
        expected = frozenset({ROLE_ADMINISTRATOR})
        for path in admin_only_paths:
            with self.subTest(path=path):
                self.assertEqual(
                    required_roles_for_request(path, "POST"),
                    expected,
                )

    def test_manual_and_auto_requests_cannot_execute_before_approval(self):
        manual_firewall = ClosureFirewall()
        manual = self.engine(manual_firewall)
        requested = manual.request_block(
            incident(),
            requested_by_user_id="administrator-requester",
        )
        self.assertEqual(requested["status"], "PENDING_APPROVAL")
        self.assertEqual(manual_firewall.blocks, [])

        with self.assertRaises(ApprovalDeniedError):
            manual.approve(
                requested["id"],
                approved_by_user_id="administrator-requester",
            )
        self.assertEqual(manual_firewall.blocks, [])

        auto_firewall = ClosureFirewall()
        auto = self.engine(
            auto_firewall,
            soar_mode="AUTO",
        )
        recommended = auto.request_block(
            incident(
                "INC-S8J-AUTO",
                severity="CRITICAL",
                threat_score=99,
            )
        )
        self.assertEqual(
            recommended["status"],
            "PENDING_APPROVAL",
        )
        self.assertIsNone(recommended["requested_by_user_id"])
        self.assertEqual(auto_firewall.blocks, [])

    def test_rejection_is_terminal_and_never_mutates_firewall(self):
        firewall = ClosureFirewall()
        engine = self.engine(firewall)
        requested = engine.request_block(
            incident(),
            requested_by_user_id="administrator-requester",
        )

        rejected = engine.reject(
            requested["id"],
            rejected_by_user_id="administrator-reviewer",
            reason="containment not authorized for this target",
        )
        self.assertEqual(rejected["status"], "REJECTED")
        self.assertEqual(firewall.blocks, [])

        later = engine.approve(
            requested["id"],
            approved_by_user_id="administrator-approver",
        )
        self.assertEqual(later["status"], "REJECTED")
        self.assertEqual(firewall.blocks, [])

    def test_failed_execution_retry_reuses_original_approval(self):
        firewall = ClosureFirewall(fail_first_block=True)
        engine = self.engine(firewall)
        requested = engine.request_block(
            incident(),
            requested_by_user_id="administrator-requester",
        )
        failed = engine.approve(
            requested["id"],
            approved_by_user_id="administrator-approver",
        )
        self.assertEqual(failed["status"], "FAILED")

        retried = engine.retry(
            failed["id"],
            retried_by_user_id="administrator-retry",
            reason="transient firewall failure cleared",
        )
        self.assertEqual(retried["status"], "EXECUTED")
        self.assertEqual(
            retried["approved_by_user_id"],
            "administrator-approver",
        )
        self.assertEqual(retried["metadata"]["retry_count"], 1)
        self.assertEqual(
            firewall.blocks,
            ["8.8.8.8", "8.8.8.8"],
        )

    def test_legacy_incident_execute_surface_remains_simulation_only(self):
        app_source = (
            Path(__file__).resolve().parents[2]
            / "backend"
            / "analyzer"
            / "app.py"
        ).read_text(encoding="utf-8")

        self.assertIn(
            'if enforce:',
            app_source,
        )
        self.assertIn(
            "legacy live playbook execution is disabled",
            app_source,
        )
        self.assertIn(
            "use the safe SOAR IP action",
            app_source,
        )


if __name__ == "__main__":
    unittest.main()
