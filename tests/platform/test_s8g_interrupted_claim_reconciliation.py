import json
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone

from backend.analyzer.database import ensure_schema
from backend.analyzer.soar import RecoveryDeniedError, SoarEngine
from backend.analyzer.soar.firewall import rule_name_for_ip
from backend.analyzer.soar.policies import ResponsePolicy


class InspectableFirewall:
    def __init__(self):
        self.rules = set()
        self.blocks = []
        self.unblocks = []
        self.fail_probe = False

    def rule_exists(self, ip):
        if self.fail_probe:
            from backend.analyzer.soar.firewall import FirewallError
            raise FirewallError("mock probe failure")
        return ip in self.rules

    def block_ip(self, ip):
        name = rule_name_for_ip(ip)
        if ip in self.rules:
            return "ALREADY_EXISTS", name
        self.rules.add(ip)
        self.blocks.append(ip)
        return "EXECUTED", name

    def unblock_ip(self, ip):
        self.rules.discard(ip)
        self.unblocks.append(ip)
        return "ROLLED_BACK", rule_name_for_ip(ip)


def incident(incident_id="INC-S8G", ip="8.8.8.8"):
    return {
        "incident_id": incident_id,
        "log_id": "LOG-S8G",
        "hostname": "HOST-S8G",
        "source_ip": ip,
        "severity": "HIGH",
        "threat_score": 80,
        "threat_type": "Brute Force Attack",
    }


class S8GInterruptedClaimReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        ensure_schema(self.conn)
        self.firewall = InspectableFirewall()

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
            ResponsePolicy(values, self_ips=set()),
        )

    def backdate(self, action_id):
        value = (
            datetime.now(timezone.utc)
            - timedelta(minutes=5)
        ).isoformat(timespec="seconds")
        self.conn.execute(
            """
            UPDATE response_actions
            SET updated_at=?
            WHERE id=?
            """,
            (value, action_id),
        )
        self.conn.commit()

    def claim_approval(self, engine, action):
        claimed, won = engine._claim_approval(
            action["id"],
            "administrator-approver",
        )
        self.assertTrue(won)
        self.assertEqual(claimed["status"], "APPROVED")
        return claimed

    def test_fresh_claim_cannot_be_reconciled(self):
        engine = self.engine()
        requested = engine.request_block(
            incident(),
            requested_by_user_id="administrator-requester",
        )
        self.claim_approval(engine, requested)

        with self.assertRaises(RecoveryDeniedError) as caught:
            engine.reconcile(
                requested["id"],
                reconciled_by_user_id="administrator-recovery",
            )

        self.assertEqual(
            caught.exception.code,
            "reconciliation_not_stale",
        )
        self.assertEqual(self.firewall.blocks, [])
        self.assertEqual(
            engine.get_action(requested["id"])["status"],
            "APPROVED",
        )

    def test_stale_dry_run_claim_recovers_without_firewall(self):
        engine = self.engine(soar_dry_run="true")
        requested = engine.request_block(
            incident(),
            requested_by_user_id="administrator-requester",
        )
        self.claim_approval(engine, requested)
        self.backdate(requested["id"])

        recovered = engine.reconcile(
            requested["id"],
            reconciled_by_user_id="administrator-recovery",
        )

        self.assertEqual(recovered["status"], "DRY_RUN")
        self.assertIn("would be created", recovered["simulation_result"])
        self.assertEqual(self.firewall.blocks, [])

    def test_stale_live_claim_with_absent_rule_executes_once(self):
        engine = self.engine()
        requested = engine.request_block(
            incident(),
            requested_by_user_id="administrator-requester",
        )
        self.claim_approval(engine, requested)
        self.backdate(requested["id"])

        recovered = engine.reconcile(
            requested["id"],
            reconciled_by_user_id="administrator-recovery",
        )

        self.assertEqual(recovered["status"], "EXECUTED")
        self.assertEqual(recovered["metadata"]["result"], "EXECUTED")
        self.assertEqual(self.firewall.blocks, ["8.8.8.8"])
        self.assertTrue(self.firewall.rule_exists("8.8.8.8"))

    def test_existing_owned_rule_preserves_prior_rollback_owner(self):
        engine = self.engine()
        first_request = engine.request_block(
            incident("INC-S8G-OWNER"),
            requested_by_user_id="requester-1",
        )
        first = engine.approve(
            first_request["id"],
            approved_by_user_id="approver-1",
        )
        self.assertEqual(first["metadata"]["result"], "EXECUTED")

        second_request = engine.request_block(
            incident("INC-S8G-RECOVERY"),
            requested_by_user_id="requester-2",
        )
        self.claim_approval(engine, second_request)
        self.backdate(second_request["id"])

        before = list(self.firewall.blocks)
        recovered = engine.reconcile(
            second_request["id"],
            reconciled_by_user_id="administrator-recovery",
        )

        self.assertEqual(recovered["status"], "EXECUTED")
        self.assertEqual(
            recovered["metadata"]["result"],
            "ALREADY_EXISTS",
        )
        self.assertEqual(self.firewall.blocks, before)

        owner = engine._rollback_candidate("8.8.8.8")
        self.assertEqual(owner["id"], first["id"])

    def test_stale_rollback_claim_with_present_rule_finishes_once(self):
        engine = self.engine()
        requested = engine.request_block(
            incident(),
            requested_by_user_id="administrator-requester",
        )
        executed = engine.approve(
            requested["id"],
            approved_by_user_id="administrator-approver",
        )
        self.assertEqual(executed["status"], "EXECUTED")

        claimed = engine._claim_rollback(
            "8.8.8.8",
            reason="simulate interrupted rollback",
            rollback_by_user_id="administrator-rollback",
        )
        self.assertEqual(claimed["rollback_status"], "IN_PROGRESS")
        self.backdate(claimed["id"])

        recovered = engine.reconcile(
            claimed["id"],
            reconciled_by_user_id="administrator-recovery",
        )

        self.assertEqual(recovered["status"], "ROLLED_BACK")
        self.assertEqual(recovered["rollback_status"], "ROLLED_BACK")
        self.assertEqual(self.firewall.unblocks, ["8.8.8.8"])

    def test_stale_rollback_claim_with_absent_rule_reconciles_without_repeat(self):
        engine = self.engine()
        requested = engine.request_block(
            incident(),
            requested_by_user_id="administrator-requester",
        )
        executed = engine.approve(
            requested["id"],
            approved_by_user_id="administrator-approver",
        )
        claimed = engine._claim_rollback(
            "8.8.8.8",
            reason="simulate completed removal before crash",
            rollback_by_user_id="administrator-rollback",
        )
        self.assertEqual(claimed["rollback_status"], "IN_PROGRESS")

        self.firewall.rules.discard("8.8.8.8")
        self.backdate(claimed["id"])

        recovered = engine.reconcile(
            claimed["id"],
            reconciled_by_user_id="administrator-recovery",
        )

        self.assertEqual(recovered["status"], "ROLLED_BACK")
        self.assertEqual(recovered["rollback_status"], "ROLLED_BACK")
        self.assertEqual(self.firewall.unblocks, [])


if __name__ == "__main__":
    unittest.main()
