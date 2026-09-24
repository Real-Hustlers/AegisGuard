import sqlite3
import threading
import unittest
from pathlib import Path

from backend.analyzer.database import ensure_schema
from backend.analyzer.soar import RejectionDeniedError, SoarEngine
from backend.analyzer.soar.firewall import rule_name_for_ip
from backend.analyzer.soar.policies import ResponsePolicy


class FakeFirewall:
    def __init__(self):
        self.lock = threading.Lock()
        self.blocks = []

    def block_ip(self, ip):
        with self.lock:
            self.blocks.append(ip)
        return "EXECUTED", rule_name_for_ip(ip)

    def unblock_ip(self, ip):
        return "ROLLED_BACK", rule_name_for_ip(ip)


class ReadBarrierEngine(SoarEngine):
    def __init__(self, *args, read_barrier=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._read_barrier = read_barrier
        self._synced = False

    def get_action(self, action_id):
        action = super().get_action(action_id)
        if (
            not self._synced
            and self._read_barrier is not None
            and action
            and action["status"] == "PENDING_APPROVAL"
        ):
            self._synced = True
            self._read_barrier.wait(timeout=2)
        return action


def incident(incident_id="INC-S8H"):
    return {
        "incident_id": incident_id,
        "log_id": "LOG-S8H",
        "hostname": "HOST-S8H",
        "source_ip": "8.8.8.8",
        "severity": "HIGH",
        "threat_score": 80,
        "threat_type": "Brute Force Attack",
    }


def policy(**overrides):
    values = {
        "soar_mode": "MANUAL",
        "soar_dry_run": "false",
        "soar_auto_min_score": "90",
        "soar_allow_private_ip_blocking": "false",
        "soar_allowlist": "[]",
    }
    values.update(overrides)
    return ResponsePolicy(values, self_ips=set())


class S8HExplicitRejectionLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        ensure_schema(self.conn)
        self.firewall = FakeFirewall()

    def tearDown(self):
        self.conn.close()

    def engine(self, **settings):
        return SoarEngine(
            self.conn,
            self.firewall,
            policy(**settings),
        )

    def test_rejection_requires_trusted_actor_identity(self):
        engine = self.engine()
        action = engine.request_block(
            incident(),
            requested_by_user_id="administrator-requester",
        )

        with self.assertRaises(RejectionDeniedError) as caught:
            engine.reject(
                action["id"],
                reason="not appropriate for this incident",
            )

        self.assertEqual(
            caught.exception.code,
            "rejection_identity_required",
        )
        self.assertEqual(
            engine.get_action(action["id"])["status"],
            "PENDING_APPROVAL",
        )
        self.assertEqual(self.firewall.blocks, [])

    def test_rejection_requires_reason(self):
        engine = self.engine()
        action = engine.request_block(
            incident(),
            requested_by_user_id="administrator-requester",
        )

        with self.assertRaises(RejectionDeniedError) as caught:
            engine.reject(
                action["id"],
                rejected_by_user_id="administrator-reviewer",
                reason="   ",
            )

        self.assertEqual(
            caught.exception.code,
            "rejection_reason_required",
        )
        self.assertEqual(
            engine.get_action(action["id"])["status"],
            "PENDING_APPROVAL",
        )

    def test_pending_action_is_rejected_with_provenance(self):
        engine = self.engine()
        action = engine.request_block(
            incident(),
            requested_by_user_id="administrator-requester",
        )

        rejected = engine.reject(
            action["id"],
            rejected_by_user_id="administrator-reviewer",
            reason="target is part of an approved external dependency",
        )

        self.assertEqual(rejected["status"], "REJECTED")
        self.assertIsNone(rejected["approved_by_user_id"])
        self.assertEqual(
            rejected["metadata"]["rejection"]["by_user_id"],
            "administrator-reviewer",
        )
        self.assertEqual(
            rejected["metadata"]["rejection"]["reason"],
            "target is part of an approved external dependency",
        )
        self.assertTrue(rejected["metadata"]["rejection"]["at"])
        self.assertEqual(self.firewall.blocks, [])

    def test_rejected_action_cannot_later_be_approved(self):
        engine = self.engine()
        action = engine.request_block(
            incident(),
            requested_by_user_id="administrator-requester",
        )
        rejected = engine.reject(
            action["id"],
            rejected_by_user_id="administrator-reviewer",
            reason="containment rejected",
        )
        self.assertEqual(rejected["status"], "REJECTED")

        later = engine.approve(
            action["id"],
            approved_by_user_id="administrator-approver",
        )

        self.assertEqual(later["status"], "REJECTED")
        self.assertEqual(self.firewall.blocks, [])

    def test_system_generated_auto_recommendation_can_be_rejected(self):
        engine = self.engine(soar_mode="AUTO")
        action = engine.request_block(
            incident("INC-S8H-AUTO") | {
                "severity": "CRITICAL",
            }
        )
        self.assertEqual(action["status"], "PENDING_APPROVAL")
        self.assertIsNone(action["requested_by_user_id"])

        rejected = engine.reject(
            action["id"],
            rejected_by_user_id="administrator-reviewer",
            reason="human review rejected automatic containment",
        )

        self.assertEqual(rejected["status"], "REJECTED")
        self.assertEqual(self.firewall.blocks, [])

    def test_approval_and_rejection_race_has_one_decision(self):
        path = Path.cwd() / ".aegisguard_s8h_race_test.db"
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(path) + suffix)
            if candidate.exists():
                candidate.unlink()

        try:
            setup = sqlite3.connect(path, timeout=5)
            setup.row_factory = sqlite3.Row
            ensure_schema(setup)
            shared_firewall = FakeFirewall()
            requested = SoarEngine(
                setup,
                shared_firewall,
                policy(),
            ).request_block(
                incident("INC-S8H-RACE"),
                requested_by_user_id="administrator-requester",
            )
            setup.close()

            barrier = threading.Barrier(2)
            results = []
            failures = []
            result_lock = threading.Lock()

            def decide(kind):
                conn = sqlite3.connect(path, timeout=5)
                conn.row_factory = sqlite3.Row
                try:
                    engine = ReadBarrierEngine(
                        conn,
                        shared_firewall,
                        policy(),
                        read_barrier=barrier,
                    )
                    if kind == "approve":
                        result = engine.approve(
                            requested["id"],
                            approved_by_user_id="administrator-approver",
                        )
                    else:
                        result = engine.reject(
                            requested["id"],
                            rejected_by_user_id="administrator-reviewer",
                            reason="concurrent reviewer rejection",
                        )
                    with result_lock:
                        results.append(result)
                except Exception as exc:
                    with result_lock:
                        failures.append(exc)
                finally:
                    conn.close()

            threads = [
                threading.Thread(target=decide, args=("approve",)),
                threading.Thread(target=decide, args=("reject",)),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)

            self.assertTrue(
                all(not thread.is_alive() for thread in threads)
            )
            self.assertEqual(failures, [])

            conn = sqlite3.connect(path, timeout=5)
            conn.row_factory = sqlite3.Row
            try:
                final = SoarEngine(
                    conn,
                    shared_firewall,
                    policy(),
                ).get_action(requested["id"])
            finally:
                conn.close()

            self.assertIn(final["status"], {"EXECUTED", "REJECTED"})
            if final["status"] == "REJECTED":
                self.assertEqual(shared_firewall.blocks, [])
            else:
                self.assertEqual(shared_firewall.blocks, ["8.8.8.8"])

            self.assertFalse(
                final["status"] == "REJECTED"
                and final["approved_by_user_id"] is not None
            )
        finally:
            for suffix in ("", "-wal", "-shm"):
                candidate = Path(str(path) + suffix)
                if candidate.exists():
                    candidate.unlink()


if __name__ == "__main__":
    unittest.main()
