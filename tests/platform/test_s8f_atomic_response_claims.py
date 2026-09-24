import sqlite3
import threading
import unittest
from pathlib import Path

from backend.analyzer.database import ensure_schema
from backend.analyzer.soar.engine import SoarEngine
from backend.analyzer.soar.firewall import rule_name_for_ip
from backend.analyzer.soar.policies import ResponsePolicy


class SharedFirewall:
    def __init__(self):
        self.lock = threading.Lock()
        self.blocks = []
        self.unblocks = []
        self.rollback_barrier = threading.Barrier(2)

    def block_ip(self, ip):
        with self.lock:
            self.blocks.append(ip)
        return "EXECUTED", rule_name_for_ip(ip)

    def unblock_ip(self, ip):
        with self.lock:
            self.unblocks.append(ip)
        try:
            self.rollback_barrier.wait(timeout=0.5)
        except threading.BrokenBarrierError:
            pass
        return "ROLLED_BACK", rule_name_for_ip(ip)


class ApprovalReadBarrierEngine(SoarEngine):
    def __init__(self, *args, approval_barrier=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._approval_barrier = approval_barrier
        self._synchronize_first_pending_read = True

    def get_action(self, action_id):
        action = super().get_action(action_id)
        if (
            self._synchronize_first_pending_read
            and self._approval_barrier is not None
            and action
            and action["status"] == "PENDING_APPROVAL"
        ):
            self._synchronize_first_pending_read = False
            self._approval_barrier.wait(timeout=2)
        return action


def incident(incident_id="INC-S8F"):
    return {
        "incident_id": incident_id,
        "log_id": "LOG-S8F",
        "hostname": "HOST-S8F",
        "source_ip": "8.8.8.8",
        "severity": "HIGH",
        "threat_score": 80,
        "threat_type": "Brute Force Attack",
    }


def policy():
    return ResponsePolicy(
        {
            "soar_mode": "MANUAL",
            "soar_dry_run": "false",
            "soar_auto_min_score": "90",
            "soar_allow_private_ip_blocking": "false",
            "soar_allowlist": "[]",
        },
        self_ips=set(),
    )


class S8FAtomicResponseClaimTests(unittest.TestCase):
    def setUp(self):
        self.path = Path.cwd() / ".aegisguard_s8f_claim_test.db"
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(self.path) + suffix)
            if candidate.exists():
                candidate.unlink()

        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        ensure_schema(conn)
        self.firewall = SharedFirewall()

        engine = SoarEngine(
            conn,
            self.firewall,
            policy(),
        )
        self.requested = engine.request_block(
            incident(),
            requested_by_user_id="administrator-requester",
        )
        conn.close()

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(self.path) + suffix)
            if candidate.exists():
                candidate.unlink()

    def connection(self):
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    def test_concurrent_approvals_claim_execution_once(self):
        barrier = threading.Barrier(2)
        results = []
        failures = []
        lock = threading.Lock()

        def approve_as(user_id):
            conn = self.connection()
            try:
                engine = ApprovalReadBarrierEngine(
                    conn,
                    self.firewall,
                    policy(),
                    approval_barrier=barrier,
                )
                result = engine.approve(
                    self.requested["id"],
                    approved_by_user_id=user_id,
                )
                with lock:
                    results.append(result)
            except Exception as exc:
                with lock:
                    failures.append(exc)
            finally:
                conn.close()

        threads = [
            threading.Thread(
                target=approve_as,
                args=(f"administrator-approver-{index}",),
            )
            for index in (1, 2)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(failures, [])
        self.assertEqual(len(results), 2)
        self.assertEqual(self.firewall.blocks, ["8.8.8.8"])

        conn = self.connection()
        try:
            final = SoarEngine(
                conn,
                self.firewall,
                policy(),
            ).get_action(self.requested["id"])
        finally:
            conn.close()

        self.assertEqual(final["status"], "EXECUTED")
        self.assertIn(
            final["approved_by_user_id"],
            {
                "administrator-approver-1",
                "administrator-approver-2",
            },
        )
        self.assertEqual(
            sum(
                1
                for result in results
                if result["approved_by_user_id"]
                == final["approved_by_user_id"]
            ),
            2,
        )

    def test_concurrent_rollbacks_claim_external_removal_once(self):
        conn = self.connection()
        try:
            engine = SoarEngine(conn, self.firewall, policy())
            executed = engine.approve(
                self.requested["id"],
                approved_by_user_id="administrator-approver",
            )
            self.assertEqual(executed["status"], "EXECUTED")
        finally:
            conn.close()

        results = []
        failures = []
        lock = threading.Lock()

        def rollback_as(user_id):
            conn = self.connection()
            try:
                result = SoarEngine(
                    conn,
                    self.firewall,
                    policy(),
                ).unblock(
                    "8.8.8.8",
                    rollback_by_user_id=user_id,
                )
                with lock:
                    results.append(result)
            except Exception as exc:
                with lock:
                    failures.append(exc)
            finally:
                conn.close()

        threads = [
            threading.Thread(
                target=rollback_as,
                args=(f"administrator-rollback-{index}",),
            )
            for index in (1, 2)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(failures, [])
        self.assertEqual(len(results), 2)
        self.assertEqual(self.firewall.unblocks, ["8.8.8.8"])

        conn = self.connection()
        try:
            final = SoarEngine(
                conn,
                self.firewall,
                policy(),
            ).get_action(self.requested["id"])
        finally:
            conn.close()

        self.assertEqual(final["status"], "ROLLED_BACK")
        self.assertEqual(final["rollback_status"], "ROLLED_BACK")
        self.assertEqual(
            sum(
                1
                for result in results
                if result.get("status") == "ROLLED_BACK"
            ),
            1,
        )
        self.assertEqual(
            sum(
                1
                for result in results
                if result.get("status") == "SKIPPED"
            ),
            1,
        )


if __name__ == "__main__":
    unittest.main()
