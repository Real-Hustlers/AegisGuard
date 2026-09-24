import sqlite3
import threading
import unittest
from pathlib import Path

from backend.analyzer.database import ensure_schema
from backend.analyzer.soar import RetryDeniedError, SoarEngine
from backend.analyzer.soar.firewall import FirewallError, rule_name_for_ip
from backend.analyzer.soar.policies import ResponsePolicy


class FailOnceFirewall:
    def __init__(self):
        self.lock = threading.Lock()
        self.block_attempts = []
        self.failures_remaining = 1

    def block_ip(self, ip):
        with self.lock:
            self.block_attempts.append(ip)
            if self.failures_remaining:
                self.failures_remaining -= 1
                raise FirewallError("mock transient firewall failure")
        return "EXECUTED", rule_name_for_ip(ip)

    def unblock_ip(self, ip):
        return "ROLLED_BACK", rule_name_for_ip(ip)

    def rule_exists(self, ip):
        return False


class FailedReadBarrierEngine(SoarEngine):
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
            and action["status"] == "FAILED"
        ):
            self._synced = True
            self._read_barrier.wait(timeout=2)
        return action


def incident(incident_id="INC-S8I", ip="8.8.8.8"):
    return {
        "incident_id": incident_id,
        "log_id": "LOG-S8I",
        "hostname": "HOST-S8I",
        "source_ip": ip,
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


class S8IGovernedFailedExecutionRetryTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        ensure_schema(self.conn)
        self.firewall = FailOnceFirewall()

    def tearDown(self):
        self.conn.close()

    def engine(self, **settings):
        return SoarEngine(
            self.conn,
            self.firewall,
            policy(**settings),
        )

    def failed_action(self, incident_id="INC-S8I"):
        engine = self.engine()
        requested = engine.request_block(
            incident(incident_id),
            requested_by_user_id="administrator-requester",
        )
        failed = engine.approve(
            requested["id"],
            approved_by_user_id="administrator-approver",
        )
        self.assertEqual(failed["status"], "FAILED")
        self.assertEqual(
            failed["approved_by_user_id"],
            "administrator-approver",
        )
        return engine, failed

    def test_retry_requires_trusted_actor_identity(self):
        engine, failed = self.failed_action()

        with self.assertRaises(RetryDeniedError) as caught:
            engine.retry(
                failed["id"],
                reason="retry after transient firewall failure",
            )

        self.assertEqual(
            caught.exception.code,
            "retry_identity_required",
        )
        self.assertEqual(
            engine.get_action(failed["id"])["status"],
            "FAILED",
        )
        self.assertEqual(len(self.firewall.block_attempts), 1)

    def test_retry_requires_bounded_reason(self):
        engine, failed = self.failed_action()

        with self.assertRaises(RetryDeniedError) as missing:
            engine.retry(
                failed["id"],
                retried_by_user_id="administrator-retry",
                reason="   ",
            )
        self.assertEqual(
            missing.exception.code,
            "retry_reason_required",
        )

        with self.assertRaises(RetryDeniedError) as too_long:
            engine.retry(
                failed["id"],
                retried_by_user_id="administrator-retry",
                reason="x" * 501,
            )
        self.assertEqual(
            too_long.exception.code,
            "retry_reason_too_long",
        )
        self.assertEqual(len(self.firewall.block_attempts), 1)

    def test_retry_requires_original_approval_authority(self):
        engine, failed = self.failed_action()
        self.conn.execute(
            """
            UPDATE response_actions
            SET approved_by_user_id=NULL
            WHERE id=?
            """,
            (failed["id"],),
        )
        self.conn.commit()

        with self.assertRaises(RetryDeniedError) as caught:
            engine.retry(
                failed["id"],
                retried_by_user_id="administrator-retry",
                reason="retry requested",
            )

        self.assertEqual(
            caught.exception.code,
            "retry_approval_missing",
        )
        self.assertEqual(len(self.firewall.block_attempts), 1)

    def test_policy_change_denies_retry_without_consuming_failed_state(self):
        engine, failed = self.failed_action()
        changed = SoarEngine(
            self.conn,
            self.firewall,
            policy(soar_mode="OFF"),
        )

        with self.assertRaises(RetryDeniedError) as caught:
            changed.retry(
                failed["id"],
                retried_by_user_id="administrator-retry",
                reason="retry requested",
            )

        self.assertEqual(
            caught.exception.code,
            "response_mode_off",
        )
        self.assertEqual(
            changed.get_action(failed["id"])["status"],
            "FAILED",
        )
        self.assertEqual(len(self.firewall.block_attempts), 1)

    def test_target_safety_change_denies_retry_and_preserves_failed_state(self):
        engine, failed = self.failed_action()
        changed = SoarEngine(
            self.conn,
            self.firewall,
            policy(soar_allowlist='["8.8.8.8"]'),
        )

        with self.assertRaises(RetryDeniedError) as caught:
            changed.retry(
                failed["id"],
                retried_by_user_id="administrator-retry",
                reason="retry requested",
            )

        self.assertEqual(
            caught.exception.code,
            "retry_target_blocked",
        )
        self.assertEqual(
            changed.get_action(failed["id"])["status"],
            "FAILED",
        )
        self.assertEqual(len(self.firewall.block_attempts), 1)

    def test_retry_succeeds_and_preserves_retry_provenance(self):
        engine, failed = self.failed_action()

        retried = engine.retry(
            failed["id"],
            retried_by_user_id="administrator-retry",
            reason="transient firewall service recovered",
        )

        self.assertEqual(retried["status"], "EXECUTED")
        self.assertEqual(
            retried["approved_by_user_id"],
            "administrator-approver",
        )
        self.assertEqual(
            retried["metadata"]["retry_count"],
            1,
        )
        history = retried["metadata"]["retry_history"]
        self.assertEqual(len(history), 1)
        self.assertEqual(
            history[0]["by_user_id"],
            "administrator-retry",
        )
        self.assertEqual(
            history[0]["reason"],
            "transient firewall service recovered",
        )
        self.assertEqual(
            history[0]["previous_error"],
            "mock transient firewall failure",
        )
        self.assertEqual(
            self.firewall.block_attempts,
            ["8.8.8.8", "8.8.8.8"],
        )

    def test_concurrent_retries_claim_external_execution_once(self):
        path = Path.cwd() / ".aegisguard_s8i_retry_race_test.db"
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(path) + suffix)
            if candidate.exists():
                candidate.unlink()

        try:
            setup = sqlite3.connect(path, timeout=5)
            setup.row_factory = sqlite3.Row
            ensure_schema(setup)
            shared_firewall = FailOnceFirewall()
            setup_engine = SoarEngine(
                setup,
                shared_firewall,
                policy(),
            )
            requested = setup_engine.request_block(
                incident("INC-S8I-RACE"),
                requested_by_user_id="administrator-requester",
            )
            failed = setup_engine.approve(
                requested["id"],
                approved_by_user_id="administrator-approver",
            )
            self.assertEqual(failed["status"], "FAILED")
            setup.close()

            barrier = threading.Barrier(2)
            results = []
            failures = []
            result_lock = threading.Lock()

            def retry(actor):
                conn = sqlite3.connect(path, timeout=5)
                conn.row_factory = sqlite3.Row
                try:
                    engine = FailedReadBarrierEngine(
                        conn,
                        shared_firewall,
                        policy(),
                        read_barrier=barrier,
                    )
                    result = engine.retry(
                        failed["id"],
                        retried_by_user_id=actor,
                        reason="concurrent retry",
                    )
                    with result_lock:
                        results.append(result)
                except Exception as exc:
                    with result_lock:
                        failures.append(exc)
                finally:
                    conn.close()

            threads = [
                threading.Thread(
                    target=retry,
                    args=("administrator-retry-a",),
                ),
                threading.Thread(
                    target=retry,
                    args=("administrator-retry-b",),
                ),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)

            self.assertTrue(
                all(not thread.is_alive() for thread in threads)
            )
            self.assertEqual(failures, [])
            self.assertEqual(len(results), 2)

            conn = sqlite3.connect(path, timeout=5)
            conn.row_factory = sqlite3.Row
            try:
                final = SoarEngine(
                    conn,
                    shared_firewall,
                    policy(),
                ).get_action(failed["id"])
            finally:
                conn.close()

            self.assertEqual(final["status"], "EXECUTED")
            self.assertEqual(
                shared_firewall.block_attempts,
                ["8.8.8.8", "8.8.8.8"],
            )
            self.assertEqual(
                final["metadata"]["retry_count"],
                1,
            )
            self.assertEqual(
                len(final["metadata"]["retry_history"]),
                1,
            )
        finally:
            for suffix in ("", "-wal", "-shm"):
                candidate = Path(str(path) + suffix)
                if candidate.exists():
                    candidate.unlink()


if __name__ == "__main__":
    unittest.main()
