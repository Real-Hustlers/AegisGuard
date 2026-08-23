"""Mock-only tests for the constrained Analyzer-side SOAR engine."""

import sqlite3
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from backend.analyzer.database import ensure_schema
from backend.analyzer.soar.engine import SoarEngine
from backend.analyzer.soar.firewall import WindowsFirewall, rule_name_for_ip
from backend.analyzer.soar.policies import ResponsePolicy


class FakeFirewall:
    def __init__(self):
        self.blocks = []
        self.unblocks = []
        self.fail = False

    def block_ip(self, ip):
        if self.fail:
            from backend.analyzer.soar.firewall import FirewallError
            raise FirewallError("mock firewall failure")
        self.blocks.append(ip)
        return "EXECUTED", rule_name_for_ip(ip)

    def unblock_ip(self, ip):
        self.unblocks.append(ip)
        return "ROLLED_BACK", rule_name_for_ip(ip)


def incident(**overrides):
    result = {
        "incident_id": "INC-1", "log_id": "LOG-1", "hostname": "COLLECTOR-1",
        "source_ip": "8.8.8.8", "severity": "HIGH", "threat_score": 80,
        "threat_type": "Brute Force Attack",
    }
    result.update(overrides)
    return result


class SoarEngineTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        ensure_schema(self.conn)
        self.firewall = FakeFirewall()

    def tearDown(self):
        self.conn.close()

    def engine(self, **settings):
        values = {"soar_mode": "MANUAL", "soar_dry_run": "false", "soar_auto_min_score": "90",
                  "soar_allow_private_ip_blocking": "false", "soar_allowlist": "[]"}
        values.update(settings)
        return SoarEngine(self.conn, self.firewall, ResponsePolicy(values, self_ips={"198.51.100.7"}))

    def test_valid_public_ip_blocks_and_is_persisted(self):
        action = self.engine().request_block(incident(), approved=True)
        self.assertEqual(action["status"], "EXECUTED")
        self.assertEqual(self.firewall.blocks, ["8.8.8.8"])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM response_actions").fetchone()[0], 1)

    def test_invalid_loopback_self_allowlist_and_private_targets_are_denied(self):
        cases = [("not-an-ip", "invalid"), ("127.0.0.1", "loopback"), ("::1", "loopback"),
                 ("198.51.100.7", "Analyzer"), ("10.0.0.5", "private")]
        for index, (target, reason) in enumerate(cases):
            action = self.engine().request_block(incident(incident_id=f"INC-{index}"), target, approved=True)
            self.assertEqual(action["status"], "BLOCKED_BY_POLICY")
            self.assertIn(reason.lower(), action["reason"].lower())
        allowlisted = self.engine(soar_allowlist='["8.8.4.4"]')
        action = allowlisted.request_block(incident(incident_id="INC-allow"), "8.8.4.4", approved=True)
        self.assertEqual(action["status"], "BLOCKED_BY_POLICY")
        self.assertEqual(self.firewall.blocks, [])

    def test_private_target_can_be_enabled_explicitly(self):
        action = self.engine(soar_allow_private_ip_blocking="true").request_block(
            incident(), "10.0.0.5", approved=True
        )
        self.assertEqual(action["status"], "EXECUTED")

    def test_block_idempotency_does_not_execute_twice(self):
        engine = self.engine()
        first = engine.request_block(incident(), approved=True)
        second = engine.request_block(incident(), approved=True)
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(self.firewall.blocks, ["8.8.8.8"])

    def test_manual_creates_pending_without_firewall_call(self):
        action = self.engine().request_block(incident())
        self.assertEqual(action["status"], "PENDING_APPROVAL")
        self.assertEqual(self.firewall.blocks, [])

    def test_auto_executes_only_qualifying_incident(self):
        auto = self.engine(soar_mode="AUTO")
        denied = auto.request_block(incident())
        self.assertEqual(denied["status"], "BLOCKED_BY_POLICY")
        action = auto.request_block(incident(incident_id="INC-critical", severity="CRITICAL"))
        self.assertEqual(action["status"], "EXECUTED")
        self.assertEqual(self.firewall.blocks, ["8.8.8.8"])

    def test_off_never_executes_and_dry_run_never_calls_firewall(self):
        off = self.engine(soar_mode="OFF")
        self.assertEqual(off.request_block(incident())["status"], "SKIPPED")
        dry = self.engine(soar_dry_run="true")
        action = dry.request_block(incident(incident_id="INC-dry"), approved=True)
        self.assertEqual(action["status"], "DRY_RUN")
        self.assertEqual(self.firewall.blocks, [])

    def test_unblock_rolls_back_only_the_owned_action(self):
        engine = self.engine()
        engine.request_block(incident(), approved=True)
        result = engine.unblock("8.8.8.8")
        self.assertEqual(result["status"], "ROLLED_BACK")
        self.assertEqual(result["rollback_status"], "ROLLED_BACK")
        self.assertEqual(self.firewall.unblocks, ["8.8.8.8"])

    def test_firewall_failure_is_recorded_not_raised(self):
        self.firewall.fail = True
        action = self.engine().request_block(incident(), approved=True)
        self.assertEqual(action["status"], "FAILED")
        self.assertIn("mock firewall failure", action["error"])

    def test_windows_adapter_uses_exact_owned_rule_name(self):
        calls = []
        class Result:
            def __init__(self, returncode):
                self.returncode, self.stdout, self.stderr = returncode, "", ""
        def runner(command, **kwargs):
            calls.append(command)
            return Result(1 if "Get-NetFirewallRule" in command[-1] else 0)
        firewall = WindowsFirewall(runner=runner, platform="win32")
        firewall.block_ip("8.8.8.8")
        firewall.unblock_ip("8.8.8.8")
        name = rule_name_for_ip("8.8.8.8")
        self.assertTrue(all(name in call[-1] for call in calls))
        self.assertTrue(any("Remove-NetFirewallRule -DisplayName '" + name + "'" in call[-1] for call in calls))
        self.assertFalse(any("*" in call[-1] for call in calls))

    def test_concurrent_duplicate_requests_create_one_action(self):
        db_path = Path.cwd() / ".aegisguard_soar_concurrency_test.db"
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(db_path) + suffix)
            if candidate.exists():
                candidate.unlink()
        try:
            setup = sqlite3.connect(db_path)
            setup.row_factory = sqlite3.Row
            ensure_schema(setup)
            setup.close()
            results, failures = [], []

            def request_from_collector():
                try:
                    conn = sqlite3.connect(db_path, timeout=5)
                    conn.row_factory = sqlite3.Row
                    engine = SoarEngine(conn, FakeFirewall(), ResponsePolicy({
                        "soar_mode": "MANUAL", "soar_dry_run": "true", "soar_allowlist": "[]"
                    }, self_ips=set()))
                    results.append(engine.request_block(incident(), approved=True)["id"])
                    conn.close()
                except Exception as exc:  # test reports a concurrent lock as failure
                    failures.append(exc)

            threads = [threading.Thread(target=request_from_collector) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(failures, [])
            self.assertEqual(len(set(results)), 1)
        finally:
            for suffix in ("", "-wal", "-shm"):
                candidate = Path(str(db_path) + suffix)
                if candidate.exists():
                    candidate.unlink()


if __name__ == "__main__":
    unittest.main()
