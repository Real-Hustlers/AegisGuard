import json
import os
import sqlite3
import shutil
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from backend.analyzer.database import ensure_schema
from backend.analyzer.ingestion import correlation_engine


class CorrelationEngineTests(unittest.TestCase):
    def _run_correlation(self, logs):
        root = Path(__file__).resolve().parent / "_correlation_tmp"
        ingestion_dir = root / "backend" / "analyzer" / "ingestion"
        output_dir = root / "output"

        shutil.rmtree(root, ignore_errors=True)
        ingestion_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)

        (output_dir / "classified_logs.json").write_text(
            json.dumps(logs, indent=4),
            encoding="utf-8",
        )

        def fake_get_connection():
            conn = sqlite3.connect(":memory:")
            conn.row_factory = sqlite3.Row
            ensure_schema(conn)
            return conn

        real_dirname = os.path.dirname

        def fake_dirname(path):
            if Path(path) == Path(correlation_engine.__file__):
                return str(ingestion_dir)
            return real_dirname(path)

        with patch(
            "os.path.dirname",
            side_effect=fake_dirname,
        ), patch(
            "backend.analyzer.database.get_connection",
            side_effect=fake_get_connection,
        ):
            correlation_engine.run_correlation()

        incidents_path = output_dir / "incidents.json"
        self.assertTrue(incidents_path.exists())
        return json.loads(incidents_path.read_text(encoding="utf-8"))

    @staticmethod
    def _log(
        record_id,
        timestamp,
        event_type,
        hostname="WIN-TEST",
        user="alice",
        source_ip="10.0.0.5",
        process="",
        file_path="",
        severity="LOW",
        raw_log="demo",
    ):
        return {
            "log_id": f"LOG-{record_id:06d}",
            "machine_id": "TEST-MACHINE",
            "hostname": hostname,
            "os": "Windows 11",
            "timestamp": timestamp,
            "event_type": event_type,
            "user": user,
            "source_ip": source_ip,
            "destination_ip": "",
            "process": process,
            "file_path": file_path,
            "severity": severity,
            "raw_log": raw_log,
            "record_id": record_id,
            "event_id": None,
        }

    def test_rule_1_brute_force(self):
        incidents = self._run_correlation([
            self._log(1, "2026-08-18T10:00:00Z", "FAILED_LOGIN", source_ip="10.0.0.5", raw_log="Failed login 1"),
            self._log(2, "2026-08-18T10:01:00Z", "FAILED_LOGIN", source_ip="10.0.0.5", raw_log="Failed login 2"),
            self._log(3, "2026-08-18T10:02:00Z", "FAILED_LOGIN", source_ip="10.0.0.5", raw_log="Failed login 3"),
            self._log(4, "2026-08-18T10:03:00Z", "LOGON_SUCCESS", source_ip="10.0.0.5", raw_log="Successful login"),
        ])

        attack_types = {incident["attack_type"] for incident in incidents}
        self.assertIn("Multiple Failed Login Attempts", attack_types)
        self.assertIn("Possible Brute Force Attack", attack_types)

    def test_rule_2_privilege_escalation_windows_admin_group_change(self):
        incidents = self._run_correlation([
            self._log(10, "2026-08-18T11:00:00Z", "LOGON_SUCCESS", user="admin", raw_log="Logon success"),
            self._log(11, "2026-08-18T11:01:00Z", "ADMIN_GROUP_ADDED", user="admin", raw_log="Member added to Administrators"),
        ])

        attack_types = {incident["attack_type"] for incident in incidents}
        self.assertIn("Privilege Escalation", attack_types)
        self.assertNotIn("Suspicious Administrative Activity", attack_types)

    def test_rule_3_malware_execution(self):
        incidents = self._run_correlation([
            self._log(20, "2026-08-18T12:00:00Z", "PROCESS_CREATED", process="powershell.exe", raw_log="Process created"),
            self._log(21, "2026-08-18T12:01:00Z", "NETWORK_CONNECTION", process="powershell.exe", raw_log="Network connection"),
        ])

        attack_types = {incident["attack_type"] for incident in incidents}
        self.assertIn("Possible Malware Execution", attack_types)

    def test_rule_4_reconnaissance(self):
        incidents = self._run_correlation([
            self._log(30, "2026-08-18T13:00:00Z", "LOCAL_GROUP_ENUMERATION", raw_log="Group enumeration"),
            self._log(31, "2026-08-18T13:01:00Z", "PROCESS_CREATED", process="cmd.exe", raw_log="Process created"),
            self._log(32, "2026-08-18T13:02:00Z", "NETWORK_CONNECTION", raw_log="Network connection"),
        ])

        attack_types = {incident["attack_type"] for incident in incidents}
        self.assertIn("Reconnaissance Activity", attack_types)

    def test_rule_5_lateral_movement(self):
        incidents = self._run_correlation([
            self._log(40, "2026-08-18T14:00:00Z", "LOGON_SUCCESS", raw_log="Successful login"),
            self._log(41, "2026-08-18T14:01:00Z", "NETWORK_CONNECTION", raw_log="Network connection"),
            self._log(42, "2026-08-18T14:02:00Z", "PROCESS_CREATED", process="wmic.exe", raw_log="Process created"),
        ])

        attack_types = {incident["attack_type"] for incident in incidents}
        self.assertIn("Possible Lateral Movement", attack_types)

    def test_rule_6_persistence(self):
        incidents = self._run_correlation([
            self._log(50, "2026-08-18T15:00:00Z", "USER_CREATED", user="newuser", raw_log="User created"),
            self._log(51, "2026-08-18T15:01:00Z", "PASSWORD_CHANGED", user="newuser", raw_log="Password changed"),
            self._log(52, "2026-08-18T15:02:00Z", "LOGON_SUCCESS", user="newuser", raw_log="Logon success"),
        ])

        attack_types = {incident["attack_type"] for incident in incidents}
        self.assertIn("Possible Persistence Established", attack_types)

    def test_rule_7_data_exfiltration(self):
        incidents = self._run_correlation([
            self._log(60, "2026-08-18T16:00:00Z", "FILE_ACCESS", file_path="C:\\secret1.txt", raw_log="File access"),
            self._log(61, "2026-08-18T16:01:00Z", "FILE_ACCESS", file_path="C:\\secret2.txt", raw_log="File access"),
            self._log(62, "2026-08-18T16:02:00Z", "FILE_ACCESS", file_path="C:\\secret3.txt", raw_log="File access"),
            self._log(63, "2026-08-18T16:03:00Z", "FILE_ACCESS", file_path="C:\\secret4.txt", raw_log="File access"),
            self._log(64, "2026-08-18T16:04:00Z", "FILE_ACCESS", file_path="C:\\secret5.txt", raw_log="File access"),
            self._log(65, "2026-08-18T16:05:00Z", "NETWORK_CONNECTION", raw_log="Network connection"),
        ])

        attack_types = {incident["attack_type"] for incident in incidents}
        self.assertIn("Possible Data Exfiltration", attack_types)

    def test_rule_8_ransomware(self):
        logs = [
            self._log(70, "2026-08-18T17:00:00Z", "PROCESS_CREATED", process="encryptor.exe", raw_log="Process created"),
        ]
        logs.extend(
            self._log(70 + index, f"2026-08-18T17:{index:02d}:00Z", "FILE_ACCESS", file_path=f"C:\\file{index}.txt", raw_log="File access")
            for index in range(1, 11)
        )

        incidents = self._run_correlation(logs)

        attack_types = {incident["attack_type"] for incident in incidents}
        self.assertIn("Possible Ransomware Activity", attack_types)


if __name__ == "__main__":
    unittest.main()
