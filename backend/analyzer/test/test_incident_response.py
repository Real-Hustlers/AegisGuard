import sys
import sqlite3
import unittest
import json
from pathlib import Path

# Add path so imports resolve correctly
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

try:
    from backend.analyzer.database import ensure_schema
    from backend.analyzer import incident_response
except ImportError:
    from database import ensure_schema
    import incident_response


class IncidentResponseTestCase(unittest.TestCase):
    def setUp(self):
        # Create an in-memory SQLite database for testing
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        ensure_schema(self.conn)

    def tearDown(self):
        self.conn.close()

    def test_brute_force_incident_generation(self):
        # Insert a security log indicating a brute force attack (via ML prediction)
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO security_logs (
                log_id, hostname, os, timestamp, event_type, source_ip, ml_prediction, severity, raw_log
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "LOG-TEST-01", "Linux-Server", "Ubuntu 24.04", "2026-07-14T09:05:11Z",
            "FAILED_LOGIN", "10.12.32.108", "BRUTE_FORCE", "HIGH", "Multiple failed login attempts."
        ))
        self.conn.commit()

        # Disable auto response for test scan
        cursor.execute("UPDATE settings SET value = 'false' WHERE key = 'auto_response_enabled'")
        self.conn.commit()

        # Run detection scanner
        created = incident_response.scan_and_generate_incidents(self.conn)
        self.assertEqual(created, 1)

        # Retrieve incident
        cursor.execute("SELECT * FROM incidents WHERE incident_id = 'INC-LOG-TEST-01'")
        incident = cursor.fetchone()
        self.assertIsNotNone(incident)
        self.assertEqual(incident["threat_type"], "Brute Force Attack")
        self.assertEqual(incident["source_ip"], "10.12.32.108")
        self.assertEqual(incident["status"], "PENDING")
        self.assertIn("iptables", incident["command_executed"])

        # Check playbook steps
        steps = json.loads(incident["playbook_steps"])
        self.assertIn("Block the attacker's IP", steps)

    def test_malware_incident_generation(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO security_logs (
                log_id, hostname, os, timestamp, event_type, process, file_path, ml_prediction, severity, raw_log
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "LOG-TEST-02", "Finance-PC", "Windows 11", "2026-07-14T09:30:10Z",
            "DEFENDER_ALERT", "MsMpEng.exe", "C:\\Downloads\\malware.exe", "MALWARE", "CRITICAL", "Trojan detected"
        ))
        self.conn.commit()

        cursor.execute("UPDATE settings SET value = 'false' WHERE key = 'auto_response_enabled'")
        self.conn.commit()

        created = incident_response.scan_and_generate_incidents(self.conn)
        self.assertEqual(created, 1)

        cursor.execute("SELECT * FROM incidents WHERE incident_id = 'INC-LOG-TEST-02'")
        incident = cursor.fetchone()
        self.assertIsNotNone(incident)
        self.assertEqual(incident["threat_type"], "Malware Infection")
        self.assertEqual(incident["process"], "MsMpEng.exe")
        self.assertEqual(incident["file_path"], "C:\\Downloads\\malware.exe")
        self.assertIn("Stop-Process", incident["command_executed"])
        self.assertEqual(incident["alert_status"], "PENDING_ALERT")
        report = json.loads(incident["incident_report"])
        self.assertEqual(report["threat_type"], "Malware Infection")
        self.assertEqual(report["hostname"], "Finance-PC")

    def test_playbook_execution_simulation(self):
        # Setup incident
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO incidents (
                incident_id, threat_type, hostname, os, command_executed, status, action_taken, playbook_steps, incident_report, alert_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "INC-MOCK-01", "USB Attack", "Finance-PC", "Windows 11",
            "Set-ItemProperty -Path HKLM...", "PENDING", "Disabled USB", "[]", "{\"summary\": \"USB attack\"}", "PENDING_ALERT"
        ))
        # Set simulation mode to true
        cursor.execute("UPDATE settings SET value = 'true' WHERE key = 'simulation_mode'")
        self.conn.commit()

        # Execute playbook
        success = incident_response.execute_incident_playbook(self.conn, "INC-MOCK-01")
        self.assertTrue(success)

        # Check status updated to SIMULATED
        cursor.execute("SELECT status, alert_status FROM incidents WHERE incident_id = 'INC-MOCK-01'")
        record = cursor.fetchone()
        self.assertEqual(record["status"], "SIMULATED")
        self.assertEqual(record["alert_status"], "ALERT_SENT")

        # Verify logs were populated
        cursor.execute("SELECT message FROM response_logs WHERE incident_id = 'INC-MOCK-01'")
        logs = cursor.fetchall()
        self.assertTrue(len(logs) > 0)
        self.assertTrue(any("Dry-run mode active" in row[0] for row in logs))


if __name__ == "__main__":
    unittest.main()
