import unittest
from unittest.mock import MagicMock, patch

from backend.analyzer.incident_response import (
    get_settings,
    get_highly_suspicious_entities,
)


class IncidentResponseTestCase(unittest.TestCase):

    def test_get_settings_returns_dictionary(self):
        conn = MagicMock()
        cursor = conn.cursor.return_value

        cursor.fetchall.return_value = [
            ("simulation_mode", "true"),
            ("auto_response_enabled", "true"),
        ]

        result = get_settings(conn)

        self.assertEqual(
            result,
            {
                "simulation_mode": "true",
                "auto_response_enabled": "true",
            },
        )

    def test_get_highly_suspicious_entities_returns_expected_structure(self):
        conn = MagicMock()
        cursor = conn.cursor.return_value

        cursor.fetchall.side_effect = [
            [
                ("192.168.1.10", 5, "CRITICAL"),
            ],
            [
                ("TEST-PC", "Windows", 8, "HIGH"),
            ],
        ]

        result = get_highly_suspicious_entities(conn)

        self.assertIn("ips", result)
        self.assertIn("hosts", result)

        self.assertEqual(
            result["ips"][0]["ip"],
            "192.168.1.10",
        )

        self.assertEqual(
            result["hosts"][0]["hostname"],
            "TEST-PC",
        )


if __name__ == "__main__":
    unittest.main()