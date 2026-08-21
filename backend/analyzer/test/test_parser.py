import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from backend.collector.parser import parse_event


class ParserTestCase(unittest.TestCase):
    def _parse(self, event_id, message, **extra):
        event = {
            "Id": event_id,
            "RecordId": extra.pop("record_id", 1000 + event_id),
            "TimeCreated": extra.pop("TimeCreated", "2026-08-18T09:30:00Z"),
            "MachineName": extra.pop("MachineName", "WIN-TEST"),
            "LevelDisplayName": extra.pop("LevelDisplayName", "Information"),
            "Message": message,
        }
        event.update(extra)
        return parse_event(event)

    def test_event_mappings_and_extractions(self):
        cases = [
            {
                "event_id": 4624,
                "event_type": "LOGON_SUCCESS",
                "message": (
                    "An account was successfully logged on.\r\n\r\n"
                    "Subject:\r\n\tSecurity ID:\tS-1-5-18\r\n"
                    "\tAccount Name:\tWIN-TEST$\r\n\r\n"
                    "New Logon:\r\n\tSecurity ID:\tS-1-5-21-1000\r\n"
                    "\tAccount Name:\tadmin\r\n\r\n"
                    "Network Information:\r\n\tSource Network Address:\t10.0.0.5"
                ),
                "expected": {"user": "admin", "source_ip": "10.0.0.5"},
            },
            {
                "event_id": 4625,
                "event_type": "FAILED_LOGIN",
                "message": (
                    "An account failed to log on.\r\n\r\n"
                    "Subject:\r\n\tSecurity ID:\tS-1-5-18\r\n"
                    "\tAccount Name:\tWIN-TEST$\r\n\r\n"
                    "Account For Which Logon Failed:\r\n\tSecurity ID:\tS-1-5-21-2000\r\n"
                    "\tAccount Name:\tfailing.user\r\n\r\n"
                    "Network Information:\r\n\tSource Address:\t10.0.0.8"
                ),
                "expected": {"user": "failing.user", "source_ip": "10.0.0.8"},
            },
            {
                "event_id": 4663,
                "event_type": "FILE_ACCESS",
                "message": (
                    "An attempt was made to access an object.\r\n\r\n"
                    "Subject:\r\n\tAccount Name:\tadmin\r\n\r\n"
                    "Object:\r\n\tObject Name:\tC:\\Sensitive\\secret.txt\r\n\r\n"
                    "Process Information:\r\n\tProcess Name:\tC:\\Windows\\System32\\notepad.exe"
                ),
                "expected": {
                    "user": "admin",
                    "file_path": "C:\\Sensitive\\secret.txt",
                    "process": "C:\\Windows\\System32\\notepad.exe",
                },
            },
            {
                "event_id": 4688,
                "event_type": "PROCESS_CREATED",
                "message": (
                    "A new process has been created.\r\n\r\n"
                    "Creator Subject:\r\n\tAccount Name:\tadmin\r\n\r\n"
                    "New Process Name:\tC:\\Windows\\System32\\cmd.exe"
                ),
                "expected": {"user": "admin", "process": "C:\\Windows\\System32\\cmd.exe"},
            },
            {
                "event_id": 4720,
                "event_type": "USER_CREATED",
                "message": (
                    "A user account was created.\r\n\r\n"
                    "Subject:\r\n\tAccount Name:\tadmin\r\n\r\n"
                    "New Account Name:\ttest.user"
                ),
                "expected": {"user": "test.user"},
            },
            {
                "event_id": 4723,
                "event_type": "PASSWORD_CHANGED",
                "message": (
                    "An attempt was made to change an account's password.\r\n\r\n"
                    "Subject:\r\n\tAccount Name:\tadmin\r\n\r\n"
                    "Target Account:\r\n\tAccount Name:\tpassword.user"
                ),
                "expected": {"user": "password.user"},
            },
            {
                "event_id": 4732,
                "event_type": "ADMIN_GROUP_ADDED",
                "message": (
                    "A member was added to a security-enabled local group.\r\n\r\n"
                    "Subject:\r\n\tAccount Name:\tadmin\r\n\r\n"
                    "Member Name:\tadded.user"
                ),
                "expected": {"user": "added.user"},
            },
            {
                "event_id": 4798,
                "event_type": "LOCAL_GROUP_ENUMERATION",
                "message": (
                    "A user's local group membership was enumerated.\r\n\r\n"
                    "Subject:\r\n\tAccount Name:\tenum.user\r\n\r\n"
                    "Process Information:\r\n\tProcess Name:\tC:\\Windows\\System32\\svchost.exe"
                ),
                "expected": {"user": "enum.user", "process": "C:\\Windows\\System32\\svchost.exe"},
            },
            {
                "event_id": 5156,
                "event_type": "NETWORK_CONNECTION",
                "message": (
                    "The Windows Filtering Platform has permitted a connection.\r\n\r\n"
                    "Application Information:\r\n\tProcess Name:\tC:\\Windows\\System32\\svchost.exe\r\n\r\n"
                    "Network Information:\r\n\tSource Address:\t10.0.0.9\r\n\tDestination Address:\t10.0.0.20"
                ),
                "expected": {
                    "process": "C:\\Windows\\System32\\svchost.exe",
                    "source_ip": "10.0.0.9",
                    "destination_ip": "10.0.0.20",
                },
            },
            {
                "event_id": 5158,
                "event_type": "NETWORK_BIND",
                "message": (
                    "The Windows Filtering Platform has permitted a bind to a local port.\r\n\r\n"
                    "Application Information:\r\n\tProcess Name:\tC:\\Windows\\System32\\svchost.exe\r\n\r\n"
                    "Network Information:\r\n\tSource Address:\t10.0.0.9"
                ),
                "expected": {
                    "process": "C:\\Windows\\System32\\svchost.exe",
                    "source_ip": "10.0.0.9",
                    "destination_ip": "",
                },
            },
        ]

        for case in cases:
            with self.subTest(event_id=case["event_id"]):
                parsed = self._parse(case["event_id"], case["message"])
                self.assertEqual(parsed["event_type"], case["event_type"])
                for field, expected in case["expected"].items():
                    self.assertEqual(parsed[field], expected)


if __name__ == "__main__":
    unittest.main()
