import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from backend.collector.durable_runtime import DurableCollectorRuntime
from backend.collector.state import CollectorState
from backend.collector.transport import (
    COLLECTOR_CREDENTIAL_HEADER,
    ENROLLMENT_TOKEN_HEADER,
    build_batch_payload,
    build_enrollment_payload,
    send_batch,
    send_enrollment,
    validate_enrollment_response,
)


class _Clock:
    def __init__(self, value=1000.0):
        self.value = float(value)

    def __call__(self):
        return self.value


class AuthenticatedCollectorRuntimeTests(unittest.TestCase):
    @staticmethod
    def accepted_response(payload):
        response = Mock(status_code=202)
        response.json.return_value = {
            "status": "accepted",
            "collector_id": payload["collector_id"],
            "batch_id": payload["batch_id"],
            "duplicate": False,
            "analysis_state": "QUEUED",
        }
        return response

    @staticmethod
    def enrolled_response(payload, credential="device-secret-001"):
        response = Mock(status_code=201)
        response.json.return_value = {
            "status": "enrolled",
            "collector_id": payload["collector_id"],
            "hostname": payload["hostname"],
            "collector_status": "ENROLLED",
            "credential": credential,
        }
        return response

    def test_collector_credential_persists_but_is_not_exposed_by_health(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "collector-state.db"
            state = CollectorState(path)
            self.assertIsNone(state.get_collector_credential())
            state.store_collector_credential("device-secret-001")

            reopened = CollectorState(path)
            self.assertEqual(
                reopened.get_collector_credential(),
                "device-secret-001",
            )
            health = reopened.transport_health(now=1000)
            self.assertNotIn("collector_credential", health)
            self.assertNotIn("device-secret-001", repr(health))

    def test_transport_uses_bootstrap_and_device_credential_headers(self):
        session = Mock()
        session.post.return_value = Mock(status_code=201)

        enrollment_payload = build_enrollment_payload(
            "collector-1", "HOST01", "Windows-11", version="0.1.0"
        )
        send_enrollment(
            "https://siem.example.test/api/collector/v1/enroll",
            enrollment_payload,
            "bootstrap-secret",
            ca_bundle="C:/AegisGuard/ca.pem",
            session=session,
        )
        _, kwargs = session.post.call_args
        self.assertEqual(
            kwargs["headers"][ENROLLMENT_TOKEN_HEADER],
            "bootstrap-secret",
        )

        session.reset_mock()
        session.post.return_value = Mock(status_code=202)
        batch = build_batch_payload(
            "collector-1", "HOST01", "Windows-11", [], batch_id="batch-1"
        )
        send_batch(
            "https://siem.example.test/api/collector/v1/batches",
            batch,
            credential="device-secret-001",
            session=session,
        )
        _, kwargs = session.post.call_args
        self.assertEqual(
            kwargs["headers"][COLLECTOR_CREDENTIAL_HEADER],
            "device-secret-001",
        )

    def test_enrollment_response_requires_exact_identity_and_credential(self):
        payload = build_enrollment_payload(
            "collector-1", "HOST01", "Windows-11"
        )
        body = validate_enrollment_response(
            self.enrolled_response(payload),
            payload,
        )
        self.assertEqual(body["credential"], "device-secret-001")

        wrong = self.enrolled_response(payload)
        wrong.json.return_value["collector_id"] = "collector-other"
        with self.assertRaisesRegex(ValueError, "collector_id mismatch"):
            validate_enrollment_response(wrong, payload)

        missing = self.enrolled_response(payload, credential="")
        with self.assertRaisesRegex(ValueError, "credential is missing"):
            validate_enrollment_response(missing, payload)

    def test_first_delivery_enrolls_once_and_authenticates(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = CollectorState(Path(tmp) / "collector-state.db")
            state.initialize_checkpoint(100)
            enrollment_calls = []
            batch_credentials = []

            def enrollment_sender(_url, payload, token, **_kwargs):
                enrollment_calls.append((dict(payload), token))
                return self.enrolled_response(payload)

            def sender(_url, payload, **kwargs):
                batch_credentials.append(kwargs.get("credential"))
                return self.accepted_response(payload)

            runtime = DurableCollectorRuntime(
                state,
                "https://siem.example.test/api/collector/v1/batches",
                hostname="HOST01",
                os_name="Windows-11",
                enrollment_url="https://siem.example.test/api/collector/v1/enroll",
                enrollment_token="bootstrap-secret",
                auth_required=True,
                collector_version="0.1.0",
                sender=sender,
                enrollment_sender=enrollment_sender,
                retry_base_seconds=2,
                retry_max_seconds=8,
                retry_jitter_ratio=0,
            )
            runtime.enqueue_logs(
                [{"record_id": 101, "event_type": "FAILED_LOGIN"}],
                [101],
            )

            self.assertTrue(runtime.flush_pending())
            self.assertEqual(len(enrollment_calls), 1)
            self.assertEqual(batch_credentials, ["device-secret-001"])
            self.assertEqual(
                state.get_collector_credential(),
                "device-secret-001",
            )
            self.assertIsNone(runtime.enrollment_token)
            self.assertEqual(state.get_checkpoint(), 101)

    def test_restart_reuses_stored_credential_without_bootstrap_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "collector-state.db"
            state = CollectorState(path)
            state.initialize_checkpoint(100)
            state.store_collector_credential("device-secret-001")
            sent_credentials = []

            def enrollment_sender(*_args, **_kwargs):
                raise AssertionError("enrollment must not run after restart")

            def sender(_url, payload, **kwargs):
                sent_credentials.append(kwargs.get("credential"))
                return self.accepted_response(payload)

            runtime = DurableCollectorRuntime(
                CollectorState(path),
                "https://siem.example.test/api/collector/v1/batches",
                hostname="HOST01",
                os_name="Windows-11",
                enrollment_url="https://siem.example.test/api/collector/v1/enroll",
                auth_required=True,
                sender=sender,
                enrollment_sender=enrollment_sender,
                retry_base_seconds=2,
                retry_max_seconds=8,
                retry_jitter_ratio=0,
            )
            runtime.enqueue_logs(
                [{"record_id": 101, "event_type": "FAILED_LOGIN"}],
                [101],
            )

            self.assertTrue(runtime.flush_pending())
            self.assertEqual(sent_credentials, ["device-secret-001"])

    def test_missing_bootstrap_token_keeps_batch_durable_and_backs_off(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = CollectorState(Path(tmp) / "collector-state.db")
            state.initialize_checkpoint(100)
            clock = _Clock()

            runtime = DurableCollectorRuntime(
                state,
                "https://siem.example.test/api/collector/v1/batches",
                hostname="HOST01",
                os_name="Windows-11",
                enrollment_url="https://siem.example.test/api/collector/v1/enroll",
                auth_required=True,
                retry_base_seconds=2,
                retry_max_seconds=8,
                retry_jitter_ratio=0,
                clock=clock,
            )
            runtime.enqueue_logs(
                [{"record_id": 101, "event_type": "FAILED_LOGIN"}],
                [101],
            )

            self.assertFalse(runtime.flush_pending())
            pending = state.pending()
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0]["attempts"], 1)
            self.assertEqual(pending[0]["next_attempt_at"], 1002.0)
            self.assertIn(
                "bootstrap token is unavailable",
                pending[0]["last_error"],
            )
            self.assertEqual(state.get_checkpoint(), 100)

    def test_from_config_reads_bootstrap_token_from_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            config_path.write_text("{}", encoding="utf-8")
            config = {
                "collector_ingest_url":
                    "https://siem.example.test/api/collector/v1/batches",
                "collector_enrollment_url":
                    "https://siem.example.test/api/collector/v1/enroll",
                "collector_state_file": "collector-state.db",
                "collector_auth_required": True,
                "collector_version": "0.1.0",
            }

            with patch.dict(
                os.environ,
                {"AEGISGUARD_COLLECTOR_ENROLLMENT_TOKEN": "bootstrap-secret"},
                clear=False,
            ):
                runtime = DurableCollectorRuntime.from_config(
                    config,
                    config_path,
                    hostname="HOST01",
                    os_name="Windows-11",
                )

            self.assertTrue(runtime.auth_required)
            self.assertEqual(runtime.enrollment_token, "bootstrap-secret")
            self.assertEqual(runtime.collector_version, "0.1.0")


if __name__ == "__main__":
    unittest.main()
