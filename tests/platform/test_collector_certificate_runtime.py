import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

import requests

from backend.collector.durable_runtime import DurableCollectorRuntime
from backend.collector.state import CollectorState
from backend.collector.transport import (
    build_certificate_rotation_payload,
    certificate_fingerprint_from_client_cert,
    send_certificate_rotation,
    validate_certificate_rotation_response,
)
from backend.storage.collector_identity import certificate_fingerprint_from_pem


CERT_A = """-----BEGIN CERTIFICATE-----
AQIDBA==
-----END CERTIFICATE-----"""
CERT_B = """-----BEGIN CERTIFICATE-----
BQYHCA==
-----END CERTIFICATE-----"""


class _TestProtector:
    PREFIX = b"TEST-PROTECTED:"

    def protect(self, plaintext: bytes) -> bytes:
        return self.PREFIX + bytes(plaintext)[::-1]

    def unprotect(self, protected: bytes) -> bytes:
        value = bytes(protected)
        if not value.startswith(self.PREFIX):
            raise ValueError("invalid test credential")
        return value[len(self.PREFIX):][::-1]


class _Accepted:
    def __init__(self, payload):
        self.status_code = 202
        self._payload = payload

    def json(self):
        return {
            "status": "accepted",
            "collector_id": self._payload["collector_id"],
            "batch_id": self._payload["batch_id"],
            "duplicate": False,
            "analysis_state": "QUEUED",
        }


class _RotationResponse:
    def __init__(self, payload, duplicate=False):
        self.status_code = 200
        self._payload = payload
        self._duplicate = bool(duplicate)

    def json(self):
        return {
            "status": "certificate_rotation_staged",
            "collector_id": self._payload["collector_id"],
            "certificate_rotation_id":
                self._payload["certificate_rotation_id"],
            "new_certificate_fingerprint":
                self._payload["new_certificate_fingerprint"],
            "duplicate": self._duplicate,
            "completed": False,
            "staged_at": "2026-09-22T00:00:00Z",
            "rotated_at": None,
        }


class CollectorCertificateRotationRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state_path = self.root / "collector.db"
        self.cert_a = self.root / "client-a.pem"
        self.cert_b = self.root / "client-b.pem"
        self.cert_a.write_text(CERT_A, encoding="utf-8")
        self.cert_b.write_text(CERT_B, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def state(self):
        return CollectorState(
            self.state_path,
            credential_protector=_TestProtector(),
        )

    def test_transport_fingerprint_and_rotation_request(self):
        expected = certificate_fingerprint_from_pem(CERT_B)
        self.assertEqual(
            certificate_fingerprint_from_client_cert(str(self.cert_b)),
            expected,
        )

        payload = build_certificate_rotation_payload(
            "collector-1",
            "HOST01",
            "cert-rot-1",
            expected,
        )
        session = Mock()
        session.post.return_value = _RotationResponse(payload)

        response = send_certificate_rotation(
            "https://siem.example.test/api/collector/v1/certificate/rotate",
            payload,
            "device-secret-001",
            ca_bundle="C:/AegisGuard/ca.pem",
            client_cert=str(self.cert_a),
            session=session,
        )
        body = validate_certificate_rotation_response(response, payload)
        self.assertEqual(
            body["new_certificate_fingerprint"],
            expected,
        )

        _, kwargs = session.post.call_args
        self.assertEqual(kwargs["cert"], str(self.cert_a))
        self.assertEqual(kwargs["verify"], "C:/AegisGuard/ca.pem")

    def test_local_pending_state_survives_restart_and_promotes(self):
        state = self.state()
        fingerprint = certificate_fingerprint_from_pem(CERT_B)

        state.begin_client_certificate_rotation(
            "cert-rot-1",
            str(self.cert_b),
            fingerprint,
        )

        reopened = self.state()
        pending = reopened.get_pending_client_certificate_rotation()
        self.assertEqual(pending["rotation_id"], "cert-rot-1")
        self.assertEqual(pending["fingerprint"], fingerprint)
        self.assertEqual(pending["client_cert"], str(self.cert_b))
        self.assertFalse(pending["staged"])

        reopened.mark_client_certificate_rotation_staged("cert-rot-1")
        reopened.complete_client_certificate_rotation("cert-rot-1")

        again = self.state()
        self.assertIsNone(
            again.get_pending_client_certificate_rotation()
        )
        self.assertEqual(
            again.get_active_client_certificate_reference(),
            str(self.cert_b),
        )

    def test_lost_stage_response_keeps_old_certificate_and_replays(self):
        state = self.state()
        state.store_collector_credential("device-secret-001")

        calls = []

        def lost_sender(_url, payload, **kwargs):
            calls.append(kwargs.get("client_cert"))
            raise requests.RequestException("simulated lost stage response")

        runtime = DurableCollectorRuntime(
            state,
            "https://siem.example.test/api/collector/v1/batches",
            hostname="HOST01",
            os_name="Windows-11",
            client_cert=str(self.cert_a),
            mtls_required=True,
            auth_required=True,
            certificate_rotation_url=(
                "https://siem.example.test/api/collector/v1/certificate/rotate"
            ),
            certificate_rotation_sender=lost_sender,
            certificate_rotation_id_factory=lambda: "cert-rot-1",
        )

        with self.assertRaisesRegex(
            requests.RequestException,
            "lost stage response",
        ):
            runtime.rotate_client_certificate(str(self.cert_b))

        pending = state.get_pending_client_certificate_rotation()
        self.assertFalse(pending["staged"])
        self.assertEqual(runtime.client_cert, str(self.cert_a))
        self.assertEqual(calls, [str(self.cert_a)])

        def replay_sender(_url, payload, **kwargs):
            calls.append(kwargs.get("client_cert"))
            return _RotationResponse(payload, duplicate=True)

        runtime.certificate_rotation_sender = replay_sender
        body = runtime.rotate_client_certificate()

        self.assertTrue(body["duplicate"])
        self.assertEqual(runtime.client_cert, str(self.cert_b))
        self.assertTrue(
            state.get_pending_client_certificate_rotation()["staged"]
        )
        self.assertEqual(
            calls,
            [str(self.cert_a), str(self.cert_a)],
        )

    def test_restart_after_staging_selects_pending_new_certificate(self):
        state = self.state()
        state.store_collector_credential("device-secret-001")
        state.begin_client_certificate_rotation(
            "cert-rot-1",
            str(self.cert_b),
            certificate_fingerprint_from_pem(CERT_B),
        )
        state.mark_client_certificate_rotation_staged("cert-rot-1")

        restarted = DurableCollectorRuntime(
            self.state(),
            "https://siem.example.test/api/collector/v1/batches",
            hostname="HOST01",
            os_name="Windows-11",
            client_cert=str(self.cert_a),
            mtls_required=True,
            auth_required=True,
        )
        self.assertEqual(
            restarted.client_cert,
            str(self.cert_b),
        )
        self.assertTrue(
            restarted.health_snapshot()["certificate_rotation_pending"]
        )

    def test_successful_batch_with_new_certificate_commits_local_transition(self):
        state = self.state()
        state.initialize_checkpoint(100)
        state.store_collector_credential("device-secret-001")
        state.begin_client_certificate_rotation(
            "cert-rot-1",
            str(self.cert_b),
            certificate_fingerprint_from_pem(CERT_B),
        )
        state.mark_client_certificate_rotation_staged("cert-rot-1")

        sent_certs = []

        def sender(_url, payload, **kwargs):
            sent_certs.append(kwargs.get("client_cert"))
            return _Accepted(payload)

        runtime = DurableCollectorRuntime(
            state,
            "https://siem.example.test/api/collector/v1/batches",
            hostname="HOST01",
            os_name="Windows-11",
            client_cert=str(self.cert_a),
            mtls_required=True,
            auth_required=True,
            sender=sender,
            retry_jitter_ratio=0,
        )
        runtime.enqueue_logs(
            [{"record_id": 101, "event_type": "FAILED_LOGIN"}],
            [101],
        )

        self.assertTrue(runtime.flush_pending())
        self.assertEqual(sent_certs, [str(self.cert_b)])
        self.assertEqual(state.get_checkpoint(), 101)
        self.assertIsNone(
            state.get_pending_client_certificate_rotation()
        )
        self.assertEqual(
            state.get_active_client_certificate_reference(),
            str(self.cert_b),
        )

    def test_active_certificate_reference_overrides_stale_config_after_restart(self):
        state = self.state()
        state.begin_client_certificate_rotation(
            "cert-rot-1",
            str(self.cert_b),
            certificate_fingerprint_from_pem(CERT_B),
        )
        state.mark_client_certificate_rotation_staged("cert-rot-1")
        state.complete_client_certificate_rotation("cert-rot-1")

        restarted = DurableCollectorRuntime(
            self.state(),
            "https://siem.example.test/api/collector/v1/batches",
            hostname="HOST01",
            os_name="Windows-11",
            client_cert=str(self.cert_a),
            mtls_required=True,
            auth_required=False,
        )
        self.assertEqual(
            restarted.client_cert,
            str(self.cert_b),
        )


if __name__ == "__main__":
    unittest.main()
