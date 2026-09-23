import unittest

from flask import Flask, g, jsonify, request

from backend.analyzer.privacy_projection import (
    install_application_privacy_projection,
)
from backend.platform.data_privacy import REDACTED


class S7CPrivacyProjectionTests(unittest.TestCase):
    def make_app(self):
        app = Flask(__name__)

        @app.before_request
        def test_identity():
            role = request.headers.get("X-Test-Role", "VIEWER")
            g.aegisguard_user = {
                "user_id": "test-user",
                "username": "test-user",
                "role": role,
                "session_id": "test-session",
            }

        @app.get("/api/events")
        def events():
            return jsonify([
                {
                    "id": 1,
                    "timestamp": "2026-09-23T12:00:00Z",
                    "severity": "HIGH",
                    "hostname": "HOST-SECRET",
                    "user": "alice",
                    "ip": "10.0.0.9",
                    "event": "Failed password for alice",
                    "api_key": "must-never-leak",
                }
            ])

        @app.get("/api/incidents/INC-1")
        def incident():
            return jsonify({
                "incident": {
                    "incident_id": "INC-1",
                    "severity": "CRITICAL",
                    "source_ip": "10.0.0.4",
                    "related_entities": {
                        "users": ["alice"],
                        "source_ips": ["10.0.0.4"],
                    },
                    "notes": [
                        {"body": "private investigation note"}
                    ],
                }
            })

        @app.get("/api/intelligence")
        def intelligence():
            return jsonify({
                "description": "non-sensitive technique description",
                "source_ip": "10.0.0.5",
            })

        install_application_privacy_projection(app)
        app.testing = True
        return app

    def test_viewer_gets_privacy_safe_event_projection(self):
        client = self.make_app().test_client()
        response = client.get(
            "/api/events",
            headers={"X-Test-Role": "VIEWER"},
        )
        self.assertEqual(response.status_code, 200)
        event = response.get_json()[0]

        self.assertEqual(event["severity"], "HIGH")
        self.assertEqual(
            event["timestamp"],
            "2026-09-23T12:00:00Z",
        )
        self.assertEqual(event["hostname"], REDACTED)
        self.assertEqual(event["user"], REDACTED)
        self.assertEqual(event["ip"], REDACTED)
        self.assertEqual(event["event"], REDACTED)
        self.assertEqual(event["api_key"], REDACTED)

    def test_analyst_keeps_soc_telemetry_but_not_secrets(self):
        client = self.make_app().test_client()
        response = client.get(
            "/api/events",
            headers={"X-Test-Role": "ANALYST"},
        )
        event = response.get_json()[0]

        self.assertEqual(event["hostname"], "HOST-SECRET")
        self.assertEqual(event["user"], "alice")
        self.assertEqual(event["ip"], "10.0.0.9")
        self.assertEqual(
            event["event"],
            "Failed password for alice",
        )
        self.assertEqual(event["api_key"], REDACTED)

    def test_administrator_keeps_soc_telemetry_but_not_secrets(self):
        client = self.make_app().test_client()
        response = client.get(
            "/api/events",
            headers={"X-Test-Role": "ADMINISTRATOR"},
        )
        event = response.get_json()[0]

        self.assertEqual(event["hostname"], "HOST-SECRET")
        self.assertEqual(event["user"], "alice")
        self.assertEqual(event["api_key"], REDACTED)

    def test_viewer_incident_projection_redacts_nested_sensitive_data(self):
        client = self.make_app().test_client()
        response = client.get(
            "/api/incidents/INC-1",
            headers={"X-Test-Role": "VIEWER"},
        )
        incident = response.get_json()["incident"]

        self.assertEqual(incident["incident_id"], "INC-1")
        self.assertEqual(incident["severity"], "CRITICAL")
        self.assertEqual(incident["source_ip"], REDACTED)
        self.assertEqual(incident["related_entities"], REDACTED)
        self.assertEqual(incident["notes"], REDACTED)

    def test_non_soc_api_is_not_over_redacted(self):
        client = self.make_app().test_client()
        response = client.get(
            "/api/intelligence",
            headers={"X-Test-Role": "VIEWER"},
        )
        payload = response.get_json()

        self.assertEqual(
            payload["description"],
            "non-sensitive technique description",
        )
        self.assertEqual(payload["source_ip"], "10.0.0.5")


if __name__ == "__main__":
    unittest.main()
