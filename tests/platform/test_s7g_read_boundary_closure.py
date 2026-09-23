import unittest

from flask import Flask, g, jsonify, request

from backend.analyzer.privacy_projection import (
    install_application_privacy_projection,
)
from backend.platform.data_privacy import REDACTED


class S7GReadBoundaryClosureTests(unittest.TestCase):
    def make_app(self):
        app = Flask(__name__)

        @app.before_request
        def test_identity():
            g.aegisguard_user = {
                "user_id": "test-user",
                "username": "test-user",
                "role": request.headers.get(
                    "X-Test-Role",
                    "VIEWER",
                ),
                "session_id": "test-session",
            }

        @app.get("/api/collectors")
        def collectors():
            return jsonify({
                "count": 1,
                "collectors": [
                    {
                        "identity": {
                            "collector_id": "collector-1",
                            "hostname": "FINANCE-HOST",
                            "status": "ENROLLED",
                        },
                        "server_observed": {
                            "peer_ip": "10.10.20.15",
                            "credential_authenticated": True,
                        },
                        "assets": [
                            {
                                "asset_id": "asset-1",
                                "hostname": "FINANCE-HOST",
                                "primary_ip": "10.10.20.15",
                            }
                        ],
                        "access_token": "must-never-leak",
                    }
                ],
            })

        @app.get("/api/intelligence")
        def intelligence():
            return jsonify({
                "snapshot_version": "intelligence-snapshot-v1",
                "description": "sensitive analyst description",
                "detection_counts": {
                    "RULE": 1,
                    "ML": 0,
                    "CORRELATION": 0,
                },
                "findings": {
                    "rule": [
                        {
                            "finding_id": "FND-1",
                            "severity": "HIGH",
                            "reason": (
                                "Authentication failure matched "
                                "the deterministic failed-login rule."
                            ),
                            "evidence": [
                                {
                                    "hostname": "FINANCE-HOST",
                                    "source_ip": "10.10.20.15",
                                    "user": "alice",
                                    "raw_event": (
                                        "Failed password for alice "
                                        "from 10.10.20.15"
                                    ),
                                }
                            ],
                        }
                    ],
                },
                "api_key": "must-never-leak",
            })

        @app.get("/api/dashboard")
        def dashboard():
            return jsonify({
                "source_ip": "10.10.20.15",
            })

        install_application_privacy_projection(app)
        app.testing = True
        return app

    def test_viewer_collector_inventory_redacts_endpoint_identity(self):
        response = self.make_app().test_client().get(
            "/api/collectors",
            headers={"X-Test-Role": "VIEWER"},
        )
        self.assertEqual(response.status_code, 200)

        payload = response.get_json()
        collector = payload["collectors"][0]

        self.assertEqual(payload["count"], 1)
        self.assertEqual(
            collector["identity"]["status"],
            "ENROLLED",
        )
        self.assertEqual(
            collector["identity"]["hostname"],
            REDACTED,
        )
        self.assertEqual(
            collector["server_observed"]["peer_ip"],
            REDACTED,
        )
        self.assertEqual(
            collector["assets"][0]["hostname"],
            REDACTED,
        )
        self.assertEqual(
            collector["assets"][0]["primary_ip"],
            REDACTED,
        )
        self.assertEqual(
            collector["access_token"],
            REDACTED,
        )

    def test_viewer_intelligence_redacts_finding_evidence(self):
        response = self.make_app().test_client().get(
            "/api/intelligence",
            headers={"X-Test-Role": "VIEWER"},
        )
        self.assertEqual(response.status_code, 200)

        payload = response.get_json()
        finding = payload["findings"]["rule"][0]
        evidence = finding["evidence"][0]

        self.assertEqual(finding["severity"], "HIGH")
        self.assertIn(
            "deterministic failed-login rule",
            finding["reason"],
        )
        self.assertEqual(payload["description"], REDACTED)
        self.assertEqual(evidence["hostname"], REDACTED)
        self.assertEqual(evidence["source_ip"], REDACTED)
        self.assertEqual(evidence["user"], REDACTED)
        self.assertEqual(evidence["raw_event"], REDACTED)
        self.assertEqual(payload["api_key"], REDACTED)

    def test_analyst_keeps_soc_telemetry_but_not_secrets(self):
        client = self.make_app().test_client()

        collector = client.get(
            "/api/collectors",
            headers={"X-Test-Role": "ANALYST"},
        ).get_json()["collectors"][0]

        self.assertEqual(
            collector["identity"]["hostname"],
            "FINANCE-HOST",
        )
        self.assertEqual(
            collector["server_observed"]["peer_ip"],
            "10.10.20.15",
        )
        self.assertEqual(
            collector["access_token"],
            REDACTED,
        )

        intelligence = client.get(
            "/api/intelligence",
            headers={"X-Test-Role": "ANALYST"},
        ).get_json()

        evidence = intelligence["findings"]["rule"][0]["evidence"][0]
        self.assertEqual(
            intelligence["description"],
            "sensitive analyst description",
        )
        self.assertEqual(evidence["user"], "alice")
        self.assertEqual(
            evidence["raw_event"],
            "Failed password for alice from 10.10.20.15",
        )
        self.assertEqual(
            intelligence["api_key"],
            REDACTED,
        )

    def test_unlisted_read_api_is_not_implicitly_projected(self):
        response = self.make_app().test_client().get(
            "/api/dashboard",
            headers={"X-Test-Role": "VIEWER"},
        )
        self.assertEqual(
            response.get_json()["source_ip"],
            "10.10.20.15",
        )


if __name__ == "__main__":
    unittest.main()
