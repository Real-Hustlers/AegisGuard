import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from backend.analyzer import app as analyzer_app
from backend.analyzer.database import ensure_schema
from backend.analyzer.runtime_reliability import (
    RuntimeReadinessError,
    analyzer_liveness,
    probe_analyzer_readiness,
    validate_analyzer_startup,
)


class S91RuntimeReliabilityTests(unittest.TestCase):
    def test_liveness_is_minimal_and_dependency_free(self):
        self.assertEqual(
            analyzer_liveness(),
            {
                "service": "aegisguard-analyzer",
                "status": "ok",
            },
        )

        client = analyzer_app.app.test_client()
        response = client.get("/healthz")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {
                "service": "aegisguard-analyzer",
                "status": "ok",
            },
        )

    def test_readiness_accepts_healthy_database_and_writable_data_directory(self):
        with TemporaryDirectory() as temp_dir:
            def connection_factory():
                conn = sqlite3.connect(":memory:")
                conn.row_factory = sqlite3.Row
                ensure_schema(conn)
                return conn

            report = probe_analyzer_readiness(
                connection_factory,
                temp_dir,
            )

        self.assertEqual(report["status"], "ready")
        self.assertTrue(report["checks"]["database"]["ok"])
        self.assertTrue(
            report["checks"]["data_directory"]["ok"]
        )

    def test_readiness_fails_closed_without_exposing_exception_text(self):
        secret = "super-secret-database-message"

        def broken_connection():
            raise RuntimeError(secret)

        with TemporaryDirectory() as temp_dir:
            report = probe_analyzer_readiness(
                broken_connection,
                temp_dir,
            )

        self.assertEqual(report["status"], "not_ready")
        self.assertFalse(report["checks"]["database"]["ok"])
        self.assertEqual(
            report["checks"]["database"]["reason"],
            "database_unavailable",
        )
        self.assertNotIn(secret, str(report))

    def test_startup_preflight_raises_before_service_when_dependency_is_unready(self):
        def broken_connection():
            raise RuntimeError("database offline")

        with TemporaryDirectory() as temp_dir:
            with self.assertRaises(
                RuntimeReadinessError,
            ) as caught:
                validate_analyzer_startup(
                    broken_connection,
                    temp_dir,
                )

        self.assertIn(
            "database",
            str(caught.exception),
        )
        self.assertNotIn(
            "database offline",
            str(caught.exception),
        )

    def test_readyz_uses_runtime_probe_and_returns_503_when_not_ready(self):
        client = analyzer_app.app.test_client()

        with patch.object(
            analyzer_app,
            "probe_analyzer_readiness",
            return_value={
                "service": "aegisguard-analyzer",
                "status": "not_ready",
                "checks": {
                    "database": {
                        "ok": False,
                        "reason": "database_unavailable",
                    },
                    "data_directory": {
                        "ok": True,
                        "reason": None,
                    },
                },
            },
        ):
            response = client.get("/readyz")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.get_json()["status"],
            "not_ready",
        )

    def test_launchers_preflight_before_workers_and_preserve_graceful_shutdown(self):
        root = Path(__file__).resolve().parents[2]

        app_source = (
            root
            / "backend"
            / "analyzer"
            / "app.py"
        ).read_text(encoding="utf-8")

        mtls_source = (
            root
            / "backend"
            / "analyzer"
            / "mtls_server.py"
        ).read_text(encoding="utf-8")

        self.assertLess(
            app_source.rfind(
                "validate_analyzer_startup("
            ),
            app_source.rfind(
                "start_default_ingest_worker_thread("
            ),
        )

        self.assertLess(
            mtls_source.find(
                "validate_analyzer_startup("
            ),
            mtls_source.find(
                "start_default_ingest_worker_thread("
            ),
        )

        for source in (
            app_source,
            mtls_source,
        ):
            self.assertIn(
                "ingest_stop_event.set()",
                source,
            )
            self.assertIn(
                "ingest_thread.join(timeout=5)",
                source,
            )

        self.assertIn(
            "server.server_close()",
            mtls_source,
        )


if __name__ == "__main__":
    unittest.main()
