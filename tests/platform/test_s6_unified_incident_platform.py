import sqlite3
import tempfile
import unittest
from pathlib import Path

from flask import Flask, jsonify

from backend.analyzer.app_authorization import (
    ROLE_ADMINISTRATOR,
    ROLE_ANALYST,
    ROLE_VIEWER,
    install_application_authorization,
)
from backend.analyzer.audit_context import install_request_correlation
from backend.analyzer.auth_api import (
    AUTH_CSRF_HEADER,
    create_auth_blueprint,
)
from backend.analyzer.detection.contracts import (
    IncidentCandidate,
    MITREMapping,
    Severity,
)
from backend.analyzer.incident_api import create_incident_blueprint
from backend.analyzer.incident_service import (
    IncidentConflictError,
    IncidentTransitionError,
    add_incident_evidence,
    add_incident_note,
    assign_incident,
    get_incident,
    persist_incident_candidate,
    transition_incident,
)
from backend.analyzer.sensitive_audit import (
    install_sensitive_operation_auditing,
)
from backend.storage.audit_integrity import verify_audit_chain
from backend.storage.migrations import (
    LATEST_PLATFORM_SCHEMA_VERSION,
    ensure_platform_schema,
)
from backend.storage.user_auth import create_user


class S6UnifiedIncidentPlatformTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "s6.db"

    def tearDown(self):
        self.tmp.cleanup()

    def connection(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        ensure_platform_schema(conn)
        return conn

    def connection_factory(self):
        return self.connection()

    def provision(self, username, role):
        conn = self.connection()
        try:
            return create_user(
                conn,
                username,
                "correct-horse-battery",
                role,
                user_id=f"user-{username}",
            )
        finally:
            conn.close()

    def candidate(self, *, candidate_id="CAND-STORY-ABC123"):
        return IncidentCandidate(
            candidate_id=candidate_id,
            finding_ids=("finding-1", "finding-2"),
            event_ids=("event-101", "event-102"),
            name="Multi-stage attack activity on host-a",
            severity=Severity.HIGH,
            confidence=0.91,
            reason="Correlated two attack stages.",
            timestamp="2026-09-23T06:30:00Z",
            mitre=(
                MITREMapping(
                    technique_id="T1110",
                    technique="Brute Force",
                    tactic="Credential Access",
                ),
                MITREMapping(
                    technique_id="T1059",
                    technique="Command and Scripting Interpreter",
                    tactic="Execution",
                ),
            ),
            related_entities={
                "hostnames": ("host-a",),
                "users": ("alice",),
                "source_ips": ("203.0.113.10",),
                "processes": ("powershell.exe",),
            },
            metadata={
                "story_version": "attack-story-v1",
                "attack_stages": (
                    "CREDENTIAL_ACCESS",
                    "EXECUTION",
                ),
                "timeline": (
                    {
                        "finding_id": "finding-1",
                        "stage": "CREDENTIAL_ACCESS",
                    },
                    {
                        "finding_id": "finding-2",
                        "stage": "EXECUTION",
                    },
                ),
            },
        )

    def persist(self, candidate=None):
        conn = self.connection()
        try:
            return persist_incident_candidate(
                conn,
                candidate or self.candidate(),
            )
        finally:
            conn.close()

    def make_app(self):
        app = Flask(__name__)
        app.register_blueprint(
            create_auth_blueprint(
                self.connection_factory,
                cookie_secure=False,
                session_ttl_seconds=3600,
                session_idle_timeout_seconds=1800,
            )
        )
        app.register_blueprint(
            create_incident_blueprint(
                self.connection_factory
            )
        )

        @app.get("/api/incidents")
        def list_incidents_stub():
            conn = self.connection()
            try:
                rows = conn.execute(
                    "SELECT incident_id FROM incidents"
                ).fetchall()
            finally:
                conn.close()
            return jsonify({
                "incident_ids": [row[0] for row in rows],
            })

        install_request_correlation(
            app,
            correlation_id_factory=lambda: "req-s6-fixed",
        )
        install_application_authorization(
            app,
            self.connection_factory,
            session_idle_timeout_seconds=1800,
        )
        install_sensitive_operation_auditing(
            app,
            self.connection_factory,
            retention_days=365,
        )
        app.testing = True
        return app

    def login(self, client, username):
        response = client.post(
            "/api/auth/login",
            json={
                "username": username,
                "password": "correct-horse-battery",
            },
        )
        self.assertEqual(response.status_code, 200)
        return response.get_json()["csrf_token"]

    def test_schema_v10_adds_unified_incident_tables(self):
        conn = self.connection()
        try:
            self.assertEqual(
                LATEST_PLATFORM_SCHEMA_VERSION,
                10,
            )
            tables = {
                row[0]
                for row in conn.execute(
                    """
                    SELECT name
                    FROM sqlite_master
                    WHERE type='table'
                    """
                ).fetchall()
            }
            columns = {
                row[1]
                for row in conn.execute(
                    "PRAGMA table_info(incidents)"
                ).fetchall()
            }
        finally:
            conn.close()

        self.assertTrue({
            "incident_finding_refs",
            "incident_event_refs",
            "incident_mitre_mappings",
            "incident_related_entities",
            "incident_notes",
            "incident_evidence_refs",
            "incident_lifecycle_history",
        }.issubset(tables))
        self.assertTrue({
            "candidate_id",
            "candidate_fingerprint",
            "confidence",
            "attack_story_id",
            "attack_story_version",
            "opened_at",
            "resolution_summary",
        }.issubset(columns))

    def test_candidate_creation_is_deterministic_and_reference_only(self):
        incident, created = self.persist()
        self.assertTrue(created)
        self.assertTrue(incident["incident_id"].startswith("INC-"))
        self.assertEqual(
            incident["candidate_id"],
            "CAND-STORY-ABC123",
        )
        self.assertEqual(
            incident["lifecycle_status"],
            "OPEN",
        )
        self.assertEqual(
            incident["finding_ids"],
            ["finding-1", "finding-2"],
        )
        self.assertEqual(
            incident["event_ids"],
            ["event-101", "event-102"],
        )
        self.assertEqual(
            incident["attack_story_id"],
            "CAND-STORY-ABC123",
        )
        self.assertEqual(len(incident["mitre_mappings"]), 2)

        # Candidate raw bodies do not exist in the persistence model.
        conn = self.connection()
        try:
            incident_sql = conn.execute(
                """
                SELECT sql
                FROM sqlite_master
                WHERE type='table'
                  AND name='incidents'
                """
            ).fetchone()[0].lower()
        finally:
            conn.close()
        self.assertNotIn("raw_event", incident_sql)

    def test_candidate_retry_is_idempotent_and_audit_is_not_duplicated(self):
        first, created_first = self.persist()
        second, created_second = self.persist()

        self.assertTrue(created_first)
        self.assertFalse(created_second)
        self.assertEqual(
            first["incident_id"],
            second["incident_id"],
        )

        conn = self.connection()
        try:
            incident_count = conn.execute(
                """
                SELECT COUNT(*)
                FROM incidents
                WHERE candidate_id = 'CAND-STORY-ABC123'
                """
            ).fetchone()[0]
            create_audits = conn.execute(
                """
                SELECT COUNT(*)
                FROM audit_events
                WHERE action = 'INCIDENT.CREATE'
                """
            ).fetchone()[0]
            integrity = verify_audit_chain(conn)
        finally:
            conn.close()

        self.assertEqual(incident_count, 1)
        self.assertEqual(create_audits, 1)
        self.assertTrue(integrity["valid"])

    def test_same_candidate_id_with_changed_content_fails_closed(self):
        self.persist()
        changed = IncidentCandidate(
            candidate_id="CAND-STORY-ABC123",
            finding_ids=("finding-1", "finding-2"),
            event_ids=("event-101", "event-102"),
            name="Changed title",
            severity=Severity.CRITICAL,
            confidence=0.99,
            reason="Changed content",
            timestamp="2026-09-23T06:30:00Z",
        )
        conn = self.connection()
        try:
            with self.assertRaises(IncidentConflictError):
                persist_incident_candidate(
                    conn,
                    changed,
                )
        finally:
            conn.close()

    def test_valid_and_invalid_lifecycle_transitions(self):
        incident, _ = self.persist()
        self.provision("analyst", ROLE_ANALYST)

        conn = self.connection()
        try:
            current = transition_incident(
                conn,
                incident_id=incident["incident_id"],
                to_status="INVESTIGATING",
                actor_user_id="user-analyst",
            )
            self.assertEqual(
                current["lifecycle_status"],
                "INVESTIGATING",
            )

            with self.assertRaises(IncidentTransitionError):
                transition_incident(
                    conn,
                    incident_id=incident["incident_id"],
                    to_status="CLOSED",
                    actor_user_id="user-analyst",
                )

            current = transition_incident(
                conn,
                incident_id=incident["incident_id"],
                to_status="CONFIRMED",
                actor_user_id="user-analyst",
            )
            current = transition_incident(
                conn,
                incident_id=incident["incident_id"],
                to_status="CONTAINMENT",
                actor_user_id="user-analyst",
            )
            current = transition_incident(
                conn,
                incident_id=incident["incident_id"],
                to_status="RESOLVED",
                actor_user_id="user-analyst",
                resolution_summary="Threat contained and credentials rotated.",
            )
            current = transition_incident(
                conn,
                incident_id=incident["incident_id"],
                to_status="CLOSED",
                actor_user_id="user-analyst",
            )
        finally:
            conn.close()

        self.assertEqual(current["lifecycle_status"], "CLOSED")
        self.assertIsNotNone(current["resolved_at"])
        self.assertIsNotNone(current["closed_at"])

    def test_false_positive_requires_resolution_summary(self):
        incident, _ = self.persist()
        self.provision("analyst", ROLE_ANALYST)

        conn = self.connection()
        try:
            transition_incident(
                conn,
                incident_id=incident["incident_id"],
                to_status="INVESTIGATING",
                actor_user_id="user-analyst",
            )
            with self.assertRaises(ValueError):
                transition_incident(
                    conn,
                    incident_id=incident["incident_id"],
                    to_status="FALSE_POSITIVE",
                    actor_user_id="user-analyst",
                )
        finally:
            conn.close()

    def test_assignment_notes_and_evidence_persist_across_restart(self):
        incident, _ = self.persist()
        self.provision("admin", ROLE_ADMINISTRATOR)
        self.provision("analyst", ROLE_ANALYST)

        conn = self.connection()
        try:
            assigned = assign_incident(
                conn,
                incident_id=incident["incident_id"],
                assigned_user_id="user-analyst",
                actor_user_id="user-admin",
            )
            self.assertEqual(
                assigned["assigned_user_id"],
                "user-analyst",
            )

            add_incident_note(
                conn,
                incident_id=incident["incident_id"],
                actor_user_id="user-analyst",
                note="Validated source host ownership.",
            )
            first = add_incident_evidence(
                conn,
                incident_id=incident["incident_id"],
                actor_user_id="user-analyst",
                reference_type="EVENT",
                reference_id="event-101",
                description="Primary authentication event.",
            )
            duplicate = add_incident_evidence(
                conn,
                incident_id=incident["incident_id"],
                actor_user_id="user-analyst",
                reference_type="EVENT",
                reference_id="event-101",
                description="Retry",
            )
        finally:
            conn.close()

        self.assertFalse(first["duplicate"])
        self.assertTrue(duplicate["duplicate"])

        # Reopen the database to prove durable restart persistence.
        conn = self.connection()
        try:
            persisted = get_incident(
                conn,
                incident["incident_id"],
            )
        finally:
            conn.close()

        self.assertEqual(
            persisted["assigned_user_id"],
            "user-analyst",
        )
        self.assertEqual(len(persisted["notes"]), 1)
        self.assertEqual(
            len(persisted["evidence_references"]),
            1,
        )

    def test_viewer_read_only_analyst_workflow_admin_assignment_override(self):
        incident, _ = self.persist()
        self.provision("viewer", ROLE_VIEWER)
        self.provision("analyst", ROLE_ANALYST)
        self.provision("admin", ROLE_ADMINISTRATOR)
        app = self.make_app()

        viewer = app.test_client()
        self.login(viewer, "viewer")
        self.assertEqual(
            viewer.get(
                f"/api/incidents/{incident['incident_id']}"
            ).status_code,
            200,
        )
        self.assertEqual(
            viewer.post(
                f"/api/incidents/{incident['incident_id']}/notes",
                json={"note": "forged"},
            ).status_code,
            403,
        )

        analyst = app.test_client()
        analyst_csrf = self.login(analyst, "analyst")
        transition = analyst.post(
            f"/api/incidents/{incident['incident_id']}/transition",
            json={"to_status": "INVESTIGATING"},
            headers={AUTH_CSRF_HEADER: analyst_csrf},
        )
        self.assertEqual(transition.status_code, 200)
        note = analyst.post(
            f"/api/incidents/{incident['incident_id']}/notes",
            json={"note": "Analyst investigation started."},
            headers={AUTH_CSRF_HEADER: analyst_csrf},
        )
        self.assertEqual(note.status_code, 201)
        self.assertEqual(
            analyst.post(
                f"/api/incidents/{incident['incident_id']}/assign",
                json={"assigned_user_id": "user-analyst"},
                headers={AUTH_CSRF_HEADER: analyst_csrf},
            ).status_code,
            403,
        )

        admin = app.test_client()
        admin_csrf = self.login(admin, "admin")
        assign = admin.post(
            f"/api/incidents/{incident['incident_id']}/assign",
            json={"assigned_user_id": "user-analyst"},
            headers={AUTH_CSRF_HEADER: admin_csrf},
        )
        self.assertEqual(assign.status_code, 200)
        override = admin.post(
            f"/api/incidents/{incident['incident_id']}/override",
            json={
                "to_status": "CLOSED",
                "reason": "Administrative closure after external case merge.",
            },
            headers={AUTH_CSRF_HEADER: admin_csrf},
        )
        self.assertEqual(override.status_code, 200)
        self.assertEqual(
            override.get_json()["incident"]["lifecycle_status"],
            "CLOSED",
        )

    def test_state_change_requires_csrf(self):
        incident, _ = self.persist()
        self.provision("analyst", ROLE_ANALYST)
        app = self.make_app()
        analyst = app.test_client()
        self.login(analyst, "analyst")

        response = analyst.post(
            f"/api/incidents/{incident['incident_id']}/transition",
            json={"to_status": "INVESTIGATING"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.get_json()["error"],
            "csrf_required",
        )

    def test_malformed_mutations_fail_safely(self):
        incident, _ = self.persist()
        self.provision("analyst", ROLE_ANALYST)
        app = self.make_app()
        client = app.test_client()
        csrf = self.login(client, "analyst")
        headers = {AUTH_CSRF_HEADER: csrf}

        self.assertEqual(
            client.post(
                f"/api/incidents/{incident['incident_id']}/transition",
                json={"to_status": "NOT_A_STATUS"},
                headers=headers,
            ).status_code,
            400,
        )
        self.assertEqual(
            client.post(
                f"/api/incidents/{incident['incident_id']}/notes",
                json={"note": ""},
                headers=headers,
            ).status_code,
            400,
        )
        self.assertEqual(
            client.post(
                f"/api/incidents/{incident['incident_id']}/evidence",
                json={
                    "reference_type": "bad type!",
                    "reference_id": "x",
                },
                headers=headers,
            ).status_code,
            400,
        )

    def test_incident_mutations_emit_s5_audit_events_without_note_body(self):
        incident, _ = self.persist()
        self.provision("analyst", ROLE_ANALYST)
        app = self.make_app()
        client = app.test_client()
        csrf = self.login(client, "analyst")
        headers = {AUTH_CSRF_HEADER: csrf}

        self.assertEqual(
            client.post(
                f"/api/incidents/{incident['incident_id']}/transition",
                json={"to_status": "INVESTIGATING"},
                headers=headers,
            ).status_code,
            200,
        )
        secret_note = "SOC note text must not be copied into audit details"
        self.assertEqual(
            client.post(
                f"/api/incidents/{incident['incident_id']}/notes",
                json={"note": secret_note},
                headers=headers,
            ).status_code,
            201,
        )

        conn = self.connection()
        try:
            rows = conn.execute(
                """
                SELECT action, details_json
                FROM audit_events
                WHERE action IN (
                    'INCIDENT.TRANSITION',
                    'INCIDENT.NOTE_ADD'
                )
                ORDER BY chain_sequence ASC
                """
            ).fetchall()
            integrity = verify_audit_chain(conn)
        finally:
            conn.close()

        self.assertEqual(
            [row[0] for row in rows],
            ["INCIDENT.TRANSITION", "INCIDENT.NOTE_ADD"],
        )
        self.assertNotIn(secret_note, rows[-1][1])
        self.assertTrue(integrity["valid"])

    def test_assignment_rejects_viewer_as_assignee(self):
        incident, _ = self.persist()
        self.provision("admin", ROLE_ADMINISTRATOR)
        self.provision("viewer", ROLE_VIEWER)

        conn = self.connection()
        try:
            with self.assertRaises(ValueError):
                assign_incident(
                    conn,
                    incident_id=incident["incident_id"],
                    assigned_user_id="user-viewer",
                    actor_user_id="user-admin",
                )
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
