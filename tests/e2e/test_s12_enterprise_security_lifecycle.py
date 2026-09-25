import json
import sqlite3

import pandas as pd
import pytest
from flask import Flask
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

from backend.analyzer import database as analyzer_database
from backend.analyzer.app_authorization import (
    ROLE_ADMINISTRATOR,
    install_application_authorization,
    required_roles_for_request,
)
from backend.analyzer.audit_context import install_request_correlation
from backend.analyzer.auth_api import (
    AUTH_CSRF_HEADER,
    create_auth_blueprint,
)
from backend.analyzer.collector_api import (
    COLLECTOR_CREDENTIAL_HEADER,
    ENROLLMENT_TOKEN_HEADER,
    create_collector_blueprint,
)
from backend.analyzer.incident_api import create_incident_blueprint
from backend.analyzer.incident_service import (
    get_incident,
    persist_incident_candidate,
)
from backend.analyzer.ingest_worker import (
    build_default_ingest_worker,
    recover_interrupted_ingest,
)
from backend.analyzer.intelligence.ml_runtime import (
    GovernedMLRuntime,
    GovernedMLRuntimeStatus,
)
from backend.analyzer.intelligence.service import (
    get_intelligence_snapshot,
)
from backend.analyzer.ml import (
    FEATURE_COLUMNS,
    FEATURE_SCHEMA_VERSION,
    MLEngine,
)
from backend.analyzer.privacy_projection import (
    install_application_privacy_projection,
)
from backend.analyzer.sensitive_audit import (
    install_sensitive_operation_auditing,
)
from backend.analyzer.soar import ApprovalDeniedError, SoarEngine
from backend.analyzer.soar.policies import ResponsePolicy
from backend.analyzer.detection.contracts import (
    IncidentCandidate,
    MITREMapping,
    Severity,
)
from backend.storage.audit_integrity import verify_audit_chain
from backend.storage.collector_ingest import claim_next_collector_batch
from backend.storage.user_auth import create_user


CERTIFICATE = """-----BEGIN CERTIFICATE-----
AQIDBAUGBwg=
-----END CERTIFICATE-----"""

COLLECTOR_ID = "collector-s12"
HOSTNAME = "S12-HOST"
SOURCE_IP = "8.8.8.8"
PASSWORD = "correct-horse-battery"


class NoLiveFirewall:
    """Fail immediately if a dry-run validation reaches live execution."""

    def block_ip(self, _ip):
        raise AssertionError(
            "S12 dry-run must not invoke live firewall block"
        )

    def unblock_ip(self, _ip):
        raise AssertionError(
            "S12 dry-run must not invoke live firewall unblock"
        )

    def rule_exists(self, _ip):
        return False


@pytest.fixture()
def enterprise_db(tmp_path, monkeypatch):
    db_path = tmp_path / "aegisguard-s12.db"

    monkeypatch.setattr(
        analyzer_database,
        "DB_PATH",
        db_path,
    )
    monkeypatch.setattr(
        analyzer_database,
        "_schema_initialized",
        False,
    )

    conn = analyzer_database.get_connection()
    conn.close()

    return analyzer_database


def _collector_app(db):
    app = Flask("s12-collector")
    app.register_blueprint(
        create_collector_blueprint(
            db.get_connection,
            auth_required=True,
            enrollment_token="s12-bootstrap-secret",
            credential_factory=lambda: "s12-device-credential",
            mtls_required=True,
        )
    )
    app.testing = True
    return app


def _mtls_environment():
    return {
        "SSL_CLIENT_VERIFY": "SUCCESS",
        "SSL_CLIENT_CERT": CERTIFICATE,
    }


def _security_payload(batch_id):
    return {
        "batch_id": batch_id,
        "collector_id": COLLECTOR_ID,
        "machine_id": HOSTNAME,
        "hostname": HOSTNAME,
        "os": "Windows-11",
        "logs": [
            {
                "record_id": 12001,
                "timestamp": "2026-09-25T03:00:00Z",
                "event_type": "FAILED_LOGIN",
                "user": "alice",
                "source_ip": SOURCE_IP,
                "severity": "HIGH",
                "raw_log": "failed login attempt one",
            },
            {
                "record_id": 12002,
                "timestamp": "2026-09-25T03:01:00Z",
                "event_type": "FAILED_LOGIN",
                "user": "alice",
                "source_ip": SOURCE_IP,
                "severity": "HIGH",
                "raw_log": "failed login attempt two",
            },
            {
                "record_id": 12003,
                "timestamp": "2026-09-25T03:02:00Z",
                "event_type": "FAILED_LOGIN",
                "user": "alice",
                "source_ip": SOURCE_IP,
                "severity": "HIGH",
                "raw_log": "failed login attempt three",
            },
            {
                "record_id": 12004,
                "timestamp": "2026-09-25T03:03:00Z",
                "event_type": "LOGON_SUCCESS",
                "user": "alice",
                "source_ip": SOURCE_IP,
                "severity": "INFO",
                "raw_log": "successful login after failures",
            },
            {
                "record_id": 12005,
                "timestamp": "2026-09-25T03:04:00Z",
                "event_type": "PRIVILEGE_ESCALATION",
                "user": "alice",
                "source_ip": SOURCE_IP,
                "process": "powershell.exe",
                "severity": "CRITICAL",
                "raw_log": "privilege escalation activity",
            },
        ],
    }


def _enroll_and_submit(db, batch_id):
    client = _collector_app(db).test_client()

    enrolled = client.post(
        "/api/collector/v1/enroll",
        json={
            "collector_id": COLLECTOR_ID,
            "hostname": HOSTNAME,
            "version": "0.1.0",
        },
        headers={
            ENROLLMENT_TOKEN_HEADER: "s12-bootstrap-secret",
        },
        environ_overrides=_mtls_environment(),
    )
    assert enrolled.status_code == 201
    credential = enrolled.get_json()["credential"]

    headers = {
        "X-AegisGuard-Collector-ID": COLLECTOR_ID,
        "X-AegisGuard-Batch-ID": batch_id,
        COLLECTOR_CREDENTIAL_HEADER: credential,
    }
    payload = _security_payload(batch_id)

    first = client.post(
        "/api/collector/v1/batches",
        json=payload,
        headers=headers,
        environ_overrides=_mtls_environment(),
    )
    duplicate = client.post(
        "/api/collector/v1/batches",
        json=payload,
        headers=headers,
        environ_overrides=_mtls_environment(),
    )

    assert first.status_code == 202
    assert first.get_json()["duplicate"] is False
    assert duplicate.status_code == 202
    assert duplicate.get_json()["duplicate"] is True

    return payload


def _candidate_from_story(story):
    return IncidentCandidate(
        candidate_id=story["candidate_id"],
        finding_ids=tuple(story["finding_ids"]),
        event_ids=tuple(story["event_ids"]),
        name=story["name"],
        severity=Severity(story["severity"]),
        confidence=float(story["confidence"]),
        reason=story["reason"],
        timestamp=story["timestamp"],
        mitre=tuple(
            MITREMapping(
                technique_id=item["technique_id"],
                technique=item["technique"],
                tactic=item["tactic"],
            )
            for item in story["mitre"]
        ),
        related_entities={
            key: tuple(values)
            for key, values in story["related_entities"].items()
        },
        metadata=dict(story["metadata"]),
    )


def _degraded_runtime():
    return GovernedMLRuntime(
        status=GovernedMLRuntimeStatus.DEGRADED,
        available=False,
        model_name="aegis-threat-classifier",
        model_version="s12-degraded",
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        reason="S12 deterministic degraded-runtime validation",
        engine=None,
    )


def _real_governed_ml_runtime():
    malicious = {column: 0 for column in FEATURE_COLUMNS}
    malicious.update({
        "FAILED_LOGIN": 3,
        "LOGON_SUCCESS": 1,
        "PRIVILEGE_ESCALATION": 1,
        "TOTAL_EVENTS": 5,
        "HIGH_EVENTS": 3,
        "CRITICAL_EVENTS": 1,
        "UNIQUE_USERS": 1,
        "UNIQUE_SOURCE_IPS": 1,
    })

    normal = {column: 0 for column in FEATURE_COLUMNS}
    normal.update({
        "LOGON_SUCCESS": 2,
        "TOTAL_EVENTS": 2,
        "UNIQUE_USERS": 1,
        "UNIQUE_SOURCE_IPS": 1,
    })

    rows = []
    labels = []

    for _ in range(12):
        rows.append(dict(malicious))
        labels.append("BRUTE_FORCE")
        rows.append(dict(normal))
        labels.append("NORMAL")

    frame = pd.DataFrame(
        rows,
        columns=FEATURE_COLUMNS,
    )

    encoder = LabelEncoder()
    encoded = encoder.fit_transform(labels)

    model = RandomForestClassifier(
        n_estimators=12,
        random_state=42,
    ).fit(frame, encoded)

    engine = MLEngine(
        model=model,
        encoder=encoder,
        model_name="aegis-threat-classifier",
        model_version="s12-real-model-1",
    )

    return GovernedMLRuntime(
        status=GovernedMLRuntimeStatus.AVAILABLE,
        available=True,
        model_name=engine.model_name,
        model_version=engine.model_version,
        feature_schema_version=engine.feature_schema_version,
        reason=None,
        engine=engine,
    )


def _provision_user(db, username, role):
    conn = db.get_connection()
    try:
        return create_user(
            conn,
            username,
            PASSWORD,
            role,
            user_id=f"user-{username}",
        )
    finally:
        conn.close()


def _human_app(db):
    app = Flask("s12-human")
    app.register_blueprint(
        create_auth_blueprint(
            db.get_connection,
            cookie_secure=False,
            session_ttl_seconds=3600,
            session_idle_timeout_seconds=1800,
        )
    )
    app.register_blueprint(
        create_incident_blueprint(
            db.get_connection,
        )
    )

    install_request_correlation(
        app,
        correlation_id_factory=lambda: "req-s12-e2e",
    )
    install_application_authorization(
        app,
        db.get_connection,
        session_idle_timeout_seconds=1800,
    )
    install_application_privacy_projection(app)
    install_sensitive_operation_auditing(
        app,
        db.get_connection,
    )
    app.testing = True
    return app


def _login(client, username):
    response = client.post(
        "/api/auth/login",
        json={
            "username": username,
            "password": PASSWORD,
        },
    )
    assert response.status_code == 200
    return response.get_json()["csrf_token"]


def _persist_story_incident(db, snapshot):
    assert snapshot["attack_stories"], (
        "real intelligence findings did not produce an attack story"
    )

    candidate = _candidate_from_story(
        snapshot["attack_stories"][0]
    )

    conn = db.get_connection()
    try:
        incident, created = persist_incident_candidate(
            conn,
            candidate,
        )
        same_incident, created_again = (
            persist_incident_candidate(
                conn,
                candidate,
            )
        )
    finally:
        conn.close()

    assert created is True
    assert created_again is False
    assert (
        same_incident["incident_id"]
        == incident["incident_id"]
    )

    return incident, candidate


def test_complete_enterprise_security_lifecycle_with_degraded_governed_ml(
    enterprise_db,
):
    db = enterprise_db
    batch_id = "s12-batch-main"

    _enroll_and_submit(
        db,
        batch_id,
    )

    conn = db.get_connection()
    try:
        batch_count = conn.execute(
            """
            SELECT COUNT(*)
            FROM collector_ingest_batches
            WHERE batch_id = ?
            """,
            (batch_id,),
        ).fetchone()[0]
    finally:
        conn.close()

    assert batch_count == 1

    worker = build_default_ingest_worker(
        db.get_connection
    )
    processed = worker.run_once()

    assert processed is not None
    assert processed["batch_id"] == batch_id
    assert processed["state"] == "PROCESSED"
    assert processed["result"]["logs_received"] == 5
    assert processed["result"]["new_logs_added"] == 5

    conn = db.get_connection()
    try:
        persisted_events = conn.execute(
            """
            SELECT COUNT(*)
            FROM security_logs
            WHERE hostname = ?
            """,
            (HOSTNAME,),
        ).fetchone()[0]

        durable_state = conn.execute(
            """
            SELECT state, payload_json
            FROM collector_ingest_batches
            WHERE batch_id = ?
            """,
            (batch_id,),
        ).fetchone()

        legacy_recommendations = conn.execute(
            """
            SELECT COUNT(*)
            FROM response_actions
            WHERE status = 'PENDING_APPROVAL'
            """
        ).fetchone()[0]
    finally:
        conn.close()

    assert persisted_events == 5
    assert durable_state[0] == "PROCESSED"
    assert durable_state[1] == "{}"
    assert legacy_recommendations >= 1

    snapshot = get_intelligence_snapshot(
        db.get_connection,
        event_limit=100,
        ml_runtime=_degraded_runtime(),
    )

    assert (
        snapshot["governed_ml_runtime"]["status"]
        == "DEGRADED"
    )
    assert snapshot["detection_counts"]["ML"] == 0
    assert snapshot["detection_counts"]["RULE"] >= 4
    assert snapshot["detection_counts"]["CORRELATION"] >= 2

    rule_ids = {
        finding["rule_id"]
        for finding in snapshot["findings"]["rule"]
    }
    assert "AG-RULE-AUTH-001" in rule_ids
    assert "AG-RULE-PRIV-001" in rule_ids

    technique_ids = {
        item["technique_id"]
        for item in snapshot["mitre_coverage"]
    }
    assert "T1110" in technique_ids
    assert "T1548" in technique_ids

    incident, candidate = _persist_story_incident(
        db,
        snapshot,
    )

    assert incident["lifecycle_status"] == "OPEN"
    assert incident["candidate_id"] == candidate.candidate_id

    conn = db.get_connection()
    try:
        engine = SoarEngine(
            conn,
            NoLiveFirewall(),
            ResponsePolicy(
                {
                    "soar_mode": "MANUAL",
                    "soar_dry_run": "true",
                    "soar_auto_min_score": "90",
                    "soar_allow_private_ip_blocking": "false",
                    "soar_allowlist": "[]",
                },
                self_ips={"192.0.2.200"},
            ),
        )

        action = engine.request_block(
            {
                "incident_id": incident["incident_id"],
                "log_id": candidate.event_ids[0],
                "hostname": HOSTNAME,
                "source_ip": SOURCE_IP,
                "severity": candidate.severity.value,
                "threat_score": 95,
                "threat_type": candidate.name,
            },
            requested_by_user_id="user-admin-requester",
        )

        assert action["status"] == "PENDING_APPROVAL"

        with pytest.raises(
            ApprovalDeniedError,
            match="cannot approve",
        ):
            engine.approve(
                action["id"],
                approved_by_user_id="user-admin-requester",
            )

        approved = engine.approve(
            action["id"],
            approved_by_user_id="user-admin-approver",
        )

        assert approved["status"] == "DRY_RUN"
        assert (
            approved["requested_by_user_id"]
            == "user-admin-requester"
        )
        assert (
            approved["approved_by_user_id"]
            == "user-admin-approver"
        )
        assert approved["simulation_result"]
    finally:
        conn.close()

    assert required_roles_for_request(
        f"/api/response-actions/{action['id']}/approve",
        "POST",
    ) == frozenset({ROLE_ADMINISTRATOR})

    _provision_user(db, "viewer", "VIEWER")
    _provision_user(db, "analyst", "ANALYST")
    _provision_user(db, "admin", "ADMINISTRATOR")

    human_app = _human_app(db)

    viewer = human_app.test_client()
    viewer_csrf = _login(viewer, "viewer")

    viewer_read = viewer.get(
        f"/api/incidents/{incident['incident_id']}"
    )
    assert viewer_read.status_code == 200

    viewer_incident = viewer_read.get_json()["incident"]

    assert viewer_incident["hostname"] == "[REDACTED]"
    assert viewer_incident["source_ip"] == "[REDACTED]"
    assert (
        viewer_incident["related_entities"]
        == "[REDACTED]"
    )

    viewer_denied = viewer.post(
        f"/api/incidents/{incident['incident_id']}/notes",
        json={
            "note": "viewer must not mutate incidents",
        },
        headers={
            AUTH_CSRF_HEADER: viewer_csrf,
        },
    )
    assert viewer_denied.status_code == 403

    analyst = human_app.test_client()
    analyst_csrf = _login(analyst, "analyst")

    analyst_read = analyst.get(
        f"/api/incidents/{incident['incident_id']}"
    )
    assert analyst_read.status_code == 200

    analyst_incident = analyst_read.get_json()["incident"]
    assert analyst_incident["hostname"] == HOSTNAME
    assert analyst_incident["source_ip"] == SOURCE_IP
    assert "raw_log" not in json.dumps(
        analyst_incident,
        sort_keys=True,
    )

    transitioned = analyst.post(
        f"/api/incidents/{incident['incident_id']}/transition",
        json={
            "to_status": "INVESTIGATING",
        },
        headers={
            AUTH_CSRF_HEADER: analyst_csrf,
            "X-AegisGuard-User": "forged-admin",
            "X-AegisGuard-Role": "ADMINISTRATOR",
        },
    )
    assert transitioned.status_code == 200
    assert (
        transitioned.get_json()["incident"][
            "lifecycle_status"
        ]
        == "INVESTIGATING"
    )

    analyst_assign_denied = analyst.post(
        f"/api/incidents/{incident['incident_id']}/assign",
        json={
            "assigned_user_id": "user-analyst",
        },
        headers={
            AUTH_CSRF_HEADER: analyst_csrf,
        },
    )
    assert analyst_assign_denied.status_code == 403

    admin = human_app.test_client()
    admin_csrf = _login(admin, "admin")

    assigned = admin.post(
        f"/api/incidents/{incident['incident_id']}/assign",
        json={
            "assigned_user_id": "user-analyst",
        },
        headers={
            AUTH_CSRF_HEADER: admin_csrf,
        },
    )
    assert assigned.status_code == 200
    assert (
        assigned.get_json()["incident"][
            "assigned_user_id"
        ]
        == "user-analyst"
    )

    # Reopen all durable state after the completed workflow.
    conn = db.get_connection()
    try:
        persisted_incident = get_incident(
            conn,
            incident["incident_id"],
        )

        persisted_action = SoarEngine(
            conn,
            NoLiveFirewall(),
            ResponsePolicy(
                {
                    "soar_mode": "MANUAL",
                    "soar_dry_run": "true",
                    "soar_allowlist": "[]",
                },
                self_ips={"192.0.2.200"},
            ),
        ).get_action(action["id"])

        integrity = verify_audit_chain(conn)

        transition_audit = conn.execute(
            """
            SELECT actor_user_id, details_json
            FROM audit_events
            WHERE action = 'INCIDENT.TRANSITION'
            ORDER BY chain_sequence DESC
            LIMIT 1
            """
        ).fetchone()

        create_audits = conn.execute(
            """
            SELECT COUNT(*)
            FROM audit_events
            WHERE action = 'INCIDENT.CREATE'
              AND target_id = ?
            """,
            (incident["incident_id"],),
        ).fetchone()[0]
    finally:
        conn.close()

    assert (
        persisted_incident["lifecycle_status"]
        == "INVESTIGATING"
    )
    assert (
        persisted_incident["assigned_user_id"]
        == "user-analyst"
    )
    assert persisted_action["status"] == "DRY_RUN"
    assert (
        persisted_action["approved_by_user_id"]
        == "user-admin-approver"
    )
    assert create_audits == 1
    assert integrity["valid"] is True

    assert transition_audit is not None
    assert transition_audit[0] == "user-analyst"
    assert "forged-admin" not in transition_audit[1]


def test_real_governed_ml_available_finding_is_preserved(
    enterprise_db,
):
    db = enterprise_db

    _enroll_and_submit(
        db,
        "s12-batch-ml",
    )

    worker = build_default_ingest_worker(
        db.get_connection
    )
    processed = worker.run_once()

    assert processed["state"] == "PROCESSED"

    runtime = _real_governed_ml_runtime()

    snapshot = get_intelligence_snapshot(
        db.get_connection,
        event_limit=100,
        ml_runtime=runtime,
    )

    assert (
        snapshot["governed_ml_runtime"]["status"]
        == "AVAILABLE"
    )
    assert (
        snapshot["governance"][
            "governed_ml_findings_available"
        ]
        is True
    )
    assert snapshot["detection_counts"]["ML"] == 1

    finding = snapshot["findings"]["ml"][0]

    assert finding["detection_type"] == "ML"
    assert (
        finding["model_version"]
        == "s12-real-model-1"
    )
    assert (
        finding["feature_schema_version"]
        == FEATURE_SCHEMA_VERSION
    )
    assert (
        finding["prediction_source"]
        == "model:aegis-threat-classifier"
    )
    assert finding["mitre"]
    assert (
        finding["mitre"][0]["technique_id"]
        == "T1110"
    )


def test_interrupted_durable_ingest_recovers_without_duplicate_events(
    enterprise_db,
):
    db = enterprise_db
    batch_id = "s12-batch-restart"

    _enroll_and_submit(
        db,
        batch_id,
    )

    conn = db.get_connection()
    try:
        claimed = claim_next_collector_batch(conn)
    finally:
        conn.close()

    assert claimed is not None
    assert claimed["batch_id"] == batch_id

    conn = db.get_connection()
    try:
        state_before = conn.execute(
            """
            SELECT state
            FROM collector_ingest_batches
            WHERE batch_id = ?
            """,
            (batch_id,),
        ).fetchone()[0]
    finally:
        conn.close()

    assert state_before == "PROCESSING"

    recovered = recover_interrupted_ingest(
        db.get_connection
    )
    assert recovered == 1

    worker = build_default_ingest_worker(
        db.get_connection
    )
    processed = worker.run_once()

    assert processed["state"] == "PROCESSED"
    assert processed["attempts"] == 2

    # A second worker pass has nothing left to replay.
    assert worker.run_once() is None

    conn = db.get_connection()
    try:
        event_count = conn.execute(
            """
            SELECT COUNT(*)
            FROM security_logs
            WHERE hostname = ?
            """,
            (HOSTNAME,),
        ).fetchone()[0]

        row = conn.execute(
            """
            SELECT state, attempts
            FROM collector_ingest_batches
            WHERE batch_id = ?
            """,
            (batch_id,),
        ).fetchone()
    finally:
        conn.close()

    assert event_count == 5
    assert row[0] == "PROCESSED"
    assert row[1] == 2
