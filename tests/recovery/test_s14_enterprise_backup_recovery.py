import hashlib
import json
import shutil
import sqlite3
import zipfile
from pathlib import Path

import pytest

from backend.analyzer.database import ensure_schema
from backend.analyzer.runtime_reliability import (
    probe_analyzer_readiness,
)
from backend.analyzer.soar import (
    ApprovalDeniedError,
    SoarEngine,
)
from backend.analyzer.soar.policies import (
    ResponsePolicy,
)
from backend.collector.state import CollectorState
from backend.deployment.enterprise_recovery import (
    BackupIntegrityError,
    create_backup,
    recover_interrupted_restore,
    restore_backup,
    sha256_file,
    verify_backup,
)
from backend.storage.audit_integrity import (
    verify_audit_chain,
)
from backend.storage.audit_log import (
    record_audit_event,
)
from backend.storage.collector_ingest import (
    claim_next_collector_batch,
    persist_collector_batch,
    recover_processing_collector_batches,
)
from backend.storage.user_auth import (
    create_session,
    create_user,
)


class FakeProtector:
    def protect(self, plaintext):
        return b"protected:" + bytes(plaintext)

    def unprotect(self, protected):
        value = bytes(protected)
        prefix = b"protected:"
        assert value.startswith(prefix)
        return value[len(prefix):]


class NoLiveFirewall:
    def block_ip(self, _ip):
        raise AssertionError(
            "recovery governance test must remain dry-run"
        )

    def unblock_ip(self, _ip):
        raise AssertionError(
            "recovery governance test must remain dry-run"
        )

    def rule_exists(self, _ip):
        return False


def _sha(path):
    return sha256_file(path)


def _analyzer_database(path):
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    ensure_schema(conn)

    create_user(
        conn,
        "admin-one",
        "correct-horse-battery",
        "ADMINISTRATOR",
        user_id="user-admin-one",
    )
    create_user(
        conn,
        "admin-two",
        "correct-horse-battery",
        "ADMINISTRATOR",
        user_id="user-admin-two",
    )

    session = create_session(
        conn,
        "user-admin-one",
        ttl_seconds=3600,
        token_factory=lambda: (
            "session-token-"
            + "a" * 48
        ),
    )

    conn.execute(
        """
        INSERT INTO collectors(
            collector_id,
            hostname,
            status,
            credential_fingerprint
        ) VALUES (?, ?, 'ENROLLED', ?)
        """,
        (
            "collector-s14",
            "S14-HOST",
            "f" * 64,
        ),
    )

    conn.execute(
        """
        INSERT INTO incidents(
            incident_id,
            title,
            threat_type,
            hostname,
            source_ip,
            severity,
            lifecycle_status,
            status,
            timestamp,
            opened_at,
            updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "INC-S14",
            "S14 recovery incident",
            "Brute Force Attack",
            "S14-HOST",
            "8.8.8.8",
            "HIGH",
            "OPEN",
            "PENDING",
            "2026-09-25T04:00:00Z",
            "2026-09-25T04:00:00Z",
            "2026-09-25T04:00:00Z",
        ),
    )
    conn.commit()

    engine = SoarEngine(
        conn,
        NoLiveFirewall(),
        ResponsePolicy(
            {
                "soar_mode": "MANUAL",
                "soar_dry_run": "true",
                "soar_allowlist": "[]",
            },
            self_ips={
                "192.0.2.200",
            },
        ),
    )

    action = engine.request_block(
        {
            "incident_id": "INC-S14",
            "log_id": "LOG-S14",
            "hostname": "S14-HOST",
            "source_ip": "8.8.8.8",
            "severity": "HIGH",
            "threat_score": 90,
            "threat_type": "Brute Force Attack",
        },
        requested_by_user_id=(
            "user-admin-one"
        ),
    )

    assert (
        action["status"]
        == "PENDING_APPROVAL"
    )

    record_audit_event(
        conn,
        actor_type="USER",
        actor_user_id="user-admin-one",
        action="RECOVERY.TEST",
        outcome="SUCCESS",
        target_type="INCIDENT",
        target_id="INC-S14",
        details={
            "purpose": "S14 backup evidence",
        },
    )

    payload = {
        "batch_id": "s14-processing-batch",
        "collector_id": "collector-s14",
        "hostname": "S14-HOST",
        "logs": [
            {
                "record_id": 9001,
                "event_type": "FAILED_LOGIN",
                "raw_log": "durable pending event",
            }
        ],
    }

    inserted, state = (
        persist_collector_batch(
            conn,
            payload,
            "192.0.2.10",
        )
    )
    assert inserted is True
    assert state == "QUEUED"

    claimed = claim_next_collector_batch(
        conn
    )
    assert claimed is not None

    conn.close()

    return {
        "session_token": session["token"],
        "response_action_id": action["id"],
    }


def _collector_state(path):
    state = CollectorState(
        path,
        credential_protector=FakeProtector(),
    )

    collector_id = (
        state.get_or_create_collector_id()
    )
    state.store_collector_credential(
        "collector-secret-value"
    )
    state.initialize_checkpoint(
        8800
    )

    state.enqueue(
        {
            "batch_id": "local-sensitive-batch",
            "collector_id": collector_id,
            "hostname": "S14-HOST",
            "logs": [
                {
                    "raw_log": "customer event body",
                }
            ],
        },
        8801,
    )

    return collector_id


def _collector_config(path):
    key_file = (
        path.parent
        / "client.key"
    )
    certificate_file = (
        path.parent
        / "client.crt"
    )

    key_file.write_text(
        "PRIVATE-KEY-CONTENT-MUST-NOT-BE-BACKED-UP",
        encoding="utf-8",
    )
    certificate_file.write_text(
        "CERTIFICATE-CONTENT-MUST-NOT-BE-BACKED-UP",
        encoding="utf-8",
    )

    path.write_text(
        json.dumps(
            {
                "collector_ingest_url": (
                    "https://127.0.0.1:5443/api/collector/v1/batches"
                ),
                "collector_enrollment_url": (
                    "https://127.0.0.1:5443/api/collector/v1/enroll"
                ),
                "collector_auth_required": True,
                "collector_mtls_required": True,
                "collector_state_file": "collector_state.db",
                "collector_client_certificate": str(
                    certificate_file
                ),
                "collector_client_key": str(
                    key_file
                ),
                "ca_bundle": str(
                    path.parent
                    / "ca.crt"
                ),
                "raw_output_enabled": False,
                "unexpected_future_secret": "must-not-copy",
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    return key_file, certificate_file


def _ml_registry(root):
    version = (
        root
        / "aegis-threat-classifier"
        / "1.0.0"
    )
    version.mkdir(
        parents=True
    )

    model = (
        version
        / "model.joblib"
    )
    encoder = (
        version
        / "encoder.joblib"
    )

    model.write_bytes(
        b"S14-model-artifact"
    )
    encoder.write_bytes(
        b"S14-encoder-artifact"
    )

    metadata = {
        "model_name": "aegis-threat-classifier",
        "model_version": "1.0.0",
        "feature_schema_version": "legacy-18-v1",
        "model_sha256": _sha(model),
        "encoder_sha256": _sha(encoder),
        "stage": "PROMOTED",
    }

    (
        version
        / "metadata.json"
    ).write_text(
        json.dumps(
            metadata
        ),
        encoding="utf-8",
    )

    (
        root
        / "aegis-threat-classifier"
        / "active.json"
    ).write_text(
        json.dumps(
            {
                "model_name": "aegis-threat-classifier",
                "model_version": "1.0.0",
                "approved_by": "security-lead",
                "approved_at": "2026-09-25T04:00:00Z",
            }
        ),
        encoding="utf-8",
    )


@pytest.fixture()
def source_state(tmp_path):
    source = (
        tmp_path
        / "source"
    )
    source.mkdir()

    analyzer = (
        source
        / "aegisguard.db"
    )
    runtime = _analyzer_database(
        analyzer
    )

    collector = (
        source
        / "collector"
    )
    collector.mkdir()

    config = (
        collector
        / "config.json"
    )
    key_file, certificate_file = (
        _collector_config(
            config
        )
    )

    state_path = (
        collector
        / "collector_state.db"
    )
    collector_id = (
        _collector_state(
            state_path
        )
    )

    ml_registry = (
        source
        / "ml_registry"
    )
    _ml_registry(
        ml_registry
    )

    return {
        "analyzer": analyzer,
        "config": config,
        "state": state_path,
        "ml_registry": ml_registry,
        "key_file": key_file,
        "certificate_file": certificate_file,
        "collector_id": collector_id,
        "runtime": runtime,
    }


def _make_backup(tmp_path, source_state):
    backup = (
        tmp_path
        / "enterprise-state.zip"
    )

    result = create_backup(
        output=backup,
        analyzer_db=source_state[
            "analyzer"
        ],
        collector_config=source_state[
            "config"
        ],
        collector_state=source_state[
            "state"
        ],
        ml_registry=source_state[
            "ml_registry"
        ],
    )

    assert backup.is_file()
    assert (
        len(
            result[
                "archive_sha256"
            ]
        )
        == 64
    )

    return backup


def test_backup_is_verified_and_excludes_transient_secrets_and_customer_spool(
    tmp_path,
    source_state,
):
    backup = _make_backup(
        tmp_path,
        source_state,
    )

    verified = verify_backup(
        backup
    )

    assert verified["valid"] is True

    with zipfile.ZipFile(
        backup,
        "r",
    ) as archive:
        names = set(
            archive.namelist()
        )
        combined = b"".join(
            archive.read(name)
            for name in names
            if not name.endswith(
                ".db"
            )
        )

        assert not any(
            name.lower().endswith(
                (
                    ".key",
                    ".pem",
                    ".pfx",
                    ".p12",
                    ".crt",
                    ".cer",
                )
            )
            for name in names
        )

        assert (
            b"PRIVATE-KEY-CONTENT-MUST-NOT-BE-BACKED-UP"
            not in combined
        )
        assert (
            b"CERTIFICATE-CONTENT-MUST-NOT-BE-BACKED-UP"
            not in combined
        )
        config_bytes = archive.read(
            "payload/collector/config.json"
        )

        # The manifest may record the *name* of an omitted key as
        # non-secret omission evidence. The backed-up config itself must
        # not contain that unapproved key or its value.
        assert (
            b"unexpected_future_secret"
            not in config_bytes
        )
        assert (
            b"must-not-copy"
            not in combined
        )

        analyzer_bytes = archive.read(
            "payload/analyzer/aegisguard.db"
        )
        analyzer_copy = (
            tmp_path
            / "analyzer-copy.db"
        )
        analyzer_copy.write_bytes(
            analyzer_bytes
        )

        collector_bytes = archive.read(
            "payload/collector/collector_state.db"
        )
        collector_copy = (
            tmp_path
            / "collector-copy.db"
        )
        collector_copy.write_bytes(
            collector_bytes
        )

    conn = sqlite3.connect(
        str(
            analyzer_copy
        )
    )
    try:
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM sessions"
            ).fetchone()[0]
            == 0
        )
    finally:
        conn.close()

    conn = sqlite3.connect(
        str(
            collector_copy
        )
    )
    try:
        keys = {
            row[0]
            for row in conn.execute(
                "SELECT key FROM collector_state"
            ).fetchall()
        }

        assert (
            "collector_id"
            in keys
        )
        assert not any(
            "credential"
            in key
            for key in keys
        )
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM outbound_batches"
            ).fetchone()[0]
            == 0
        )
    finally:
        conn.close()


def test_backup_verification_rejects_tampered_payload(
    tmp_path,
    source_state,
):
    backup = _make_backup(
        tmp_path,
        source_state,
    )

    tampered = (
        tmp_path
        / "tampered.zip"
    )

    with zipfile.ZipFile(
        backup,
        "r",
    ) as source:
        with zipfile.ZipFile(
            tampered,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as target:
            for info in source.infolist():
                data = source.read(
                    info.filename
                )
                if (
                    info.filename
                    == "payload/collector/config.json"
                ):
                    data += b"\nTAMPERED"
                target.writestr(
                    info.filename,
                    data,
                )

    with pytest.raises(
        BackupIntegrityError,
        match="hash mismatch|size mismatch",
    ):
        verify_backup(
            tampered
        )


def test_restore_plan_is_non_mutating(
    tmp_path,
    source_state,
):
    backup = _make_backup(
        tmp_path,
        source_state,
    )

    target = (
        tmp_path
        / "fresh"
    )

    result = restore_backup(
        backup=backup,
        analyzer_db=target / "aegisguard.db",
        collector_config=target / "collector" / "config.json",
        collector_state=target / "collector" / "collector_state.db",
        ml_registry=target / "ml_registry",
    )

    assert (
        result["status"]
        == "VERIFIED_PLAN_ONLY"
    )

    assert not target.exists()


def test_restore_recovers_enterprise_state_and_preserves_governance(
    tmp_path,
    source_state,
):
    backup = _make_backup(
        tmp_path,
        source_state,
    )

    target = (
        tmp_path
        / "restored"
    )

    analyzer = (
        target
        / "aegisguard.db"
    )
    config = (
        target
        / "collector"
        / "config.json"
    )
    state = (
        target
        / "collector"
        / "collector_state.db"
    )
    ml_registry = (
        target
        / "ml_registry"
    )

    result = restore_backup(
        backup=backup,
        analyzer_db=analyzer,
        collector_config=config,
        collector_state=state,
        ml_registry=ml_registry,
        apply=True,
        services_stopped=True,
    )

    assert (
        result["status"]
        == "RESTORED"
    )

    conn = sqlite3.connect(
        str(
            analyzer
        )
    )
    conn.row_factory = sqlite3.Row

    try:
        assert (
            conn.execute(
                """
                SELECT COUNT(*)
                FROM incidents
                WHERE incident_id = 'INC-S14'
                """
            ).fetchone()[0]
            == 1
        )

        assert (
            conn.execute(
                "SELECT COUNT(*) FROM sessions"
            ).fetchone()[0]
            == 0
        )

        audit = verify_audit_chain(
            conn
        )
        assert audit["valid"] is True

        action_id = (
            source_state[
                "runtime"
            ][
                "response_action_id"
            ]
        )

        engine = SoarEngine(
            conn,
            NoLiveFirewall(),
            ResponsePolicy(
                {
                    "soar_mode": "MANUAL",
                    "soar_dry_run": "true",
                    "soar_allowlist": "[]",
                },
                self_ips={
                    "192.0.2.200",
                },
            ),
        )

        restored_action = (
            engine.get_action(
                action_id
            )
        )

        assert (
            restored_action[
                "status"
            ]
            == "PENDING_APPROVAL"
        )

        with pytest.raises(
            ApprovalDeniedError,
            match="cannot approve",
        ):
            engine.approve(
                action_id,
                approved_by_user_id=(
                    "user-admin-one"
                ),
            )

        approved = engine.approve(
            action_id,
            approved_by_user_id=(
                "user-admin-two"
            ),
        )

        assert (
            approved["status"]
            == "DRY_RUN"
        )

        same = engine.approve(
            action_id,
            approved_by_user_id=(
                "user-admin-two"
            ),
        )

        assert (
            same["status"]
            == "DRY_RUN"
        )
    finally:
        conn.close()

    conn = sqlite3.connect(
        str(
            state
        )
    )
    try:
        values = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT key, value FROM collector_state"
            ).fetchall()
        }
        assert (
            values[
                "collector_id"
            ]
            == source_state[
                "collector_id"
            ]
        )
        assert (
            values[
                "last_acked_record_id"
            ]
            == "8800"
        )
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM outbound_batches"
            ).fetchone()[0]
            == 0
        )
    finally:
        conn.close()

    assert (
        ml_registry
        / "aegis-threat-classifier"
        / "1.0.0"
        / "model.joblib"
    ).is_file()

    restored_config = json.loads(
        config.read_text(
            encoding="utf-8"
        )
    )

    assert (
        "unexpected_future_secret"
        not in restored_config
    )


def test_restored_analyzer_restarts_ready_and_recovers_interrupted_ingest(
    tmp_path,
    source_state,
):
    backup = _make_backup(
        tmp_path,
        source_state,
    )

    target = (
        tmp_path
        / "restart"
    )

    analyzer = (
        target
        / "aegisguard.db"
    )

    restore_backup(
        backup=backup,
        analyzer_db=analyzer,
        collector_config=target / "collector" / "config.json",
        collector_state=target / "collector" / "collector_state.db",
        ml_registry=target / "ml_registry",
        apply=True,
        services_stopped=True,
    )

    def connection_factory():
        connection = sqlite3.connect(
            str(
                analyzer
            )
        )
        connection.row_factory = sqlite3.Row
        return connection

    readiness = probe_analyzer_readiness(
        connection_factory,
        analyzer.parent,
    )

    assert (
        readiness["status"]
        == "ready"
    )

    conn = connection_factory()
    try:
        state_before = conn.execute(
            """
            SELECT state
            FROM collector_ingest_batches
            WHERE batch_id = ?
            """,
            (
                "s14-processing-batch",
            ),
        ).fetchone()[0]

        assert (
            state_before
            == "PROCESSING"
        )

        recovered = (
            recover_processing_collector_batches(
                conn
            )
        )
        assert recovered == 1

        state_after = conn.execute(
            """
            SELECT state
            FROM collector_ingest_batches
            WHERE batch_id = ?
            """,
            (
                "s14-processing-batch",
            ),
        ).fetchone()[0]

        assert (
            state_after
            == "QUEUED"
        )
    finally:
        conn.close()


def test_corrupt_audit_chain_blocks_backup_creation(
    tmp_path,
    source_state,
):
    conn = sqlite3.connect(
        str(
            source_state[
                "analyzer"
            ]
        )
    )
    try:
        conn.execute(
            """
            UPDATE audit_events
            SET event_hash = ?
            WHERE chain_sequence = 1
            """,
            (
                "0" * 64,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(
        BackupIntegrityError,
        match="audit chain is invalid",
    ):
        create_backup(
            output=(
                tmp_path
                / "invalid.zip"
            ),
            analyzer_db=source_state[
                "analyzer"
            ],
            collector_config=source_state[
                "config"
            ],
            collector_state=source_state[
                "state"
            ],
            ml_registry=source_state[
                "ml_registry"
            ],
        )


def test_incomplete_restore_transaction_can_recover_original_target(
    tmp_path,
):
    target = (
        tmp_path
        / "aegisguard.db"
    )
    target.write_bytes(
        b"partially-restored"
    )

    transaction = (
        tmp_path
        / "transaction"
    )
    original = (
        transaction
        / "original"
        / "analyzer_database"
    )
    original.parent.mkdir(
        parents=True
    )
    original.write_bytes(
        b"original-state"
    )

    metadata = {
        "schema_version": 1,
        "backup_id": "AGB-S14TEST",
        "phase": "APPLYING",
        "snapshot": [
            {
                "label": "analyzer_database",
                "kind": "file",
                "target": str(
                    target.resolve()
                ),
                "existed": True,
                "recovery_path": str(
                    original.resolve()
                ),
            }
        ],
        "targets": [],
    }

    (
        transaction
        / "transaction.json"
    ).write_text(
        json.dumps(
            metadata
        ),
        encoding="utf-8",
    )

    recovered = (
        recover_interrupted_restore(
            transaction
        )
    )

    assert (
        recovered["phase"]
        == "RECOVERED_INTERRUPTED_RESTORE"
    )
    assert (
        target.read_bytes()
        == b"original-state"
    )
