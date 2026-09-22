import unittest

from backend.analyzer.ingest_pipeline import (
    IngestDependencies,
    normalize_collector_payload,
    process_collector_payload,
)
from backend.analyzer.ingest_worker import build_default_ingest_worker


class _FakeConnection:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class SharedIngestPipelineTests(unittest.TestCase):
    def test_normalize_preserves_collector_identity_and_aliases(self):
        machine_id, logs = normalize_collector_payload({
            "collector_id": "collector-1",
            "hostname": "HOST01",
            "os": "Windows",
            "logs": [{
                "RecordId": 101,
                "Id": 4625,
                "TimeCreated": "2026-09-21T10:00:00",
                "MachineName": "HOST01",
                "User": "alice",
                "SourceIp": "10.0.0.8",
                "Message": "failed login",
            }],
        })

        self.assertEqual(machine_id, "HOST01")
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["record_id"], 101)
        self.assertEqual(logs[0]["event_type"], "4625")
        self.assertEqual(logs[0]["user"], "alice")
        self.assertEqual(logs[0]["source_ip"], "10.0.0.8")

    def test_normalize_rejects_non_list_logs(self):
        with self.assertRaisesRegex(ValueError, "'logs' must be a list"):
            normalize_collector_payload({
                "hostname": "HOST01",
                "logs": {"record_id": 101},
            })

    def test_duplicate_events_are_not_reclassified_or_reinserted(self):
        stored = {"windows:host01:100"}
        classified_batches = []
        inserted_batches = []
        endpoint_calls = []
        incident_calls = []
        connections = []

        def identity(log):
            return f"windows:{str(log['hostname']).lower()}:{log['record_id']}"

        def existing(logs):
            return {identity(log) for log in logs if identity(log) in stored}

        def classify(logs):
            logs = [dict(log) for log in logs]
            classified_batches.append(logs)
            for log in logs:
                log["ml_prediction"] = "BRUTE_FORCE"
            return logs

        def insert(logs):
            inserted = []
            inserted_batches.append([dict(log) for log in logs])
            for log in logs:
                log_id = identity(log)
                if log_id in stored:
                    continue
                stored.add(log_id)
                item = dict(log)
                item["log_id"] = log_id
                inserted.append(item)
            return inserted

        def connection():
            conn = _FakeConnection()
            connections.append(conn)
            return conn

        deps = IngestDependencies(
            build_log_identity=identity,
            get_existing_log_ids=existing,
            classify_records=classify,
            insert_new_security_logs=insert,
            record_collector_endpoint=lambda host, ip: endpoint_calls.append(
                (host, ip)
            ),
            get_connection=connection,
            scan_and_generate_incidents=lambda conn: incident_calls.append(conn) or 1,
        )

        payload = {
            "hostname": "HOST01",
            "os": "Windows",
            "logs": [
                {"record_id": 100, "event_type": "FAILED_LOGIN"},
                {"record_id": 101, "event_type": "FAILED_LOGIN"},
                {"record_id": 101, "event_type": "FAILED_LOGIN"},
            ],
        }

        first = process_collector_payload(
            payload,
            collector_ip="10.20.30.40",
            dependencies=deps,
        )
        self.assertEqual(first["logs_received"], 3)
        self.assertEqual(first["new_logs_added"], 1)
        self.assertEqual(first["incidents_created"], 1)
        self.assertEqual(first["inserted_log_ids"], ["windows:host01:101"])
        self.assertEqual(len(classified_batches), 1)
        self.assertEqual(len(classified_batches[0]), 1)
        self.assertEqual(len(inserted_batches), 1)
        self.assertEqual(len(incident_calls), 1)
        self.assertTrue(connections[0].closed)
        self.assertEqual(endpoint_calls, [("HOST01", "10.20.30.40")])

        second = process_collector_payload(
            payload,
            collector_ip="10.20.30.40",
            dependencies=deps,
        )
        self.assertEqual(second["new_logs_added"], 0)
        self.assertEqual(second["incidents_created"], 0)
        self.assertEqual(second["inserted_log_ids"], [])
        self.assertEqual(len(classified_batches), 1)
        self.assertEqual(len(incident_calls), 1)

    def test_pipeline_exception_is_not_hidden_from_worker(self):
        deps = IngestDependencies(
            build_log_identity=lambda log: str(log["record_id"]),
            get_existing_log_ids=lambda logs: set(),
            classify_records=lambda logs: (_ for _ in ()).throw(
                RuntimeError("classifier unavailable")
            ),
            insert_new_security_logs=lambda logs: [],
            record_collector_endpoint=lambda host, ip: None,
            get_connection=lambda: _FakeConnection(),
            scan_and_generate_incidents=lambda conn: 0,
        )

        with self.assertRaisesRegex(RuntimeError, "classifier unavailable"):
            process_collector_payload(
                {
                    "hostname": "HOST01",
                    "logs": [{"record_id": 101, "event_type": "FAILED_LOGIN"}],
                },
                dependencies=deps,
            )

    def test_default_worker_uses_shared_non_flask_processor(self):
        worker = build_default_ingest_worker(lambda: None)

        from backend.analyzer.ingest_pipeline import process_collector_payload

        self.assertIs(worker.processor, process_collector_payload)


if __name__ == "__main__":
    unittest.main()
