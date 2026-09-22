import sqlite3
import tempfile
import unittest
from pathlib import Path

import requests
from flask import Flask

from backend.analyzer.collector_api import create_collector_blueprint
from backend.analyzer.ingest_pipeline import (
    IngestDependencies,
    process_collector_payload,
)
from backend.analyzer.ingest_worker import CollectorIngestWorker
from backend.collector.durable_runtime import DurableCollectorRuntime
from backend.collector.state import CollectorState
from backend.storage.collector_ingest import (
    claim_next_collector_batch,
    recover_processing_collector_batches,
)
from backend.storage.migrations import ensure_platform_schema


class _Clock:
    def __init__(self, value=1000.0):
        self.value = float(value)

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += float(seconds)


class _ResponseAdapter:
    def __init__(self, response):
        self._response = response
        self.status_code = response.status_code

    def json(self):
        return self._response.get_json()


class _FakeConnection:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class _AnalyzerHarness:
    def __init__(self):
        self.stored = set()
        self.classified_batches = []
        self.inserted_batches = []
        self.endpoint_calls = []
        self.incident_calls = []
        self.connections = []

        self.dependencies = IngestDependencies(
            build_log_identity=self.identity,
            get_existing_log_ids=self.existing,
            classify_records=self.classify,
            insert_new_security_logs=self.insert,
            record_collector_endpoint=self.record_endpoint,
            get_connection=self.connection,
            scan_and_generate_incidents=self.scan_incidents,
        )

    @staticmethod
    def identity(log):
        return (
            f"windows:{str(log['hostname']).lower()}:"
            f"{int(log['record_id'])}"
        )

    def existing(self, logs):
        return {
            self.identity(log)
            for log in logs
            if self.identity(log) in self.stored
        }

    def classify(self, logs):
        batch = [dict(log) for log in logs]
        self.classified_batches.append(batch)
        for log in batch:
            log["ml_prediction"] = "TEST_DETECTION"
        return batch

    def insert(self, logs):
        batch = [dict(log) for log in logs]
        self.inserted_batches.append(batch)
        inserted = []
        for log in batch:
            log_id = self.identity(log)
            if log_id in self.stored:
                continue
            self.stored.add(log_id)
            item = dict(log)
            item["log_id"] = log_id
            inserted.append(item)
        return inserted

    def record_endpoint(self, host, ip):
        self.endpoint_calls.append((host, ip))

    def connection(self):
        conn = _FakeConnection()
        self.connections.append(conn)
        return conn

    def scan_incidents(self, conn):
        self.incident_calls.append(conn)
        return 1


class S2BDurabilityEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.server_db = root / "server.db"
        self.collector_db = root / "collector-state.db"

        def connection_factory():
            conn = sqlite3.connect(str(self.server_db), timeout=30)
            ensure_platform_schema(conn)
            return conn

        self.connection_factory = connection_factory

        app = Flask(__name__)
        app.register_blueprint(
            create_collector_blueprint(self.connection_factory)
        )
        app.testing = True
        self.client = app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def server_batch_row(self, batch_id):
        conn = self.connection_factory()
        try:
            return conn.execute(
                """
                SELECT batch_id, state, attempts, event_count, max_record_id
                FROM collector_ingest_batches
                WHERE batch_id = ?
                """,
                (batch_id,),
            ).fetchone()
        finally:
            conn.close()

    def server_batch_count(self):
        conn = self.connection_factory()
        try:
            return conn.execute(
                "SELECT COUNT(*) FROM collector_ingest_batches"
            ).fetchone()[0]
        finally:
            conn.close()

    def make_http_sender(self, response_bodies, lose_first_ack=False):
        calls = {"count": 0}

        def sender(_url, payload, **_kwargs):
            response = self.client.post(
                "/api/collector/v1/batches",
                json=payload,
                headers={
                    "X-AegisGuard-Collector-ID": payload["collector_id"],
                    "X-AegisGuard-Batch-ID": payload["batch_id"],
                },
            )
            response_bodies.append(response.get_json())
            calls["count"] += 1

            if lose_first_ack and calls["count"] == 1:
                raise requests.RequestException("simulated lost durable ACK")

            return _ResponseAdapter(response)

        return sender

    def make_runtime(self, sender, clock):
        state = CollectorState(self.collector_db)
        state.initialize_checkpoint(100)

        runtime = DurableCollectorRuntime(
            state,
            "https://siem.example.test/api/collector/v1/batches",
            hostname="HOST01",
            os_name="Windows-11",
            sender=sender,
            retry_base_seconds=2,
            retry_max_seconds=8,
            retry_jitter_ratio=0,
            clock=clock,
        )
        return state, runtime

    @staticmethod
    def event(record_id):
        return {
            "record_id": int(record_id),
            "event_type": "FAILED_LOGIN",
            "user": "alice",
            "source_ip": "10.10.10.8",
            "destination_ip": "10.10.10.20",
            "severity": "HIGH",
            "raw_log": f"failed login record {record_id}",
        }

    def test_lost_ack_retry_then_worker_processes_batch_once(self):
        clock = _Clock(1000)
        response_bodies = []
        sender = self.make_http_sender(
            response_bodies,
            lose_first_ack=True,
        )
        collector_state, runtime = self.make_runtime(sender, clock)
        analyzer = _AnalyzerHarness()

        batch_id = runtime.enqueue_logs([self.event(101)], [101])

        self.assertEqual(len(collector_state.pending()), 1)
        self.assertEqual(collector_state.get_checkpoint(), 100)
        self.assertEqual(self.server_batch_count(), 0)

        self.assertFalse(runtime.flush_pending())
        self.assertEqual(self.server_batch_count(), 1)
        row = self.server_batch_row(batch_id)
        self.assertEqual(row[1], "QUEUED")
        self.assertEqual(row[3], 1)
        self.assertEqual(row[4], 101)
        self.assertEqual(collector_state.get_checkpoint(), 100)
        self.assertEqual(len(collector_state.pending()), 1)
        self.assertFalse(response_bodies[0]["duplicate"])

        self.assertEqual(analyzer.classified_batches, [])
        self.assertEqual(analyzer.incident_calls, [])

        clock.advance(2)
        self.assertTrue(runtime.flush_pending())
        self.assertEqual(self.server_batch_count(), 1)
        self.assertEqual(len(response_bodies), 2)
        self.assertTrue(response_bodies[1]["duplicate"])
        self.assertEqual(response_bodies[1]["batch_id"], batch_id)
        self.assertEqual(collector_state.pending(), [])
        self.assertEqual(collector_state.get_checkpoint(), 101)
        self.assertEqual(runtime.health_snapshot()["status"], "HEALTHY")

        def processor(payload, peer_ip):
            return process_collector_payload(
                payload,
                peer_ip,
                dependencies=analyzer.dependencies,
            )

        worker = CollectorIngestWorker(
            self.connection_factory,
            processor,
        )
        result = worker.run_once()

        self.assertEqual(result["batch_id"], batch_id)
        self.assertEqual(result["state"], "PROCESSED")
        self.assertEqual(result["attempts"], 1)
        self.assertEqual(result["result"]["new_logs_added"], 1)
        self.assertEqual(result["result"]["incidents_created"], 1)
        self.assertIsNone(worker.run_once())

        row = self.server_batch_row(batch_id)
        self.assertEqual(row[1], "PROCESSED")
        self.assertEqual(row[2], 1)
        self.assertEqual(len(analyzer.classified_batches), 1)
        self.assertEqual(len(analyzer.inserted_batches), 1)
        self.assertEqual(len(analyzer.incident_calls), 1)
        self.assertEqual(len(analyzer.stored), 1)

    def test_worker_crash_recovery_replay_is_effectively_exactly_once(self):
        clock = _Clock(2000)
        response_bodies = []
        sender = self.make_http_sender(response_bodies)
        _collector_state, runtime = self.make_runtime(sender, clock)
        analyzer = _AnalyzerHarness()

        batch_id = runtime.enqueue_logs([self.event(102)], [102])
        self.assertTrue(runtime.flush_pending())
        self.assertEqual(self.server_batch_row(batch_id)[1], "QUEUED")

        conn = self.connection_factory()
        try:
            claimed = claim_next_collector_batch(conn)
        finally:
            conn.close()

        self.assertEqual(claimed["batch_id"], batch_id)
        self.assertEqual(claimed["attempts"], 1)
        self.assertEqual(self.server_batch_row(batch_id)[1], "PROCESSING")

        first = process_collector_payload(
            claimed["payload"],
            claimed["peer_ip"],
            dependencies=analyzer.dependencies,
        )
        self.assertEqual(first["new_logs_added"], 1)
        self.assertEqual(first["incidents_created"], 1)
        self.assertEqual(len(analyzer.stored), 1)

        conn = self.connection_factory()
        try:
            recovered = recover_processing_collector_batches(conn)
        finally:
            conn.close()

        self.assertEqual(recovered, 1)
        self.assertEqual(self.server_batch_row(batch_id)[1], "QUEUED")

        def processor(payload, peer_ip):
            return process_collector_payload(
                payload,
                peer_ip,
                dependencies=analyzer.dependencies,
            )

        worker = CollectorIngestWorker(
            self.connection_factory,
            processor,
        )
        replay = worker.run_once()

        self.assertEqual(replay["state"], "PROCESSED")
        self.assertEqual(replay["attempts"], 2)
        self.assertEqual(replay["result"]["new_logs_added"], 0)
        self.assertEqual(replay["result"]["incidents_created"], 0)

        row = self.server_batch_row(batch_id)
        self.assertEqual(row[1], "PROCESSED")
        self.assertEqual(row[2], 2)
        self.assertEqual(len(analyzer.classified_batches), 1)
        self.assertEqual(len(analyzer.inserted_batches), 2)
        self.assertEqual(len(analyzer.inserted_batches[0]), 1)
        self.assertEqual(analyzer.inserted_batches[1], [])
        self.assertEqual(len(analyzer.incident_calls), 1)
        self.assertEqual(len(analyzer.stored), 1)


if __name__ == "__main__":
    unittest.main()
