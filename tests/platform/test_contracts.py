import unittest

from backend.platform.contracts import (
    Asset,
    AuditEvent,
    CanonicalEvent,
    CollectorIdentity,
    Incident,
    IncidentLifecycleStatus,
    ResponseAction,
    ResponseActionStatus,
    Role,
)


class PlatformContractTests(unittest.TestCase):
    def test_core_contracts_construct(self):
        event = CanonicalEvent(
            event_id="evt-1",
            observed_at="2026-09-21T00:00:00Z",
            event_type="windows.security.4625",
        )
        collector = CollectorIdentity(
            collector_id="collector-1",
            hostname="host-a",
        )
        asset = Asset(asset_id="asset-1", hostname="host-a")
        incident = Incident(
            incident_id="inc-1",
            title="Multiple failed logons",
            lifecycle_status=IncidentLifecycleStatus.OPEN,
        )
        audit = AuditEvent(
            audit_id="audit-1",
            timestamp="2026-09-21T00:00:00Z",
            action="INCIDENT_CREATED",
            outcome="SUCCESS",
        )
        action = ResponseAction(
            action_id="resp-1",
            incident_id=incident.incident_id,
            action_type="BLOCK_IP",
            target="203.0.113.10",
            status=ResponseActionStatus.PENDING,
        )

        self.assertEqual(event.event_id, "evt-1")
        self.assertEqual(collector.collector_id, "collector-1")
        self.assertEqual(asset.hostname, "host-a")
        self.assertEqual(incident.lifecycle_status, IncidentLifecycleStatus.OPEN)
        self.assertEqual(audit.outcome, "SUCCESS")
        self.assertEqual(action.status, ResponseActionStatus.PENDING)
        self.assertEqual(Role.ADMINISTRATOR.value, "ADMINISTRATOR")

    def test_required_identifiers_reject_empty_values(self):
        with self.assertRaises(ValueError):
            CollectorIdentity(collector_id="", hostname="host-a")

        with self.assertRaises(ValueError):
            CanonicalEvent(
                event_id="evt-1",
                observed_at="",
                event_type="test",
            )


if __name__ == "__main__":
    unittest.main()
