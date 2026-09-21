"""Pure deterministic rule detection for AegisGuard Enterprise."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Iterable

from .contracts import CanonicalEvent, DetectionFinding, DetectionType, Severity


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    name: str
    severity: Severity
    classification_label: str
    reason: str


_RULES = {
    "FAILED_LOGIN": RuleSpec(
        "AG-RULE-AUTH-001",
        "Failed authentication",
        Severity.HIGH,
        "BRUTE_FORCE",
        "Authentication failure matched the deterministic failed-login rule.",
    ),
    "AUTHENTICATION_FAILURE": RuleSpec(
        "AG-RULE-AUTH-001",
        "Failed authentication",
        Severity.HIGH,
        "BRUTE_FORCE",
        "Authentication failure matched the deterministic failed-login rule.",
    ),
    "DEFENDER_ALERT": RuleSpec(
        "AG-RULE-MALWARE-001",
        "Endpoint malware alert",
        Severity.CRITICAL,
        "MALWARE",
        "Endpoint protection generated a deterministic malware alert.",
    ),
    "PRIVILEGE_ESCALATION": RuleSpec(
        "AG-RULE-PRIV-001",
        "Privilege escalation activity",
        Severity.CRITICAL,
        "PRIVILEGE_ESCALATION",
        "Privilege escalation activity matched the deterministic privilege rule.",
    ),
    "SUDO_COMMAND": RuleSpec(
        "AG-RULE-PRIV-001",
        "Privilege escalation activity",
        Severity.CRITICAL,
        "PRIVILEGE_ESCALATION",
        "Privileged command activity matched the deterministic privilege rule.",
    ),
    "SUDO_EXECUTED": RuleSpec(
        "AG-RULE-PRIV-001",
        "Privilege escalation activity",
        Severity.CRITICAL,
        "PRIVILEGE_ESCALATION",
        "Privileged command activity matched the deterministic privilege rule.",
    ),
}


def _finding_id(rule_id: str, event_id: str) -> str:
    digest = sha256(f"{rule_id}|{event_id}".encode("utf-8")).hexdigest()[:16].upper()
    return f"FND-RULE-{digest}"


class RuleEngine:
    """Evaluate canonical events without invoking an ML model."""

    engine_name = "rule-engine-v1"

    def detect(self, event: CanonicalEvent) -> DetectionFinding | None:
        event_type = event.event_type.upper().strip()
        spec = _RULES.get(event_type)
        if spec is None:
            return None

        return DetectionFinding(
            finding_id=_finding_id(spec.rule_id, event.event_id),
            event_ids=(event.event_id,),
            detection_type=DetectionType.RULE,
            name=spec.name,
            severity=spec.severity,
            confidence=1.0,
            reason=spec.reason,
            timestamp=event.timestamp,
            prediction_source=f"rule:{spec.rule_id}",
            source_engine=self.engine_name,
            rule_id=spec.rule_id,
            evidence=(
                {
                    "event_id": event.event_id,
                    "event_type": event_type,
                    "hostname": event.hostname,
                    "source_ip": event.source_ip,
                    "user": event.user,
                },
            ),
            metadata={"classification_label": spec.classification_label},
        )

    def detect_many(self, events: Iterable[CanonicalEvent]) -> tuple[DetectionFinding, ...]:
        findings = []
        for event in events:
            finding = self.detect(event)
            if finding is not None:
                findings.append(finding)
        return tuple(findings)
