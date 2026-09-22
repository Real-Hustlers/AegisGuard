"""Deterministic validation harness for authorized isolated AegisGuard labs.

The harness does not generate attacks, execute response actions, or write to the
Analyzer database. It validates normalized event captures against expected
AegisGuard Rule/Correlation/MITRE/Attack Story outcomes.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .service import build_intelligence_snapshot


LAB_VALIDATION_VERSION = "isolated-lab-validation-v1"


@dataclass(frozen=True)
class LabScenario:
    scenario_id: str
    name: str
    required_event_types: tuple[str, ...]
    expected_rule_ids: tuple[str, ...] = ()
    expected_correlation_ids: tuple[str, ...] = ()
    expected_technique_ids: tuple[str, ...] = ()
    expected_attack_stages: tuple[str, ...] = ()


SCENARIOS: dict[str, LabScenario] = {
    "credential-to-privilege": LabScenario(
        scenario_id="credential-to-privilege",
        name="Credential access followed by privilege escalation",
        required_event_types=(
            "FAILED_LOGIN",
            "LOGON_SUCCESS",
            "ADMIN_GROUP_ADDED",
        ),
        expected_rule_ids=("AG-RULE-AUTH-001",),
        expected_correlation_ids=(
            "AG-CORR-AUTH-001A",
            "AG-CORR-AUTH-001B",
            "AG-CORR-PRIV-001A",
        ),
        expected_technique_ids=("T1110", "T1098.007"),
        expected_attack_stages=(
            "CREDENTIAL_ACCESS",
            "PRIVILEGE_ESCALATION",
        ),
    ),
    "discovery-to-persistence": LabScenario(
        scenario_id="discovery-to-persistence",
        name="Discovery followed by account-based persistence",
        required_event_types=(
            "LOCAL_GROUP_ENUMERATION",
            "PROCESS_CREATED",
            "NETWORK_CONNECTION",
            "USER_CREATED",
            "PASSWORD_CHANGED",
            "LOGON_SUCCESS",
        ),
        expected_correlation_ids=(
            "AG-CORR-DISC-001",
            "AG-CORR-PERSIST-001",
        ),
        expected_technique_ids=("T1069.001", "T1136"),
        expected_attack_stages=("DISCOVERY", "PERSISTENCE"),
    ),
}


@dataclass(frozen=True)
class LabValidationReport:
    validation_version: str
    scenario_id: str
    scenario_name: str
    passed: bool
    events_analyzed: int
    missing_event_types: tuple[str, ...]
    missing_rule_ids: tuple[str, ...]
    missing_correlation_ids: tuple[str, ...]
    missing_technique_ids: tuple[str, ...]
    missing_attack_stages: tuple[str, ...]
    observed_rule_ids: tuple[str, ...]
    observed_correlation_ids: tuple[str, ...]
    observed_technique_ids: tuple[str, ...]
    observed_attack_stages: tuple[str, ...]
    attack_story_count: int
    governance: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "validation_version": self.validation_version,
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "passed": self.passed,
            "events_analyzed": self.events_analyzed,
            "missing_event_types": list(self.missing_event_types),
            "missing_rule_ids": list(self.missing_rule_ids),
            "missing_correlation_ids": list(self.missing_correlation_ids),
            "missing_technique_ids": list(self.missing_technique_ids),
            "missing_attack_stages": list(self.missing_attack_stages),
            "observed_rule_ids": list(self.observed_rule_ids),
            "observed_correlation_ids": list(self.observed_correlation_ids),
            "observed_technique_ids": list(self.observed_technique_ids),
            "observed_attack_stages": list(self.observed_attack_stages),
            "attack_story_count": self.attack_story_count,
            "governance": dict(self.governance),
        }


def _unique(values: Iterable[object]) -> tuple[str, ...]:
    return tuple(sorted({
        str(value).strip()
        for value in values
        if str(value or "").strip()
    }))


def normalize_lab_records(payload: object) -> list[dict[str, Any]]:
    """Normalize a JSON list or Collector-style ``{"logs": [...]}`` capture."""

    if isinstance(payload, Mapping):
        records = payload.get("logs")
    else:
        records = payload

    if not isinstance(records, list):
        raise ValueError("lab input must be a JSON list or an object containing a logs list")

    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(records, start=1):
        if not isinstance(raw, Mapping):
            raise ValueError(f"lab event {index} must be an object")

        record = dict(raw)
        event_type = str(
            record.get("event_type")
            or record.get("event")
            or record.get("EventType")
            or ""
        ).upper().strip()
        timestamp = str(
            record.get("timestamp")
            or record.get("TimeCreated")
            or ""
        ).strip()

        if not event_type:
            raise ValueError(f"lab event {index} requires event_type")
        if not timestamp:
            raise ValueError(f"lab event {index} requires timestamp")

        hostname = str(
            record.get("hostname")
            or record.get("MachineName")
            or "LAB-HOST"
        )
        record_id = (
            record.get("record_id")
            or record.get("RecordId")
            or index
        )

        normalized.append({
            "log_id": str(
                record.get("log_id")
                or record.get("event_id")
                or f"lab:{hostname.lower()}:{record_id}"
            ),
            "record_id": record_id,
            "timestamp": timestamp,
            "event_type": event_type,
            "severity": record.get("severity") or "INFO",
            "hostname": hostname,
            "source_ip": record.get("source_ip") or record.get("SourceIp"),
            "destination_ip": (
                record.get("destination_ip")
                or record.get("DestinationIp")
            ),
            "user": record.get("user") or record.get("User"),
            "process": record.get("process") or record.get("ProcessName"),
            "file_path": record.get("file_path") or record.get("FilePath"),
            "raw_log": record.get("raw_log") or record.get("Message") or event_type,
            "ml_prediction": record.get("ml_prediction"),
            "ml_confidence": record.get("ml_confidence"),
            "threat_level": record.get("threat_level"),
            "threat_score": record.get("threat_score"),
            "threat_category": record.get("threat_category"),
        })

    return normalized


def validate_lab_records(
    records: Sequence[Mapping[str, Any]],
    scenario_id: str,
) -> LabValidationReport:
    scenario = SCENARIOS.get(str(scenario_id))
    if scenario is None:
        raise ValueError(
            f"unknown lab scenario: {scenario_id}; "
            f"available={','.join(sorted(SCENARIOS))}"
        )

    normalized = normalize_lab_records(list(records))
    snapshot = build_intelligence_snapshot(normalized)

    observed_event_types = _unique(
        record.get("event_type") for record in normalized
    )
    rule_findings = snapshot["findings"]["rule"]
    correlation_findings = snapshot["findings"]["correlation"]

    observed_rule_ids = _unique(
        finding.get("rule_id") for finding in rule_findings
    )
    observed_correlation_ids = _unique(
        finding.get("correlation_id") for finding in correlation_findings
    )
    observed_technique_ids = _unique(
        mapping.get("technique_id")
        for mapping in snapshot["mitre_coverage"]
    )
    observed_attack_stages = _unique(
        stage
        for story in snapshot["attack_stories"]
        for stage in (story.get("metadata") or {}).get("attack_stages", ())
    )

    missing_event_types = tuple(
        value for value in scenario.required_event_types
        if value not in observed_event_types
    )
    missing_rule_ids = tuple(
        value for value in scenario.expected_rule_ids
        if value not in observed_rule_ids
    )
    missing_correlation_ids = tuple(
        value for value in scenario.expected_correlation_ids
        if value not in observed_correlation_ids
    )
    missing_technique_ids = tuple(
        value for value in scenario.expected_technique_ids
        if value not in observed_technique_ids
    )
    missing_attack_stages = tuple(
        value for value in scenario.expected_attack_stages
        if value not in observed_attack_stages
    )

    passed = not any((
        missing_event_types,
        missing_rule_ids,
        missing_correlation_ids,
        missing_technique_ids,
        missing_attack_stages,
    ))

    return LabValidationReport(
        validation_version=LAB_VALIDATION_VERSION,
        scenario_id=scenario.scenario_id,
        scenario_name=scenario.name,
        passed=passed,
        events_analyzed=len(normalized),
        missing_event_types=missing_event_types,
        missing_rule_ids=missing_rule_ids,
        missing_correlation_ids=missing_correlation_ids,
        missing_technique_ids=missing_technique_ids,
        missing_attack_stages=missing_attack_stages,
        observed_rule_ids=observed_rule_ids,
        observed_correlation_ids=observed_correlation_ids,
        observed_technique_ids=observed_technique_ids,
        observed_attack_stages=observed_attack_stages,
        attack_story_count=len(snapshot["attack_stories"]),
        governance=snapshot["governance"],
    )


def validate_lab_payload(payload: object, scenario_id: str) -> LabValidationReport:
    return validate_lab_records(normalize_lab_records(payload), scenario_id)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate an authorized isolated-VM event capture against AegisGuard detections."
    )
    parser.add_argument(
        "--scenario",
        required=True,
        choices=sorted(SCENARIOS),
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="JSON list or Collector-style object containing a logs list.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional JSON report path.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        payload = json.loads(args.input.read_text(encoding="utf-8"))
        report = validate_lab_payload(payload, args.scenario)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({
            "validation_version": LAB_VALIDATION_VERSION,
            "passed": False,
            "error": str(exc),
        }, indent=2))
        return 2

    rendered = json.dumps(report.to_dict(), indent=2)
    print(rendered)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")

    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
