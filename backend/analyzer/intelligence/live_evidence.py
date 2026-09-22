"""Live evidence capture for authorized isolated AegisGuard VM validation.

This module performs GET-only reads from an Analyzer. It never generates attack
traffic, changes Analyzer settings, writes the Analyzer database, approves SOAR
actions, or executes response playbooks.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import quote
from urllib.request import Request, urlopen

from .lab_validation import SCENARIOS, validate_lab_records


LIVE_EVIDENCE_VERSION = "isolated-vm-live-evidence-v1"
DEFAULT_TIMEOUT_SECONDS = 10.0
INTELLIGENCE_EVENT_LIMIT = 5000


JsonGetter = Callable[[str], Any]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_analyzer_url(value: str) -> str:
    url = str(value or "").strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        raise ValueError("analyzer_url must start with http:// or https://")
    return url


def response_safety(settings: Mapping[str, Any]) -> dict[str, Any]:
    """Require both legacy response simulation and safe SOAR behavior."""

    simulation_mode = settings.get("simulation_mode") is True
    soar_mode = str(settings.get("soar_mode") or "").upper().strip()
    soar_dry_run = settings.get("soar_dry_run") is True

    reasons = []
    if not simulation_mode:
        reasons.append("simulation_mode must be true")
    if not (soar_mode == "OFF" or soar_dry_run):
        reasons.append("SOAR must be OFF or soar_dry_run must be true")

    return {
        "safe": not reasons,
        "simulation_mode": simulation_mode,
        "soar_mode": soar_mode or None,
        "soar_dry_run": soar_dry_run,
        "reasons": reasons,
    }


def _require_safe_settings(settings: Mapping[str, Any]) -> dict[str, Any]:
    safety = response_safety(settings)
    if not safety["safe"]:
        raise RuntimeError(
            "Analyzer response controls are not safe for Y9 validation: "
            + "; ".join(safety["reasons"])
        )
    return safety


def _event_id(event: Mapping[str, Any]) -> str:
    value = event.get("id") or event.get("log_id") or event.get("event_id")
    return str(value or "").strip()


def _api_event_to_lab_event(event: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "log_id": _event_id(event),
        "record_id": event.get("record_id"),
        "timestamp": event.get("timestamp"),
        "event_type": event.get("event_type"),
        "severity": event.get("severity") or event.get("threat_level") or "INFO",
        "hostname": event.get("hostname"),
        "source_ip": event.get("source_ip") or event.get("ip"),
        "destination_ip": event.get("destination_ip"),
        "user": event.get("user"),
        "process": event.get("process"),
        "file_path": event.get("file_path"),
        "raw_log": event.get("raw_log") or event.get("event") or "",
        "ml_prediction": event.get("ml_prediction"),
        "ml_confidence": event.get("ml_confidence"),
        "threat_level": event.get("threat_level"),
        "threat_score": event.get("threat_score"),
        "threat_category": event.get("threat_category"),
    }


def _finding_matches_host(finding: Mapping[str, Any], hostname: str) -> bool:
    wanted = hostname.casefold()
    for evidence in finding.get("evidence") or ():
        if not isinstance(evidence, Mapping):
            continue
        if str(evidence.get("hostname") or "").casefold() == wanted:
            return True
    metadata = finding.get("metadata")
    return (
        isinstance(metadata, Mapping)
        and str(metadata.get("hostname") or "").casefold() == wanted
    )


def _story_matches_host(story: Mapping[str, Any], hostname: str) -> bool:
    entities = story.get("related_entities")
    if not isinstance(entities, Mapping):
        return False
    wanted = hostname.casefold()
    return any(
        str(value or "").casefold() == wanted
        for value in (entities.get("hostnames") or ())
    )


def verify_live_snapshot(
    snapshot: Mapping[str, Any],
    *,
    scenario_id: str,
    hostname: str,
) -> dict[str, Any]:
    scenario = SCENARIOS.get(scenario_id)
    if scenario is None:
        raise ValueError(f"unknown lab scenario: {scenario_id}")

    findings = snapshot.get("findings")
    if not isinstance(findings, Mapping):
        findings = {}

    rule_findings = [
        finding
        for finding in (findings.get("rule") or ())
        if isinstance(finding, Mapping)
        and _finding_matches_host(finding, hostname)
    ]
    correlation_findings = [
        finding
        for finding in (findings.get("correlation") or ())
        if isinstance(finding, Mapping)
        and _finding_matches_host(finding, hostname)
    ]

    observed_rule_ids = sorted({
        str(finding.get("rule_id"))
        for finding in rule_findings
        if finding.get("rule_id")
    })
    observed_correlation_ids = sorted({
        str(finding.get("correlation_id"))
        for finding in correlation_findings
        if finding.get("correlation_id")
    })

    observed_technique_ids = sorted({
        str(mapping.get("technique_id"))
        for finding in [*rule_findings, *correlation_findings]
        for mapping in (finding.get("mitre") or ())
        if isinstance(mapping, Mapping) and mapping.get("technique_id")
    })

    host_stories = [
        story
        for story in (snapshot.get("attack_stories") or ())
        if isinstance(story, Mapping) and _story_matches_host(story, hostname)
    ]
    observed_attack_stages = sorted({
        str(stage)
        for story in host_stories
        for stage in (
            ((story.get("metadata") or {}).get("attack_stages") or ())
            if isinstance(story.get("metadata"), Mapping)
            else ()
        )
    })

    missing_rule_ids = [
        value
        for value in scenario.expected_rule_ids
        if value not in observed_rule_ids
    ]
    missing_correlation_ids = [
        value
        for value in scenario.expected_correlation_ids
        if value not in observed_correlation_ids
    ]
    missing_technique_ids = [
        value
        for value in scenario.expected_technique_ids
        if value not in observed_technique_ids
    ]
    missing_attack_stages = [
        value
        for value in scenario.expected_attack_stages
        if value not in observed_attack_stages
    ]

    return {
        "passed": not any((
            missing_rule_ids,
            missing_correlation_ids,
            missing_technique_ids,
            missing_attack_stages,
        )),
        "hostname": hostname,
        "snapshot_scope": dict(snapshot.get("scope") or {}),
        "observed_rule_ids": observed_rule_ids,
        "observed_correlation_ids": observed_correlation_ids,
        "observed_technique_ids": observed_technique_ids,
        "observed_attack_stages": observed_attack_stages,
        "attack_story_count": len(host_stories),
        "missing_rule_ids": missing_rule_ids,
        "missing_correlation_ids": missing_correlation_ids,
        "missing_technique_ids": missing_technique_ids,
        "missing_attack_stages": missing_attack_stages,
    }


def start_capture(
    get_json: JsonGetter,
    *,
    analyzer_url: str,
    hostname: str,
) -> dict[str, Any]:
    analyzer_url = normalize_analyzer_url(analyzer_url)
    hostname = str(hostname or "").strip()
    if not hostname:
        raise ValueError("hostname is required")

    settings = get_json("/api/incidents/settings")
    if not isinstance(settings, Mapping):
        raise RuntimeError("Analyzer settings response must be a JSON object")
    safety = _require_safe_settings(settings)

    events = get_json(f"/api/events?hostname={quote(hostname, safe='')}")
    if not isinstance(events, list):
        raise RuntimeError("Analyzer events response must be a JSON list")

    event_ids = sorted({
        event_id
        for event in events
        if isinstance(event, Mapping)
        for event_id in [_event_id(event)]
        if event_id
    })

    return {
        "evidence_version": LIVE_EVIDENCE_VERSION,
        "analyzer_url": analyzer_url,
        "hostname": hostname,
        "started_at": _utc_now(),
        "existing_event_ids": event_ids,
        "existing_event_count": len(event_ids),
        "settings_before": dict(settings),
        "response_safety_before": safety,
    }


def finish_capture(
    get_json: JsonGetter,
    baseline: Mapping[str, Any],
    *,
    scenario_id: str,
) -> dict[str, Any]:
    if baseline.get("evidence_version") != LIVE_EVIDENCE_VERSION:
        raise ValueError("baseline evidence_version is not supported")

    hostname = str(baseline.get("hostname") or "").strip()
    if not hostname:
        raise ValueError("baseline hostname is missing")

    if scenario_id not in SCENARIOS:
        raise ValueError(f"unknown lab scenario: {scenario_id}")

    settings = get_json("/api/incidents/settings")
    if not isinstance(settings, Mapping):
        raise RuntimeError("Analyzer settings response must be a JSON object")
    safety = _require_safe_settings(settings)

    events = get_json(f"/api/events?hostname={quote(hostname, safe='')}")
    if not isinstance(events, list):
        raise RuntimeError("Analyzer events response must be a JSON list")

    baseline_ids = {
        str(value)
        for value in (baseline.get("existing_event_ids") or ())
        if str(value or "").strip()
    }
    new_api_events = [
        event
        for event in events
        if isinstance(event, Mapping)
        and _event_id(event)
        and _event_id(event) not in baseline_ids
    ]
    new_events = [_api_event_to_lab_event(event) for event in new_api_events]

    local_report = validate_lab_records(new_events, scenario_id)

    snapshot = get_json(
        f"/api/intelligence?event_limit={INTELLIGENCE_EVENT_LIMIT}"
    )
    if not isinstance(snapshot, Mapping):
        raise RuntimeError("Analyzer intelligence response must be a JSON object")

    live_verification = verify_live_snapshot(
        snapshot,
        scenario_id=scenario_id,
        hostname=hostname,
    )

    passed = (
        local_report.passed
        and live_verification["passed"]
        and safety["safe"]
    )

    return {
        "evidence_version": LIVE_EVIDENCE_VERSION,
        "scenario_id": scenario_id,
        "hostname": hostname,
        "analyzer_url": baseline.get("analyzer_url"),
        "started_at": baseline.get("started_at"),
        "finished_at": _utc_now(),
        "passed": passed,
        "baseline_event_count": baseline.get("existing_event_count", len(baseline_ids)),
        "new_event_count": len(new_events),
        "new_events": new_events,
        "settings_before": dict(baseline.get("settings_before") or {}),
        "settings_after": dict(settings),
        "response_safety_before": dict(
            baseline.get("response_safety_before") or {}
        ),
        "response_safety_after": safety,
        "local_validation": local_report.to_dict(),
        "live_intelligence_verification": live_verification,
        "governance": {
            "analyzer_requests_are_get_only": True,
            "changes_analyzer_settings": False,
            "writes_analyzer_database": False,
            "approves_response_actions": False,
            "executes_response_actions": False,
        },
    }


class AnalyzerClient:
    def __init__(
        self,
        analyzer_url: str,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.analyzer_url = normalize_analyzer_url(analyzer_url)
        self.timeout_seconds = float(timeout_seconds)
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")

    def get_json(self, path: str) -> Any:
        if not str(path).startswith("/"):
            raise ValueError("Analyzer path must start with /")
        request = Request(
            self.analyzer_url + path,
            method="GET",
            headers={"Accept": "application/json"},
        )
        with urlopen(request, timeout=self.timeout_seconds) as response:
            payload = response.read().decode("utf-8")
        return json.loads(payload)


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture GET-only evidence from an authorized isolated AegisGuard lab."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    start = subparsers.add_parser("start", help="Record the pre-test event baseline.")
    start.add_argument("--analyzer-url", required=True)
    start.add_argument("--hostname", required=True)
    start.add_argument("--output", required=True, type=Path)
    start.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
    )

    finish = subparsers.add_parser(
        "finish",
        help="Validate events added since a previously recorded baseline.",
    )
    finish.add_argument("--baseline", required=True, type=Path)
    finish.add_argument("--scenario", required=True, choices=sorted(SCENARIOS))
    finish.add_argument("--output", required=True, type=Path)
    finish.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)

    try:
        if args.command == "start":
            client = AnalyzerClient(
                args.analyzer_url,
                timeout_seconds=args.timeout,
            )
            payload = start_capture(
                client.get_json,
                analyzer_url=client.analyzer_url,
                hostname=args.hostname,
            )
            _write_json(args.output, payload)
            print(json.dumps(payload, indent=2))
            return 0

        baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
        if not isinstance(baseline, Mapping):
            raise ValueError("baseline file must contain a JSON object")

        client = AnalyzerClient(
            str(baseline.get("analyzer_url") or ""),
            timeout_seconds=args.timeout,
        )
        payload = finish_capture(
            client.get_json,
            baseline,
            scenario_id=args.scenario,
        )
        _write_json(args.output, payload)
        print(json.dumps(payload, indent=2))
        return 0 if payload["passed"] else 1

    except Exception as exc:
        print(json.dumps({
            "evidence_version": LIVE_EVIDENCE_VERSION,
            "passed": False,
            "error": str(exc),
        }, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
