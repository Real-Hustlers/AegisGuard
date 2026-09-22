"""Pure multi-stage attack-story construction for AegisGuard Enterprise."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from hashlib import sha256
from typing import Iterable, Mapping, Sequence

from backend.analyzer.detection.contracts import (
    DetectionFinding,
    IncidentCandidate,
    MITREMapping,
    Severity,
)


STORY_VERSION = "attack-story-v1"
DEFAULT_STORY_WINDOW = timedelta(hours=24)


class AttackStage(str, Enum):
    INITIAL_ACCESS = "INITIAL_ACCESS"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    DISCOVERY = "DISCOVERY"
    EXECUTION = "EXECUTION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    PERSISTENCE = "PERSISTENCE"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    COLLECTION = "COLLECTION"
    EXFILTRATION = "EXFILTRATION"
    IMPACT = "IMPACT"
    STEALTH = "STEALTH"
    DEFENSE_IMPAIRMENT = "DEFENSE_IMPAIRMENT"


_CORRELATION_STAGES: dict[str, AttackStage] = {
    "AG-CORR-AUTH-001A": AttackStage.CREDENTIAL_ACCESS,
    "AG-CORR-AUTH-001B": AttackStage.CREDENTIAL_ACCESS,
    "AG-CORR-PRIV-001A": AttackStage.PRIVILEGE_ESCALATION,
    "AG-CORR-PRIV-001B": AttackStage.PRIVILEGE_ESCALATION,
    "AG-CORR-EXEC-001": AttackStage.EXECUTION,
    "AG-CORR-DISC-001": AttackStage.DISCOVERY,
    "AG-CORR-LAT-001": AttackStage.LATERAL_MOVEMENT,
    "AG-CORR-PERSIST-001": AttackStage.PERSISTENCE,
    "AG-CORR-EXFIL-001": AttackStage.EXFILTRATION,
    "AG-CORR-IMPACT-001": AttackStage.IMPACT,
}

_TACTIC_STAGES: dict[str, AttackStage] = {
    "INITIAL ACCESS": AttackStage.INITIAL_ACCESS,
    "CREDENTIAL ACCESS": AttackStage.CREDENTIAL_ACCESS,
    "DISCOVERY": AttackStage.DISCOVERY,
    "EXECUTION": AttackStage.EXECUTION,
    "PRIVILEGE ESCALATION": AttackStage.PRIVILEGE_ESCALATION,
    "PERSISTENCE": AttackStage.PERSISTENCE,
    "LATERAL MOVEMENT": AttackStage.LATERAL_MOVEMENT,
    "COLLECTION": AttackStage.COLLECTION,
    "EXFILTRATION": AttackStage.EXFILTRATION,
    "IMPACT": AttackStage.IMPACT,
    "STEALTH": AttackStage.STEALTH,
    "DEFENSE IMPAIRMENT": AttackStage.DEFENSE_IMPAIRMENT,
}

_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class _StagedFinding:
    finding: DetectionFinding
    stage: AttackStage
    observed_at: datetime
    group_type: str
    group_value: str


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid finding timestamp: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _stage_for_finding(finding: DetectionFinding) -> AttackStage | None:
    correlation_id = str(finding.correlation_id or "").strip()
    if correlation_id in _CORRELATION_STAGES:
        return _CORRELATION_STAGES[correlation_id]

    resolved: list[AttackStage] = []
    for mapping in finding.mitre:
        stage = _TACTIC_STAGES.get(mapping.tactic.upper().strip())
        if stage is not None and stage not in resolved:
            resolved.append(stage)
    return resolved[0] if len(resolved) == 1 else None


def _clean_values(values: Iterable[object]) -> tuple[str, ...]:
    return tuple(sorted({str(value).strip() for value in values if str(value or "").strip()}))


def _finding_entity(finding: DetectionFinding) -> tuple[str, str] | None:
    metadata_host = ""
    if isinstance(finding.metadata, Mapping):
        metadata_host = str(finding.metadata.get("hostname") or "").strip()

    evidence = finding.evidence
    hosts = _clean_values(
        [metadata_host]
        + [item.get("hostname") for item in evidence if isinstance(item, Mapping)]
    )
    if len(hosts) == 1:
        return "hostname", hosts[0]
    if len(hosts) > 1:
        return None

    source_ips = _clean_values(
        item.get("source_ip") for item in evidence if isinstance(item, Mapping)
    )
    if len(source_ips) == 1:
        return "source_ip", source_ips[0]

    users = _clean_values(
        item.get("user") for item in evidence if isinstance(item, Mapping)
    )
    if len(users) == 1:
        return "user", users[0]
    return None


def _candidate_id(group_type: str, group_value: str, finding_ids: Sequence[str]) -> str:
    material = "|".join((STORY_VERSION, group_type, group_value, *finding_ids))
    digest = sha256(material.encode("utf-8")).hexdigest()[:20].upper()
    return f"CAND-STORY-{digest}"


def _dedupe_mitre(findings: Sequence[_StagedFinding]) -> tuple[MITREMapping, ...]:
    mappings: list[MITREMapping] = []
    seen: set[tuple[str, str, str]] = set()
    for staged in findings:
        for mapping in staged.finding.mitre:
            key = (mapping.technique_id, mapping.technique, mapping.tactic)
            if key not in seen:
                seen.add(key)
                mappings.append(mapping)
    return tuple(mappings)


def _related_entities(findings: Sequence[_StagedFinding]) -> dict[str, tuple[str, ...]]:
    evidence = [
        item
        for staged in findings
        for item in staged.finding.evidence
        if isinstance(item, Mapping)
    ]
    return {
        "hostnames": _clean_values(item.get("hostname") for item in evidence),
        "users": _clean_values(item.get("user") for item in evidence),
        "source_ips": _clean_values(item.get("source_ip") for item in evidence),
        "processes": _clean_values(item.get("process") for item in evidence),
    }


def _clusters(
    findings: Sequence[_StagedFinding],
    story_window: timedelta,
) -> tuple[tuple[_StagedFinding, ...], ...]:
    if not findings:
        return ()
    clusters: list[list[_StagedFinding]] = []
    current: list[_StagedFinding] = []
    started_at: datetime | None = None
    for staged in findings:
        if not current:
            current = [staged]
            started_at = staged.observed_at
            continue
        assert started_at is not None
        if staged.observed_at - started_at > story_window:
            clusters.append(current)
            current = [staged]
            started_at = staged.observed_at
        else:
            current.append(staged)
    if current:
        clusters.append(current)
    return tuple(tuple(cluster) for cluster in clusters)


class AttackStoryBuilder:
    """Build incident candidates from evidence-backed multi-stage findings only."""

    def __init__(
        self,
        *,
        minimum_stages: int = 2,
        story_window: timedelta = DEFAULT_STORY_WINDOW,
    ) -> None:
        if minimum_stages < 2:
            raise ValueError("minimum_stages must be at least 2")
        if story_window <= timedelta(0):
            raise ValueError("story_window must be positive")
        self.minimum_stages = minimum_stages
        self.story_window = story_window

    def build(self, findings: Iterable[DetectionFinding]) -> tuple[IncidentCandidate, ...]:
        supplied = tuple(findings)
        finding_ids = [finding.finding_id for finding in supplied]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("duplicate finding_id values are not allowed")

        grouped: dict[tuple[str, str], list[_StagedFinding]] = defaultdict(list)
        for finding in supplied:
            stage = _stage_for_finding(finding)
            entity = _finding_entity(finding)
            if stage is None or entity is None:
                continue
            grouped[entity].append(
                _StagedFinding(
                    finding=finding,
                    stage=stage,
                    observed_at=_parse_timestamp(finding.timestamp),
                    group_type=entity[0],
                    group_value=entity[1],
                )
            )

        candidates: list[IncidentCandidate] = []
        for (group_type, group_value), group_findings in sorted(grouped.items()):
            ordered = sorted(
                group_findings,
                key=lambda item: (item.observed_at, item.finding.finding_id),
            )
            for cluster in _clusters(ordered, self.story_window):
                stages: list[AttackStage] = []
                for staged in cluster:
                    if staged.stage not in stages:
                        stages.append(staged.stage)
                if len(stages) < self.minimum_stages:
                    continue

                ids = tuple(staged.finding.finding_id for staged in cluster)
                event_ids = tuple(
                    dict.fromkeys(
                        event_id
                        for staged in cluster
                        for event_id in staged.finding.event_ids
                    )
                )
                severity = max(
                    (staged.finding.severity for staged in cluster),
                    key=lambda value: _SEVERITY_RANK[value],
                )
                confidence = max(staged.finding.confidence for staged in cluster)
                first_seen = cluster[0].observed_at
                last_seen = cluster[-1].observed_at
                timeline = tuple(
                    {
                        "timestamp": staged.finding.timestamp,
                        "stage": staged.stage.value,
                        "finding_id": staged.finding.finding_id,
                        "detection_type": staged.finding.detection_type.value,
                        "name": staged.finding.name,
                        "correlation_id": staged.finding.correlation_id,
                    }
                    for staged in cluster
                )

                candidates.append(
                    IncidentCandidate(
                        candidate_id=_candidate_id(group_type, group_value, ids),
                        finding_ids=ids,
                        event_ids=event_ids,
                        name=f"Multi-stage attack activity on {group_value}",
                        severity=severity,
                        confidence=confidence,
                        reason=(
                            f"Correlated {len(cluster)} findings across {len(stages)} "
                            f"distinct attack stages for {group_type} {group_value}."
                        ),
                        timestamp=cluster[-1].finding.timestamp,
                        mitre=_dedupe_mitre(cluster),
                        related_entities=_related_entities(cluster),
                        metadata={
                            "story_version": STORY_VERSION,
                            "grouping_entity": {
                                "type": group_type,
                                "value": group_value,
                            },
                            "attack_stages": tuple(stage.value for stage in stages),
                            "timeline": timeline,
                            "first_seen": cluster[0].finding.timestamp,
                            "last_seen": cluster[-1].finding.timestamp,
                            "duration_seconds": int((last_seen - first_seen).total_seconds()),
                            "finding_count": len(cluster),
                        },
                    )
                )

        return tuple(candidates)


def build_attack_stories(
    findings: Iterable[DetectionFinding],
    *,
    minimum_stages: int = 2,
    story_window: timedelta = DEFAULT_STORY_WINDOW,
) -> tuple[IncidentCandidate, ...]:
    return AttackStoryBuilder(
        minimum_stages=minimum_stages,
        story_window=story_window,
    ).build(findings)
