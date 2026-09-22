"""Pure correlation engine that emits DetectionFinding objects only."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Iterable, Sequence

from backend.analyzer.detection.contracts import (
    CanonicalEvent,
    DetectionFinding,
    DetectionType,
    Severity,
)
from backend.analyzer.mitre import mappings_for_correlation

FIVE_MINUTES = timedelta(minutes=5)
TEN_MINUTES = timedelta(minutes=10)


def _dt(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except Exception:
        return datetime.min


def _finding_id(correlation_id: str, event_ids: tuple[str, ...]) -> str:
    material = "|".join((correlation_id, *event_ids))
    digest = sha256(material.encode("utf-8")).hexdigest()[:16].upper()
    return f"FND-CORR-{digest}"


def _evidence(events: Sequence[CanonicalEvent]) -> tuple[dict[str, object], ...]:
    return tuple(
        {
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "event_type": event.event_type,
            "hostname": event.hostname,
            "user": event.user,
            "source_ip": event.source_ip,
            "process": event.process,
            "file_path": event.file_path,
        }
        for event in events
    )


class CorrelationEngine:
    """Correlate canonical events without persistence or response side effects."""

    engine_name = "correlation-engine-v1"

    def correlate(self, events: Iterable[CanonicalEvent]) -> tuple[DetectionFinding, ...]:
        by_host: dict[str, list[CanonicalEvent]] = defaultdict(list)
        for event in events:
            by_host[event.hostname or "unknown"].append(event)

        findings: list[DetectionFinding] = []
        emitted: set[tuple[str, str]] = set()

        def emit(
            host: str,
            correlation_id: str,
            name: str,
            severity: Severity,
            confidence: float,
            reason: str,
            related: Sequence[CanonicalEvent],
        ) -> None:
            if not related or (correlation_id, host) in emitted:
                return
            emitted.add((correlation_id, host))
            event_ids = tuple(event.event_id for event in related)
            findings.append(
                DetectionFinding(
                    finding_id=_finding_id(correlation_id, event_ids),
                    event_ids=event_ids,
                    detection_type=DetectionType.CORRELATION,
                    name=name,
                    severity=severity,
                    confidence=confidence,
                    reason=reason,
                    timestamp=related[-1].timestamp,
                    prediction_source=f"correlation:{correlation_id}",
                    source_engine=self.engine_name,
                    correlation_id=correlation_id,
                    mitre=mappings_for_correlation(correlation_id),
                    evidence=_evidence(related),
                    metadata={"hostname": host},
                )
            )

        for host, host_events in by_host.items():
            ordered = sorted(host_events, key=lambda event: _dt(event.timestamp))

            failed_groups: dict[tuple[str, str], list[CanonicalEvent]] = defaultdict(list)
            for event in ordered:
                if event.event_type in {"FAILED_LOGIN", "AUTHENTICATION_FAILURE"}:
                    failed_groups[(event.user or "", event.source_ip or "")].append(event)

            for failed in failed_groups.values():
                if len(failed) >= 3:
                    emit(
                        host,
                        "AG-CORR-AUTH-001A",
                        "Multiple Failed Login Attempts",
                        Severity.HIGH,
                        0.80,
                        "Three or more failed authentications were observed for the same user/source pair.",
                        failed,
                    )

                last_failed = failed[-1]
                last_failed_dt = _dt(last_failed.timestamp)
                for event in ordered:
                    if event.event_type != "LOGON_SUCCESS" or (event.user or "") != (last_failed.user or ""):
                        continue
                    event_dt = _dt(event.timestamp)
                    if event_dt >= last_failed_dt and event_dt - last_failed_dt <= FIVE_MINUTES:
                        emit(
                            host,
                            "AG-CORR-AUTH-001B",
                            "Possible Brute Force Attack",
                            Severity.CRITICAL,
                            0.95,
                            "Failed authentications were followed by a successful login within five minutes.",
                            [*failed, event],
                        )
                        break

            admin_changes: list[CanonicalEvent] = []
            for index, current in enumerate(ordered):
                if current.event_type == "LOGON_SUCCESS":
                    current_dt = _dt(current.timestamp)
                    for nxt in ordered[index + 1 :]:
                        nxt_dt = _dt(nxt.timestamp)
                        if nxt_dt - current_dt > FIVE_MINUTES:
                            break
                        if nxt.event_type == "ADMIN_GROUP_ADDED":
                            emit(
                                host,
                                "AG-CORR-PRIV-001A",
                                "Privilege Escalation",
                                Severity.CRITICAL,
                                0.90,
                                "A successful login was followed by an administrator-group modification.",
                                [current, nxt],
                            )
                            admin_changes.append(nxt)
                            break
                if current.event_type == "ADMIN_GROUP_ADDED":
                    admin_changes.append(current)

            # Preserve legacy behavior, including its duplicate collection semantics.
            if len(admin_changes) >= 5:
                emit(
                    host,
                    "AG-CORR-PRIV-001B",
                    "Suspicious Administrative Activity",
                    Severity.HIGH,
                    0.75,
                    "Repeated administrator-group modifications were observed.",
                    admin_changes,
                )

            suspicious = ("powershell", "cmd.exe", "wscript", "cscript", "rundll32", "mshta")
            for index, current in enumerate(ordered):
                if current.event_type != "PROCESS_CREATED":
                    continue
                current_dt = _dt(current.timestamp)
                if not any(token in (current.process or "").lower() for token in suspicious):
                    continue
                for nxt in ordered[index + 1 :]:
                    nxt_dt = _dt(nxt.timestamp)
                    if nxt_dt - current_dt > FIVE_MINUTES:
                        break
                    if nxt.event_type == "NETWORK_CONNECTION":
                        emit(
                            host,
                            "AG-CORR-EXEC-001",
                            "Possible Malware Execution",
                            Severity.CRITICAL,
                            0.95,
                            "A suspicious process created a network connection within five minutes.",
                            [current, nxt],
                        )
                        break

            for index, current in enumerate(ordered):
                if current.event_type != "LOCAL_GROUP_ENUMERATION":
                    continue
                current_dt = _dt(current.timestamp)
                related = [current]
                process_found = False
                for nxt in ordered[index + 1 :]:
                    nxt_dt = _dt(nxt.timestamp)
                    if nxt_dt - current_dt > FIVE_MINUTES:
                        break
                    if not process_found and nxt.event_type == "PROCESS_CREATED":
                        process_found = True
                        related.append(nxt)
                    elif process_found and nxt.event_type == "NETWORK_CONNECTION":
                        related.append(nxt)
                        emit(
                            host,
                            "AG-CORR-DISC-001",
                            "Reconnaissance Activity",
                            Severity.HIGH,
                            0.75,
                            "Local group enumeration was followed by process and network activity.",
                            related,
                        )
                        break

            for index, current in enumerate(ordered):
                if current.event_type != "LOGON_SUCCESS":
                    continue
                current_dt = _dt(current.timestamp)
                related = [current]
                network_found = False
                for nxt in ordered[index + 1 :]:
                    nxt_dt = _dt(nxt.timestamp)
                    if nxt_dt - current_dt > FIVE_MINUTES:
                        break
                    if not network_found and nxt.event_type == "NETWORK_CONNECTION":
                        network_found = True
                        related.append(nxt)
                    elif network_found and nxt.event_type == "PROCESS_CREATED":
                        related.append(nxt)
                        emit(
                            host,
                            "AG-CORR-LAT-001",
                            "Possible Lateral Movement",
                            Severity.CRITICAL,
                            0.90,
                            "A successful login was followed by network and process activity.",
                            related,
                        )
                        break

            for index, current in enumerate(ordered):
                if current.event_type != "USER_CREATED":
                    continue
                current_dt = _dt(current.timestamp)
                related = [current]
                password_changed = False
                for nxt in ordered[index + 1 :]:
                    nxt_dt = _dt(nxt.timestamp)
                    if nxt_dt - current_dt > FIVE_MINUTES:
                        break
                    if not password_changed and nxt.event_type == "PASSWORD_CHANGED":
                        password_changed = True
                        related.append(nxt)
                    elif password_changed and nxt.event_type == "LOGON_SUCCESS":
                        related.append(nxt)
                        emit(
                            host,
                            "AG-CORR-PERSIST-001",
                            "Possible Persistence Established",
                            Severity.HIGH,
                            0.85,
                            "User creation was followed by password change and successful login.",
                            related,
                        )
                        break

            file_accesses = [event for event in ordered if event.event_type == "FILE_ACCESS"]
            if len(file_accesses) >= 5:
                last_file = file_accesses[-1]
                last_file_dt = _dt(last_file.timestamp)
                for event in ordered:
                    if event.event_type != "NETWORK_CONNECTION":
                        continue
                    event_dt = _dt(event.timestamp)
                    if event_dt >= last_file_dt and event_dt - last_file_dt <= FIVE_MINUTES:
                        emit(
                            host,
                            "AG-CORR-EXFIL-001",
                            "Possible Data Exfiltration",
                            Severity.CRITICAL,
                            0.92,
                            "Repeated file access was followed by a network connection.",
                            [*file_accesses, event],
                        )
                        break

            for index, current in enumerate(ordered):
                if current.event_type != "PROCESS_CREATED":
                    continue
                current_dt = _dt(current.timestamp)
                related = [current]
                file_count = 0
                for nxt in ordered[index + 1 :]:
                    nxt_dt = _dt(nxt.timestamp)
                    if nxt_dt - current_dt > TEN_MINUTES:
                        break
                    if nxt.event_type == "FILE_ACCESS":
                        related.append(nxt)
                        file_count += 1
                if file_count >= 10:
                    emit(
                        host,
                        "AG-CORR-IMPACT-001",
                        "Possible Ransomware Activity",
                        Severity.CRITICAL,
                        0.98,
                        "A process was followed by high-volume file activity within ten minutes.",
                        related,
                    )

        return tuple(findings)
