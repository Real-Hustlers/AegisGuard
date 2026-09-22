"""Reviewed historical-learning inputs for AegisGuard Enterprise.

This module turns analyst-reviewed historical outcomes into the exact feature
schema consumed by the governed Y3 training pipeline. It deliberately does not
query production databases, infer truth from model predictions, register a
candidate, or promote a model.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
from typing import Iterable, Mapping, Sequence

import pandas as pd

from backend.analyzer.detection.contracts import CanonicalEvent
from backend.platform.contracts import IncidentLifecycleStatus

from .engine import FEATURE_COLUMNS, FEATURE_SCHEMA_VERSION, build_feature_frame
from .training import TrainedCandidate, fingerprint_training_data, train_candidate


class HistoricalDisposition(str, Enum):
    """Human-reviewed outcome allowed to become training truth."""

    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    KNOWN_BENIGN = "KNOWN_BENIGN"


def _require_text(value: str, field_name: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError(f"{field_name} must be non-empty")
    return normalized


def _normalize_label(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = str(value).upper().strip()
    return normalized or None


@dataclass(frozen=True)
class HistoricalObservation:
    """One reviewed historical case and the events used to learn from it."""

    observation_id: str
    events: tuple[CanonicalEvent, ...]
    disposition: HistoricalDisposition
    reviewed_by: str
    reviewed_at: str
    threat_label: str | None = None
    incident_id: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.observation_id, "observation_id")
        _require_text(self.reviewed_by, "reviewed_by")
        _require_text(self.reviewed_at, "reviewed_at")
        if not isinstance(self.disposition, HistoricalDisposition):
            raise TypeError("disposition must be a HistoricalDisposition")
        if not self.events:
            raise ValueError("events must contain at least one reviewed event")
        event_ids = [event.event_id for event in self.events]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("events must not contain duplicate event_ids")
        if self.incident_id is not None:
            _require_text(self.incident_id, "incident_id")

        normalized_label = _normalize_label(self.threat_label)
        if self.disposition is HistoricalDisposition.TRUE_POSITIVE:
            if normalized_label is None:
                raise ValueError("TRUE_POSITIVE observations require an explicit threat_label")
            if normalized_label in {"NORMAL", "UNKNOWN"}:
                raise ValueError(
                    "TRUE_POSITIVE threat_label must identify a confirmed threat class"
                )
        elif normalized_label not in {None, "NORMAL"}:
            raise ValueError(
                "FALSE_POSITIVE and KNOWN_BENIGN observations may only use NORMAL"
            )

    @property
    def training_label(self) -> str:
        if self.disposition is HistoricalDisposition.TRUE_POSITIVE:
            return str(self.threat_label).upper().strip()
        return "NORMAL"

    def provenance_dict(self) -> dict[str, object]:
        """Minimal audit lineage; raw event content is intentionally excluded."""

        return {
            "observation_id": self.observation_id,
            "incident_id": self.incident_id,
            "disposition": self.disposition.value,
            "training_label": self.training_label,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at,
            "event_ids": [event.event_id for event in self.events],
        }


@dataclass(frozen=True)
class HistoricalDataset:
    """Deterministic training snapshot produced from reviewed observations."""

    features: pd.DataFrame
    labels: tuple[str, ...]
    observation_ids: tuple[str, ...]
    provenance: tuple[Mapping[str, object], ...]
    training_data_fingerprint: str
    review_provenance_fingerprint: str
    feature_schema_version: str = FEATURE_SCHEMA_VERSION

    @property
    def sample_count(self) -> int:
        return len(self.labels)

    @property
    def class_counts(self) -> dict[str, int]:
        return dict(sorted(Counter(self.labels).items()))

    def to_training_frame(self) -> pd.DataFrame:
        frame = self.features.copy()
        frame["LABEL"] = list(self.labels)
        return frame

    def manifest(self) -> dict[str, object]:
        return {
            "feature_schema_version": self.feature_schema_version,
            "sample_count": self.sample_count,
            "class_counts": self.class_counts,
            "training_data_fingerprint": self.training_data_fingerprint,
            "review_provenance_fingerprint": self.review_provenance_fingerprint,
            "observation_ids": list(self.observation_ids),
            "provenance": [dict(item) for item in self.provenance],
        }


@dataclass(frozen=True)
class HistoricalTrainingRun:
    """Offline Y4 dataset plus the unregistered Y3 candidate it produced."""

    dataset: HistoricalDataset
    candidate: TrainedCandidate


def observation_from_incident_review(
    *,
    observation_id: str,
    incident_id: str,
    lifecycle_status: IncidentLifecycleStatus | str,
    events: Sequence[CanonicalEvent],
    reviewed_by: str,
    reviewed_at: str,
    confirmed_label: str | None = None,
) -> HistoricalObservation:
    """Adapt a final analyst incident review into historical-learning truth.

    Only explicit CONFIRMED and FALSE_POSITIVE outcomes are accepted. RESOLVED
    or CLOSED alone do not establish whether the underlying detection was true.
    """

    try:
        status = (
            lifecycle_status
            if isinstance(lifecycle_status, IncidentLifecycleStatus)
            else IncidentLifecycleStatus(str(lifecycle_status))
        )
    except ValueError as exc:
        raise ValueError("unsupported incident lifecycle status for learning") from exc

    if status is IncidentLifecycleStatus.CONFIRMED:
        disposition = HistoricalDisposition.TRUE_POSITIVE
    elif status is IncidentLifecycleStatus.FALSE_POSITIVE:
        disposition = HistoricalDisposition.FALSE_POSITIVE
    else:
        raise ValueError(
            "historical learning requires CONFIRMED or FALSE_POSITIVE incident review"
        )

    return HistoricalObservation(
        observation_id=observation_id,
        incident_id=incident_id,
        events=tuple(events),
        disposition=disposition,
        reviewed_by=reviewed_by,
        reviewed_at=reviewed_at,
        threat_label=confirmed_label,
    )


def known_benign_observation(
    *,
    observation_id: str,
    events: Sequence[CanonicalEvent],
    reviewed_by: str,
    reviewed_at: str,
) -> HistoricalObservation:
    """Create an explicitly reviewed benign historical example."""

    return HistoricalObservation(
        observation_id=observation_id,
        events=tuple(events),
        disposition=HistoricalDisposition.KNOWN_BENIGN,
        reviewed_by=reviewed_by,
        reviewed_at=reviewed_at,
    )


def _provenance_fingerprint(
    features: pd.DataFrame,
    labels: Sequence[str],
    provenance: Sequence[Mapping[str, object]],
) -> str:
    material = features.to_csv(index=False, lineterminator="\n")
    material += "LABEL\n" + "\n".join(labels) + "\n"
    material += json.dumps(
        [dict(item) for item in provenance],
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(material.encode("utf-8")).hexdigest()


def build_historical_dataset(
    observations: Iterable[HistoricalObservation],
) -> HistoricalDataset:
    """Build one deterministic feature row per reviewed historical outcome."""

    items = tuple(observations)
    if not items:
        raise ValueError("historical dataset requires at least one reviewed observation")
    if any(not isinstance(item, HistoricalObservation) for item in items):
        raise TypeError("observations must contain HistoricalObservation values")

    ordered = tuple(sorted(items, key=lambda item: item.observation_id))
    observation_ids = [item.observation_id for item in ordered]
    if len(observation_ids) != len(set(observation_ids)):
        raise ValueError("observation_id values must be unique")

    event_owner: dict[str, str] = {}
    rows: list[dict[str, object]] = []
    labels: list[str] = []
    provenance: list[Mapping[str, object]] = []

    for observation in ordered:
        for event in observation.events:
            previous = event_owner.get(event.event_id)
            if previous is not None:
                raise ValueError(
                    f"event_id {event.event_id} appears in multiple reviewed observations: "
                    f"{previous} and {observation.observation_id}"
                )
            event_owner[event.event_id] = observation.observation_id

        frame = build_feature_frame(observation.events)
        rows.append({column: frame.iloc[0][column] for column in FEATURE_COLUMNS})
        labels.append(observation.training_label)
        provenance.append(observation.provenance_dict())

    features = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    label_tuple = tuple(labels)
    provenance_tuple = tuple(provenance)
    return HistoricalDataset(
        features=features,
        labels=label_tuple,
        observation_ids=tuple(observation_ids),
        provenance=provenance_tuple,
        training_data_fingerprint=fingerprint_training_data(features, label_tuple),
        review_provenance_fingerprint=_provenance_fingerprint(
            features, label_tuple, provenance_tuple
        ),
    )


def train_historical_candidate(
    observations: Iterable[HistoricalObservation],
    *,
    validation_fraction: float = 0.20,
    random_state: int = 42,
    n_estimators: int = 100,
) -> HistoricalTrainingRun:
    """Build reviewed history and train an unregistered candidate offline."""

    dataset = build_historical_dataset(observations)
    candidate = train_candidate(
        dataset.features,
        dataset.labels,
        validation_fraction=validation_fraction,
        random_state=random_state,
        n_estimators=n_estimators,
    )
    if candidate.training_data_fingerprint != dataset.training_data_fingerprint:
        raise RuntimeError("historical training fingerprint mismatch")
    return HistoricalTrainingRun(dataset=dataset, candidate=candidate)
