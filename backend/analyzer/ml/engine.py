"""Model-only detection engine for AegisGuard Enterprise."""

from __future__ import annotations

from collections import Counter
from hashlib import sha256
from typing import Iterable, Sequence

import pandas as pd

from backend.analyzer.detection.contracts import (
    CanonicalEvent,
    DetectionFinding,
    DetectionType,
    MLPrediction,
    Severity,
)

FEATURE_SCHEMA_VERSION = "legacy-18-v1"
FEATURE_COLUMNS = (
    "FAILED_LOGIN",
    "LOGON_SUCCESS",
    "AUTHENTICATION_FAILURE",
    "SUDO_COMMAND",
    "PRIVILEGE_ESCALATION",
    "FILE_MODIFIED",
    "FILE_DELETED",
    "USB_CONNECTED",
    "DEFENDER_ALERT",
    "PASSWORD_CHANGED",
    "USER_CREATED",
    "USER_DELETED",
    "KERNEL_EVENT",
    "TOTAL_EVENTS",
    "HIGH_EVENTS",
    "CRITICAL_EVENTS",
    "UNIQUE_USERS",
    "UNIQUE_SOURCE_IPS",
)


def build_feature_frame(events: Sequence[CanonicalEvent]) -> pd.DataFrame:
    counts = Counter(event.event_type.upper().strip() for event in events)
    users = {event.user for event in events if event.user}
    source_ips = {event.source_ip for event in events if event.source_ip}
    high = sum(1 for event in events if event.severity.upper() == "HIGH")
    critical = sum(1 for event in events if event.severity.upper() == "CRITICAL")

    row = {
        "FAILED_LOGIN": counts.get("FAILED_LOGIN", 0),
        "LOGON_SUCCESS": counts.get("LOGON_SUCCESS", 0),
        "AUTHENTICATION_FAILURE": counts.get("AUTHENTICATION_FAILURE", 0),
        "SUDO_COMMAND": counts.get("SUDO_COMMAND", 0),
        "PRIVILEGE_ESCALATION": counts.get("PRIVILEGE_ESCALATION", 0),
        "FILE_MODIFIED": counts.get("FILE_MODIFIED", 0),
        "FILE_DELETED": counts.get("FILE_DELETED", 0),
        "USB_CONNECTED": counts.get("USB_CONNECTED", 0),
        "DEFENDER_ALERT": counts.get("DEFENDER_ALERT", 0),
        "PASSWORD_CHANGED": counts.get("PASSWORD_CHANGED", 0),
        "USER_CREATED": counts.get("USER_CREATED", 0),
        "USER_DELETED": counts.get("USER_DELETED", 0),
        "KERNEL_EVENT": counts.get("KERNEL_EVENT", 0),
        "TOTAL_EVENTS": len(events),
        "HIGH_EVENTS": high,
        "CRITICAL_EVENTS": critical,
        "UNIQUE_USERS": len(users),
        "UNIQUE_SOURCE_IPS": len(source_ips),
    }
    return pd.DataFrame([row], columns=FEATURE_COLUMNS)


def _severity_for_label(label: str) -> Severity:
    if label in {"MALWARE", "PRIVILEGE_ESCALATION", "RANSOMWARE"}:
        return Severity.CRITICAL
    if label in {"BRUTE_FORCE", "INSIDER_THREAT", "ACCOUNT_COMPROMISE"}:
        return Severity.HIGH
    return Severity.MEDIUM


def _finding_id(model_version: str, label: str, event_ids: tuple[str, ...]) -> str:
    material = "|".join((model_version, label, *event_ids))
    digest = sha256(material.encode("utf-8")).hexdigest()[:16].upper()
    return f"FND-ML-{digest}"


class MLEngine:
    """Run only model inference; deterministic rules do not belong here."""

    engine_name = "ml-engine-v1"

    def __init__(
        self,
        *,
        model,
        encoder,
        model_name: str,
        model_version: str,
        feature_schema_version: str = FEATURE_SCHEMA_VERSION,
    ) -> None:
        if not model_name.strip():
            raise ValueError("model_name must be non-empty")
        if not model_version.strip():
            raise ValueError("model_version must be non-empty")
        self.model = model
        self.encoder = encoder
        self.model_name = model_name
        self.model_version = model_version
        self.feature_schema_version = feature_schema_version

    def predict(self, events: Iterable[CanonicalEvent]) -> MLPrediction:
        event_list = tuple(events)
        if not event_list:
            raise ValueError("ML prediction requires at least one event")

        features = build_feature_frame(event_list)
        encoded = self.model.predict(features)[0]
        label = str(self.encoder.inverse_transform([encoded])[0]).upper().strip()

        fallback_reason = None
        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(features)[0]
            confidence = float(max(probabilities))
        else:
            confidence = 0.0
            fallback_reason = "model does not expose predict_proba"

        confidence = min(1.0, max(0.0, confidence))
        return MLPrediction(
            prediction=label,
            confidence=confidence,
            model_name=self.model_name,
            model_version=self.model_version,
            feature_schema_version=self.feature_schema_version,
            prediction_source=f"model:{self.model_name}",
            event_ids=tuple(event.event_id for event in event_list),
            timestamp=event_list[-1].timestamp,
            fallback_reason=fallback_reason,
            metadata={"engine": self.engine_name},
        )

    def detect(self, events: Iterable[CanonicalEvent]) -> DetectionFinding | None:
        event_list = tuple(events)
        prediction = self.predict(event_list)
        if prediction.prediction == "NORMAL":
            return None

        return DetectionFinding(
            finding_id=_finding_id(
                prediction.model_version,
                prediction.prediction,
                prediction.event_ids,
            ),
            event_ids=prediction.event_ids,
            detection_type=DetectionType.ML,
            name=f"ML detection: {prediction.prediction}",
            severity=_severity_for_label(prediction.prediction),
            confidence=prediction.confidence,
            reason=(
                f"Model {prediction.model_name}@{prediction.model_version} "
                f"predicted {prediction.prediction}."
            ),
            timestamp=prediction.timestamp,
            prediction_source=prediction.prediction_source,
            model_version=prediction.model_version,
            feature_schema_version=prediction.feature_schema_version,
            source_engine=self.engine_name,
            evidence=tuple(
                {
                    "event_id": event.event_id,
                    "event_type": event.event_type,
                    "hostname": event.hostname,
                    "source_ip": event.source_ip,
                    "user": event.user,
                }
                for event in event_list
            ),
            metadata={
                "prediction": prediction.prediction,
                "model_name": prediction.model_name,
                "fallback_reason": prediction.fallback_reason,
            },
        )
