"""Versioned ML artifact metadata and integrity helpers for AegisGuard."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping
import json
import re


METADATA_SCHEMA_VERSION = "1.0"
_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class ModelStage(str, Enum):
    CANDIDATE = "CANDIDATE"
    PROMOTED = "PROMOTED"
    RETIRED = "RETIRED"


def require_safe_component(value: str, field_name: str) -> str:
    value = str(value or "").strip()
    if not value or not _SAFE_COMPONENT.fullmatch(value):
        raise ValueError(
            f"{field_name} must contain only letters, digits, '.', '_' or '-'"
        )
    return value


def sha256_file(path: str | Path) -> str:
    digest = sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json_write(path: str | Path, payload: Mapping[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.flush()
    temporary.replace(destination)


@dataclass(frozen=True)
class ModelMetadata:
    """Auditable identity and compatibility information for one model version."""

    model_name: str
    model_version: str
    feature_schema_version: str
    feature_columns: tuple[str, ...]
    sklearn_version: str
    trained_at: str
    classes: tuple[str, ...]
    training_data_fingerprint: str
    model_sha256: str
    encoder_sha256: str
    evaluation: Mapping[str, Any] = field(default_factory=dict)
    stage: ModelStage = ModelStage.CANDIDATE
    approved_by: str | None = None
    approved_at: str | None = None
    metadata_schema_version: str = METADATA_SCHEMA_VERSION

    def __post_init__(self) -> None:
        require_safe_component(self.model_name, "model_name")
        require_safe_component(self.model_version, "model_version")
        if not str(self.feature_schema_version).strip():
            raise ValueError("feature_schema_version must be non-empty")
        if not self.feature_columns:
            raise ValueError("feature_columns must not be empty")
        if len(set(self.feature_columns)) != len(self.feature_columns):
            raise ValueError("feature_columns must be unique")
        if not str(self.sklearn_version).strip():
            raise ValueError("sklearn_version must be non-empty")
        if not str(self.trained_at).strip():
            raise ValueError("trained_at must be non-empty")
        if not self.classes:
            raise ValueError("classes must not be empty")
        for field_name in ("training_data_fingerprint", "model_sha256", "encoder_sha256"):
            value = str(getattr(self, field_name))
            if len(value) != 64 or any(char not in "0123456789abcdef" for char in value.lower()):
                raise ValueError(f"{field_name} must be a SHA-256 hex digest")
        if self.stage is ModelStage.PROMOTED:
            if not str(self.approved_by or "").strip() or not str(self.approved_at or "").strip():
                raise ValueError("promoted models require approved_by and approved_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata_schema_version": self.metadata_schema_version,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "feature_schema_version": self.feature_schema_version,
            "feature_columns": list(self.feature_columns),
            "sklearn_version": self.sklearn_version,
            "trained_at": self.trained_at,
            "classes": list(self.classes),
            "training_data_fingerprint": self.training_data_fingerprint,
            "model_sha256": self.model_sha256,
            "encoder_sha256": self.encoder_sha256,
            "evaluation": dict(self.evaluation),
            "stage": self.stage.value,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ModelMetadata":
        return cls(
            model_name=str(payload["model_name"]),
            model_version=str(payload["model_version"]),
            feature_schema_version=str(payload["feature_schema_version"]),
            feature_columns=tuple(str(value) for value in payload["feature_columns"]),
            sklearn_version=str(payload["sklearn_version"]),
            trained_at=str(payload["trained_at"]),
            classes=tuple(str(value) for value in payload["classes"]),
            training_data_fingerprint=str(payload["training_data_fingerprint"]),
            model_sha256=str(payload["model_sha256"]),
            encoder_sha256=str(payload["encoder_sha256"]),
            evaluation=dict(payload.get("evaluation") or {}),
            stage=ModelStage(str(payload.get("stage") or ModelStage.CANDIDATE.value)),
            approved_by=payload.get("approved_by"),
            approved_at=payload.get("approved_at"),
            metadata_schema_version=str(
                payload.get("metadata_schema_version") or METADATA_SCHEMA_VERSION
            ),
        )
