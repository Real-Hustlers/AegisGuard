"""Safe runtime access to the governed promoted ML model."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import os
from pathlib import Path
from typing import Callable, Mapping

from backend.analyzer.ml import (
    ArtifactIntegrityError,
    MLEngine,
    ModelCompatibilityError,
    ModelRegistry,
    ModelRegistryError,
)


DEFAULT_GOVERNED_MODEL_NAME = "aegis-threat-classifier"
ML_REGISTRY_PATH_ENV = "AEGISGUARD_ML_REGISTRY_PATH"
ML_MODEL_NAME_ENV = "AEGISGUARD_ML_MODEL_NAME"


class GovernedMLRuntimeStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    DEGRADED = "DEGRADED"


@dataclass(frozen=True)
class GovernedMLRuntime:
    status: GovernedMLRuntimeStatus
    available: bool
    model_name: str
    model_version: str | None = None
    feature_schema_version: str | None = None
    reason: str | None = None
    engine: MLEngine | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "available": self.available,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "feature_schema_version": self.feature_schema_version,
            "reason": self.reason,
        }


def load_governed_ml_runtime(
    registry: ModelRegistry,
    *,
    model_name: str,
) -> GovernedMLRuntime:
    """Load only the registry's verified PROMOTED model.

    Missing promotion is an ordinary unavailable state.

    Registry corruption, artifact-integrity failure, or runtime
    incompatibility becomes DEGRADED instead of crashing the
    intelligence pipeline.
    """

    try:
        metadata = registry.get_promoted_metadata(
            model_name
        )
    except ModelRegistryError as exc:
        return GovernedMLRuntime(
            status=GovernedMLRuntimeStatus.DEGRADED,
            available=False,
            model_name=model_name,
            reason=str(exc),
        )

    if metadata is None:
        return GovernedMLRuntime(
            status=GovernedMLRuntimeStatus.UNAVAILABLE,
            available=False,
            model_name=model_name,
            reason="no promoted model",
        )

    try:
        engine = registry.load_promoted_engine(
            model_name
        )
    except (
        ArtifactIntegrityError,
        ModelCompatibilityError,
        ModelRegistryError,
    ) as exc:
        return GovernedMLRuntime(
            status=GovernedMLRuntimeStatus.DEGRADED,
            available=False,
            model_name=model_name,
            model_version=metadata.model_version,
            feature_schema_version=(
                metadata.feature_schema_version
            ),
            reason=str(exc),
        )

    return GovernedMLRuntime(
        status=GovernedMLRuntimeStatus.AVAILABLE,
        available=True,
        model_name=metadata.model_name,
        model_version=metadata.model_version,
        feature_schema_version=(
            metadata.feature_schema_version
        ),
        reason=None,
        engine=engine,
    )


def create_configured_ml_runtime_provider(
    *,
    default_registry_root: str | Path,
    environ: Mapping[str, str] | None = None,
) -> Callable[[], GovernedMLRuntime]:
    """Build the production governed-ML provider.

    Configuration controls only where promoted model artifacts are read
    from and which governed model identity is requested. Promotion itself
    remains an explicit ModelRegistry operation.
    """

    environment = os.environ if environ is None else environ

    configured_root = str(
        environment.get(ML_REGISTRY_PATH_ENV, "")
    ).strip()

    registry_root = (
        Path(configured_root)
        if configured_root
        else Path(default_registry_root)
    )

    configured_model_name = str(
        environment.get(ML_MODEL_NAME_ENV, "")
    ).strip()

    model_name = (
        configured_model_name
        or DEFAULT_GOVERNED_MODEL_NAME
    )

    registry = ModelRegistry(registry_root)

    def provider() -> GovernedMLRuntime:
        return load_governed_ml_runtime(
            registry,
            model_name=model_name,
        )

    return provider
