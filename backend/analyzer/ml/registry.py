"""Local, approval-gated model registry for AegisGuard Enterprise."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import json
import shutil

import joblib
import sklearn

from .artifacts import (
    ModelMetadata,
    ModelStage,
    atomic_json_write,
    require_safe_component,
    sha256_file,
)
from .engine import FEATURE_COLUMNS, FEATURE_SCHEMA_VERSION, MLEngine
from .evaluation import EvaluationMetrics, PromotionAssessment


MODEL_FILENAME = "model.joblib"
ENCODER_FILENAME = "encoder.joblib"
METADATA_FILENAME = "metadata.json"
ACTIVE_FILENAME = "active.json"


class ModelRegistryError(RuntimeError):
    pass


class ArtifactIntegrityError(ModelRegistryError):
    pass


class ModelCompatibilityError(ModelRegistryError):
    pass


@dataclass(frozen=True)
class LoadedModel:
    model: object
    encoder: object
    metadata: ModelMetadata


class ModelRegistry:
    """Filesystem registry with explicit candidate registration and promotion."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _model_dir(self, model_name: str) -> Path:
        return self.root / require_safe_component(model_name, "model_name")

    def _version_dir(self, model_name: str, model_version: str) -> Path:
        return self._model_dir(model_name) / require_safe_component(
            model_version, "model_version"
        )

    def _metadata_path(self, model_name: str, model_version: str) -> Path:
        return self._version_dir(model_name, model_version) / METADATA_FILENAME

    def register_candidate(
        self,
        *,
        model,
        encoder,
        model_name: str,
        model_version: str,
        feature_schema_version: str,
        training_data_fingerprint: str,
        evaluation: EvaluationMetrics,
        trained_at: str | None = None,
    ) -> ModelMetadata:
        """Persist a candidate. Registration never makes it active."""

        model_name = require_safe_component(model_name, "model_name")
        model_version = require_safe_component(model_version, "model_version")
        version_dir = self._version_dir(model_name, model_version)
        if version_dir.exists():
            raise ModelRegistryError(
                f"model version already exists: {model_name}@{model_version}"
            )

        version_dir.mkdir(parents=True, exist_ok=False)
        model_path = version_dir / MODEL_FILENAME
        encoder_path = version_dir / ENCODER_FILENAME
        try:
            joblib.dump(model, model_path)
            joblib.dump(encoder, encoder_path)
            classes = tuple(str(value) for value in getattr(encoder, "classes_", ()))
            if not classes:
                raise ModelRegistryError("encoder does not expose fitted classes_")
            metadata = ModelMetadata(
                model_name=model_name,
                model_version=model_version,
                feature_schema_version=feature_schema_version,
                feature_columns=tuple(FEATURE_COLUMNS),
                sklearn_version=sklearn.__version__,
                trained_at=trained_at
                or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                classes=classes,
                training_data_fingerprint=training_data_fingerprint,
                model_sha256=sha256_file(model_path),
                encoder_sha256=sha256_file(encoder_path),
                evaluation=evaluation.to_dict(),
                stage=ModelStage.CANDIDATE,
            )
            atomic_json_write(version_dir / METADATA_FILENAME, metadata.to_dict())
            return metadata
        except Exception:
            shutil.rmtree(version_dir, ignore_errors=True)
            raise

    def read_metadata(self, model_name: str, model_version: str) -> ModelMetadata:
        path = self._metadata_path(model_name, model_version)
        if not path.exists():
            raise ModelRegistryError(
                f"model version not found: {model_name}@{model_version}"
            )
        with open(path, "r", encoding="utf-8") as handle:
            return ModelMetadata.from_dict(json.load(handle))

    def list_versions(self, model_name: str) -> tuple[ModelMetadata, ...]:
        model_dir = self._model_dir(model_name)
        if not model_dir.exists():
            return ()
        versions = []
        for child in sorted(model_dir.iterdir(), key=lambda value: value.name):
            metadata_path = child / METADATA_FILENAME
            if child.is_dir() and metadata_path.exists():
                with open(metadata_path, "r", encoding="utf-8") as handle:
                    versions.append(ModelMetadata.from_dict(json.load(handle)))
        return tuple(versions)

    def load(
        self,
        model_name: str,
        model_version: str,
        *,
        expected_feature_schema_version: str = FEATURE_SCHEMA_VERSION,
        require_runtime_version_match: bool = True,
    ) -> LoadedModel:
        metadata = self.read_metadata(model_name, model_version)
        version_dir = self._version_dir(model_name, model_version)
        model_path = version_dir / MODEL_FILENAME
        encoder_path = version_dir / ENCODER_FILENAME

        if sha256_file(model_path) != metadata.model_sha256:
            raise ArtifactIntegrityError("model artifact SHA-256 mismatch")
        if sha256_file(encoder_path) != metadata.encoder_sha256:
            raise ArtifactIntegrityError("encoder artifact SHA-256 mismatch")
        if metadata.feature_schema_version != expected_feature_schema_version:
            raise ModelCompatibilityError(
                "feature schema mismatch: "
                f"artifact={metadata.feature_schema_version}, "
                f"runtime={expected_feature_schema_version}"
            )
        if tuple(metadata.feature_columns) != tuple(FEATURE_COLUMNS):
            raise ModelCompatibilityError("feature column contract mismatch")
        if require_runtime_version_match and metadata.sklearn_version != sklearn.__version__:
            raise ModelCompatibilityError(
                "scikit-learn version mismatch: "
                f"artifact={metadata.sklearn_version}, runtime={sklearn.__version__}"
            )

        model = joblib.load(model_path)
        encoder = joblib.load(encoder_path)
        runtime_classes = tuple(str(value) for value in getattr(encoder, "classes_", ()))
        if runtime_classes != metadata.classes:
            raise ArtifactIntegrityError("encoder classes do not match model metadata")
        feature_names = tuple(str(value) for value in getattr(model, "feature_names_in_", ()))
        if feature_names and feature_names != metadata.feature_columns:
            raise ModelCompatibilityError("model feature_names_in_ does not match metadata")
        return LoadedModel(model=model, encoder=encoder, metadata=metadata)

    def get_promoted_metadata(self, model_name: str) -> ModelMetadata | None:
        active_path = self._model_dir(model_name) / ACTIVE_FILENAME
        if not active_path.exists():
            return None

        with open(active_path, "r", encoding="utf-8") as handle:
            active = json.load(handle)

        metadata = self.read_metadata(
            model_name,
            str(active["model_version"]),
        )

        if metadata.stage is not ModelStage.PROMOTED:
            raise ModelRegistryError(
                "active model metadata must be PROMOTED"
            )

        return metadata

    def promote(
        self,
        model_name: str,
        model_version: str,
        *,
        approved_by: str,
        assessment: PromotionAssessment,
        approved_at: str | None = None,
    ) -> ModelMetadata:
        """Promote only an eligible candidate with an explicit human approver."""

        approved_by = str(approved_by or "").strip()
        if not approved_by:
            raise ValueError("approved_by is required for promotion")
        if not assessment.eligible_for_approval:
            raise ModelRegistryError(
                "candidate is not eligible for approval: " + "; ".join(assessment.reasons)
            )

        metadata = self.read_metadata(model_name, model_version)
        if metadata.stage is not ModelStage.CANDIDATE:
            raise ModelRegistryError("only CANDIDATE model versions may be promoted")

        candidate_accuracy = float(metadata.evaluation.get("accuracy", -1.0))
        candidate_macro_f1 = float(metadata.evaluation.get("macro_f1", -1.0))
        if (
            abs(candidate_accuracy - assessment.candidate_accuracy) > 1e-12
            or abs(candidate_macro_f1 - assessment.candidate_macro_f1) > 1e-12
        ):
            raise ModelRegistryError(
                "promotion assessment does not match the registered candidate evaluation"
            )

        timestamp = approved_at or datetime.now(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
        previous = self.get_promoted_metadata(model_name)
        if previous is not None:
            current_accuracy = float(previous.evaluation.get("accuracy", -1.0))
            current_macro_f1 = float(previous.evaluation.get("macro_f1", -1.0))
            if assessment.current_accuracy is None or assessment.current_macro_f1 is None:
                raise ModelRegistryError(
                    "promotion assessment must compare the candidate with the current promoted model"
                )
            if (
                abs(current_accuracy - assessment.current_accuracy) > 1e-12
                or abs(current_macro_f1 - assessment.current_macro_f1) > 1e-12
            ):
                raise ModelRegistryError(
                    "promotion assessment does not match the current promoted model evaluation"
                )
        if previous is not None and previous.model_version != metadata.model_version:
            retired = replace(previous, stage=ModelStage.RETIRED)
            atomic_json_write(
                self._metadata_path(previous.model_name, previous.model_version),
                retired.to_dict(),
            )

        promoted = replace(
            metadata,
            stage=ModelStage.PROMOTED,
            approved_by=approved_by,
            approved_at=timestamp,
        )
        atomic_json_write(
            self._metadata_path(model_name, model_version), promoted.to_dict()
        )
        atomic_json_write(
            self._model_dir(model_name) / ACTIVE_FILENAME,
            {
                "model_name": promoted.model_name,
                "model_version": promoted.model_version,
                "approved_by": approved_by,
                "approved_at": timestamp,
                "assessment": assessment.to_dict(),
            },
        )
        return promoted

    def load_promoted_engine(self, model_name: str) -> MLEngine:
        metadata = self.get_promoted_metadata(model_name)
        if metadata is None:
            raise ModelRegistryError(f"no promoted model for {model_name}")
        loaded = self.load(model_name, metadata.model_version)
        return MLEngine(
            model=loaded.model,
            encoder=loaded.encoder,
            model_name=loaded.metadata.model_name,
            model_version=loaded.metadata.model_version,
            feature_schema_version=loaded.metadata.feature_schema_version,
        )
