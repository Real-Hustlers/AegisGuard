"""Offline model evaluation and promotion-eligibility policy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from sklearn.metrics import accuracy_score, confusion_matrix, f1_score


@dataclass(frozen=True)
class EvaluationMetrics:
    accuracy: float
    macro_f1: float
    weighted_f1: float
    sample_count: int
    labels: tuple[str, ...]
    confusion_matrix: tuple[tuple[int, ...], ...]

    def __post_init__(self) -> None:
        for name in ("accuracy", "macro_f1", "weighted_f1"):
            value = float(getattr(self, name))
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1")
        if self.sample_count <= 0:
            raise ValueError("sample_count must be positive")
        if not self.labels:
            raise ValueError("labels must not be empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "accuracy": self.accuracy,
            "macro_f1": self.macro_f1,
            "weighted_f1": self.weighted_f1,
            "sample_count": self.sample_count,
            "labels": list(self.labels),
            "confusion_matrix": [list(row) for row in self.confusion_matrix],
        }


@dataclass(frozen=True)
class PromotionPolicy:
    min_accuracy: float = 0.70
    min_macro_f1: float = 0.60
    max_accuracy_drop: float = 0.02
    max_macro_f1_drop: float = 0.02

    def __post_init__(self) -> None:
        for name in (
            "min_accuracy",
            "min_macro_f1",
            "max_accuracy_drop",
            "max_macro_f1_drop",
        ):
            value = float(getattr(self, name))
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1")


@dataclass(frozen=True)
class PromotionAssessment:
    eligible_for_approval: bool
    reasons: tuple[str, ...]
    candidate_accuracy: float
    candidate_macro_f1: float
    current_accuracy: float | None
    current_macro_f1: float | None
    accuracy_delta: float | None
    macro_f1_delta: float | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "eligible_for_approval": self.eligible_for_approval,
            "reasons": list(self.reasons),
            "candidate_accuracy": self.candidate_accuracy,
            "candidate_macro_f1": self.candidate_macro_f1,
            "current_accuracy": self.current_accuracy,
            "current_macro_f1": self.current_macro_f1,
            "accuracy_delta": self.accuracy_delta,
            "macro_f1_delta": self.macro_f1_delta,
        }


def evaluate_classifier(model, encoder, features, labels: Sequence[str]) -> EvaluationMetrics:
    """Evaluate one classifier without mutating or promoting it."""

    expected = [str(label).upper().strip() for label in labels]
    if not expected:
        raise ValueError("evaluation requires at least one label")
    if len(features) != len(expected):
        raise ValueError("features and labels must have the same length")

    encoded_predictions = model.predict(features)
    predictions = [
        str(value).upper().strip()
        for value in encoder.inverse_transform(encoded_predictions)
    ]
    ordered_labels = tuple(sorted(set(expected) | set(predictions)))
    matrix = confusion_matrix(expected, predictions, labels=ordered_labels)

    return EvaluationMetrics(
        accuracy=float(accuracy_score(expected, predictions)),
        macro_f1=float(
            f1_score(expected, predictions, labels=ordered_labels, average="macro", zero_division=0)
        ),
        weighted_f1=float(
            f1_score(expected, predictions, labels=ordered_labels, average="weighted", zero_division=0)
        ),
        sample_count=len(expected),
        labels=ordered_labels,
        confusion_matrix=tuple(tuple(int(cell) for cell in row) for row in matrix.tolist()),
    )


def assess_candidate(
    candidate: EvaluationMetrics,
    *,
    current: EvaluationMetrics | None = None,
    policy: PromotionPolicy | None = None,
) -> PromotionAssessment:
    """Determine whether a candidate is eligible for human approval.

    Eligibility never promotes a model by itself.
    """

    policy = policy or PromotionPolicy()
    reasons: list[str] = []

    if candidate.accuracy < policy.min_accuracy:
        reasons.append(
            f"candidate accuracy {candidate.accuracy:.4f} is below minimum {policy.min_accuracy:.4f}"
        )
    if candidate.macro_f1 < policy.min_macro_f1:
        reasons.append(
            f"candidate macro_f1 {candidate.macro_f1:.4f} is below minimum {policy.min_macro_f1:.4f}"
        )

    accuracy_delta = None
    macro_f1_delta = None
    if current is not None:
        accuracy_delta = candidate.accuracy - current.accuracy
        macro_f1_delta = candidate.macro_f1 - current.macro_f1
        if accuracy_delta < -policy.max_accuracy_drop:
            reasons.append(
                f"candidate accuracy regression {accuracy_delta:.4f} exceeds allowed drop {-policy.max_accuracy_drop:.4f}"
            )
        if macro_f1_delta < -policy.max_macro_f1_drop:
            reasons.append(
                f"candidate macro_f1 regression {macro_f1_delta:.4f} exceeds allowed drop {-policy.max_macro_f1_drop:.4f}"
            )

    return PromotionAssessment(
        eligible_for_approval=not reasons,
        reasons=tuple(reasons),
        candidate_accuracy=candidate.accuracy,
        candidate_macro_f1=candidate.macro_f1,
        current_accuracy=current.accuracy if current is not None else None,
        current_macro_f1=current.macro_f1 if current is not None else None,
        accuracy_delta=accuracy_delta,
        macro_f1_delta=macro_f1_delta,
    )
