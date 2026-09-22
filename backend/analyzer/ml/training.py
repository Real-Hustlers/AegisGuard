"""Controlled offline candidate-model training for the legacy 18-feature schema."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from math import ceil
from typing import Sequence

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from .engine import FEATURE_COLUMNS, FEATURE_SCHEMA_VERSION
from .evaluation import EvaluationMetrics, evaluate_classifier


@dataclass(frozen=True)
class TrainedCandidate:
    model: object
    encoder: LabelEncoder
    evaluation: EvaluationMetrics
    feature_schema_version: str
    training_data_fingerprint: str
    training_sample_count: int
    validation_sample_count: int


def _validate_feature_frame(features: pd.DataFrame) -> pd.DataFrame:
    if tuple(features.columns) != FEATURE_COLUMNS:
        raise ValueError(
            "training features must exactly match FEATURE_COLUMNS in the declared order"
        )
    if features.empty:
        raise ValueError("training features must not be empty")
    numeric = features.copy()
    for column in FEATURE_COLUMNS:
        numeric[column] = pd.to_numeric(numeric[column], errors="raise")
    return numeric


def fingerprint_training_data(features: pd.DataFrame, labels: Sequence[str]) -> str:
    normalized_labels = [str(label).upper().strip() for label in labels]
    if len(features) != len(normalized_labels):
        raise ValueError("features and labels must have the same length")
    material = features.to_csv(index=False, lineterminator="\n")
    material += "LABEL\n" + "\n".join(normalized_labels) + "\n"
    return sha256(material.encode("utf-8")).hexdigest()


def train_candidate(
    features: pd.DataFrame,
    labels: Sequence[str],
    *,
    validation_fraction: float = 0.20,
    random_state: int = 42,
    n_estimators: int = 100,
) -> TrainedCandidate:
    """Train and evaluate a candidate; never registers or promotes it automatically."""

    frame = _validate_feature_frame(features)
    normalized_labels = [str(label).upper().strip() for label in labels]
    if len(frame) != len(normalized_labels):
        raise ValueError("features and labels must have the same length")
    if not 0.05 <= validation_fraction <= 0.50:
        raise ValueError("validation_fraction must be between 0.05 and 0.50")
    if n_estimators <= 0:
        raise ValueError("n_estimators must be positive")

    counts = pd.Series(normalized_labels).value_counts()
    if len(counts) < 2:
        raise ValueError("training requires at least two classes")
    if int(counts.min()) < 2:
        raise ValueError("every class requires at least two samples for stratified validation")
    validation_count = ceil(len(frame) * validation_fraction)
    class_count = len(counts)
    if validation_count < class_count or len(frame) - validation_count < class_count:
        raise ValueError(
            "dataset is too small for a stratified train/validation split at this validation_fraction"
        )

    encoder = LabelEncoder()
    encoded = encoder.fit_transform(normalized_labels)
    x_train, x_validation, y_train, y_validation = train_test_split(
        frame,
        encoded,
        test_size=validation_fraction,
        random_state=random_state,
        stratify=encoded,
    )

    model = RandomForestClassifier(n_estimators=n_estimators, random_state=random_state)
    model.fit(x_train, y_train)
    validation_labels = encoder.inverse_transform(y_validation)
    evaluation = evaluate_classifier(
        model,
        encoder,
        x_validation,
        [str(value) for value in validation_labels],
    )

    return TrainedCandidate(
        model=model,
        encoder=encoder,
        evaluation=evaluation,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        training_data_fingerprint=fingerprint_training_data(frame, normalized_labels),
        training_sample_count=len(x_train),
        validation_sample_count=len(x_validation),
    )
