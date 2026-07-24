import json
from collections import Counter
from pathlib import Path
import sys
import joblib

ROOT_DIR = None
for candidate in Path(__file__).resolve().parents:
    if (candidate / "backend").is_dir():
        ROOT_DIR = candidate
        break

if ROOT_DIR is None:
    raise RuntimeError("Could not resolve repository root for backend imports")

sys.path.insert(0, str(ROOT_DIR))

from backend.analyzer.ingestion.mitre_mapper import get_mitre_mapping

MODEL_PATH = Path(__file__).resolve().parent / "model.pkl"
ENCODER_PATH = Path(__file__).resolve().parent / "label_encoder.pkl"


def _load_artifacts():
    model = joblib.load(MODEL_PATH)
    encoder = joblib.load(ENCODER_PATH)
    return model, encoder


def _build_feature_vector(logs):
    counts = Counter(log.get("event_type", "") for log in logs)
    users = {log.get("user") for log in logs if log.get("user")}
    ips = {log.get("source_ip") for log in logs if log.get("source_ip")}

    high = sum(1 for log in logs if str(log.get("severity", "")).upper() == "HIGH")
    critical = sum(1 for log in logs if str(log.get("severity", "")).upper() == "CRITICAL")

    return [
        counts.get("FAILED_LOGIN", 0),
        counts.get("SUCCESSFUL_LOGIN", 0),
        counts.get("AUTHENTICATION_FAILURE", 0),
        counts.get("SUDO_COMMAND", 0),
        counts.get("PRIVILEGE_ESCALATION", 0),
        counts.get("FILE_MODIFIED", 0),
        counts.get("FILE_DELETED", 0),
        counts.get("USB_CONNECTED", 0),
        counts.get("DEFENDER_ALERT", 0),
        counts.get("PASSWORD_CHANGED", 0),
        counts.get("USER_CREATED", 0),
        counts.get("USER_DELETED", 0),
        counts.get("KERNEL_EVENT", 0),
        len(logs),
        high,
        critical,
        len(users),
        len(ips),
    ]


def predict_logs(logs):
    model, encoder = _load_artifacts()
    features = _build_feature_vector(logs)
    prediction = model.predict([features])[0]
    confidence = max(model.predict_proba([features])[0]) * 100
    label = encoder.inverse_transform([prediction])[0]
    mitre = get_mitre_mapping(label)

    return {
        "prediction": str(label).upper(),
        "confidence": round(float(confidence), 2),
        "mitre": mitre,
    }


if __name__ == "__main__":
    logs_path = Path(__file__).resolve().parent / "classified_logs.json"
    with open(logs_path, "r", encoding="utf-8") as f:
        logs = json.load(f)

    result = predict_logs(logs)

    print("=" * 60)
    print("AEGISGUARD ML ANALYSIS")
    print("=" * 60)
    print()
    print("Prediction :", result["prediction"])
    print("Confidence :", f"{result['confidence']:.2f}%")
    print("MITRE Technique:", result["mitre"])
    print("=" * 60)
