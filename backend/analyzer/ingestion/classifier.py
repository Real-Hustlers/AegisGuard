import json
import os
from collections import Counter
from pathlib import Path

import joblib
import pandas as pd

# Threat category mapping for fallback behavior
CATEGORIES = {
    "SUCCESSFUL_LOGIN": "Authentication",
    "FAILED_LOGIN": "Authentication",
    "SUDO_COMMAND": "Privilege Escalation",
    "SUDO_EXECUTED": "Privilege Escalation",
    "PRIVILEGE_ESCALATION": "Privilege Escalation",
    "USB_CONNECTED": "Device Activity",
    "FILE_MODIFIED": "File Activity",
    "FILE_DELETED": "File Activity",
    "DEFENDER_ALERT": "Malware",
    "AUTHENTICATION_FAILURE": "Authentication",
    "PASSWORD_CHANGED": "Account Activity",
    "USER_CREATED": "Account Activity",
    "USER_DELETED": "Account Activity",
    "KERNEL_EVENT": "System Activity",
}

BASE_SCORES = {
    "SUCCESSFUL_LOGIN": 5,
    "FAILED_LOGIN": 25,
    "SUDO_COMMAND": 60,
    "SUDO_EXECUTED": 60,
    "PRIVILEGE_ESCALATION": 80,
    "USB_CONNECTED": 35,
    "FILE_MODIFIED": 15,
    "FILE_DELETED": 50,
    "DEFENDER_ALERT": 95,
    "AUTHENTICATION_FAILURE": 30,
    "PASSWORD_CHANGED": 10,
    "USER_CREATED": 10,
    "USER_DELETED": 20,
    "KERNEL_EVENT": 15,
}


def _resolve_ml_artifacts():
    base_dir = Path(__file__).resolve().parents[2]
    ml_dir = base_dir / "ML Aegis" / "ml"
    model_path = ml_dir / "model.pkl"
    encoder_path = ml_dir / "label_encoder.pkl"
    return model_path, encoder_path


def _build_feature_vector(logs):
    counts = Counter(log.get("event_type", "") for log in logs)
    users = {log.get("user") for log in logs if log.get("user")}
    ips = {log.get("source_ip") for log in logs if log.get("source_ip")}

    high = sum(1 for log in logs if str(log.get("severity", "")).upper() == "HIGH")
    critical = sum(1 for log in logs if str(log.get("severity", "")).upper() == "CRITICAL")

    features = {
        "FAILED_LOGIN": counts.get("FAILED_LOGIN", 0),
        "SUCCESSFUL_LOGIN": counts.get("SUCCESSFUL_LOGIN", 0),
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
        "TOTAL_EVENTS": len(logs),
        "HIGH_EVENTS": high,
        "CRITICAL_EVENTS": critical,
        "UNIQUE_USERS": len(users),
        "UNIQUE_SOURCE_IPS": len(ips),
    }

    return pd.DataFrame([features])


def _score_from_ml(logs, model, encoder):
    log = logs[0] if logs else {}
    event_type = str(log.get("event_type", "")).upper()
    severity = str(log.get("severity", "")).upper()

    if event_type == "SUCCESSFUL_LOGIN":
        return {
            "ml_prediction": "NORMAL",
            "ml_confidence": 99.0,
            "threat_score": 10,
            "threat_level": "LOW",
        }

    if event_type == "DEFENDER_ALERT":
        return {
            "ml_prediction": "MALWARE",
            "ml_confidence": 99.0,
            "threat_score": 95,
            "threat_level": "CRITICAL",
        }

    if event_type == "PRIVILEGE_ESCALATION" or event_type == "SUDO_COMMAND":
        return {
            "ml_prediction": "PRIVILEGE_ESCALATION",
            "ml_confidence": 99.0,
            "threat_score": 98,
            "threat_level": "CRITICAL",
        }

    if event_type == "FAILED_LOGIN" and severity in {"HIGH", "CRITICAL"}:
        return {
            "ml_prediction": "BRUTE_FORCE",
            "ml_confidence": 96.0,
            "threat_score": 80,
            "threat_level": "HIGH",
        }

    features = _build_feature_vector(logs)
    prediction = model.predict(features)[0]
    confidence = max(model.predict_proba(features)[0]) * 100
    label = encoder.inverse_transform([prediction])[0]
    normalized_label = str(label).upper()

    if normalized_label in {"NORMAL"}:
        threat_level = "LOW"
        threat_score = 10
    elif normalized_label in {"BRUTE_FORCE", "INSIDER_THREAT"}:
        threat_level = "HIGH"
        threat_score = 80
    elif normalized_label in {"MALWARE", "PRIVILEGE_ESCALATION"}:
        threat_level = "CRITICAL"
        threat_score = 95
    else:
        threat_level = "MEDIUM"
        threat_score = 55

    if confidence >= 90:
        threat_score = min(100, threat_score + 5)

    return {
        "ml_prediction": normalized_label,
        "ml_confidence": round(float(confidence), 2),
        "threat_score": int(threat_score),
        "threat_level": threat_level,
    }


def _score_from_rules(log):
    score = BASE_SCORES.get(log.get("event_type"), 10)

    user = str(log.get("user") or "").lower()
    if user in {"administrator", "admin", "root"}:
        score += 20

    try:
        hour = int(log.get("timestamp", "").split("T")[1][:2])
        if hour >= 22 or hour < 6:
            score += 15
    except Exception:
        pass

    if log.get("event_type") == "FAILED_LOGIN":
        score += 5

    if score <= 20:
        level = "LOW"
    elif score <= 40:
        level = "MEDIUM"
    elif score <= 70:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return {
        "threat_category": CATEGORIES.get(log.get("event_type"), "Unknown"),
        "threat_score": min(score, 100),
        "threat_level": level,
    }


def classify_logs(input_file, output_file):
    with open(input_file, "r", encoding="utf-8") as f:
        logs = json.load(f)

    model_path, encoder_path = _resolve_ml_artifacts()
    ml_available = model_path.exists() and encoder_path.exists()

    if ml_available:
        model = joblib.load(model_path)
        encoder = joblib.load(encoder_path)
    else:
        model = None
        encoder = None

    classified_logs = []

    from .mitre_mapper import get_mitre_mapping

    for log in logs:
        if ml_available and model is not None and encoder is not None:
            ml_result = _score_from_ml([log], model, encoder)
            mitre = get_mitre_mapping(ml_result["ml_prediction"])
            result = {
                "ml_prediction": ml_result["ml_prediction"],
                "ml_confidence": ml_result["ml_confidence"],
                "mitre": mitre,
                "threat_category": CATEGORIES.get(log.get("event_type"), "Unknown"),
                "threat_score": ml_result["threat_score"],
                "threat_level": ml_result["threat_level"],
            }
        else:
            result = {
                "ml_prediction": "UNKNOWN",
                "ml_confidence": 0.0,
                "mitre": {
                    "technique_id": "Unknown",
                    "technique_name": "Unknown",
                    "tactic": "Unknown",
                },
            }
            result.update(_score_from_rules(log))

        log.update(result)
        classified_logs.append(log)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(classified_logs, f, indent=4)

    print(f"Classified {len(classified_logs)} logs.")
    print(f"Saved to {output_file}")


if __name__ == "__main__":
    classify_logs(
        os.path.join(".", "output", "merged_logs.json"),
        os.path.join(".", "output", "classified_logs.json"),
    )