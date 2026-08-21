import json
import os
from collections import Counter
from pathlib import Path

import joblib
import pandas as pd


# ============================================================
# THREAT CATEGORY MAPPING
# ============================================================

CATEGORIES = {
    "LOGON_SUCCESS": "Authentication",
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


# ============================================================
# BASE THREAT SCORES
# ============================================================

BASE_SCORES = {
    "LOGON_SUCCESS": 5,
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


# ============================================================
# ML ARTIFACT PATHS
# ============================================================

def _resolve_ml_artifacts():
    """
    Return paths to the trained ML model and label encoder.
    """

    # classifier.py:
    # backend/analyzer/ingestion/classifier.py
    #
    # parents[2] = backend
    backend_dir = Path(__file__).resolve().parents[2]

    ml_dir = (
        backend_dir
        / "ML Aegis"
        / "ml"
    )

    model_path = (
        ml_dir
        / "model.pkl"
    )

    encoder_path = (
        ml_dir
        / "label_encoder.pkl"
    )

    return (
        model_path,
        encoder_path
    )


# ============================================================
# ATOMIC JSON WRITER
# ============================================================

def _atomic_json_write(path, data):
    """
    Safely write JSON.

    The new content is written completely to a temporary file
    before replacing the real output file.

    This prevents other parts of AegisGuard from seeing an
    empty or partially-written classified_logs.json.
    """

    path = Path(path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    temp_path = path.with_suffix(
        path.suffix + ".tmp"
    )

    try:

        with open(
            temp_path,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                data,
                f,
                indent=4,
                default=str
            )

            # Force Python buffer to disk
            f.flush()

            os.fsync(
                f.fileno()
            )

        # Atomic replacement
        os.replace(
            temp_path,
            path
        )

    except Exception:

        # Clean temporary file if something fails
        try:

            if temp_path.exists():

                temp_path.unlink()

        except Exception:

            pass

        raise


# ============================================================
# FEATURE VECTOR
# ============================================================

def _build_feature_vector(logs):

    counts = Counter(
        log.get(
            "event_type",
            ""
        )
        for log in logs
    )

    users = {
        log.get("user")
        for log in logs
        if log.get("user")
    }

    ips = {
        log.get("source_ip")
        for log in logs
        if log.get("source_ip")
    }

    high = sum(

        1
        for log in logs

        if str(
            log.get(
                "severity",
                ""
            )
        ).upper() == "HIGH"
    )

    critical = sum(

        1
        for log in logs

        if str(
            log.get(
                "severity",
                ""
            )
        ).upper() == "CRITICAL"
    )

    features = {

        "FAILED_LOGIN":
            counts.get(
                "FAILED_LOGIN",
                0
            ),

        "LOGON_SUCCESS":
            counts.get(
                "LOGON_SUCCESS",
                0
            ),

        "AUTHENTICATION_FAILURE":
            counts.get(
                "AUTHENTICATION_FAILURE",
                0
            ),

        "SUDO_COMMAND":
            counts.get(
                "SUDO_COMMAND",
                0
            ),

        "PRIVILEGE_ESCALATION":
            counts.get(
                "PRIVILEGE_ESCALATION",
                0
            ),

        "FILE_MODIFIED":
            counts.get(
                "FILE_MODIFIED",
                0
            ),

        "FILE_DELETED":
            counts.get(
                "FILE_DELETED",
                0
            ),

        "USB_CONNECTED":
            counts.get(
                "USB_CONNECTED",
                0
            ),

        "DEFENDER_ALERT":
            counts.get(
                "DEFENDER_ALERT",
                0
            ),

        "PASSWORD_CHANGED":
            counts.get(
                "PASSWORD_CHANGED",
                0
            ),

        "USER_CREATED":
            counts.get(
                "USER_CREATED",
                0
            ),

        "USER_DELETED":
            counts.get(
                "USER_DELETED",
                0
            ),

        "KERNEL_EVENT":
            counts.get(
                "KERNEL_EVENT",
                0
            ),

        "TOTAL_EVENTS":
            len(logs),

        "HIGH_EVENTS":
            high,

        "CRITICAL_EVENTS":
            critical,

        "UNIQUE_USERS":
            len(users),

        "UNIQUE_SOURCE_IPS":
            len(ips),
    }

    return pd.DataFrame(
        [features]
    )


# ============================================================
# MACHINE LEARNING SCORING
# ============================================================

def _score_from_ml(
    logs,
    model,
    encoder
):

    log = (
        logs[0]
        if logs
        else {}
    )

    event_type = str(
        log.get(
            "event_type",
            ""
        )
    ).upper()

    severity = str(
        log.get(
            "severity",
            ""
        )
    ).upper()

    # --------------------------------------------------------
    # Canonical Windows successful login
    # --------------------------------------------------------

    if event_type == "LOGON_SUCCESS":

        return {
            "ml_prediction": "NORMAL",
            "ml_confidence": 99.0,
            "threat_score": 10,
            "threat_level": "LOW",
        }

    # --------------------------------------------------------
    # Defender / malware
    # --------------------------------------------------------

    if event_type == "DEFENDER_ALERT":

        return {
            "ml_prediction": "MALWARE",
            "ml_confidence": 99.0,
            "threat_score": 95,
            "threat_level": "CRITICAL",
        }

    # --------------------------------------------------------
    # Privilege escalation
    # --------------------------------------------------------

    if event_type in (
        "PRIVILEGE_ESCALATION",
        "SUDO_COMMAND",
        "SUDO_EXECUTED",
    ):

        return {
            "ml_prediction":
                "PRIVILEGE_ESCALATION",

            "ml_confidence":
                99.0,

            "threat_score":
                98,

            "threat_level":
                "CRITICAL",
        }

    # --------------------------------------------------------
    # Failed login
    # --------------------------------------------------------

    if (
        event_type
        in (
            "FAILED_LOGIN",
            "AUTHENTICATION_FAILURE",
        )
        and
        severity
        in (
            "HIGH",
            "CRITICAL",
        )
    ):

        return {
            "ml_prediction":
                "BRUTE_FORCE",

            "ml_confidence":
                96.0,

            "threat_score":
                80,

            "threat_level":
                "HIGH",
        }

    # --------------------------------------------------------
    # ML model inference
    # --------------------------------------------------------

    features = _build_feature_vector(
        logs
    )

    prediction = model.predict(
        features
    )[0]

    probability = model.predict_proba(
        features
    )[0]

    confidence = (
        max(probability)
        *
        100
    )

    label = encoder.inverse_transform(
        [prediction]
    )[0]

    normalized_label = str(
        label
    ).upper()

    # --------------------------------------------------------
    # Threat level
    # --------------------------------------------------------

    if normalized_label == "NORMAL":

        threat_level = "LOW"
        threat_score = 10

    elif normalized_label in (
        "BRUTE_FORCE",
        "INSIDER_THREAT",
    ):

        threat_level = "HIGH"
        threat_score = 80

    elif normalized_label in (
        "MALWARE",
        "PRIVILEGE_ESCALATION",
    ):

        threat_level = "CRITICAL"
        threat_score = 95

    else:

        threat_level = "MEDIUM"
        threat_score = 55

    if confidence >= 90:

        threat_score = min(
            100,
            threat_score + 5
        )

    return {

        "ml_prediction":
            normalized_label,

        "ml_confidence":
            round(
                float(confidence),
                2
            ),

        "threat_score":
            int(threat_score),

        "threat_level":
            threat_level,
    }


# ============================================================
# RULE-BASED FALLBACK
# ============================================================

def _score_from_rules(log):

    event_type = str(
        log.get(
            "event_type",
            ""
        )
    ).upper()

    severity = str(
        log.get(
            "severity",
            ""
        )
    ).upper()

    score = BASE_SCORES.get(
        event_type,
        10
    )

    # --------------------------------------------------------
    # Privileged user adjustment
    # --------------------------------------------------------

    user = str(
        log.get(
            "user"
        )
        or
        ""
    ).lower()

    if user in {
        "administrator",
        "admin",
        "root",
    }:

        score += 20

    # --------------------------------------------------------
    # Off-hours adjustment
    # --------------------------------------------------------

    try:

        timestamp = str(
            log.get(
                "timestamp",
                ""
            )
        )

        if "T" in timestamp:

            hour = int(
                timestamp
                .split("T")[1][:2]
            )

        else:

            hour = int(
                timestamp
                .split(" ")[1][:2]
            )

        if (
            hour >= 22
            or
            hour < 6
        ):

            score += 15

    except Exception:

        pass

    # --------------------------------------------------------
    # Failed login adjustment
    # --------------------------------------------------------

    if event_type == "FAILED_LOGIN":

        score += 5

    # --------------------------------------------------------
    # Threat level
    # --------------------------------------------------------

    if score <= 20:

        level = "LOW"

    elif score <= 40:

        level = "MEDIUM"

    elif score <= 70:

        level = "HIGH"

    else:

        level = "CRITICAL"

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    if event_type == "LOGON_SUCCESS":

        pred = "NORMAL"

    elif event_type == "DEFENDER_ALERT":

        pred = "MALWARE"

    elif event_type in (
        "PRIVILEGE_ESCALATION",
        "SUDO_COMMAND",
        "SUDO_EXECUTED",
    ):

        pred = (
            "PRIVILEGE_ESCALATION"
        )

    elif event_type in (
        "FAILED_LOGIN",
        "AUTHENTICATION_FAILURE",
    ):

        pred = "BRUTE_FORCE"

    elif (
        event_type == "USB_CONNECTED"
        and
        severity in (
            "HIGH",
            "CRITICAL",
        )
    ):

        pred = "USB_THREAT"

    else:

        pred = (
            "NORMAL"
            if level == "LOW"
            else "UNKNOWN"
        )

    return {

        "ml_prediction":
            pred,

        "threat_category":
            CATEGORIES.get(
                event_type,
                "Unknown"
            ),

        "threat_score":
            min(
                score,
                100
            ),

        "threat_level":
            level,
    }


# ============================================================
# CLASSIFY LOGS
# ============================================================

def classify_logs(
    input_file,
    output_file
):

    # --------------------------------------------------------
    # READ MERGED LOGS
    # --------------------------------------------------------

    try:

        with open(
            input_file,
            "r",
            encoding="utf-8"
        ) as f:

            logs = json.load(f)

    except json.JSONDecodeError as e:

        raise RuntimeError(
            f"Invalid merged logs JSON "
            f"'{input_file}': {e}"
        ) from e

    if not isinstance(
        logs,
        list
    ):

        raise ValueError(
            "Merged logs must contain "
            "a JSON list."
        )

    # --------------------------------------------------------
    # ML MODEL
    # --------------------------------------------------------

    model_path, encoder_path = (
        _resolve_ml_artifacts()
    )

    ml_available = (
        model_path.exists()
        and
        encoder_path.exists()
    )

    model = None
    encoder = None

    if ml_available:

        try:

            model = joblib.load(
                model_path
            )

            encoder = joblib.load(
                encoder_path
            )

        except Exception as exc:

            print(
                "ML model could not "
                f"be loaded: {exc}",
                flush=True
            )

            model = None
            encoder = None

    if (
        model is None
        or
        encoder is None
    ):

        ml_available = False

    # --------------------------------------------------------
    # MITRE IMPORT
    # --------------------------------------------------------

    try:

        from .mitre_mapper import (
            get_mitre_mapping
        )

    except ImportError:

        from backend.analyzer.ingestion.mitre_mapper import (
            get_mitre_mapping
        )

    # --------------------------------------------------------
    # CLASSIFY EVERY LOG
    # --------------------------------------------------------

    classified_logs = []

    for log in logs:

        if not isinstance(
            log,
            dict
        ):

            continue

        if (
            ml_available
            and
            model is not None
            and
            encoder is not None
        ):

            ml_result = _score_from_ml(
                [log],
                model,
                encoder
            )

            mitre = get_mitre_mapping(
                ml_result[
                    "ml_prediction"
                ]
            )

            result = {

                "ml_prediction":
                    ml_result[
                        "ml_prediction"
                    ],

                "ml_confidence":
                    ml_result[
                        "ml_confidence"
                    ],

                "mitre":
                    mitre,

                "threat_category":
                    CATEGORIES.get(
                        str(
                            log.get(
                                "event_type",
                                ""
                            )
                        ).upper(),
                        "Unknown"
                    ),

                "threat_score":
                    ml_result[
                        "threat_score"
                    ],

                "threat_level":
                    ml_result[
                        "threat_level"
                    ],
            }

        else:

            rule_res = (
                _score_from_rules(
                    log
                )
            )

            pred = rule_res.get(
                "ml_prediction",
                "UNKNOWN"
            )

            mitre = get_mitre_mapping(
                pred
            )

            result = {

                "ml_prediction":
                    pred,

                "ml_confidence":
                    0.0,

                "mitre":
                    mitre,
            }

            result.update(
                rule_res
            )

        # Preserve normalized log + add classification
        classified_log = dict(
            log
        )

        classified_log.update(
            result
        )

        classified_logs.append(
            classified_log
        )

    # --------------------------------------------------------
    # ATOMIC OUTPUT
    # --------------------------------------------------------

    _atomic_json_write(
        output_file,
        classified_logs
    )

    print(
        f"Classified "
        f"{len(classified_logs)} logs.",
        flush=True
    )

    print(
        f"Saved to "
        f"{output_file}",
        flush=True
    )

    return classified_logs


# ============================================================
# DIRECT EXECUTION
# ============================================================

if __name__ == "__main__":

    # classifier.py
    # ↓
    # ingestion
    # ↓
    # analyzer
    # ↓
    # backend
    # ↓
    # project root

    PROJECT_ROOT = (
        Path(__file__)
        .resolve()
        .parents[3]
    )

    INPUT_FILE = (
        PROJECT_ROOT
        / "output"
        / "merged_logs.json"
    )

    OUTPUT_FILE = (
        PROJECT_ROOT
        / "output"
        / "classified_logs.json"
    )

    classify_logs(
        str(INPUT_FILE),
        str(OUTPUT_FILE)
    )