import json
import os
import sys
import threading
from collections import Counter
from pathlib import Path

import joblib
import pandas as pd


_ml_cache_lock = threading.Lock()
_cached_model = None
_cached_encoder = None
_ml_cache_initialized = False


# ============================================================
# THREAT CATEGORY MAPPING
# ============================================================

CATEGORIES = {
    "LOGON_SUCCESS": "Authentication",
    "FAILED_LOGIN": "Authentication",
    "AUTHENTICATION_FAILURE": "Authentication",

    "SUDO_COMMAND": "Privilege Escalation",
    "SUDO_EXECUTED": "Privilege Escalation",
    "PRIVILEGE_ESCALATION": "Privilege Escalation",

    "USB_CONNECTED": "Device Activity",

    "FILE_MODIFIED": "File Activity",
    "FILE_DELETED": "File Activity",

    "DEFENDER_ALERT": "Malware",

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

    "FAILED_LOGIN": 80,
    "AUTHENTICATION_FAILURE": 80,

    "SUDO_COMMAND": 60,
    "SUDO_EXECUTED": 60,
    "PRIVILEGE_ESCALATION": 80,

    "USB_CONNECTED": 35,

    "FILE_MODIFIED": 15,
    "FILE_DELETED": 50,

    "DEFENDER_ALERT": 95,

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

    Source mode:
        <project>\\backend\\ML Aegis\\ml\\

    PyInstaller mode:
        <_MEIPASS>\\backend\\ML Aegis\\ml\\
    """

    # --------------------------------------------------------
    # PYINSTALLER / FROZEN MODE
    # --------------------------------------------------------

    if getattr(sys, "frozen", False):

        base_dir = Path(
            sys._MEIPASS
        )

        ml_dir = (
            base_dir
            / "backend"
            / "ML Aegis"
            / "ml"
        )

    # --------------------------------------------------------
    # NORMAL SOURCE MODE
    # --------------------------------------------------------

    else:

        # classifier.py:
        #
        # project/
        # └── backend/
        #     ├── analyzer/
        #     │   └── ingestion/
        #     │       └── classifier.py
        #     │
        #     └── ML Aegis/
        #         └── ml/
        #
        # parents[2] = backend/

        backend_dir = (
            Path(__file__)
            .resolve()
            .parents[2]
        )

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

    # --------------------------------------------------------
    # DEBUG INFORMATION
    # --------------------------------------------------------

    print(
        f"[Classifier] Frozen: "
        f"{getattr(sys, 'frozen', False)}",
        flush=True
    )

    if getattr(
        sys,
        "frozen",
        False
    ):

        print(
            f"[Classifier] _MEIPASS: "
            f"{sys._MEIPASS}",
            flush=True
        )

    print(
        f"[Classifier] ML directory: "
        f"{ml_dir}",
        flush=True
    )

    print(
        f"[Classifier] Model path: "
        f"{model_path}",
        flush=True
    )

    print(
        f"[Classifier] Model exists: "
        f"{model_path.exists()}",
        flush=True
    )

    print(
        f"[Classifier] Encoder path: "
        f"{encoder_path}",
        flush=True
    )

    print(
        f"[Classifier] Encoder exists: "
        f"{encoder_path.exists()}",
        flush=True
    )

    return (
        model_path,
        encoder_path
    )


def _get_cached_ml_artifacts():
    """Load the bundled model once per Analyzer process, not once per upload."""

    global _cached_model, _cached_encoder, _ml_cache_initialized

    if _ml_cache_initialized:
        return _cached_model, _cached_encoder

    with _ml_cache_lock:
        if _ml_cache_initialized:
            return _cached_model, _cached_encoder

        model_path, encoder_path = _resolve_ml_artifacts()
        if model_path.exists() and encoder_path.exists():
            try:
                print("[Classifier] Loading ML model...", flush=True)
                _cached_model = joblib.load(model_path)
                _cached_encoder = joblib.load(encoder_path)
                print("[Classifier] ML model loaded successfully.", flush=True)
                print("[Classifier] ML enabled.", flush=True)
            except Exception as exc:
                print(f"[Classifier] ML model could not be loaded: {exc}", flush=True)
                _cached_model = None
                _cached_encoder = None
        else:
            print("[Classifier] ML unavailable. Using rule-based fallback.", flush=True)

        _ml_cache_initialized = True
        return _cached_model, _cached_encoder


def warm_up_classifier():
    """Preload ML artifacts during Analyzer startup so uploads stay fast."""

    return _get_cached_ml_artifacts()


# ============================================================
# ATOMIC JSON WRITER
# ============================================================

def _atomic_json_write(
    path,
    data
):
    """
    Safely write JSON.

    The new file is fully written to a temporary file first.
    Only after the write succeeds is the original file replaced.

    This prevents other AegisGuard components from reading
    an empty or partially-written classified_logs.json.
    """

    path = Path(
        path
    )

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

            f.flush()

            os.fsync(
                f.fileno()
            )

        os.replace(
            temp_path,
            path
        )

    except Exception:

        try:

            if temp_path.exists():

                temp_path.unlink()

        except Exception:

            pass

        raise


# ============================================================
# FEATURE VECTOR
# ============================================================

def _build_feature_vector(
    logs
):
    """
    Build the feature vector expected by the trained ML model.
    """

    counts = Counter(
        str(
            log.get(
                "event_type",
                ""
            )
        ).upper()
        for log in logs
        if isinstance(
            log,
            dict
        )
    )

    users = {
        log.get(
            "user"
        )
        for log in logs
        if (
            isinstance(
                log,
                dict
            )
            and
            log.get(
                "user"
            )
        )
    }

    ips = {
        log.get(
            "source_ip"
        )
        for log in logs
        if (
            isinstance(
                log,
                dict
            )
            and
            log.get(
                "source_ip"
            )
        )
    }

    high = sum(
        1
        for log in logs
        if (
            isinstance(
                log,
                dict
            )
            and
            str(
                log.get(
                    "severity",
                    ""
                )
            ).upper()
            ==
            "HIGH"
        )
    )

    critical = sum(
        1
        for log in logs
        if (
            isinstance(
                log,
                dict
            )
            and
            str(
                log.get(
                    "severity",
                    ""
                )
            ).upper()
            ==
            "CRITICAL"
        )
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
            len(
                logs
            ),

        "HIGH_EVENTS":
            high,

        "CRITICAL_EVENTS":
            critical,

        "UNIQUE_USERS":
            len(
                users
            ),

        "UNIQUE_SOURCE_IPS":
            len(
                ips
            ),
    }

    return pd.DataFrame(
        [
            features
        ]
    )


# ============================================================
# MACHINE LEARNING SCORING
# ============================================================

def _score_from_ml(
    logs,
    model,
    encoder
):
    """
    Score one normalized event.

    Canonical high-value security events override ML inference
    so known Windows events cannot be incorrectly downgraded.
    """

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
    ).upper().strip()

    # --------------------------------------------------------
    # SUCCESSFUL LOGIN
    # --------------------------------------------------------

    if event_type == "LOGON_SUCCESS":

        return {
            "ml_prediction":
                "NORMAL",

            "ml_confidence":
                99.0,

            "threat_score":
                10,

            "threat_level":
                "LOW",
        }

    # --------------------------------------------------------
    # FAILED LOGIN / WINDOWS EVENT 4625
    #
    # Do NOT rely on Windows severity here.
    #
    # Windows Event 4625 may be reported as:
    #
    # severity = Information
    #
    # but event_type is still FAILED_LOGIN.
    # --------------------------------------------------------

    if event_type in {
        "FAILED_LOGIN",
        "AUTHENTICATION_FAILURE",
    }:

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
    # DEFENDER ALERT / MALWARE
    # --------------------------------------------------------

    if event_type == "DEFENDER_ALERT":

        return {
            "ml_prediction":
                "MALWARE",

            "ml_confidence":
                99.0,

            "threat_score":
                95,

            "threat_level":
                "CRITICAL",
        }

    # --------------------------------------------------------
    # PRIVILEGE ESCALATION
    # --------------------------------------------------------

    if event_type in {
        "PRIVILEGE_ESCALATION",
        "SUDO_COMMAND",
        "SUDO_EXECUTED",
    }:

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
    # ACTUAL ML MODEL INFERENCE
    # --------------------------------------------------------

    features = (
        _build_feature_vector(
            logs
        )
    )

    prediction = (
        model.predict(
            features
        )[0]
    )

    probability = (
        model.predict_proba(
            features
        )[0]
    )

    confidence = (
        max(
            probability
        )
        * 100
    )

    label = (
        encoder.inverse_transform(
            [
                prediction
            ]
        )[0]
    )

    normalized_label = str(
        label
    ).upper().strip()

    # --------------------------------------------------------
    # MODEL LABEL → RISK
    # --------------------------------------------------------

    if (
        normalized_label
        ==
        "NORMAL"
    ):

        threat_level = "LOW"
        threat_score = 10

    elif normalized_label in {
        "BRUTE_FORCE",
        "INSIDER_THREAT",
    }:

        threat_level = "HIGH"
        threat_score = 80

    elif normalized_label in {
        "MALWARE",
        "PRIVILEGE_ESCALATION",
    }:

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
                float(
                    confidence
                ),
                2
            ),

        "threat_score":
            int(
                threat_score
            ),

        "threat_level":
            threat_level,
    }


# ============================================================
# RULE-BASED FALLBACK
# ============================================================

def _score_from_rules(
    log
):
    """
    Rule-based fallback when the trained ML artifacts
    cannot be loaded.
    """

    event_type = str(
        log.get(
            "event_type",
            ""
        )
    ).upper().strip()

    score = BASE_SCORES.get(
        event_type,
        10
    )

    # --------------------------------------------------------
    # PRIVILEGED USER ADJUSTMENT
    # --------------------------------------------------------

    user = str(
        log.get(
            "user"
        )
        or ""
    ).lower()

    if user in {
        "administrator",
        "admin",
        "root",
    }:

        score += 20

    # --------------------------------------------------------
    # OFF-HOURS ADJUSTMENT
    # --------------------------------------------------------

    try:

        timestamp = str(
            log.get(
                "timestamp",
                ""
            )
        )

        hour = None

        if "T" in timestamp:

            hour = int(
                timestamp
                .split("T")[1][:2]
            )

        elif " " in timestamp:

            hour = int(
                timestamp
                .split(" ")[1][:2]
            )

        if (
            hour is not None
            and (
                hour >= 22
                or hour < 6
            )
        ):

            score += 15

    except Exception:

        pass

    # --------------------------------------------------------
    # CANONICAL PREDICTION
    # --------------------------------------------------------

    if event_type == "LOGON_SUCCESS":

        pred = "NORMAL"
        score = 10
        level = "LOW"

    elif event_type in {
        "FAILED_LOGIN",
        "AUTHENTICATION_FAILURE",
    }:

        pred = "BRUTE_FORCE"

        score = max(
            score,
            80
        )

        level = "HIGH"

    elif event_type == "DEFENDER_ALERT":

        pred = "MALWARE"

        score = max(
            score,
            95
        )

        level = "CRITICAL"

    elif event_type in {
        "PRIVILEGE_ESCALATION",
        "SUDO_COMMAND",
        "SUDO_EXECUTED",
    }:

        pred = (
            "PRIVILEGE_ESCALATION"
        )

        score = max(
            score,
            80
        )

        level = "CRITICAL"

    else:

        # ----------------------------------------------------
        # GENERIC SCORE → THREAT LEVEL
        # ----------------------------------------------------

        if score <= 20:

            level = "LOW"

        elif score <= 40:

            level = "MEDIUM"

        elif score <= 70:

            level = "HIGH"

        else:

            level = "CRITICAL"

        pred = (
            "NORMAL"
            if level == "LOW"
            else "UNKNOWN"
        )

    score = min(
        int(
            score
        ),
        100
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
            score,

        "threat_level":
            level,
    }


def classify_records(logs):
    """Classify an in-memory batch without reading or rewriting history."""

    try:
        from .mitre_mapper import get_mitre_mapping
    except ImportError:
        from backend.analyzer.ingestion.mitre_mapper import get_mitre_mapping

    model, encoder = _get_cached_ml_artifacts()
    ml_available = model is not None and encoder is not None
    classified_logs = []

    for log in logs:
        if not isinstance(log, dict):
            continue

        normalized_log = dict(log)
        event_type = str(normalized_log.get("event_type", "")).upper().strip()
        normalized_log["event_type"] = event_type

        if ml_available:
            score = _score_from_ml([normalized_log], model, encoder)
            result = {
                "ml_prediction": score["ml_prediction"],
                "ml_confidence": score["ml_confidence"],
                "mitre": get_mitre_mapping(score["ml_prediction"]),
                "threat_category": CATEGORIES.get(event_type, "Unknown"),
                "threat_score": score["threat_score"],
                "threat_level": score["threat_level"],
            }
        else:
            score = _score_from_rules(normalized_log)
            result = {
                "ml_prediction": score.get("ml_prediction", "UNKNOWN"),
                "ml_confidence": 0.0,
                "mitre": get_mitre_mapping(score.get("ml_prediction", "UNKNOWN")),
                "threat_category": score.get(
                    "threat_category", CATEGORIES.get(event_type, "Unknown")
                ),
                "threat_score": score.get("threat_score", 10),
                "threat_level": score.get("threat_level", "LOW"),
            }

        normalized_log.update(result)
        classified_logs.append(normalized_log)

    return classified_logs


# ============================================================
# CLASSIFY LOGS
# ============================================================

def classify_logs(
    input_file,
    output_file
):
    """
    Read merged logs, classify them, add MITRE information,
    and atomically save classified_logs.json.
    """

    # --------------------------------------------------------
    # READ MERGED LOGS
    # --------------------------------------------------------

    try:

        with open(
            input_file,
            "r",
            encoding="utf-8"
        ) as f:

            logs = json.load(
                f
            )

    except FileNotFoundError as exc:

        raise RuntimeError(
            "Merged logs file "
            f"not found: {input_file}"
        ) from exc

    except json.JSONDecodeError as exc:

        raise RuntimeError(
            "Invalid merged logs JSON "
            f"'{input_file}': {exc}"
        ) from exc

    if not isinstance(
        logs,
        list
    ):

        raise ValueError(
            "Merged logs must "
            "contain a JSON list."
        )

    model, encoder = _get_cached_ml_artifacts()
    ml_available = model is not None and encoder is not None

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

        # ----------------------------------------------------
        # CANONICAL EVENT TYPE
        # ----------------------------------------------------

        event_type = str(
            log.get(
                "event_type",
                ""
            )
        ).upper().strip()

        normalized_log = dict(
            log
        )

        normalized_log[
            "event_type"
        ] = event_type

        # ----------------------------------------------------
        # ML PATH
        # ----------------------------------------------------

        if (
            ml_available
            and model is not None
            and encoder is not None
        ):

            ml_result = (
                _score_from_ml(
                    [
                        normalized_log
                    ],
                    model,
                    encoder
                )
            )

            prediction = (
                ml_result[
                    "ml_prediction"
                ]
            )

            mitre = (
                get_mitre_mapping(
                    prediction
                )
            )

            result = {
                "ml_prediction":
                    prediction,

                "ml_confidence":
                    ml_result[
                        "ml_confidence"
                    ],

                "mitre":
                    mitre,

                "threat_category":
                    CATEGORIES.get(
                        event_type,
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

        # ----------------------------------------------------
        # RULE FALLBACK
        # ----------------------------------------------------

        else:

            rule_result = (
                _score_from_rules(
                    normalized_log
                )
            )

            prediction = (
                rule_result.get(
                    "ml_prediction",
                    "UNKNOWN"
                )
            )

            mitre = (
                get_mitre_mapping(
                    prediction
                )
            )

            result = {
                "ml_prediction":
                    prediction,

                "ml_confidence":
                    0.0,

                "mitre":
                    mitre,

                "threat_category":
                    rule_result.get(
                        "threat_category",
                        CATEGORIES.get(
                            event_type,
                            "Unknown"
                        )
                    ),

                "threat_score":
                    rule_result.get(
                        "threat_score",
                        10
                    ),

                "threat_level":
                    rule_result.get(
                        "threat_level",
                        "LOW"
                    ),
            }

        # ----------------------------------------------------
        # PRESERVE ORIGINAL LOG + CLASSIFICATION
        # ----------------------------------------------------

        classified_log = dict(
            normalized_log
        )

        classified_log.update(
            result
        )

        classified_logs.append(
            classified_log
        )

    # --------------------------------------------------------
    # ATOMIC OUTPUT WRITE
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

    # --------------------------------------------------------
    # SOURCE MODE
    #
    # classifier.py
    # backend/analyzer/ingestion/classifier.py
    #
    # parents[3] = project root
    # --------------------------------------------------------

    if getattr(
        sys,
        "frozen",
        False
    ):

        # This section normally won't be used because the
        # Analyzer EXE starts through app.py.
        PROJECT_ROOT = (
            Path(
                sys.executable
            )
            .resolve()
            .parent
        )

    else:

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
        str(
            INPUT_FILE
        ),
        str(
            OUTPUT_FILE
        )
    )
