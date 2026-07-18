import json
from collections import Counter
import pandas as pd
import joblib

# -----------------------------
# Load ML Model
# -----------------------------

model = joblib.load("model.pkl")
encoder = joblib.load("label_encoder.pkl")

# -----------------------------
# Load Classified Logs
# -----------------------------

with open("../output/classified_logs.json", "r") as f:
    logs = json.load(f)

# -----------------------------
# Feature Extraction
# -----------------------------

counts = Counter()

users = set()
ips = set()

high = 0
critical = 0

for log in logs:

    counts[log["event_type"]] += 1

    if log.get("user"):
        users.add(log["user"])

    if log.get("source_ip"):
        ips.add(log["source_ip"])

    severity = log.get("severity","").upper()

    if severity == "HIGH":
        high += 1

    elif severity == "CRITICAL":
        critical += 1

# -----------------------------
# Feature Vector
# -----------------------------

features = {

    "FAILED_LOGIN":
        counts["FAILED_LOGIN"],

    "SUCCESSFUL_LOGIN":
        counts["SUCCESSFUL_LOGIN"],

    "AUTHENTICATION_FAILURE":
        counts["AUTHENTICATION_FAILURE"],

    "SUDO_COMMAND":
        counts["SUDO_COMMAND"],

    "PRIVILEGE_ESCALATION":
        counts["PRIVILEGE_ESCALATION"],

    "FILE_MODIFIED":
        counts["FILE_MODIFIED"],

    "FILE_DELETED":
        counts["FILE_DELETED"],

    "USB_CONNECTED":
        counts["USB_CONNECTED"],

    "DEFENDER_ALERT":
        counts["DEFENDER_ALERT"],

    "PASSWORD_CHANGED":
        counts["PASSWORD_CHANGED"],

    "USER_CREATED":
        counts["USER_CREATED"],

    "USER_DELETED":
        counts["USER_DELETED"],

    "KERNEL_EVENT":
        counts["KERNEL_EVENT"],

    "TOTAL_EVENTS":
        len(logs),

    "HIGH_EVENTS":
        high,

    "CRITICAL_EVENTS":
        critical,

    "UNIQUE_USERS":
        len(users),

    "UNIQUE_SOURCE_IPS":
        len(ips)
}

X = pd.DataFrame([features])

# -----------------------------
# Prediction
# -----------------------------

prediction = model.predict(X)[0]

confidence = max(model.predict_proba(X)[0]) * 100

label = encoder.inverse_transform([prediction])[0]

print("="*60)
print("AEGISGUARD ML ANALYSIS")
print("="*60)
print()

print("Prediction :",label)
print("Confidence :",f"{confidence:.2f}%")

print("="*60)