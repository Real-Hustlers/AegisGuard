import os
import joblib
import pandas as pd
from collections import Counter

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# ==========================================================
# Configuration
# ==========================================================

DATASET = "training_dataset.csv"

# ==========================================================
# Check Dataset
# ==========================================================

print("Looking for dataset...")
print(os.path.abspath(DATASET))

if not os.path.exists(DATASET):
    print("ERROR: training_dataset.csv not found!")
    exit()

df = pd.read_csv(DATASET)

print("\n========== RAW DATA ==========")
print(df.head())
print("==============================\n")

if df.empty:
    print("ERROR: Dataset is empty!")
    exit()

# ==========================================================
# Remove duplicate header rows
# ==========================================================

if "LABEL" in df.columns:
    df = df[df["LABEL"] != "LABEL"]
    df = df[df["LABEL"] != "UNKNOWN"]

# Remove duplicated machine header if present
if "machine_id" in df.columns:
    df = df[df["machine_id"] != "machine_id"]

if "machine" in df.columns:
    df = df[df["machine"] != "machine"]

print(f"Loaded {len(df)} investigations.\n")

if len(df) == 0:
    print("ERROR: No labelled data available.")
    exit()

# ==========================================================
# Column Mapping
# ==========================================================

rename_map = {
    "TOTAL_EVENTS": "TOTAL_EVENT",
    "HIGH_EVENTS": "HIGH_EVENT",
    "CRITICAL_EVENTS": "CRITICAL_EVENT",
    "UNIQUE_USERS": "UNIQUE_USER",
}

df.rename(columns=rename_map, inplace=True)

# ==========================================================
# Remove non-feature columns automatically
# ==========================================================

drop_columns = []

for col in [
    "machine",
    "machine_id",
    "hostname",
    "os",
    "LABEL"
]:
    if col in df.columns:
        drop_columns.append(col)

X = df.drop(columns=drop_columns)

y = df["LABEL"]

# ==========================================================
# Convert every feature into numeric
# ==========================================================

for column in X.columns:
    X[column] = pd.to_numeric(X[column], errors="coerce")

X = X.fillna(0)

# ==========================================================
# Print Features
# ==========================================================

print("Features Used")
print("--------------------------------")

for col in X.columns:
    print(col)

print()

# ==========================================================
# Label Distribution
# ==========================================================

print("Class Distribution")
print("--------------------------------")

counts = Counter(y)

for label, total in counts.items():
    print(f"{label:20} : {total}")

print()

# ==========================================================
# Encode Labels
# ==========================================================

encoder = LabelEncoder()
y_encoded = encoder.fit_transform(y)

# ==========================================================
# Train/Test Split
# ==========================================================

minimum = min(counts.values())

if minimum >= 2:

    print("Using Stratified Split\n")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y_encoded,
        test_size=0.20,
        random_state=42,
        stratify=y_encoded
    )

else:

    print("WARNING")
    print("Some classes contain only one sample.")
    print("Using normal train/test split.\n")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y_encoded,
        test_size=0.20,
        random_state=42
    )

# ==========================================================
# Train Model
# ==========================================================

print("Training Random Forest...\n")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)

# ==========================================================
# Predict
# ==========================================================

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

# ==========================================================
# Report
# ==========================================================

print("\nClassification Report")
print("----------------------------------------")

try:

    print(
        classification_report(
            y_test,
            predictions,
            target_names=encoder.classes_,
            zero_division=0
        )
    )

except Exception as e:

    print("Could not generate complete classification report.")
    print(e)

# ==========================================================
# Save Model
# ==========================================================

joblib.dump(model, "model.pkl")
joblib.dump(encoder, "label_encoder.pkl")

# ==========================================================
# Summary
# ==========================================================

print("\n" + "=" * 60)
print("MODEL TRAINED SUCCESSFULLY")
print("=" * 60)
print(f"Training Samples : {len(X_train)}")
print(f"Testing Samples  : {len(X_test)}")
print(f"Accuracy         : {accuracy*100:.2f}%")
print(f"Classes          : {list(encoder.classes_)}")
print("\nClass Counts")
print(counts)
print("\nSaved Files")
print("model.pkl")
print("label_encoder.pkl")
print("=" * 60)