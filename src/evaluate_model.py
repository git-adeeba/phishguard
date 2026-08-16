import os
import sys

import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

# Allow imports from src
sys.path.append(
    os.path.dirname(os.path.abspath(__file__))
)

from feature_extraction import extract_features


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

DATASET_PATH = os.path.join(
    BASE_DIR,
    "data",
    "phiusiil+phishing+url+dataset",
    "phishing_dataset.csv"
)

RANDOM_STATE = 42


# ============================================================
# LOAD DATASET
# ============================================================

print("=" * 60)
print("PHISHING URL DETECTION - ERROR ANALYSIS")
print("=" * 60)

print("\nLoading dataset...")

df = pd.read_csv(DATASET_PATH)

print(f"Total rows: {len(df):,}")


# ============================================================
# FEATURE EXTRACTION
# ============================================================

print("\nExtracting URL features...")

feature_rows = []

for index, url in enumerate(df["URL"]):

    feature_rows.append(
        extract_features(url)
    )

    if (index + 1) % 10_000 == 0:
        print(
            f"Processed {index + 1:,} URLs"
        )

X = pd.DataFrame(feature_rows)

# Dataset:
# 0 = Legitimate
# 1 = Phishing
#
# Our ML target:
# 0 = Legitimate
# 1 = Phishing

y = 1 - df["label"]


# ============================================================
# DOMAIN-LEVEL SPLIT
# ============================================================

print("\nCreating domain-level split...")

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=RANDOM_STATE
)

train_idx, test_idx = next(
    splitter.split(
        X,
        y,
        groups=df["Domain"]
    )
)

X_train = X.iloc[train_idx]
X_test = X.iloc[test_idx]

y_train = y.iloc[train_idx]
y_test = y.iloc[test_idx]

print(
    f"Training samples: {len(X_train):,}"
)

print(
    f"Testing samples : {len(X_test):,}"
)


# ============================================================
# TRAIN RANDOM FOREST
# ============================================================

print("\nTraining Random Forest...")

model = RandomForestClassifier(
    n_estimators=150,
    random_state=RANDOM_STATE,
    n_jobs=-1
)

model.fit(
    X_train,
    y_train
)


# ============================================================
# PREDICTIONS
# ============================================================

print("\nGenerating predictions...")

predictions = model.predict(X_test)


# ============================================================
# PERFORMANCE
# ============================================================

accuracy = accuracy_score(
    y_test,
    predictions
)

precision = precision_score(
    y_test,
    predictions,
    zero_division=0
)

recall = recall_score(
    y_test,
    predictions,
    zero_division=0
)

f1 = f1_score(
    y_test,
    predictions,
    zero_division=0
)

print("\n" + "=" * 60)
print("MODEL PERFORMANCE")
print("=" * 60)

print(f"Accuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")


# ============================================================
# CONFUSION MATRIX
# ============================================================

matrix = confusion_matrix(
    y_test,
    predictions
)

print("\nConfusion Matrix:")
print(matrix)

print("""
Matrix meaning:

[[TN  FP]
 [FN  TP]]

TN = Legitimate correctly detected
FP = Legitimate incorrectly detected as phishing
FN = Phishing incorrectly detected as legitimate
TP = Phishing correctly detected
""")


# ============================================================
# CLASSIFICATION REPORT
# ============================================================

print("\n" + "=" * 60)
print("CLASSIFICATION REPORT")
print("=" * 60)

print(
    classification_report(
        y_test,
        predictions,
        target_names=[
            "Legitimate",
            "Phishing"
        ],
        zero_division=0
    )
)


# ============================================================
# ERROR ANALYSIS DATAFRAME
# ============================================================

results = df.iloc[test_idx].copy()

results["actual"] = y_test.values

results["predicted"] = predictions

results["correct"] = (
    results["actual"] ==
    results["predicted"]
)


# ============================================================
# FALSE POSITIVES
# ============================================================

false_positives = results[
    (results["actual"] == 0) &
    (results["predicted"] == 1)
]

print("\n" + "=" * 60)
print("FALSE POSITIVES")
print("=" * 60)

print(
    f"Count: {len(false_positives)}"
)

print(
    "\nLegitimate URLs incorrectly classified "
    "as phishing:"
)

print(
    false_positives[
        ["URL", "Domain"]
    ].head(20).to_string(index=False)
)


# ============================================================
# FALSE NEGATIVES
# ============================================================

false_negatives = results[
    (results["actual"] == 1) &
    (results["predicted"] == 0)
]

print("\n" + "=" * 60)
print("FALSE NEGATIVES")
print("=" * 60)

print(
    f"Count: {len(false_negatives)}"
)

print(
    "\nPhishing URLs incorrectly classified "
    "as legitimate:"
)

print(
    false_negatives[
        ["URL", "Domain"]
    ].head(20).to_string(index=False)
)