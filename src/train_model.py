import os
import sys
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)


# Allow imports from src
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from feature_extraction import extract_features


# ============================================================
# CONFIGURATION
# ============================================================

DATASET_PATH = (
    "data/phiusiil+phishing+url+dataset/phishing_dataset.csv"
)

RANDOM_STATE = 42
TEST_SIZE = 0.20


# ============================================================
# LOAD DATASET
# ============================================================

def load_dataset():

    print("Loading dataset...")

    df = pd.read_csv(DATASET_PATH)

    print(f"Dataset loaded successfully.")
    print(f"Total rows: {len(df):,}")

    return df


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def prepare_data(df):

    print("\nExtracting URL features...")

    feature_rows = []

    for index, url in enumerate(df["URL"]):

        feature_rows.append(
            extract_features(url)
        )

        if (index + 1) % 10_000 == 0:
            print(f"Processed {index + 1:,} URLs")

    X = pd.DataFrame(feature_rows)

    # Dataset:
    # 1 = Legitimate
    # 0 = Phishing
    #
    # Convert to:
    # 0 = Legitimate
    # 1 = Phishing

    y = 1 - df["label"]

    return X, y


# ============================================================
# EVALUATE MODEL
# ============================================================

def evaluate_model(model_name, model, X_test, y_test):

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)

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

    matrix = confusion_matrix(
        y_test,
        predictions
    )

    print("\n" + "=" * 60)
    print(model_name)
    print("=" * 60)

    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1 Score : {f1:.4f}")

    print("\nConfusion Matrix:")
    print(matrix)

    return {
        "model": model_name,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("PHISHING URL DETECTION - MODEL TRAINING")
    print("=" * 60)

    # --------------------------------------------------------
    # Load data
    # --------------------------------------------------------

    df = load_dataset()

    # --------------------------------------------------------
    # Extract features
    # --------------------------------------------------------

    X, y = prepare_data(df)
    # --------------------------------------------------------
    # Domain-level train/test split
    # --------------------------------------------------------

    print("\nCreating domain-level train/test split...")

    groups = df["Domain"]

    group_splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE
    )

    train_idx, test_idx = next(
        group_splitter.split(X, y, groups=groups)
    )

    X_domain_train = X.iloc[train_idx]
    X_domain_test = X.iloc[test_idx]

    y_domain_train = y.iloc[train_idx]
    y_domain_test = y.iloc[test_idx]

    print(f"Training samples: {len(X_domain_train):,}")
    print(f"Testing samples : {len(X_domain_test):,}")

    print(
        f"Training domains: {groups.iloc[train_idx].nunique():,}"
    )

    print(
        f"Testing domains : {groups.iloc[test_idx].nunique():,}"
    )

    print("\nFeature matrix:")
    print(X.shape)

    print("\nTarget distribution:")
    print(y.value_counts())
    # --------------------------------------------------------
    # Domain-level Random Forest
    # --------------------------------------------------------

    print("\nTraining: Random Forest (Domain Split)")

    domain_rf = RandomForestClassifier(
        n_estimators=150,
        random_state=RANDOM_STATE,
        n_jobs=-1
    )

    domain_rf.fit(
        X_domain_train,
        y_domain_train
    )

    domain_predictions = domain_rf.predict(X_domain_test)

    print("\n" + "=" * 60)
    print("RANDOM FOREST - DOMAIN LEVEL VALIDATION")
    print("=" * 60)

    print(
        f"Accuracy : "
        f"{accuracy_score(y_domain_test, domain_predictions):.4f}"
    )

    print(
        f"Precision: "
        f"{precision_score(y_domain_test, domain_predictions, zero_division=0):.4f}"
    )

    print(
        f"Recall   : "
        f"{recall_score(y_domain_test, domain_predictions, zero_division=0):.4f}"
    )

    print(
        f"F1 Score : "
        f"{f1_score(y_domain_test, domain_predictions, zero_division=0):.4f}"
    )

    print("\nConfusion Matrix:")
    print(
        confusion_matrix(
            y_domain_test,
            domain_predictions
        )
    )
    # --------------------------------------------------------
    # Train/Test Split
    # --------------------------------------------------------

    print("\nCreating train/test split...")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    print(f"Training samples: {len(X_train):,}")
    print(f"Testing samples : {len(X_test):,}")

    # --------------------------------------------------------
    # Models
    # --------------------------------------------------------

    models = {

        "Logistic Regression": LogisticRegression(
            max_iter=1000,
            random_state=RANDOM_STATE
        ),

        "Random Forest": RandomForestClassifier(
            n_estimators=150,
            random_state=RANDOM_STATE,
            n_jobs=-1
        ),

        "Gradient Boosting": GradientBoostingClassifier(
            random_state=RANDOM_STATE
        ),
    }

    results = []

    # --------------------------------------------------------
    # Train and evaluate
    # --------------------------------------------------------

    for model_name, model in models.items():

        print("\nTraining:", model_name)

        model.fit(X_train, y_train)

        result = evaluate_model(
            model_name,
            model,
            X_test,
            y_test
        )

        results.append(result)

    # --------------------------------------------------------
    # Random Forest Feature Importance
    # --------------------------------------------------------

    if model_name == "Random Forest":

        feature_importance = pd.DataFrame({
            "feature": X.columns,
            "importance": model.feature_importances_
        })

        feature_importance = feature_importance.sort_values(
            by="importance",
            ascending=False
        )

        print("\n" + "=" * 60)
        print("RANDOM FOREST - FEATURE IMPORTANCE")
        print("=" * 60)

        print(
            feature_importance.to_string(index=False)
        )
            
    # --------------------------------------------------------
    # Save trained Random Forest
    # --------------------------------------------------------

    os.makedirs("models", exist_ok=True)

    joblib.dump(
        model,
        "models/phishing_model.pkl"
    )

    joblib.dump(
        list(X.columns),
        "models/feature_names.pkl"
    )

    print("\nRandom Forest model saved successfully.")
    print("Model: models/phishing_model.pkl")
    print("Features: models/feature_names.pkl")
    
    # --------------------------------------------------------
    # Compare models
    # --------------------------------------------------------

    results_df = pd.DataFrame(results)

    print("\n" + "=" * 60)
    print("MODEL COMPARISON")
    print("=" * 60)

    print(
        results_df.sort_values(
            by="f1",
            ascending=False
        ).to_string(index=False)
    )


if __name__ == "__main__":
    main()