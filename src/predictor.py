import os
import sys
import joblib
import pandas as pd

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

MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "phishing_model.pkl"
)

FEATURE_PATH = os.path.join(
    BASE_DIR,
    "models",
    "feature_names.pkl"
)


# ============================================================
# LOAD MODEL
# ============================================================

model = joblib.load(MODEL_PATH)

feature_names = joblib.load(
    FEATURE_PATH
)


# ============================================================
# PREDICT URL
# ============================================================

def predict_url(url):

    # Extract URL features
    features = extract_features(url)

    # Convert to DataFrame
    X = pd.DataFrame(
        [features],
        columns=feature_names
    )

    # Prediction
    prediction = model.predict(X)[0]

    # Probability
    probabilities = model.predict_proba(X)[0]

    phishing_probability = probabilities[1]
    legitimate_probability = probabilities[0]

    # Our ML labels:
    # 0 = Legitimate
    # 1 = Phishing

    if prediction == 1:
        result = "Phishing"
    else:
        result = "Legitimate"

    return {
        "url": url,
        "prediction": result,
        "phishing_probability": phishing_probability,
        "legitimate_probability": legitimate_probability,
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_url = "https://bit.ly/3Example"

    result = predict_url(test_url)

    print("\n" + "=" * 60)
    print("PHISHING URL PREDICTION")
    print("=" * 60)

    print(f"URL: {result['url']}")
    print(f"Prediction: {result['prediction']}")

    print(
        f"Phishing Probability: "
        f"{result['phishing_probability']:.2%}"
    )

    print(
        f"Legitimate Probability: "
        f"{result['legitimate_probability']:.2%}"
    )