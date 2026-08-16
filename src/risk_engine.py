import os
import sys

# Allow imports from src
sys.path.append(
    os.path.dirname(os.path.abspath(__file__))
)

from feature_extraction import extract_features
from rule_detector import analyze_url
from predictor import predict_url


# ============================================================
# RISK ENGINE
# ============================================================

def analyze_risk(url):

    # --------------------------------------------------------
    # Extract features
    # --------------------------------------------------------

    features = extract_features(url)

    # --------------------------------------------------------
    # Rule-based analysis
    # --------------------------------------------------------

    rule_score, rule_level, rule_reasons = analyze_url(
        features
    )

    # --------------------------------------------------------
    # Machine Learning analysis
    # --------------------------------------------------------

    ml_result = predict_url(url)

    phishing_probability = (
        ml_result["phishing_probability"]
    )

    # Convert probability to 0-100
    ml_score = phishing_probability * 100

    # --------------------------------------------------------
    # Combine ML + Rule scores
    # --------------------------------------------------------

    final_score = (
        (ml_score * 0.70) +
        (rule_score * 0.30)
    )

    final_score = round(
        min(final_score, 100),
        2
    )

    # --------------------------------------------------------
    # Final risk level
    # --------------------------------------------------------

    if final_score >= 70:
        risk_level = "High Risk"

    elif final_score >= 40:
        risk_level = "Suspicious"

    elif final_score >= 20:
        risk_level = "Low Risk"

    else:
        risk_level = "Legitimate"

    # --------------------------------------------------------
    # Combine reasons
    # --------------------------------------------------------

    reasons = []

    # ML reason
    if phishing_probability >= 0.70:

        reasons.append(
            "The machine-learning model strongly "
            "classifies this URL as phishing."
        )

    elif phishing_probability >= 0.40:

        reasons.append(
            "The machine-learning model detected "
            "moderate phishing risk."
        )

    # Rule-based reasons
    reasons.extend(rule_reasons)

    # No reasons
    if not reasons:

        reasons.append(
            "No significant risk indicators detected."
        )

    # Remove duplicates
    reasons = list(dict.fromkeys(reasons))

    # --------------------------------------------------------
    # Return final analysis
    # --------------------------------------------------------

    return {
        "url": url,

        "prediction":
            ml_result["prediction"],

        "phishing_probability":
            phishing_probability,

        "legitimate_probability":
            ml_result["legitimate_probability"],

        "rule_score":
            rule_score,

        "rule_level":
            rule_level,

        "risk_score":
            final_score,

        "risk_level":
            risk_level,

        "reasons":
            reasons
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_url = (
        "https://bit.ly/3Example"
    )

    result = analyze_risk(test_url)

    print("\n" + "=" * 60)
    print("PHISHING URL SECURITY ANALYSIS")
    print("=" * 60)

    print(f"\nURL: {result['url']}")

    print("\n" + "-" * 60)
    print("ML ANALYSIS")
    print("-" * 60)

    print(
        f"Prediction: "
        f"{result['prediction']}"
    )

    print(
        f"Phishing Probability: "
        f"{result['phishing_probability']:.2%}"
    )

    print(
        f"Legitimate Probability: "
        f"{result['legitimate_probability']:.2%}"
    )

    print("\n" + "-" * 60)
    print("RULE-BASED ANALYSIS")
    print("-" * 60)

    print(
        f"Rule Score: "
        f"{result['rule_score']}/100"
    )

    print(
        f"Rule Level: "
        f"{result['rule_level']}"
    )

    print("\n" + "-" * 60)
    print("FINAL ASSESSMENT")
    print("-" * 60)

    print(
        f"Risk Score: "
        f"{result['risk_score']}/100"
    )

    print(
        f"Risk Level: "
        f"{result['risk_level']}"
    )

    print("\nReasons:")

    for reason in result["reasons"]:

        print(f"- {reason}")