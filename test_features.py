from src.feature_extraction import extract_features
from src.rule_detector import analyze_url


test_urls = [
    "https://www.google.com",
    "https://login.example.com/account/verify",
    "http://192.168.1.10/login/verify",
    "https://bit.ly/3Example"
]


for url in test_urls:

    print("\n" + "=" * 60)
    print("URL:", url)

    features = extract_features(url)

    risk_score, risk_level, reasons = analyze_url(features)

    print("Risk Score:", risk_score)
    print("Risk Level:", risk_level)

    print("\nReasons:")

    if reasons:
        for reason in reasons:
            print("-", reason)
    else:
        print("- No significant risk indicators detected.")