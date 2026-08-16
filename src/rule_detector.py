def analyze_url(features):
    """
    Analyze extracted URL features and calculate a risk score.

    Returns:
        risk_score: numerical score from 0 to 100
        risk_level: Legitimate / Suspicious / High Risk
        reasons: list of reasons for the score
    """

    risk_score = 0
    reasons = []

    # --------------------------------------------------
    # 1. IP ADDRESS
    # --------------------------------------------------

    if features["has_ip_address"]:
        risk_score += 25
        reasons.append(
            "The URL uses an IP address instead of a domain name."
        )

    # --------------------------------------------------
    # 2. HTTPS
    # --------------------------------------------------

    if not features["uses_https"]:
        risk_score += 15
        reasons.append(
            "The URL does not use HTTPS."
        )

    # --------------------------------------------------
    # 3. SUSPICIOUS KEYWORDS
    # --------------------------------------------------

    keyword_count = features["num_suspicious_keywords"]

    if keyword_count >= 3:
        risk_score += 15
        reasons.append(
            f"The URL contains {keyword_count} suspicious keywords."
        )

    elif keyword_count > 0:
        risk_score += 7
        reasons.append(
            f"The URL contains {keyword_count} suspicious keyword(s)."
        )

    # --------------------------------------------------
    # 4. URL SHORTENER
    # --------------------------------------------------

    if features["is_shortened"]:
        risk_score += 15
        reasons.append(
            "The URL uses a URL-shortening service."
        )

    # --------------------------------------------------
    # 5. VERY LONG URL
    # --------------------------------------------------

    if features["url_length"] > 100:
        risk_score += 10
        reasons.append(
            "The URL is unusually long."
        )

    # --------------------------------------------------
    # 6. EXCESSIVE SUBDOMAINS
    # --------------------------------------------------

    # Ignore normal www subdomain.
    if features["num_subdomains"] >= 3:
        risk_score += 10
        reasons.append(
            "The URL contains an unusually large number of subdomains."
        )

    # --------------------------------------------------
    # 7. @ SYMBOL
    # --------------------------------------------------

    if features["num_at_symbols"] > 0:
        risk_score += 15
        reasons.append(
            "The URL contains an '@' symbol, which can be used to obscure the actual destination."
        )

    # --------------------------------------------------
    # 8. EXCESSIVE SPECIAL CHARACTERS
    # --------------------------------------------------

    if features["num_special_characters"] > 15:
        risk_score += 10
        reasons.append(
            "The URL contains an unusually high number of special characters."
        )

    # --------------------------------------------------
    # 9. EXCESSIVE DIGITS
    # --------------------------------------------------

    if features["num_digits"] > 10:
        risk_score += 5
        reasons.append(
            "The URL contains an unusually high number of digits."
        )

    # --------------------------------------------------
    # 10. PERCENT ENCODING
    # --------------------------------------------------

    if features["has_percent_encoding"]:
        risk_score += 5
        reasons.append(
            "The URL contains percent-encoded characters."
        )

    # --------------------------------------------------
    # LIMIT SCORE TO 100
    # --------------------------------------------------

    risk_score = min(risk_score, 100)

    # --------------------------------------------------
    # CLASSIFICATION
    # --------------------------------------------------

    if risk_score >= 50:
        risk_level = "High Risk"

    elif risk_score >= 20:
        risk_level = "Suspicious"

    else:
         risk_level = "Low Risk"

    return risk_score, risk_level, reasons