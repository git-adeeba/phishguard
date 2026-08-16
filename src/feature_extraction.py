from urllib.parse import urlparse
import ipaddress
import re
import math


# ============================================================
# SUSPICIOUS KEYWORDS
# ============================================================

SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "security",
    "confirm",
    "confirmation",
    "password",
    "credential",
    "banking",
    "wallet",
    "payment",
    "unlock",
    "authenticate",
}


# ============================================================
# URL SHORTENERS
# ============================================================

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "buff.ly",
    "ow.ly",
    "shorturl.at",
}


# ============================================================
# SUSPICIOUS TLDs
# ============================================================

SUSPICIOUS_TLDS = {
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
}


# ============================================================
# COMMON BRANDS
# Used only to detect possible brand + suspicious-word
# combinations.
# ============================================================

COMMON_BRANDS = {
    "google",
    "microsoft",
    "apple",
    "amazon",
    "paypal",
    "facebook",
    "instagram",
    "linkedin",
    "netflix",
    "bank",
    "outlook",
    "icloud",
    "coinbase",
    "binance",
}


# ============================================================
# IP ADDRESS CHECK
# ============================================================

def is_ip_address(domain):
    """
    Check whether the domain is an IPv4 or IPv6 address.
    """

    try:
        ipaddress.ip_address(domain)
        return True

    except ValueError:
        return False


# ============================================================
# ENTROPY CALCULATION
# ============================================================

def calculate_entropy(value):
    """
    Calculate Shannon entropy of a string.

    Higher entropy can indicate a more random-looking
    domain name.
    """

    if not value:
        return 0.0

    length = len(value)

    frequencies = {}

    for character in value:
        frequencies[character] = (
            frequencies.get(character, 0) + 1
        )

    entropy = 0.0

    for count in frequencies.values():

        probability = count / length

        entropy -= probability * math.log2(probability)

    return entropy


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_features(url):
    """
    Extract cybersecurity-related features from a URL.

    Returns:
        Dictionary containing 35 numerical features.
    """

    parsed_url = urlparse(url)

    domain = parsed_url.netloc
    path = parsed_url.path
    query = parsed_url.query

    # Remove username/password and port from hostname
    hostname = parsed_url.hostname or ""

    hostname_lower = hostname.lower()

    # --------------------------------------------------------
    # Domain parts
    # --------------------------------------------------------

    domain_parts = (
        hostname.split(".")
        if hostname
        else []
    )

    # Ignore normal domain + TLD
    num_subdomains = max(
        len(domain_parts) - 2,
        0
    )

    # --------------------------------------------------------
    # Suspicious keywords
    # --------------------------------------------------------

    url_lower = url.lower()

    suspicious_keywords_found = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in url_lower
    ]

    # --------------------------------------------------------
    # URL shortener
    # --------------------------------------------------------

    is_shortened = (
        hostname_lower in URL_SHORTENERS
    )

    # --------------------------------------------------------
    # Special characters
    # --------------------------------------------------------

    special_characters = re.findall(
        r"[^a-zA-Z0-9]",
        url
    )

    # --------------------------------------------------------
    # Digits
    # --------------------------------------------------------

    digits = re.findall(
        r"\d",
        url
    )

    # ========================================================
    # NEW FEATURES
    # ========================================================

    # --------------------------------------------------------
    # 1. Domain entropy
    # --------------------------------------------------------

    domain_entropy = calculate_entropy(
        hostname_lower
    )

    # --------------------------------------------------------
    # 2. Digit-to-letter ratio
    # --------------------------------------------------------

    letters_in_domain = len(
        re.findall(
            r"[a-zA-Z]",
            hostname
        )
    )

    digits_in_domain = len(
        re.findall(
            r"\d",
            hostname
        )
    )

    if letters_in_domain > 0:
        digit_letter_ratio = (
            digits_in_domain /
            letters_in_domain
        )
    else:
        digit_letter_ratio = 0.0

    # --------------------------------------------------------
    # 3. Suspicious TLD
    # --------------------------------------------------------

    tld = (
        domain_parts[-1].lower()
        if domain_parts
        else ""
    )

    suspicious_tld = int(
        tld in SUSPICIOUS_TLDS
    )

    # --------------------------------------------------------
    # 4. Hyphen ratio
    # --------------------------------------------------------

    if len(hostname) > 0:
        hyphen_ratio = (
            hostname.count("-") /
            len(hostname)
        )
    else:
        hyphen_ratio = 0.0

    # --------------------------------------------------------
    # 5. Domain hyphen count
    # --------------------------------------------------------

    domain_hyphen_count = hostname.count("-")

    # --------------------------------------------------------
    # 6. Suspicious domain + path combination
    # --------------------------------------------------------

    suspicious_domain_path_combo = 0

    for keyword in SUSPICIOUS_KEYWORDS:

        if (
            keyword in hostname_lower
            and keyword in path.lower()
        ):
            suspicious_domain_path_combo = 1
            break

    # --------------------------------------------------------
    # 7. Brand impersonation
    # --------------------------------------------------------

    brand_impersonation = 0

    for brand in COMMON_BRANDS:

        if brand in hostname_lower:

            for keyword in SUSPICIOUS_KEYWORDS:

                if keyword in hostname_lower:

                    brand_impersonation = 1
                    break

        if brand_impersonation:
            break

    # --------------------------------------------------------
    # 8. Domain randomness
    #
    # Uses entropy as a normalized feature.
    # --------------------------------------------------------

    domain_randomness = int(
        domain_entropy >= 3.5
    )

    # --------------------------------------------------------
    # 9. Subdomain complexity
    # --------------------------------------------------------

    subdomain_complexity = (
        num_subdomains
        + hostname.count("-")
    )

    # --------------------------------------------------------
    # 10. Suspicious path depth
    # --------------------------------------------------------

    path_parts = [
        part
        for part in path.split("/")
        if part
    ]

    suspicious_path_depth = int(
        len(path_parts) >= 4
    )

    # ========================================================
    # FEATURE DICTIONARY
    # ========================================================

    features = {

        # ----------------------------------------------------
        # Existing 25 features
        # ----------------------------------------------------

        # Basic URL characteristics

        "url_length": len(url),

        "domain_length": len(domain),

        "path_length": len(path),

        "query_length": len(query),

        # Character counts

        "num_dots": url.count("."),

        "num_hyphens": url.count("-"),

        "num_underscores": url.count("_"),

        "num_slashes": url.count("/"),

        "num_question_marks": url.count("?"),

        "num_equals": url.count("="),

        "num_at_symbols": url.count("@"),

        "num_ampersands": url.count("&"),

        "num_percent_symbols": url.count("%"),

        "num_special_characters": len(
            special_characters
        ),

        "num_digits": len(digits),

        # Domain characteristics

        "num_subdomains": num_subdomains,

        "has_ip_address": int(
            is_ip_address(hostname)
        ),

        "has_port": int(
            parsed_url.port is not None
        ),

        # Protocol / security

        "uses_https": int(
            parsed_url.scheme.lower()
            == "https"
        ),

        # Suspicious URL characteristics

        "has_suspicious_keyword": int(
            len(suspicious_keywords_found) > 0
        ),

        "num_suspicious_keywords": len(
            suspicious_keywords_found
        ),

        # URL shortening

        "is_shortened": int(
            is_shortened
        ),

        # Encoding

        "has_percent_encoding": int(
            "%" in url
        ),

        # Additional structural checks

        "has_double_slash": int(
            "//" in path
        ),

        "has_fragment": int(
            bool(parsed_url.fragment)
        ),

        # ----------------------------------------------------
        # New 10 features
        # ----------------------------------------------------

        "domain_entropy": domain_entropy,

        "digit_letter_ratio": digit_letter_ratio,

        "suspicious_tld": suspicious_tld,

        "hyphen_ratio": hyphen_ratio,

        "domain_hyphen_count": domain_hyphen_count,

        "suspicious_domain_path_combo":
            suspicious_domain_path_combo,

        "brand_impersonation":
            brand_impersonation,

        "domain_randomness":
            domain_randomness,

        "subdomain_complexity":
            subdomain_complexity,

        "suspicious_path_depth":
            suspicious_path_depth,
    }

    return features