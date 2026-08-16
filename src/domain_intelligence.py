import socket
from urllib.parse import urlparse

import whois


# ============================================================
# DOMAIN INTELLIGENCE
# ============================================================

def get_domain(url):
    """
    Extract the domain name from a URL.
    """

    try:
        parsed = urlparse(url)

        domain = parsed.netloc

        # Remove username/password if present
        if "@" in domain:
            domain = domain.split("@")[-1]

        # Remove port
        domain = domain.split(":")[0]

        return domain.lower()

    except Exception:
        return None


# ============================================================
# DOMAIN AGE
# ============================================================

def calculate_domain_age(created_date):
    """
    Calculate approximate domain age in days.
    """

    from datetime import datetime, timezone

    if not created_date:
        return None

    # WHOIS can return either a single date or a list
    if isinstance(created_date, list):
        created_date = created_date[0]

    try:

        if created_date.tzinfo is None:
            created_date = created_date.replace(
                tzinfo=timezone.utc
            )

        now = datetime.now(timezone.utc)

        age = now - created_date

        return age.days

    except Exception:
        return None


# ============================================================
# DNS / IP INFORMATION
# ============================================================

def get_ip_address(domain):

    if not domain:
        return None

    try:

        return socket.gethostbyname(domain)

    except Exception:

        return None


# ============================================================
# WHOIS INFORMATION
# ============================================================

def get_whois_information(domain):

    if not domain:

        return {
            "available": False,
            "registrar": None,
            "created": None,
            "expires": None,
            "domain_age_days": None
        }

    try:

        data = whois.whois(domain)

        created = data.creation_date

        expires = data.expiration_date

        registrar = data.registrar

        domain_age = calculate_domain_age(
            created
        )

        return {

            "available": True,

            "registrar": registrar,

            "created": created,

            "expires": expires,

            "domain_age_days": domain_age

        }

    except Exception:

        return {

            "available": False,

            "registrar": None,

            "created": None,

            "expires": None,

            "domain_age_days": None

        }


# ============================================================
# MAIN DOMAIN INTELLIGENCE FUNCTION
# ============================================================

def analyze_domain(url):

    domain = get_domain(url)

    if not domain:

        return {

            "domain": None,

            "ip_address": None,

            "whois_available": False,

            "registrar": None,

            "created": None,

            "expires": None,

            "domain_age_days": None

        }

    ip_address = get_ip_address(
        domain
    )

    whois_data = get_whois_information(
        domain
    )

    return {

        "domain": domain,

        "ip_address": ip_address,

        "whois_available":
            whois_data["available"],

        "registrar":
            whois_data["registrar"],

        "created":
            whois_data["created"],

        "expires":
            whois_data["expires"],

        "domain_age_days":
            whois_data["domain_age_days"]

    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_url = "https://example.com/login"

    print("\n" + "=" * 60)
    print("DOMAIN INTELLIGENCE")
    print("=" * 60)

    result = analyze_domain(
        test_url
    )

    for key, value in result.items():

        print(
            f"{key}: {value}"
        )