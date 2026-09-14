"""
Sender authenticity checks:

1. SPF / DKIM / DMARC verdicts, read from the
   "Authentication-Results" header that Gmail/Google already adds
   to every incoming message (no external DNS lookups required).

2. Look-alike / typosquatting domain detection, comparing the
   sender's domain against a list of protected brand domains using
   edit-distance + common substitution tricks (0/o, 1/l, rn/m, etc).
"""

import re
from email.utils import parseaddr

from config import PROTECTED_DOMAINS


def get_sender_domain(from_header):
    """
    Extract the domain part of the sender's email address.
    """
    _, addr = parseaddr(from_header or "")
    if "@" not in addr:
        return ""
    return addr.split("@")[-1].lower().strip()


def parse_authentication_results(headers_text):
    """
    Parse SPF / DKIM / DMARC results out of the raw
    "Authentication-Results" header text.

    Returns a dict like:
        {"spf": "pass", "dkim": "fail", "dmarc": "pass"}

    Any field not found is reported as "unknown".
    """

    result = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}

    if not headers_text:
        return result

    for field in ("spf", "dkim", "dmarc"):
        match = re.search(
            rf"{field}=([a-zA-Z]+)",
            headers_text,
            flags=re.IGNORECASE,
        )
        if match:
            result[field] = match.group(1).lower()

    return result


def is_authentication_suspicious(auth_results):
    """
    True if SPF or DMARC explicitly failed (a strong spoofing signal).
    DKIM failing alone is weighted less since some legit mailing
    lists break DKIM signatures.
    """
    return auth_results.get("spf") == "fail" or auth_results.get("dmarc") == "fail"


def _levenshtein(a, b):
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)

    previous_row = list(range(len(b) + 1))

    for i, ca in enumerate(a):
        current_row = [i + 1]
        for j, cb in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def _normalize_lookalikes(domain):
    """
    Normalize common visual substitution tricks so that
    'micr0soft.com' and 'microsoft.com' compare closer.
    """
    subs = {
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "rn": "m",
        "vv": "w",
    }
    normalized = domain
    for bad, good in subs.items():
        normalized = normalized.replace(bad, good)
    return normalized


def find_lookalike_domain(sender_domain, protected_domains=None):
    """
    Compare the sender's domain against each protected brand domain.

    Returns the matched protected domain if the sender domain looks
    like a typosquat of it (but is NOT an exact or legitimate
    subdomain match), otherwise returns None.
    """

    if not sender_domain:
        return None

    protected_domains = protected_domains or PROTECTED_DOMAINS
    sender_domain = sender_domain.lower()

    for brand in protected_domains:
        brand = brand.lower()

        # Exact match or legitimate subdomain -> not a look-alike
        if sender_domain == brand or sender_domain.endswith("." + brand):
            return None

        distance = _levenshtein(
            _normalize_lookalikes(sender_domain),
            _normalize_lookalikes(brand),
        )

        # Small edit distance relative to domain length = likely typosquat
        threshold = 1 if len(brand) <= 8 else 2

        # Note: sender_domain != brand was already confirmed above, so a
        # normalized distance of 0 here still means "different string, but
        # looks identical to a human eye" (e.g. micr0soft.com vs microsoft.com).
        if distance <= threshold:
            return brand

    return None


def analyze_sender(from_header, headers_text):
    """
    Run all sender-authenticity checks and return a combined report.
    """

    domain = get_sender_domain(from_header)
    auth_results = parse_authentication_results(headers_text)
    lookalike_of = find_lookalike_domain(domain)

    suspicious = is_authentication_suspicious(auth_results) or bool(lookalike_of)

    return {
        "domain": domain,
        "auth_results": auth_results,
        "lookalike_of": lookalike_of,
        "suspicious": suspicious,
    }
