"""
Keyword / heuristic phishing scoring.

Gives every email a 0-100 "phishing likelihood" score based on
common social-engineering language, urgency cues, and structural
red flags. This catches phishing emails that don't even contain a
malicious link (e.g. asking the victim to reply with credentials,
or call a fake number).
"""

import re

URGENCY_PHRASES = [
    "act now", "immediate action", "urgent", "verify your account",
    "your account has been suspended", "unusual activity",
    "confirm your identity", "click here immediately",
    "will be closed", "expires today", "final notice",
    "limited time", "you have won", "claim your prize",
    "update your payment", "reset your password now",
    "unauthorized login attempt", "security alert",
]

CREDENTIAL_HARVEST_PHRASES = [
    "enter your password", "enter your pin", "ssn", "social security",
    "card number", "cvv", "confirm your password", "login to verify",
    "provide your credentials", "otp", "one time password",
]

GENERIC_GREETING_PATTERNS = [
    r"\bdear customer\b", r"\bdear user\b", r"\bdear valued\b",
    r"\bdear account holder\b",
]

SCORE_WEIGHTS = {
    "urgency": 8,
    "credential_harvest": 15,
    "generic_greeting": 10,
    "mismatched_reply_to": 20,
    "excessive_links": 10,
    "poor_grammar_markers": 5,
}


def _count_hits(text, phrases):
    text_lower = text.lower()
    return sum(1 for p in phrases if p in text_lower)


def score_email(body, sender_header="", reply_to_header="", url_count=0):
    """
    Returns (score: int 0-100, reasons: list[str])
    """

    body = body or ""
    reasons = []
    score = 0

    urgency_hits = _count_hits(body, URGENCY_PHRASES)
    if urgency_hits:
        score += min(urgency_hits, 3) * SCORE_WEIGHTS["urgency"]
        reasons.append(f"Urgency/pressure language ({urgency_hits} phrase(s))")

    cred_hits = _count_hits(body, CREDENTIAL_HARVEST_PHRASES)
    if cred_hits:
        score += min(cred_hits, 2) * SCORE_WEIGHTS["credential_harvest"]
        reasons.append(f"Credential-harvesting language ({cred_hits} phrase(s))")

    for pattern in GENERIC_GREETING_PATTERNS:
        if re.search(pattern, body, flags=re.IGNORECASE):
            score += SCORE_WEIGHTS["generic_greeting"]
            reasons.append("Generic greeting instead of a personal name")
            break

    # Reply-To domain differs from From domain -> classic phishing trick
    if reply_to_header and sender_header:
        from_domain = sender_header.split("@")[-1].lower().strip(">").strip()
        reply_domain = reply_to_header.split("@")[-1].lower().strip(">").strip()
        if from_domain and reply_domain and from_domain != reply_domain:
            score += SCORE_WEIGHTS["mismatched_reply_to"]
            reasons.append(
                f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})"
            )

    if url_count >= 5:
        score += SCORE_WEIGHTS["excessive_links"]
        reasons.append(f"Unusually high number of links ({url_count})")

    # Very rough grammar smell test: excessive exclamation marks / ALL CAPS words
    exclamations = body.count("!")
    caps_words = len(re.findall(r"\b[A-Z]{4,}\b", body))
    if exclamations >= 3 or caps_words >= 3:
        score += SCORE_WEIGHTS["poor_grammar_markers"]
        reasons.append("Excessive exclamation marks / ALL-CAPS shouting")

    score = min(score, 100)

    return score, reasons
