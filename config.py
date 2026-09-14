import os
from dotenv import load_dotenv

load_dotenv()  # reads variables from a local ".env" file if present


def _get(name, default=None, required=False):
    value = os.getenv(name, default)
    if required and not value:
        raise RuntimeError(
            f"Missing required environment variable: {name}. "
            f"Copy .env.example to .env and fill it in."
        )
    return value


# ============================
# VirusTotal Configuration (shared app-level key, used for every user)
# ============================

VIRUSTOTAL_API_KEY = _get("VIRUSTOTAL_API_KEY", required=True)


# ============================
# Encryption (used to store each user's IMAP app-password at rest)
# ============================

ENCRYPTION_KEY = _get("ENCRYPTION_KEY", required=True)


# ============================
# Optional notification channels (shared/global; per-account override
# could be added later if needed)
# ============================

TELEGRAM_BOT_TOKEN = _get("TELEGRAM_BOT_TOKEN", default="")
TELEGRAM_CHAT_ID = _get("TELEGRAM_CHAT_ID", default="")
SLACK_WEBHOOK_URL = _get("SLACK_WEBHOOK_URL", default="")


# ============================
# Defaults offered when a user connects a new email account
# ============================

DEFAULT_IMAP_SERVER = "imap.gmail.com"
DEFAULT_SMTP_SERVER = "smtp.gmail.com"
DEFAULT_SMTP_PORT = 587


# ============================
# Database
# ============================

DATABASE_NAME = "phishing_alerts.db"


# ============================
# Quarantine Folder
# ============================

QUARANTINE_FOLDER = "Quarantine"


# ============================
# Background scan interval (seconds) for every connected account
# ============================

CHECK_INTERVAL = 60


# ============================
# Detection tuning
# ============================

DANGEROUS_ATTACHMENT_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".msi", ".jar", ".docm",
    ".xlsm", ".pptm", ".dll", ".hta", ".lnk",
}

# Brand domains to protect against look-alike / typosquatting attempts.
PROTECTED_DOMAINS = [
    "google.com", "gmail.com", "microsoft.com", "outlook.com",
    "paypal.com", "amazon.com", "apple.com", "facebook.com",
    "bankofamerica.com", "chase.com", "dbbl.com.bd", "bkash.com",
]

# Minimum score (out of 100) at which an email is treated as phishing
# based on the keyword/heuristic scoring engine alone (no malicious URL).
KEYWORD_SCORE_THRESHOLD = 50
