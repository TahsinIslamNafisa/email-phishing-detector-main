"""
Attachment scanning.

Two layers of detection:

1. Extension/type blacklist  - instant, no network call.
2. VirusTotal file-hash lookup - checks the attachment's SHA256
   against VirusTotal's existing database (does NOT upload the
   file content anywhere, only the hash).
"""

import os
import hashlib

import requests

from config import VIRUSTOTAL_API_KEY, DANGEROUS_ATTACHMENT_EXTENSIONS

VT_BASE_URL = "https://www.virustotal.com/api/v3"


def has_dangerous_extension(filename):
    if not filename:
        return False
    ext = os.path.splitext(filename)[1].lower()
    return ext in DANGEROUS_ATTACHMENT_EXTENSIONS


def sha256_of(data):
    return hashlib.sha256(data).hexdigest()


def check_file_hash_virustotal(file_hash):
    """
    Look up an existing VirusTotal report for a file by its SHA256.

    Returns:
        True  -> known malicious/suspicious
        False -> known and clean, or no report available
    """

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json",
    }

    try:
        response = requests.get(
            f"{VT_BASE_URL}/files/{file_hash}",
            headers=headers,
            timeout=15,
        )
    except requests.exceptions.RequestException as e:
        print("❌ VirusTotal file lookup failed:")
        print(e)
        return False

    if response.status_code == 200:
        stats = (
            response.json()
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        print(f"Attachment VT stats -> malicious: {malicious}, suspicious: {suspicious}")

        return malicious > 0 or suspicious > 0

    if response.status_code == 404:
        print("ℹ️ No existing VirusTotal report for this attachment hash.")
        return False

    print("VirusTotal file lookup HTTP status:", response.status_code)
    return False


def scan_attachments(attachments):
    """
    Scan a list of attachment dicts: {"filename": str, "data": bytes}.

    Returns (is_suspicious: bool, findings: list[str])
    """

    findings = []
    suspicious = False

    for att in attachments or []:
        filename = att.get("filename", "unknown")
        data = att.get("data", b"")

        if has_dangerous_extension(filename):
            findings.append(f"Dangerous file type: {filename}")
            suspicious = True
            continue  # no need to also hash-check an already-flagged file

        if data:
            file_hash = sha256_of(data)
            if check_file_hash_virustotal(file_hash):
                findings.append(f"Known-malicious attachment: {filename}")
                suspicious = True

    return suspicious, findings
