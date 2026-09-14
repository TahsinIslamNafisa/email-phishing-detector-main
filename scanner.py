"""
Core scanning logic, shared between the CLI monitor (main.py) and the
dashboard's background scanning thread (dashboard.py).

scan_account() does everything for ONE user's ONE connected mailbox:
connect -> fetch unread -> run every detection layer -> quarantine/alert
if phishing -> record results scoped to that user -> mark read.
"""

from email_handler import connect_to_email, fetch_emails, mark_email_as_read
from phishing_detection import check_url_virustotal, extract_urls
from quarantine import quarantine_email
from alert import send_alert_email
from notifications import notify_all_channels
from logger import log_flagged_email
from domain_analysis import analyze_sender
from attachment_scanner import scan_attachments
from keyword_scoring import score_email
from config import KEYWORD_SCORE_THRESHOLD, DEFAULT_SMTP_SERVER, DEFAULT_SMTP_PORT

from database import record_scan, check_sender_against_lists, mark_account_scanned
from crypto_utils import decrypt


def evaluate_email(user_id, email_data):
    """
    Runs every detection layer for one email and returns:
        (is_phishing: bool, reasons: list[str], score: int)
    """

    sender = email_data.get("from", "")
    body = email_data.get("body", "")
    reply_to = email_data.get("reply_to", "")
    auth_headers_text = email_data.get("auth_headers_text", "")
    attachments = email_data.get("attachments", [])

    reasons = []

    # 0. Whitelist / blacklist short-circuit (scoped to this user)
    list_verdict = check_sender_against_lists(user_id, sender)
    if list_verdict == "whitelist":
        print("✅ Sender is whitelisted, skipping further checks.")
        return False, ["Whitelisted sender"], 0
    if list_verdict == "blacklist":
        print("🚨 Sender is blacklisted.")
        return True, ["Blacklisted sender"], 100

    # 1. Sender authenticity (SPF/DKIM/DMARC + look-alike domain)
    sender_report = analyze_sender(sender, auth_headers_text)
    if sender_report["suspicious"]:
        if sender_report["lookalike_of"]:
            reasons.append(
                f"Look-alike domain of '{sender_report['lookalike_of']}': "
                f"{sender_report['domain']}"
            )
        auth = sender_report["auth_results"]
        if auth.get("spf") == "fail":
            reasons.append("SPF check failed")
        if auth.get("dmarc") == "fail":
            reasons.append("DMARC check failed")

    # 2. Attachment scanning
    attachments_suspicious, attachment_findings = scan_attachments(attachments)
    reasons.extend(attachment_findings)

    # 3. Keyword / heuristic scoring
    urls = extract_urls(body)
    keyword_score, keyword_reasons = score_email(
        body, sender_header=sender, reply_to_header=reply_to, url_count=len(urls),
    )
    reasons.extend(keyword_reasons)

    # 4. URL reputation (VirusTotal) + hidden-link mismatch
    url_phishing = check_url_virustotal(body)
    if url_phishing:
        reasons.append("Malicious/suspicious URL found (VirusTotal)")

    is_phishing = (
        url_phishing
        or attachments_suspicious
        or bool(sender_report["lookalike_of"])
        or keyword_score >= KEYWORD_SCORE_THRESHOLD
    )

    return is_phishing, reasons, keyword_score


def scan_account(account_row):
    """
    account_row: (id, user_id, email_address, imap_server, encrypted_password, alert_email)
    Connects to this ONE account, scans unread mail, and records results
    scoped to that account's owning user.

    Returns a small summary dict for UI feedback.
    """

    account_id, user_id, email_address, imap_server, encrypted_password, alert_email = account_row

    summary = {"scanned": 0, "phishing": 0, "error": None}

    try:
        password = decrypt(encrypted_password)
    except Exception as e:
        summary["error"] = f"Could not decrypt stored credentials: {e}"
        return summary

    try:
        mail = connect_to_email(email_address, password, imap_server)
    except Exception as e:
        summary["error"] = f"IMAP connection failed: {e}"
        return summary

    try:
        emails = fetch_emails(mail)
        summary["scanned"] = len(emails)

        for email_data in emails:
            subject = email_data.get("subject", "")
            sender = email_data.get("from", "")

            if subject.strip().lower() == "phishing alert":
                mark_email_as_read(mail, email_data["id"])
                continue

            phishing, reasons, score = evaluate_email(user_id, email_data)

            if phishing:
                summary["phishing"] += 1

                quarantined = quarantine_email(mail, email_data["id"])
                log_flagged_email(user_id, email_address, email_data)
                record_scan(user_id, email_address, email_data, "PHISHING", score=score, reasons=reasons)

                alert_body = f"""
PHISHING EMAIL DETECTED

Account:
{email_address}

Sender:
{sender}

Subject:
{subject}

Reasons:
{chr(10).join('- ' + r for r in reasons) if reasons else 'N/A'}

Quarantine status:
{quarantined}
"""
                send_alert_email(
                    "Phishing Alert", alert_body,
                    from_email=email_address, from_password=password,
                    to_email=alert_email or email_address,
                )
                notify_all_channels(
                    f"🚨 Phishing email detected in {email_address} from {sender} - {subject}"
                )

            else:
                record_scan(user_id, email_address, email_data, "SAFE", score=score, reasons=reasons)

            mark_email_as_read(mail, email_data["id"])

        mark_account_scanned(account_id)

    except Exception as e:
        summary["error"] = f"Error while scanning: {e}"

    finally:
        try:
            mail.logout()
        except Exception:
            pass

    return summary
