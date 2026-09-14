import imaplib
import email


def connect_to_email(email_address, password, imap_server):
    """
    Connect to an IMAP mailbox using account-specific credentials
    (each user brings their own email + app password + server).
    """
    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(email_address, password)
        print(f"✅ Successfully connected to {email_address}.")
        return mail
    except Exception as e:
        print(f"❌ Login failed for {email_address}.")
        print(e)
        raise


def decode_payload(part):
    """
    Safely decode email payload.
    """
    try:
        payload = part.get_payload(decode=True)
        if not payload:
            return ""
        charset = part.get_content_charset()
        if charset:
            return payload.decode(charset, errors="ignore")
        return payload.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def fetch_emails(mail):
    """
    Fetch unread emails from Gmail, including attachment bytes and
    the raw Authentication-Results header (for SPF/DKIM/DMARC checks).
    """

    print("Entered fetch_emails()")

    emails = []

    status, mailbox = mail.select("INBOX")
    print("Select:", status, mailbox)

    if status != "OK":
        print("❌ Unable to open INBOX.")
        return emails

    status, data = mail.search(None, "UNSEEN")
    print("Search status:", status)
    print("Search data:", data)

    if status != "OK":
        print("❌ Unable to search emails.")
        return emails

    email_ids = data[0].split()
    print("Email IDs:", email_ids)

    if not email_ids:
        return emails

    for email_id in email_ids:

        status, msg_data = mail.fetch(email_id, "(RFC822)")

        if status != "OK":
            continue

        raw_email = msg_data[0][1]
        msg = email.message_from_bytes(raw_email)

        sender = msg.get("From", "")
        subject = msg.get("Subject", "")
        reply_to = msg.get("Reply-To", "")

        # Authentication-Results is what carries SPF/DKIM/DMARC verdicts
        auth_headers = msg.get_all("Authentication-Results", [])
        auth_headers_text = " ".join(auth_headers)

        plain_body = ""
        html_body = ""
        attachments = []

        if msg.is_multipart():

            for part in msg.walk():

                content_type = part.get_content_type()
                disposition = str(part.get("Content-Disposition", ""))
                filename = part.get_filename()

                if "attachment" in disposition or filename:
                    try:
                        att_data = part.get_payload(decode=True) or b""
                    except Exception:
                        att_data = b""

                    attachments.append({
                        "filename": filename or "unnamed_attachment",
                        "data": att_data,
                    })
                    continue

                if content_type == "text/plain":
                    text = decode_payload(part)
                    if text:
                        plain_body += "\n" + text

                elif content_type == "text/html":
                    html = decode_payload(part)
                    if html:
                        html_body += "\n" + html

        else:
            content_type = msg.get_content_type()
            body = decode_payload(msg)

            if content_type == "text/html":
                html_body = body
            else:
                plain_body = body

        combined_body = plain_body + "\n" + html_body

        emails.append({
            "id": email_id,
            "from": sender,
            "subject": subject,
            "body": combined_body,
            "reply_to": reply_to,
            "auth_headers_text": auth_headers_text,
            "attachments": attachments,
        })

    return emails


def mark_email_as_read(mail, email_id):
    """
    Mark an email as read after processing.
    """
    try:
        status, _ = mail.store(email_id, "+FLAGS", "\\Seen")

        if status == "OK":
            print("📖 Email marked as read.")
            return True

        print("⚠️ Could not mark email as read.")
        return False

    except Exception as e:
        print("❌ Error marking email as read:")
        print(e)
        return False
