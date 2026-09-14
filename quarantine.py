import imaplib

from config import QUARANTINE_FOLDER


def quarantine_email(mail, email_id):
    """
    Move an email to the Quarantine folder.
    """

    try:
        # Try to create folder (ignore if it already exists)
        try:
            mail.create(QUARANTINE_FOLDER)
        except:
            pass

        # Copy email
        status, _ = mail.copy(email_id, QUARANTINE_FOLDER)

        if status != "OK":
            print("❌ Unable to copy email to Quarantine.")
            return False

        # Mark original for deletion
        mail.store(email_id, "+FLAGS", "\\Deleted")

        # Permanently delete from Inbox
        mail.expunge()

        print("✅ Email moved to Quarantine.")

        return True

    except imaplib.IMAP4.error as e:
        print("❌ IMAP Error while quarantining email:")
        print(e)
        return False

    except Exception as e:
        print("❌ Unexpected error while quarantining email:")
        print(e)
        return False