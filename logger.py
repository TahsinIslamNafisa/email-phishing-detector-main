from database import record_phishing_email


def log_flagged_email(user_id, account_email, email_data):
    """
    Log a phishing email for a specific user's account.
    """
    try:
        record_phishing_email(user_id, account_email, email_data)
        print("📝 Phishing email logged.")
    except Exception as e:
        print("❌ Failed to log email:")
        print(e)
