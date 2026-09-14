import time

from database import initialize_database, get_all_active_accounts
from scanner import scan_account
from config import CHECK_INTERVAL


def run_one_pass():
    accounts = get_all_active_accounts()

    if not accounts:
        print("No connected email accounts yet. Add one from the dashboard first.")
        return

    print(f"Scanning {len(accounts)} connected account(s)...")

    for account in accounts:
        email_address = account[2]
        print("-" * 60)
        print("Account:", email_address)

        summary = scan_account(account)

        if summary["error"]:
            print("❌", summary["error"])
        else:
            print(f"Scanned {summary['scanned']} email(s), "
                  f"{summary['phishing']} flagged as phishing.")


def run():
    initialize_database()

    print("=" * 60)
    print("   PHISHING EMAIL DETECTOR - MULTI-ACCOUNT MONITOR")
    print("=" * 60)
    print(f"Checking every connected account every {CHECK_INTERVAL} seconds.")
    print("Accounts are added/managed from the web dashboard (dashboard.py).")
    print("Press CTRL + C to stop.\n")

    try:
        while True:
            run_one_pass()
            print(f"\nNext check in {CHECK_INTERVAL} seconds...\n")
            time.sleep(CHECK_INTERVAL)

    except KeyboardInterrupt:
        print("\n\nStopping detector...")


if __name__ == "__main__":
    run()
