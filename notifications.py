"""
Extra notification channels beyond email: Telegram and Slack.
Both are optional - if not configured in .env, they are silently skipped.
"""

import requests

from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, SLACK_WEBHOOK_URL


def send_telegram_alert(message):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

    try:
        response = requests.post(
            url,
            data={"chat_id": TELEGRAM_CHAT_ID, "text": message},
            timeout=10,
        )
        if response.status_code == 200:
            print("✅ Telegram alert sent.")
            return True
        print("❌ Telegram alert failed:", response.status_code)
    except requests.exceptions.RequestException as e:
        print("❌ Telegram alert error:", e)

    return False


def send_slack_alert(message):
    if not SLACK_WEBHOOK_URL:
        return False

    try:
        response = requests.post(
            SLACK_WEBHOOK_URL,
            json={"text": message},
            timeout=10,
        )
        if response.status_code == 200:
            print("✅ Slack alert sent.")
            return True
        print("❌ Slack alert failed:", response.status_code)
    except requests.exceptions.RequestException as e:
        print("❌ Slack alert error:", e)

    return False


def notify_all_channels(message):
    """
    Fire the message to every configured extra channel.
    Email alerting stays in alert.py and is called separately.
    """
    send_telegram_alert(message)
    send_slack_alert(message)
