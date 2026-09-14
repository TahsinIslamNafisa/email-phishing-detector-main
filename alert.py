import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from config import DEFAULT_SMTP_SERVER, DEFAULT_SMTP_PORT


def send_alert_email(subject, message, from_email, from_password, to_email,
                      smtp_server=DEFAULT_SMTP_SERVER, smtp_port=DEFAULT_SMTP_PORT):
    """
    Send an alert email using the connected account's own credentials
    (each user's alerts are sent "from" their own inbox).
    """
    try:
        msg = MIMEMultipart()
        msg["From"] = from_email
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(message, "plain"))

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(from_email, from_password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()

        print("✅ Alert email sent successfully.")

    except Exception as e:
        print("❌ Failed to send alert email.")
        print(e)
