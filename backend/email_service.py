import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from config import settings


def send_otp_email(to_email: str, otp: str) -> bool:
    if not settings.SMTP_USERNAME or not settings.SMTP_PASSWORD:
        print(f"[DEV] OTP for {to_email}: {otp}")
        return False

    message = MIMEMultipart()
    message["From"] = settings.SMTP_FROM_EMAIL or settings.SMTP_USERNAME
    message["To"] = to_email
    message["Subject"] = "CyberTrust Decision Engine - Password Reset OTP"

    body = f"""
CyberTrust Decision Engine

Your password reset OTP is:

{otp}

This OTP is valid for 10 minutes.

If you did not request a password reset, please ignore this email.

Do not share this OTP with anyone.
"""

    message.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.starttls()
            server.login(
                settings.SMTP_USERNAME,
                settings.SMTP_PASSWORD
            )
            server.send_message(message)

        return True

    except Exception as exc:
        print(f"Failed to send OTP email: {exc}")
        return False