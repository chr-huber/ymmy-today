"""
Email sending via SMTP.

Required environment variables:
  SMTP_HOST         e.g. smtp.mailgun.org
  SMTP_PORT         e.g. 587 (STARTTLS) or 465 (SSL)
  SMTP_USERNAME     your SMTP login
  SMTP_PASSWORD     your SMTP password
  SMTP_FROM         sender address, e.g. newsletter@ymmy.app
  SMTP_FROM_NAME    sender display name, e.g. ymmy (optional)
"""

import logging
import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)


def _smtp_config() -> dict:
    return {
        "host": os.getenv("SMTP_HOST", ""),
        "port": int(os.getenv("SMTP_PORT", "587")),
        "username": os.getenv("SMTP_USERNAME", ""),
        "password": os.getenv("SMTP_PASSWORD", ""),
        "from_addr": os.getenv("SMTP_FROM", ""),
        "from_name": os.getenv("SMTP_FROM_NAME", "ymmy"),
    }


def send_email(to: str, subject: str, html: str, text: str = "") -> None:
    """Send a single email. Raises on failure."""
    cfg = _smtp_config()
    if not cfg["host"] or not cfg["from_addr"]:
        raise RuntimeError("SMTP_HOST and SMTP_FROM must be set to send email")

    from_header = f"{cfg['from_name']} <{cfg['from_addr']}>" if cfg["from_name"] else cfg["from_addr"]

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_header
    msg["To"] = to

    if text:
        msg.attach(MIMEText(text, "plain", "utf-8"))
    msg.attach(MIMEText(html, "html", "utf-8"))

    port = cfg["port"]
    context = ssl.create_default_context()

    if port == 465:
        with smtplib.SMTP_SSL(cfg["host"], port, context=context) as server:
            if cfg["username"]:
                server.login(cfg["username"], cfg["password"])
            server.sendmail(cfg["from_addr"], to, msg.as_string())
    else:
        with smtplib.SMTP(cfg["host"], port) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            if cfg["username"]:
                server.login(cfg["username"], cfg["password"])
            server.sendmail(cfg["from_addr"], to, msg.as_string())

    logger.info("Email sent to %s: %s", to, subject)


def smtp_configured() -> bool:
    """Return True if SMTP env vars are set."""
    return bool(os.getenv("SMTP_HOST")) and bool(os.getenv("SMTP_FROM"))


def send_welcome_email(to: str, username: str) -> None:
    """Send a welcome email to a newly registered user."""
    html = f"""
<html><body style="font-family:Georgia,serif;color:#292524;max-width:480px;margin:0 auto;padding:32px 16px">
  <h2 style="font-size:1.4rem;margin-bottom:8px">Welcome to ymmy, {username}!</h2>
  <p style="color:#57534e">You're all set. Start reading today's news in your target language and build your vocabulary as you go.</p>
  <p style="margin-top:24px">
    <a href="https://ymmy.app" style="background:#fbbf24;color:#fff;text-decoration:none;padding:10px 20px;border-radius:8px;font-size:0.9rem">Open ymmy →</a>
  </p>
  <p style="margin-top:32px;font-size:0.8rem;color:#a8a29e">You're receiving this because you just created an account. Questions? Reply to this email.</p>
</body></html>
"""
    text = f"Welcome to ymmy, {username}!\n\nYou're all set — start reading at https://ymmy.app"
    send_email(to, "Welcome to ymmy!", html, text)
