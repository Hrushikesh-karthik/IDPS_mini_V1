# =============================================================================
# alerts/mailer.py — Email Alert System
# =============================================================================
# Sends an email to the administrator whenever a request is blocked.
#
# Configure SMTP credentials in config.py:
#   SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, ADMIN_EMAIL
#
# For Gmail: create an App Password at
#   https://myaccount.google.com/apppasswords
#   (requires 2FA to be enabled on your Google account)
#
# To disable alerts during development, set in config.py:
#   EMAIL_ALERTS_ENABLED = False
# =============================================================================

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config import (
    SMTP_HOST, SMTP_PORT,
    SMTP_USERNAME, SMTP_PASSWORD,
    ADMIN_EMAIL, ALERT_FROM,
    EMAIL_ALERTS_ENABLED
)

logger = logging.getLogger("mailer")


def send_alert(
    ip:          str,
    attack_type: str,
    timestamp:   str,
    confidence:  float,
    subject:     str,
    body:        str
) -> bool:
    """
    Sends a security alert email to the administrator.

    Args:
        ip:          Source IP that was blocked
        attack_type: Detected attack class (e.g. "SQL Injection")
        timestamp:   ISO timestamp of the block event
        confidence:  ML confidence score (0.0–1.0)
        subject:     Email subject line (built by explainer)
        body:        Full email body text (built by explainer)

    Returns:
        True if email was sent successfully, False otherwise.
    """
    # Respect the kill switch — skip sending during development/testing
    if not EMAIL_ALERTS_ENABLED:
        logger.info(
            f"[mailer] Email alerts disabled. Would have sent: "
            f"{attack_type} alert for {ip}"
        )
        return False

    try:
        # Build the MIME message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[SECURITY ALERT] {subject}"
        msg["From"]    = ALERT_FROM
        msg["To"]      = ADMIN_EMAIL

        # Attach the plain-text body
        msg.attach(MIMEText(body, "plain"))

        # Connect to SMTP server and send
        # STARTTLS upgrades the connection to encrypted after connecting
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()          # Encrypt the connection
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(
                from_addr = SMTP_USERNAME,
                to_addrs  = [ADMIN_EMAIL],
                msg       = msg.as_string()
            )

        logger.info(f"[mailer] Alert sent to {ADMIN_EMAIL} | Attack: {attack_type} | IP: {ip}")
        return True

    except smtplib.SMTPAuthenticationError:
        logger.error(
            "[mailer] SMTP authentication failed. "
            "Check SMTP_USERNAME and SMTP_PASSWORD in config.py."
        )
    except smtplib.SMTPConnectError:
        logger.error(
            f"[mailer] Could not connect to SMTP server {SMTP_HOST}:{SMTP_PORT}."
        )
    except Exception as e:
        logger.error(f"[mailer] Unexpected error sending email: {e}")

    return False