"""
alerts/email_notifier.py
========================
Sends email notifications for CRITICAL alerts via SMTP.

Configuration is read from environment variables so credentials
are never hardcoded in source code:

  SIEM_SMTP_HOST     (default: smtp.gmail.com)
  SIEM_SMTP_PORT     (default: 587)
  SIEM_SMTP_USER     your Gmail / SMTP username
  SIEM_SMTP_PASS     your Gmail app password
  SIEM_ALERT_EMAIL   recipient address

Usage:
  from alerts.email_notifier import notify_if_critical
  notify_if_critical(alerts_list)
"""

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText
from datetime             import datetime


# ──────────────────────────────────────────────────────────────────────────────
# CONFIG  (from environment variables)
# ──────────────────────────────────────────────────────────────────────────────
SMTP_HOST   = os.getenv("SIEM_SMTP_HOST",   "smtp.gmail.com")
SMTP_PORT   = int(os.getenv("SIEM_SMTP_PORT",   "587"))
SMTP_USER   = os.getenv("SIEM_SMTP_USER",   "")
SMTP_PASS   = os.getenv("SIEM_SMTP_PASS",   "")
ALERT_EMAIL = os.getenv("SIEM_ALERT_EMAIL", "")


def _build_email_body(alerts: list) -> str:
    """Build a plain-text email body from a list of alert dicts."""
    lines = [
        "=== SIEM ALERT NOTIFICATION ===",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total CRITICAL alerts: {len(alerts)}",
        "",
    ]
    for idx, alert in enumerate(alerts, 1):
        lines += [
            f"[{idx}] {alert['alert_type']}",
            f"    Severity  : {alert['severity']}",
            f"    Time      : {alert['timestamp']}",
            f"    IP        : {alert['ip']}",
            f"    Username  : {alert['username']}",
            f"    Detail    : {alert['detail']}",
            "",
        ]
    return "\n".join(lines)


def send_alert_email(alerts: list) -> bool:
    """
    Send an email for the given list of critical alerts.
    Returns True on success, False on failure.
    """
    if not all([SMTP_USER, SMTP_PASS, ALERT_EMAIL]):
        print("[EMAIL] SMTP credentials not configured. Skipping email.")
        return False

    msg             = MIMEMultipart("alternative")
    msg["Subject"]  = f"🚨 SIEM CRITICAL ALERT — {len(alerts)} issue(s) detected"
    msg["From"]     = SMTP_USER
    msg["To"]       = ALERT_EMAIL

    body = _build_email_body(alerts)
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, ALERT_EMAIL, msg.as_string())
        print(f"[EMAIL] Alert email sent to {ALERT_EMAIL}")
        return True
    except smtplib.SMTPException as exc:
        print(f"[EMAIL] Failed to send email: {exc}")
        return False


def notify_if_critical(alerts: list) -> None:
    """
    Filter for CRITICAL alerts and send a single notification email.
    Call this after running the detection engine.
    """
    critical = [a for a in alerts if a.get("severity") == "CRITICAL"]
    if critical:
        send_alert_email(critical)
    else:
        print("[EMAIL] No CRITICAL alerts — no email sent.")
