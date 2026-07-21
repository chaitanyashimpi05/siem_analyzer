import os
import smtplib
import requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

SMTP_HOST = os.getenv("SIEM_SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SIEM_SMTP_PORT", "587"))
SMTP_USER = os.getenv("SIEM_SMTP_USER", "")
SMTP_PASS = os.getenv("SIEM_SMTP_PASS", "")
ALERT_EMAIL = os.getenv("SIEM_ALERT_EMAIL", "")

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")


def send_email_notification(alerts: list) -> bool:
    if not all([SMTP_USER, SMTP_PASS, ALERT_EMAIL]):
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"🚨 SIEM SECURITY ALERT — {len(alerts)} Issue(s) Detected"
    msg["From"] = SMTP_USER
    msg["To"] = ALERT_EMAIL

    lines = [
        "=== ENTERPRISE SIEM ALERT NOTIFICATION ===",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total Alerts: {len(alerts)}",
        "",
    ]
    for idx, a in enumerate(alerts, 1):
        lines += [
            f"[{idx}] {a.get('attack_type')} ({a.get('severity')})",
            f"    Source IP : {a.get('source_ip')}",
            f"    MITRE Tag : {a.get('mitre_technique_id')} - {a.get('mitre_technique_name')}",
            f"    Detail    : {a.get('description')}",
            "",
        ]
    msg.attach(MIMEText("\n".join(lines), "plain"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, ALERT_EMAIL, msg.as_string())
        print(f"[NOTIFY] Email alert sent to {ALERT_EMAIL}")
        return True
    except Exception as exc:
        print(f"[NOTIFY] Email failed: {exc}")
        return False


def send_discord_webhook(alerts: list) -> bool:
    if not DISCORD_WEBHOOK_URL:
        return False
    try:
        embeds = []
        for a in alerts[:5]:
            color = 15158332 if a.get("severity") == "CRITICAL" else 15105570 if a.get("severity") == "HIGH" else 3447003
            embeds.append({
                "title": f"🚨 {a.get('attack_type')}",
                "description": a.get("description"),
                "color": color,
                "fields": [
                    {"name": "Severity", "value": a.get("severity"), "inline": True},
                    {"name": "Source IP", "value": a.get("source_ip"), "inline": True},
                    {"name": "MITRE Technique", "value": f"{a.get('mitre_technique_id')} ({a.get('mitre_technique_name')})", "inline": False},
                ]
            })
        payload = {"username": "Enterprise SIEM Bot", "embeds": embeds}
        res = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=3)
        return res.status_code in (200, 204)
    except Exception as exc:
        print(f"[NOTIFY] Discord webhook error: {exc}")
        return False


def send_slack_webhook(alerts: list) -> bool:
    if not SLACK_WEBHOOK_URL:
        return False
    try:
        text_lines = [f"*🚨 SIEM Alert Notification ({len(alerts)} items)*"]
        for a in alerts[:5]:
            text_lines.append(f"• *{a.get('attack_type')}* [{a.get('severity')}] from `{a.get('source_ip')}` - {a.get('description')}")
        payload = {"text": "\n".join(text_lines)}
        res = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=3)
        return res.status_code == 200
    except Exception as exc:
        print(f"[NOTIFY] Slack webhook error: {exc}")
        return False


def dispatch_alert_notifications(alerts: list) -> None:
    critical_or_high = [a for a in alerts if a.get("severity") in ("CRITICAL", "HIGH")]
    if not critical_or_high:
        return

    send_email_notification(critical_or_high)
    send_discord_webhook(critical_or_high)
    send_slack_webhook(critical_or_high)
