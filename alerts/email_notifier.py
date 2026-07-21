from backend.app.services.notifications import send_email_notification as send_alert_email, dispatch_alert_notifications

def notify_if_critical(alerts: list) -> None:
    dispatch_alert_notifications(alerts)

__all__ = ["send_alert_email", "notify_if_critical"]
