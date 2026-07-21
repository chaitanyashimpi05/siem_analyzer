import pytest
from backend.app.detectors.engine import run_detection

def test_detect_ssh_brute_force():
    events = [
        {"event_type": "FAILED_LOGIN", "ip": "10.0.0.1", "username": "root", "timestamp": "2026-07-21T10:00:00", "source": "auth.log", "raw": "failed login"}
        for _ in range(6)
    ]
    alerts = run_detection(events)
    assert any(a["attack_type"] == "SSH Brute Force" and a["severity"] == "CRITICAL" for a in alerts)
    assert any(a["mitre_technique_id"] == "T1110.001" for a in alerts)

def test_detect_sql_injection():
    events = [
        {"event_type": "WEB_REQUEST", "ip": "192.168.1.5", "username": "anonymous", "timestamp": "2026-07-21T10:01:00", "source": "access.log", "raw": "GET /search?id=1 UNION SELECT username, password FROM users--"}
    ]
    alerts = run_detection(events)
    assert any(a["attack_type"] == "SQL Injection" and a["severity"] == "CRITICAL" for a in alerts)
    assert any(a["mitre_technique_id"] == "T1190" for a in alerts)

def test_detect_xss():
    events = [
        {"event_type": "WEB_REQUEST", "ip": "192.168.1.5", "username": "anonymous", "timestamp": "2026-07-21T10:02:00", "source": "access.log", "raw": "POST /comment payload=<script>alert('XSS')</script>"}
    ]
    alerts = run_detection(events)
    assert any(a["attack_type"] == "Cross-Site Scripting (XSS)" for a in alerts)

def test_detect_sensitive_file_access():
    events = [
        {"event_type": "WEB_REQUEST", "ip": "172.16.0.4", "username": "anonymous", "timestamp": "2026-07-21T10:03:00", "source": "access.log", "raw": "GET /static/../../etc/passwd HTTP/1.1"}
    ]
    alerts = run_detection(events)
    assert any(a["attack_type"] == "Sensitive File Access" for a in alerts)
