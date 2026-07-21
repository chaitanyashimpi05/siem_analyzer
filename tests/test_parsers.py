import pytest
from backend.app.utils.log_parsers import parse_log_text

def test_parse_authlog_failed_login():
    raw_log = "May  3 02:14:22 server sshd[1234]: Failed password for root from 10.20.30.40 port 22 ssh2"
    events = parse_log_text(raw_log, "auth")
    assert len(events) == 1
    assert events[0]["event_type"] == "FAILED_LOGIN"
    assert events[0]["ip"] == "10.20.30.40"
    assert events[0]["username"] == "root"

def test_parse_authlog_accepted_login():
    raw_log = "May  3 02:15:00 server sshd[1235]: Accepted password for alice from 192.168.1.50 port 22 ssh2"
    events = parse_log_text(raw_log, "auth")
    assert len(events) == 1
    assert events[0]["event_type"] == "SUCCESSFUL_LOGIN"
    assert events[0]["username"] == "alice"

def test_parse_apache_access_log():
    raw_log = '192.168.1.10 - admin [10/Oct/2000:13:55:36 -0700] "GET /admin.php HTTP/1.1" 200 2326'
    events = parse_log_text(raw_log, "apache")
    assert len(events) == 1
    assert events[0]["ip"] == "192.168.1.10"
    assert events[0]["url"] == "/admin.php"

def test_parse_json_log():
    raw_log = '{"timestamp": "2026-07-21T12:00:00", "source_ip": "1.2.3.4", "user": "bob", "event": "FAILED_LOGIN"}'
    events = parse_log_text(raw_log, "json")
    assert len(events) == 1
    assert events[0]["ip"] == "1.2.3.4"
    assert events[0]["username"] == "bob"
