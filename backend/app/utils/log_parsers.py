"""
backend/app/utils/log_parsers.py
================================
Parses raw security log files and text into structured event dictionaries.

Supports:
  - Linux auth.log (SSH failed/accepted, sudo, invalid user) - BSD & ISO 8601 formats
  - Linux syslog (kernel firewall drops, system services, invalid users)
  - Apache access.log (HTTP requests, status, user-agent, query strings)
  - Apache error.log (Server errors, PHP execution notices)
  - Windows Event logs (Event IDs 4625, 4624, 4672, 4688)
  - Firewall logs (iptables, UFW, PF)
  - Custom JSON logs (structured JSON objects per line)
  - Generic fallback parser
"""

import re
import os
import json
from datetime import datetime

# ──────────────────────────────────────────────────────────────────────────────
# REGEX PATTERNS
# ──────────────────────────────────────────────────────────────────────────────

# Classic BSD Syslog header: Jul 22 12:01:42 host process[123]: message
SYSLOG_BSD_HEADER = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<process>\S+?)(?:\[\d+\])?:\s+(?P<message>.+)$'
)

# Modern ISO 8601 Syslog header: 2026-07-22T09:44:31.332584+00:00 host process[123]: message
SYSLOG_ISO_HEADER = re.compile(
    r'^(?P<iso_time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+'
    r'(?P<host>\S+)\s+(?P<process>\S+?)(?:\[\d+\])?:\s+(?P<message>.+)$'
)

# Linux auth patterns
AUTH_FAILED   = re.compile(r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)', re.IGNORECASE)
AUTH_ACCEPTED = re.compile(r'Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)', re.IGNORECASE)
AUTH_INVALID  = re.compile(r'Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)', re.IGNORECASE)
SUDO_USE      = re.compile(r'(?P<user>\S+)\s+:.*COMMAND=(?P<cmd>.+)', re.IGNORECASE)

# Firewall pattern
IPTABLES_DROP = re.compile(r'SRC=(?P<ip>[\d.]+).*DST=(?P<dst>[\d.]+)', re.IGNORECASE)

# Apache Combined Log Format: 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "referer" "user-agent"
APACHE_ACCESS = re.compile(
    r'^(?P<ip>[\d.]+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<url>\S+)\s+HTTP/[0-9.]+"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

# Windows Log pattern: Event ID 4625 / 4624 / etc.
WIN_EVENT = re.compile(
    r'(?P<time>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})?\s*.*EventID=(?P<event_id>\d+).*User=(?P<user>\S+).*IP=(?P<ip>[\d.]+)'
)

CURRENT_YEAR = datetime.now().year


def _build_timestamp(month: str, day: str, time_str: str) -> str:
    try:
        raw = f"{month} {int(day):02d} {time_str} {CURRENT_YEAR}"
        dt = datetime.strptime(raw, "%b %d %H:%M:%S %Y")
        return dt.isoformat()
    except ValueError:
        return datetime.now().isoformat()


def _extract_header(line: str):
    m = SYSLOG_ISO_HEADER.match(line)
    if m:
        return m.group("iso_time"), m.group("message")
    m = SYSLOG_BSD_HEADER.match(line)
    if m:
        ts = _build_timestamp(m.group("month"), m.group("day"), m.group("time"))
        return ts, m.group("message")
    return None, line


def _parse_authlog_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None

    timestamp, message = _extract_header(line)
    if not timestamp:
        timestamp = datetime.now().isoformat()

    m = AUTH_FAILED.search(message)
    if m:
        return {
            "timestamp": timestamp,
            "ip": m.group("ip"),
            "username": m.group("user"),
            "event_type": "FAILED_LOGIN",
            "raw": line,
            "source": "auth.log"
        }

    m = AUTH_ACCEPTED.search(message)
    if m:
        return {
            "timestamp": timestamp,
            "ip": m.group("ip"),
            "username": m.group("user"),
            "event_type": "SUCCESSFUL_LOGIN",
            "raw": line,
            "source": "auth.log"
        }

    m = AUTH_INVALID.search(message)
    if m:
        return {
            "timestamp": timestamp,
            "ip": m.group("ip"),
            "username": m.group("user"),
            "event_type": "INVALID_USER",
            "raw": line,
            "source": "auth.log"
        }

    m = SUDO_USE.search(message)
    if m and "COMMAND" in message:
        return {
            "timestamp": timestamp,
            "ip": "localhost",
            "username": m.group("user"),
            "event_type": "PRIVILEGE_ESCALATION",
            "raw": line,
            "source": "auth.log"
        }

    return None


def _parse_syslog_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None

    timestamp, message = _extract_header(line)
    if not timestamp:
        timestamp = datetime.now().isoformat()

    m = IPTABLES_DROP.search(message)
    if m and ("packet dropped" in message.lower() or "ufw" in message.lower() or "drop" in message.lower()):
        return {
            "timestamp": timestamp,
            "ip": m.group("ip"),
            "username": "N/A",
            "event_type": "PACKET_DROPPED",
            "raw": line,
            "source": "syslog"
        }

    m = AUTH_INVALID.search(message)
    if m:
        return {
            "timestamp": timestamp,
            "ip": m.group("ip"),
            "username": m.group("user"),
            "event_type": "INVALID_USER",
            "raw": line,
            "source": "syslog"
        }

    m = AUTH_FAILED.search(message)
    if m:
        return {
            "timestamp": timestamp,
            "ip": m.group("ip"),
            "username": m.group("user"),
            "event_type": "FAILED_LOGIN",
            "raw": line,
            "source": "syslog"
        }

    return None


def _parse_apache_access_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None

    m = APACHE_ACCESS.match(line)
    if m:
        ip = m.group("ip")
        url = m.group("url")
        status = m.group("status")
        agent = m.group("agent") or "N/A"
        user = m.group("user") if m.group("user") != "-" else "anonymous"

        return {
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "username": user,
            "url": url,
            "status_code": status,
            "user_agent": agent,
            "event_type": "WEB_REQUEST",
            "raw": line,
            "source": "access.log"
        }
    return None


def _parse_windows_event_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None

    m = WIN_EVENT.search(line)
    if m:
        event_id = m.group("event_id")
        ip = m.group("ip")
        user = m.group("user")
        event_type = "FAILED_LOGIN" if event_id == "4625" else "SUCCESSFUL_LOGIN" if event_id == "4624" else "PRIVILEGE_ESCALATION" if event_id == "4672" else "WIN_EVENT"

        return {
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "username": user,
            "event_type": event_type,
            "raw": line,
            "source": "windows.log"
        }
    return None


def _parse_json_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
        return {
            "timestamp": data.get("timestamp") or datetime.now().isoformat(),
            "ip": data.get("ip") or data.get("source_ip") or "N/A",
            "username": data.get("username") or data.get("user") or "N/A",
            "event_type": data.get("event_type") or data.get("event") or "INFO",
            "url": data.get("url"),
            "raw": line,
            "source": data.get("source") or "json"
        }
    except Exception:
        return None


def _parse_generic_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None

    # Try JSON parse first
    if line.startswith("{") and line.endswith("}"):
        res = _parse_json_line(line)
        if res:
            return res

    ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
    ip = ip_match.group(1) if ip_match else "N/A"

    lower = line.lower()
    if "failed" in lower or "failure" in lower or "401" in lower:
        event_type = "FAILED_LOGIN"
    elif "accepted" in lower or "success" in lower or "200" in lower:
        event_type = "SUCCESSFUL_LOGIN"
    elif "error" in lower or "500" in lower:
        event_type = "ERROR"
    elif "warn" in lower:
        event_type = "WARNING"
    else:
        event_type = "INFO"

    return {
        "timestamp": datetime.now().isoformat(),
        "ip": ip,
        "username": "unknown",
        "event_type": event_type,
        "raw": line,
        "source": "uploaded"
    }


PARSER_MAP = {
    "auth": _parse_authlog_line,
    "syslog": _parse_syslog_line,
    "apache": _parse_apache_access_line,
    "windows": _parse_windows_event_line,
    "json": _parse_json_line,
    "generic": _parse_generic_line,
}


def parse_log_file(filepath: str, log_type: str = "auth") -> list[dict]:
    parser_fn = PARSER_MAP.get(log_type, _parse_generic_line)
    events = []

    if not os.path.isfile(filepath):
        print(f"[PARSER] File not found: {filepath}")
        return events

    try:
        with open(filepath, "r", errors="replace") as fh:
            for line in fh:
                res = parser_fn(line)
                if not res and log_type != "generic":
                    res = _parse_generic_line(line)
                if res:
                    events.append(res)
    except OSError as exc:
        print(f"[PARSER] Error reading {filepath}: {exc}")

    return events


def parse_log_text(text: str, log_type: str = "generic") -> list[dict]:
    parser_fn = PARSER_MAP.get(log_type, _parse_generic_line)
    events = []
    for line in text.splitlines():
        res = parser_fn(line)
        if not res and log_type != "generic":
            res = _parse_generic_line(line)
        if res:
            events.append(res)
    return events
