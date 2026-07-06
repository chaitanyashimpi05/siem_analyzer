"""
parser/log_parser.py
====================
Responsible for reading raw log files and converting each line into a
structured Python dictionary (timestamp, IP, username, event_type, raw_line).

Supports:
  - Linux auth.log  (SSH failed/accepted password, sudo, invalid user)
  - Linux syslog    (kernel drops, CRON, systemd, invalid users)
  - Generic fallback for any other text log

How to add a new log format:
  1. Write a new _parse_<format>_line(line) function below.
  2. Add it to the PARSER_MAP dict at the bottom.
  3. Pass log_type="<format>" when calling parse_log_file().
"""

import re
import os
from datetime import datetime

# ──────────────────────────────────────────────────────────────────────────────
# REGEX PATTERNS
# ──────────────────────────────────────────────────────────────────────────────

# Matches: "May  3 02:14:22 hostname process[pid]: message"
SYSLOG_HEADER = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<process>\S+?)(?:\[\d+\])?:\s+(?P<message>.+)$'
)

# SSH patterns inside the message field
AUTH_FAILED   = re.compile(r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)')
AUTH_ACCEPTED = re.compile(r'Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)')
AUTH_INVALID  = re.compile(r'Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)')
SUDO_USE      = re.compile(r'(?P<user>\S+)\s+:.*COMMAND=(?P<cmd>.+)$')

# Kernel / iptables drop
IPTABLES_DROP = re.compile(r'SRC=(?P<ip>[\d.]+).*DST=(?P<dst>[\d.]+)')

# Current year (log lines often omit year)
CURRENT_YEAR = datetime.now().year


# ──────────────────────────────────────────────────────────────────────────────
# TIMESTAMP HELPER
# ──────────────────────────────────────────────────────────────────────────────

def _build_timestamp(month: str, day: str, time_str: str) -> str:
    """Convert syslog-style date parts to ISO-8601 string."""
    try:
        raw = f"{month} {int(day):02d} {time_str} {CURRENT_YEAR}"
        dt  = datetime.strptime(raw, "%b %d %H:%M:%S %Y")
        return dt.isoformat()
    except ValueError:
        return datetime.now().isoformat()  # fallback


# ──────────────────────────────────────────────────────────────────────────────
# AUTH.LOG PARSER
# ──────────────────────────────────────────────────────────────────────────────

def _parse_authlog_line(line: str) -> dict | None:
    """
    Parse a single auth.log line.
    Returns a dict or None if the line is unrecognised / empty.
    """
    line = line.strip()
    if not line:
        return None

    header = SYSLOG_HEADER.match(line)
    if not header:
        return None

    timestamp = _build_timestamp(
        header.group("month"),
        header.group("day"),
        header.group("time")
    )
    message = header.group("message")

    # ── Failed password ──────────────────────────────────────────────────────
    m = AUTH_FAILED.search(message)
    if m:
        return {
            "timestamp":  timestamp,
            "ip":         m.group("ip"),
            "username":   m.group("user"),
            "event_type": "FAILED_LOGIN",
            "raw":        line,
            "source":     "auth.log"
        }

    # ── Accepted login ───────────────────────────────────────────────────────
    m = AUTH_ACCEPTED.search(message)
    if m:
        return {
            "timestamp":  timestamp,
            "ip":         m.group("ip"),
            "username":   m.group("user"),
            "event_type": "SUCCESSFUL_LOGIN",
            "raw":        line,
            "source":     "auth.log"
        }

    # ── Invalid user ─────────────────────────────────────────────────────────
    m = AUTH_INVALID.search(message)
    if m:
        return {
            "timestamp":  timestamp,
            "ip":         m.group("ip"),
            "username":   m.group("user"),
            "event_type": "INVALID_USER",
            "raw":        line,
            "source":     "auth.log"
        }

    # ── Sudo privilege escalation ────────────────────────────────────────────
    m = SUDO_USE.search(message)
    if m and "COMMAND" in message:
        return {
            "timestamp":  timestamp,
            "ip":         "localhost",
            "username":   m.group("user"),
            "event_type": "PRIVILEGE_ESCALATION",
            "raw":        line,
            "source":     "auth.log"
        }

    return None   # line recognised but not a security-relevant event


# ──────────────────────────────────────────────────────────────────────────────
# SYSLOG PARSER
# ──────────────────────────────────────────────────────────────────────────────

def _parse_syslog_line(line: str) -> dict | None:
    """Parse a single syslog line."""
    line = line.strip()
    if not line:
        return None

    header = SYSLOG_HEADER.match(line)
    if not header:
        return None

    timestamp = _build_timestamp(
        header.group("month"),
        header.group("day"),
        header.group("time")
    )
    message = header.group("message")

    # ── iptables / kernel packet drops ──────────────────────────────────────
    m = IPTABLES_DROP.search(message)
    if m and "packet dropped" in message:
        return {
            "timestamp":  timestamp,
            "ip":         m.group("ip"),
            "username":   "N/A",
            "event_type": "PACKET_DROPPED",
            "raw":        line,
            "source":     "syslog"
        }

    # ── Invalid user (also appears in syslog sometimes) ─────────────────────
    m = AUTH_INVALID.search(message)
    if m:
        return {
            "timestamp":  timestamp,
            "ip":         m.group("ip"),
            "username":   m.group("user"),
            "event_type": "INVALID_USER",
            "raw":        line,
            "source":     "syslog"
        }

    # ── Failed SSH in syslog ─────────────────────────────────────────────────
    m = AUTH_FAILED.search(message)
    if m:
        return {
            "timestamp":  timestamp,
            "ip":         m.group("ip"),
            "username":   m.group("user"),
            "event_type": "FAILED_LOGIN",
            "raw":        line,
            "source":     "syslog"
        }

    return None


# ──────────────────────────────────────────────────────────────────────────────
# GENERIC FALLBACK PARSER
# ──────────────────────────────────────────────────────────────────────────────

def _parse_generic_line(line: str) -> dict | None:
    """
    Best-effort parser for unknown log formats.
    Extracts an IP address if one exists; classifies the event by keywords.
    """
    line = line.strip()
    if not line:
        return None

    ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
    ip = ip_match.group(1) if ip_match else "N/A"

    # Keyword-based event type detection
    lower = line.lower()
    if "failed" in lower or "failure" in lower:
        event_type = "FAILED_LOGIN"
    elif "accepted" in lower or "success" in lower:
        event_type = "SUCCESSFUL_LOGIN"
    elif "error" in lower:
        event_type = "ERROR"
    elif "warn" in lower:
        event_type = "WARNING"
    else:
        event_type = "INFO"

    return {
        "timestamp":  datetime.now().isoformat(),
        "ip":         ip,
        "username":   "unknown",
        "event_type": event_type,
        "raw":        line,
        "source":     "uploaded"
    }


# ──────────────────────────────────────────────────────────────────────────────
# MAP: log_type → parser function
# ──────────────────────────────────────────────────────────────────────────────
# To add a new parser: write a function above and add an entry here.
PARSER_MAP = {
    "auth":    _parse_authlog_line,
    "syslog":  _parse_syslog_line,
    "generic": _parse_generic_line,
}


# ──────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ──────────────────────────────────────────────────────────────────────────────

def parse_log_file(filepath: str, log_type: str = "auth") -> list[dict]:
    """
    Read a log file and return a list of structured event dicts.

    Parameters
    ----------
    filepath : str
        Absolute or relative path to the log file.
    log_type : str
        One of 'auth', 'syslog', 'generic'.  Defaults to 'auth'.

    Returns
    -------
    list[dict]
        Each dict contains: timestamp, ip, username, event_type, raw, source.
        Lines that cannot be parsed are silently skipped.
    """
    parser_fn = PARSER_MAP.get(log_type, _parse_generic_line)
    events    = []

    if not os.path.isfile(filepath):
        print(f"[PARSER] File not found: {filepath}")
        return events

    try:
        with open(filepath, "r", errors="replace") as fh:
            for line in fh:
                result = parser_fn(line)
                if result:
                    events.append(result)
    except OSError as exc:
        print(f"[PARSER] Error reading {filepath}: {exc}")

    print(f"[PARSER] Parsed {len(events)} events from '{filepath}' (type={log_type})")
    return events


def parse_log_text(text: str, log_type: str = "generic") -> list[dict]:
    """
    Same as parse_log_file but accepts raw text (e.g., from an uploaded file).
    """
    parser_fn = PARSER_MAP.get(log_type, _parse_generic_line)
    events    = []
    for line in text.splitlines():
        result = parser_fn(line)
        if result:
            events.append(result)
    print(f"[PARSER] Parsed {len(events)} events from raw text (type={log_type})")
    return events
