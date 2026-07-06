"""
detection/engine.py
===================
The Detection Engine processes parsed log events and applies
a set of modular threat-detection RULES to produce alerts.

Architecture (modular / extensible):
  - Each rule is a plain Python function that accepts the full list
    of parsed events and returns a list of alert dicts.
  - Rules are registered in the RULES list at the bottom of this file.
  - To add a new rule: write a function and append it to RULES.

Alert dict schema:
  {
    "alert_type": str,          # human-readable rule name
    "severity":   str,          # "INFO" | "WARNING" | "CRITICAL"
    "timestamp":  str,          # ISO-8601
    "ip":         str,
    "username":   str,
    "detail":     str,          # full explanation
    "raw":        str           # triggering log line (first match)
  }
"""

from datetime import datetime
from collections import defaultdict

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION  (tweak these thresholds without changing rule logic)
# ──────────────────────────────────────────────────────────────────────────────

BRUTE_FORCE_THRESHOLD   = 5      # failed logins from same IP within window
ACTIVITY_SPIKE_FACTOR   = 3.0    # events-per-minute vs baseline to call spike
OFF_HOURS_START         = 2      # 02:00  (inclusive)
OFF_HOURS_END           = 5      # 05:00  (exclusive)

# IPs that are always considered suspicious (extend as needed)
SUSPICIOUS_IPS = {
    "45.33.32.156",    # known scanner / Shodan node (example)
    "185.220.101.1",   # Tor exit node (example)
    "91.92.93.94",     # public blacklisted IP (example)
}


# ──────────────────────────────────────────────────────────────────────────────
# HELPER
# ──────────────────────────────────────────────────────────────────────────────

def _make_alert(alert_type, severity, ip, username, detail, raw, timestamp=None):
    return {
        "alert_type": alert_type,
        "severity":   severity,
        "timestamp":  timestamp or datetime.now().isoformat(),
        "ip":         ip,
        "username":   username,
        "detail":     detail,
        "raw":        raw,
    }


# ──────────────────────────────────────────────────────────────────────────────
# RULE 1 — Brute Force Detection
# ──────────────────────────────────────────────────────────────────────────────

def rule_brute_force(events: list) -> list:
    """
    Fires CRITICAL when a single IP generates >= BRUTE_FORCE_THRESHOLD
    failed login attempts (regardless of time window for simplicity).
    Fires WARNING if 3-4 failures are detected.
    """
    alerts = []
    # Count failures per IP
    failures_per_ip = defaultdict(list)
    for ev in events:
        if ev["event_type"] == "FAILED_LOGIN":
            failures_per_ip[ev["ip"]].append(ev)

    for ip, fail_events in failures_per_ip.items():
        count = len(fail_events)
        if count >= BRUTE_FORCE_THRESHOLD:
            first = fail_events[0]
            alerts.append(_make_alert(
                alert_type = "Brute Force Attack",
                severity   = "CRITICAL",
                ip         = ip,
                username   = first["username"],
                detail     = (
                    f"IP {ip} made {count} failed login attempts. "
                    f"Threshold is {BRUTE_FORCE_THRESHOLD}. Possible brute-force attack."
                ),
                raw        = first["raw"],
                timestamp  = first["timestamp"],
            ))
        elif count >= 3:
            first = fail_events[0]
            alerts.append(_make_alert(
                alert_type = "Multiple Failed Logins",
                severity   = "WARNING",
                ip         = ip,
                username   = first["username"],
                detail     = f"IP {ip} had {count} failed login attempts.",
                raw        = first["raw"],
                timestamp  = first["timestamp"],
            ))

    return alerts


# ──────────────────────────────────────────────────────────────────────────────
# RULE 2 — Suspicious IP Detection
# ──────────────────────────────────────────────────────────────────────────────

def rule_suspicious_ip(events: list) -> list:
    """
    Fires CRITICAL when any activity is seen from a known-bad IP address.
    """
    alerts  = []
    seen    = set()  # avoid duplicate alerts for same IP

    for ev in events:
        ip = ev["ip"]
        if ip in SUSPICIOUS_IPS and ip not in seen:
            seen.add(ip)
            alerts.append(_make_alert(
                alert_type = "Suspicious IP Activity",
                severity   = "CRITICAL",
                ip         = ip,
                username   = ev["username"],
                detail     = (
                    f"IP {ip} is on the known-suspicious list. "
                    f"Event type: {ev['event_type']}."
                ),
                raw        = ev["raw"],
                timestamp  = ev["timestamp"],
            ))

    return alerts


# ──────────────────────────────────────────────────────────────────────────────
# RULE 3 — Off-Hours Login Detection
# ──────────────────────────────────────────────────────────────────────────────

def rule_off_hours_login(events: list) -> list:
    """
    Fires WARNING when a SUCCESSFUL login occurs between OFF_HOURS_START
    and OFF_HOURS_END (default: 02:00–05:00).
    """
    alerts = []

    for ev in events:
        if ev["event_type"] != "SUCCESSFUL_LOGIN":
            continue

        try:
            dt   = datetime.fromisoformat(ev["timestamp"])
            hour = dt.hour
        except ValueError:
            continue

        if OFF_HOURS_START <= hour < OFF_HOURS_END:
            alerts.append(_make_alert(
                alert_type = "Off-Hours Login",
                severity   = "WARNING",
                ip         = ev["ip"],
                username   = ev["username"],
                detail     = (
                    f"Successful login by '{ev['username']}' from {ev['ip']} "
                    f"at {dt.strftime('%H:%M:%S')} — outside business hours "
                    f"({OFF_HOURS_START:02d}:00–{OFF_HOURS_END:02d}:00)."
                ),
                raw        = ev["raw"],
                timestamp  = ev["timestamp"],
            ))

    return alerts


# ──────────────────────────────────────────────────────────────────────────────
# RULE 4 — Activity Spike Detection
# ──────────────────────────────────────────────────────────────────────────────

def rule_activity_spike(events: list) -> list:
    """
    Detects a sudden spike in activity per minute.
    Fires WARNING when any minute has ACTIVITY_SPIKE_FACTOR× more events
    than the average events-per-minute.
    """
    if len(events) < 5:
        return []

    alerts = []
    events_per_minute = defaultdict(int)

    for ev in events:
        try:
            dt  = datetime.fromisoformat(ev["timestamp"])
            key = dt.strftime("%Y-%m-%d %H:%M")
            events_per_minute[key] += 1
        except ValueError:
            continue

    if not events_per_minute:
        return []

    counts  = list(events_per_minute.values())
    average = sum(counts) / len(counts)
    spike_seen = set()

    for minute, count in events_per_minute.items():
        if count >= average * ACTIVITY_SPIKE_FACTOR and minute not in spike_seen:
            spike_seen.add(minute)
            alerts.append(_make_alert(
                alert_type = "Activity Spike",
                severity   = "WARNING",
                ip         = "N/A",
                username   = "N/A",
                detail     = (
                    f"At {minute}: {count} events in one minute "
                    f"(avg={average:.1f}, factor={ACTIVITY_SPIKE_FACTOR}×). "
                    f"Possible automated attack or scan."
                ),
                raw        = f"[spike at {minute}]",
                timestamp  = f"{minute}:00",
            ))

    return alerts


# ──────────────────────────────────────────────────────────────────────────────
# RULE 5 — Privilege Escalation
# ──────────────────────────────────────────────────────────────────────────────

def rule_privilege_escalation(events: list) -> list:
    """
    Fires WARNING whenever a sudo/privilege-escalation event is detected.
    """
    alerts = []
    for ev in events:
        if ev["event_type"] == "PRIVILEGE_ESCALATION":
            alerts.append(_make_alert(
                alert_type = "Privilege Escalation",
                severity   = "WARNING",
                ip         = ev["ip"],
                username   = ev["username"],
                detail     = (
                    f"User '{ev['username']}' escalated privileges (sudo/su). "
                    f"Verify this action is authorised."
                ),
                raw        = ev["raw"],
                timestamp  = ev["timestamp"],
            ))
    return alerts


# ──────────────────────────────────────────────────────────────────────────────
# RULE 6 — Invalid User Probing
# ──────────────────────────────────────────────────────────────────────────────

def rule_invalid_user_probe(events: list) -> list:
    """
    Fires INFO for invalid username login attempts (username enumeration).
    """
    alerts    = []
    seen_ips  = set()

    for ev in events:
        if ev["event_type"] == "INVALID_USER" and ev["ip"] not in seen_ips:
            seen_ips.add(ev["ip"])
            alerts.append(_make_alert(
                alert_type = "Invalid User Probe",
                severity   = "INFO",
                ip         = ev["ip"],
                username   = ev["username"],
                detail     = (
                    f"Login attempt with non-existent user '{ev['username']}' "
                    f"from {ev['ip']}. Could be username enumeration."
                ),
                raw        = ev["raw"],
                timestamp  = ev["timestamp"],
            ))

    return alerts


# ──────────────────────────────────────────────────────────────────────────────
# ★ RULES REGISTRY — add new rule functions here ★
# ──────────────────────────────────────────────────────────────────────────────
RULES = [
    rule_brute_force,
    rule_suspicious_ip,
    rule_off_hours_login,
    rule_activity_spike,
    rule_privilege_escalation,
    rule_invalid_user_probe,
]


# ──────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ──────────────────────────────────────────────────────────────────────────────

def run_detection(events: list) -> list:
    """
    Run all registered rules against the parsed event list.

    Parameters
    ----------
    events : list[dict]
        Output of parser.log_parser.parse_log_file().

    Returns
    -------
    list[dict]
        All alerts produced by all rules, sorted newest-first.
    """
    all_alerts = []

    for rule_fn in RULES:
        try:
            results = rule_fn(events)
            all_alerts.extend(results)
            if results:
                print(f"[DETECTION] Rule '{rule_fn.__name__}' → {len(results)} alert(s)")
        except Exception as exc:
            print(f"[DETECTION] Rule '{rule_fn.__name__}' raised error: {exc}")

    # Sort newest first
    all_alerts.sort(key=lambda a: a["timestamp"], reverse=True)
    print(f"[DETECTION] Total alerts generated: {len(all_alerts)}")
    return all_alerts
