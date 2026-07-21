"""
backend/app/detectors/engine.py
================================
Modular Security Detection Engine mapping security log events to MITRE ATT&CK techniques.

Includes preserved logic for brute force, suspicious IP, off-hours login, activity spike,
privilege escalation, and invalid user probes, plus expanded web app, network, and systemic detectors.
"""

import re
from datetime import datetime
from collections import defaultdict

BRUTE_FORCE_THRESHOLD = 5
ACTIVITY_SPIKE_FACTOR = 3.0
OFF_HOURS_START = 2
OFF_HOURS_END = 5

SUSPICIOUS_IPS = {
    "45.33.32.156", "185.220.101.1", "91.92.93.94", "198.51.100.44", "203.0.113.88"
}

SUSPICIOUS_USER_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirbuster", "wpscan", "python-requests/2"
]

SENSITIVE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/.env", "/wp-config.php", "/.git/config", "/id_rsa", "/config.json"
]


def _make_alert(
    attack_type: str,
    severity: str,
    source_ip: str,
    description: str,
    raw_log: str,
    timestamp: str = None,
    destination_ip: str = "N/A",
    log_source: str = "syslog",
    mitre_id: str = "T1110",
    mitre_name: str = "Brute Force",
    mitre_tactic: str = "Credential Access",
    recommendation: str = "Investigate event details and isolate source IP if suspicious."
) -> dict:
    return {
        "attack_type": attack_type,
        "severity": severity,
        "timestamp": timestamp or datetime.now().isoformat(),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "description": description,
        "log_source": log_source,
        "raw_log": raw_log,
        "mitre_technique_id": mitre_id,
        "mitre_technique_name": mitre_name,
        "mitre_tactic": mitre_tactic,
        "recommendation": recommendation,
    }


# ── RULE 1: SSH Brute Force ──────────────────────────────────────────────────
def rule_brute_force(events: list) -> list:
    alerts = []
    failures_per_ip = defaultdict(list)
    for ev in events:
        if ev.get("event_type") == "FAILED_LOGIN":
            failures_per_ip[ev.get("ip")].append(ev)

    for ip, fail_events in failures_per_ip.items():
        count = len(fail_events)
        if count >= BRUTE_FORCE_THRESHOLD:
            first = fail_events[0]
            alerts.append(_make_alert(
                attack_type="SSH Brute Force",
                severity="CRITICAL",
                source_ip=ip,
                description=f"IP {ip} generated {count} failed login attempts. Possible brute force attack.",
                raw_log=first.get("raw", ""),
                timestamp=first.get("timestamp"),
                log_source=first.get("source", "auth.log"),
                mitre_id="T1110.001",
                mitre_name="Password Guessing",
                mitre_tactic="Credential Access",
                recommendation="Block source IP via firewall and check for successful logins."
            ))
        elif count >= 3:
            first = fail_events[0]
            alerts.append(_make_alert(
                attack_type="Multiple Failed Logins",
                severity="MEDIUM",
                source_ip=ip,
                description=f"IP {ip} produced {count} failed login attempts.",
                raw_log=first.get("raw", ""),
                timestamp=first.get("timestamp"),
                log_source=first.get("source", "auth.log"),
                mitre_id="T1110",
                mitre_name="Brute Force",
                mitre_tactic="Credential Access",
                recommendation="Monitor user accounts targeted by this IP."
            ))

    return alerts


# ── RULE 2: Password Spraying ────────────────────────────────────────────────
def rule_password_spray(events: list) -> list:
    alerts = []
    users_per_ip = defaultdict(set)
    first_seen = {}

    for ev in events:
        if ev.get("event_type") == "FAILED_LOGIN" and ev.get("username") not in ("N/A", "unknown"):
            ip = ev.get("ip")
            users_per_ip[ip].add(ev.get("username"))
            if ip not in first_seen:
                first_seen[ip] = ev

    for ip, users in users_per_ip.items():
        if len(users) >= 4:
            ev = first_seen[ip]
            alerts.append(_make_alert(
                attack_type="Password Spray",
                severity="HIGH",
                source_ip=ip,
                description=f"IP {ip} attempted failed logins across {len(users)} distinct user accounts.",
                raw_log=ev.get("raw", ""),
                timestamp=ev.get("timestamp"),
                log_source=ev.get("source", "auth.log"),
                mitre_id="T1110.003",
                mitre_name="Password Spraying",
                mitre_tactic="Credential Access",
                recommendation="Enforce MFA and reset passwords for affected accounts."
            ))
    return alerts


# ── RULE 3: Suspicious IP Reputation ─────────────────────────────────────────
def rule_suspicious_ip(events: list) -> list:
    alerts = []
    seen = set()

    for ev in events:
        ip = ev.get("ip")
        if ip in SUSPICIOUS_IPS and ip not in seen:
            seen.add(ip)
            alerts.append(_make_alert(
                attack_type="Suspicious IP Reputation",
                severity="CRITICAL",
                source_ip=ip,
                description=f"Traffic detected from known malicious/scanner IP {ip}.",
                raw_log=ev.get("raw", ""),
                timestamp=ev.get("timestamp"),
                log_source=ev.get("source", "syslog"),
                mitre_id="T1071",
                mitre_name="Application Layer Protocol",
                mitre_tactic="Command and Control",
                recommendation="Immediately drop all incoming traffic from this IP address."
            ))
    return alerts


# ── RULE 4: SQL Injection ────────────────────────────────────────────────────
def rule_sql_injection(events: list) -> list:
    alerts = []
    sqli_pattern = re.compile(r"(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|' OR ''='|' OR '1'='1|--\s*$|;\s*drop\b|\bexec\b|\bcast\b)", re.IGNORECASE)

    for ev in events:
        raw = ev.get("raw", "")
        if sqli_pattern.search(raw):
            alerts.append(_make_alert(
                attack_type="SQL Injection",
                severity="CRITICAL",
                source_ip=ev.get("ip", "N/A"),
                description="SQL injection payload detected in HTTP query or payload.",
                raw_log=raw,
                timestamp=ev.get("timestamp"),
                log_source=ev.get("source", "access.log"),
                mitre_id="T1190",
                mitre_name="Exploit Public-Facing Application",
                mitre_tactic="Initial Access",
                recommendation="Sanitize database inputs and use parameterized SQL queries."
            ))
    return alerts


# ── RULE 5: Cross-Site Scripting (XSS) ────────────────────────────────────────
def rule_xss(events: list) -> list:
    alerts = []
    xss_pattern = re.compile(r"(<script.*?>|javascript:|onerror\s*=|onload\s*=|alert\(|document\.cookie)", re.IGNORECASE)

    for ev in events:
        raw = ev.get("raw", "")
        if xss_pattern.search(raw):
            alerts.append(_make_alert(
                attack_type="Cross-Site Scripting (XSS)",
                severity="HIGH",
                source_ip=ev.get("ip", "N/A"),
                description="XSS payload found in web application log line.",
                raw_log=raw,
                timestamp=ev.get("timestamp"),
                log_source=ev.get("source", "access.log"),
                mitre_id="T1190",
                mitre_name="Exploit Public-Facing Application",
                mitre_tactic="Initial Access",
                recommendation="Apply HTML output encoding and Content Security Policy (CSP)."
            ))
    return alerts


# ── RULE 6: Command Injection ─────────────────────────────────────────────────
def rule_command_injection(events: list) -> list:
    alerts = []
    cmd_pattern = re.compile(r"(;\s*cat\s+/etc/|\|\s*id\b|&&\s*whoami\b|\$\(nc\s+|\bsh\s+-c\b|;\s*rm\s+-rf)", re.IGNORECASE)

    for ev in events:
        raw = ev.get("raw", "")
        if cmd_pattern.search(raw):
            alerts.append(_make_alert(
                attack_type="Command Injection",
                severity="CRITICAL",
                source_ip=ev.get("ip", "N/A"),
                description="OS command injection syntax detected in input parameters.",
                raw_log=raw,
                timestamp=ev.get("timestamp"),
                log_source=ev.get("source", "access.log"),
                mitre_id="T1059",
                mitre_name="Command and Scripting Interpreter",
                mitre_tactic="Execution",
                recommendation="Never pass untrusted inputs directly to system shell execution."
            ))
    return alerts


# ── RULE 7: Web Shell Upload ──────────────────────────────────────────────────
def rule_webshell_upload(events: list) -> list:
    alerts = []
    shell_pattern = re.compile(r"(\.php|\.jsp|\.asp|\.aspx|\.cgi)\s+.*(c99|r57|cmd|shell|b374k|wso)", re.IGNORECASE)

    for ev in events:
        raw = ev.get("raw", "")
        if shell_pattern.search(raw) or "webshell" in raw.lower():
            alerts.append(_make_alert(
                attack_type="Web Shell Upload",
                severity="CRITICAL",
                source_ip=ev.get("ip", "N/A"),
                description="Potential Web Shell payload or file upload activity identified.",
                raw_log=raw,
                timestamp=ev.get("timestamp"),
                log_source=ev.get("source", "access.log"),
                mitre_id="T1505.003",
                mitre_name="Web Shell",
                mitre_tactic="Persistence",
                recommendation="Inspect file uploads directory and revoke execution permissions."
            ))
    return alerts


# ── RULE 8: Sensitive File Access ──────────────────────────────────────────────
def rule_sensitive_file_access(events: list) -> list:
    alerts = []
    for ev in events:
        raw = ev.get("raw", "")
        for path in SENSITIVE_PATHS:
            if path in raw:
                alerts.append(_make_alert(
                    attack_type="Sensitive File Access",
                    severity="HIGH",
                    source_ip=ev.get("ip", "N/A"),
                    description=f"Attempted access to sensitive system/configuration file: {path}.",
                    raw_log=raw,
                    timestamp=ev.get("timestamp"),
                    log_source=ev.get("source", "access.log"),
                    mitre_id="T1083",
                    mitre_name="File and Directory Discovery",
                    mitre_tactic="Discovery",
                    recommendation="Restrict read permissions on sensitive files and update web root scope."
                ))
                break
    return alerts


# ── RULE 9: Port Scanning ─────────────────────────────────────────────────────
def rule_port_scan(events: list) -> list:
    alerts = []
    drops_per_ip = defaultdict(list)
    for ev in events:
        if ev.get("event_type") == "PACKET_DROPPED":
            drops_per_ip[ev.get("ip")].append(ev)

    for ip, drop_events in drops_per_ip.items():
        if len(drop_events) >= 5:
            ev = drop_events[0]
            alerts.append(_make_alert(
                attack_type="Port Scan",
                severity="HIGH",
                source_ip=ip,
                description=f"Port scan / probe detected: {len(drop_events)} dropped packets from IP {ip}.",
                raw_log=ev.get("raw", ""),
                timestamp=ev.get("timestamp"),
                log_source=ev.get("source", "syslog"),
                mitre_id="T1046",
                mitre_name="Network Service Discovery",
                mitre_tactic="Discovery",
                recommendation="Deploy automatic rate-limiting or firewall drop rules for scanner IPs."
            ))
    return alerts


# ── RULE 10: Suspicious User Agent ───────────────────────────────────────────
def rule_suspicious_user_agent(events: list) -> list:
    alerts = []
    seen = set()
    for ev in events:
        raw = ev.get("raw", "").lower()
        ip = ev.get("ip", "N/A")
        for ua in SUSPICIOUS_USER_AGENTS:
            if ua in raw and (ip, ua) not in seen:
                seen.add((ip, ua))
                alerts.append(_make_alert(
                    attack_type="Suspicious User Agent",
                    severity="MEDIUM",
                    source_ip=ip,
                    description=f"Automated security scanner user-agent detected: '{ua}'.",
                    raw_log=ev.get("raw", ""),
                    timestamp=ev.get("timestamp"),
                    log_source=ev.get("source", "access.log"),
                    mitre_id="T1071.001",
                    mitre_name="Web Protocols",
                    mitre_tactic="Command and Control",
                    recommendation="Block known scanner user-agents in web server configuration."
                ))
                break
    return alerts


# ── RULE 11: Privilege Escalation ─────────────────────────────────────────────
def rule_privilege_escalation(events: list) -> list:
    alerts = []
    for ev in events:
        if ev.get("event_type") == "PRIVILEGE_ESCALATION":
            alerts.append(_make_alert(
                attack_type="Privilege Escalation",
                severity="HIGH",
                source_ip=ev.get("ip", "localhost"),
                description=f"User '{ev.get('username')}' executed administrative sudo/su command.",
                raw_log=ev.get("raw", ""),
                timestamp=ev.get("timestamp"),
                log_source=ev.get("source", "auth.log"),
                mitre_id="T1548",
                mitre_name="Abuse Elevation Control Mechanism",
                mitre_tactic="Privilege Escalation",
                recommendation="Audit sudoers policy and verify administrator session history."
            ))
    return alerts


# ── RULE 12: Off-Hours Login ──────────────────────────────────────────────────
def rule_off_hours_login(events: list) -> list:
    alerts = []
    for ev in events:
        if ev.get("event_type") != "SUCCESSFUL_LOGIN":
            continue
        try:
            dt = datetime.fromisoformat(ev.get("timestamp"))
            hour = dt.hour
        except Exception:
            continue

        if OFF_HOURS_START <= hour < OFF_HOURS_END:
            alerts.append(_make_alert(
                attack_type="Off-Hours Login",
                severity="LOW",
                source_ip=ev.get("ip", "N/A"),
                description=f"User '{ev.get('username')}' logged in during off-hours ({OFF_HOURS_START:02d}:00–{OFF_HOURS_END:02d}:00).",
                raw_log=ev.get("raw", ""),
                timestamp=ev.get("timestamp"),
                log_source=ev.get("source", "auth.log"),
                mitre_id="T1078",
                mitre_name="Valid Accounts",
                mitre_tactic="Defense Evasion",
                recommendation="Confirm with account owner if off-hours access was authorized."
            ))
    return alerts


# ── RULE 13: Activity Spike Detection ─────────────────────────────────────────
def rule_activity_spike(events: list) -> list:
    if len(events) < 5:
        return []
    alerts = []
    events_per_minute = defaultdict(int)
    for ev in events:
        try:
            dt = datetime.fromisoformat(ev["timestamp"])
            key = dt.strftime("%Y-%m-%d %H:%M")
            events_per_minute[key] += 1
        except Exception:
            continue

    if not events_per_minute:
        return []

    counts = list(events_per_minute.values())
    average = sum(counts) / len(counts)
    spike_seen = set()

    for minute, count in events_per_minute.items():
        if count >= average * ACTIVITY_SPIKE_FACTOR and minute not in spike_seen:
            spike_seen.add(minute)
            alerts.append(_make_alert(
                attack_type="Activity Spike",
                severity="MEDIUM",
                source_ip="N/A",
                description=f"Unusual spike in log volume at {minute}: {count} events (average={average:.1f}).",
                raw_log=f"[Volume spike at {minute}]",
                timestamp=f"{minute}:00",
                log_source="syslog",
                mitre_id="T1499",
                mitre_name="Endpoint Denial of Service",
                mitre_tactic="Impact",
                recommendation="Check system resource usage and incoming request patterns."
            ))
    return alerts


# ── RULE 14: Invalid User Probing ─────────────────────────────────────────────
def rule_invalid_user_probe(events: list) -> list:
    alerts = []
    seen = set()
    for ev in events:
        if ev.get("event_type") == "INVALID_USER" and ev.get("ip") not in seen:
            seen.add(ev.get("ip"))
            alerts.append(_make_alert(
                attack_type="Invalid User Probe",
                severity="LOW",
                source_ip=ev.get("ip"),
                description=f"Login attempt with non-existent account '{ev.get('username')}' from {ev.get('ip')}.",
                raw_log=ev.get("raw", ""),
                timestamp=ev.get("timestamp"),
                log_source=ev.get("source", "auth.log"),
                mitre_id="T1087",
                mitre_name="Account Discovery",
                mitre_tactic="Discovery",
                recommendation="Monitor IP for subsequent credential guessing attacks."
            ))
    return alerts


# ── RULE 15: Impossible Travel ────────────────────────────────────────────────
def rule_impossible_travel(events: list) -> list:
    alerts = []
    logins_by_user = defaultdict(list)
    for ev in events:
        if ev.get("event_type") == "SUCCESSFUL_LOGIN" and ev.get("ip") not in ("N/A", "localhost", "127.0.0.1"):
            logins_by_user[ev.get("username")].append(ev)

    for user, logins in logins_by_user.items():
        if len(logins) >= 2:
            ips = {l.get("ip") for l in logins}
            if len(ips) >= 2:
                first = logins[0]
                alerts.append(_make_alert(
                    attack_type="Impossible Travel",
                    severity="HIGH",
                    source_ip=first.get("ip"),
                    description=f"User '{user}' logged in from multiple geographically distinct IPs within short timeframe ({', '.join(ips)}).",
                    raw_log=first.get("raw", ""),
                    timestamp=first.get("timestamp"),
                    log_source=first.get("source", "auth.log"),
                    mitre_id="T1078.004",
                    mitre_name="Cloud Accounts",
                    mitre_tactic="Initial Access",
                    recommendation="Revoke active sessions for user and trigger immediate password reset."
                ))
    return alerts


# ── RULE 16: IOC Signature Matching ───────────────────────────────────────────
def rule_ioc_match(events: list) -> list:
    alerts = []
    ioc_hashes = {"44d888234a9730047306f4f010956122", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
    for ev in events:
        raw = ev.get("raw", "")
        for hash_val in ioc_hashes:
            if hash_val in raw:
                alerts.append(_make_alert(
                    attack_type="IOC Signature Match",
                    severity="CRITICAL",
                    source_ip=ev.get("ip", "N/A"),
                    description=f"Known malicious Indicator of Compromise (IOC) hash matched: {hash_val}.",
                    raw_log=raw,
                    timestamp=ev.get("timestamp"),
                    log_source=ev.get("source", "syslog"),
                    mitre_id="T1204",
                    mitre_name="User Execution",
                    mitre_tactic="Execution",
                    recommendation="Perform endpoint memory dump and isolate host machine from network."
                ))
                break
    return alerts


RULES = [
    rule_brute_force,
    rule_password_spray,
    rule_suspicious_ip,
    rule_sql_injection,
    rule_xss,
    rule_command_injection,
    rule_webshell_upload,
    rule_sensitive_file_access,
    rule_port_scan,
    rule_suspicious_user_agent,
    rule_privilege_escalation,
    rule_off_hours_login,
    rule_activity_spike,
    rule_invalid_user_probe,
    rule_impossible_travel,
    rule_ioc_match,
]


def run_detection(events: list) -> list:
    all_alerts = []
    for rule_fn in RULES:
        try:
            results = rule_fn(events)
            all_alerts.extend(results)
        except Exception as exc:
            print(f"[DETECTION] Rule '{rule_fn.__name__}' error: {exc}")

    all_alerts.sort(key=lambda a: a.get("timestamp", ""), reverse=True)
    return all_alerts
