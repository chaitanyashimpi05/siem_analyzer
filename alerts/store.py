"""
alerts/store.py
===============
Stores and retrieves alerts using SQLite (production) or an
in-memory fallback list if the DB cannot be created.

Table schema: alerts
  id          INTEGER PRIMARY KEY AUTOINCREMENT
  alert_type  TEXT
  severity    TEXT    ("INFO" | "WARNING" | "CRITICAL")
  timestamp   TEXT    (ISO-8601)
  ip          TEXT
  username    TEXT
  detail      TEXT
  raw         TEXT
  created_at  TEXT    (when the row was inserted)
"""

import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "alerts.db")

# In-memory fallback (used if SQLite is unavailable)
_MEMORY_STORE: list[dict] = []


# ──────────────────────────────────────────────────────────────────────────────
# DATABASE SETUP
# ──────────────────────────────────────────────────────────────────────────────

def init_db():
    """Create the alerts table if it does not already exist."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type  TEXT    NOT NULL,
                    severity    TEXT    NOT NULL,
                    timestamp   TEXT    NOT NULL,
                    ip          TEXT,
                    username    TEXT,
                    detail      TEXT,
                    raw         TEXT,
                    created_at  TEXT    NOT NULL
                )
            """)
            conn.commit()
        print(f"[STORE] Database ready at {DB_PATH}")
    except sqlite3.Error as exc:
        print(f"[STORE] SQLite error during init: {exc}. Using in-memory store.")


# ──────────────────────────────────────────────────────────────────────────────
# WRITE
# ──────────────────────────────────────────────────────────────────────────────

def save_alerts(alerts: list[dict]) -> int:
    """
    Insert a list of alert dicts into the database.
    Skips duplicates (same alert_type + ip + timestamp).
    Returns the number of new rows inserted.
    """
    if not alerts:
        return 0

    inserted = 0
    now      = datetime.now().isoformat()

    try:
        with sqlite3.connect(DB_PATH) as conn:
            for alert in alerts:
                # Duplicate check
                existing = conn.execute(
                    "SELECT 1 FROM alerts WHERE alert_type=? AND ip=? AND timestamp=?",
                    (alert["alert_type"], alert["ip"], alert["timestamp"])
                ).fetchone()

                if not existing:
                    conn.execute(
                        """INSERT INTO alerts
                           (alert_type, severity, timestamp, ip, username, detail, raw, created_at)
                           VALUES (?,?,?,?,?,?,?,?)""",
                        (
                            alert.get("alert_type", "Unknown"),
                            alert.get("severity",   "INFO"),
                            alert.get("timestamp",  now),
                            alert.get("ip",         "N/A"),
                            alert.get("username",   "N/A"),
                            alert.get("detail",     ""),
                            alert.get("raw",        ""),
                            now,
                        )
                    )
                    inserted += 1
            conn.commit()
    except sqlite3.Error as exc:
        print(f"[STORE] Insert error: {exc}. Falling back to memory.")
        _MEMORY_STORE.extend(alerts)
        return len(alerts)

    print(f"[STORE] Saved {inserted} new alert(s) to database.")
    return inserted


# ──────────────────────────────────────────────────────────────────────────────
# READ
# ──────────────────────────────────────────────────────────────────────────────

def get_all_alerts(limit: int = 500) -> list[dict]:
    """Return all alerts, newest first, up to `limit` rows."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.Error as exc:
        print(f"[STORE] Read error: {exc}")
        return list(reversed(_MEMORY_STORE[-limit:]))


def get_alerts_by_severity(severity: str) -> list[dict]:
    """Return alerts filtered by severity level."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM alerts WHERE severity=? ORDER BY timestamp DESC",
                (severity.upper(),)
            ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.Error as exc:
        print(f"[STORE] Read error: {exc}")
        return [a for a in _MEMORY_STORE if a.get("severity") == severity.upper()]


def get_top_ips(n: int = 10) -> list[dict]:
    """Return the top N IPs by alert count."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute(
                """SELECT ip, COUNT(*) as count
                   FROM alerts
                   WHERE ip != 'N/A' AND ip != 'localhost'
                   GROUP BY ip
                   ORDER BY count DESC
                   LIMIT ?""",
                (n,)
            ).fetchall()
        return [{"ip": r[0], "count": r[1]} for r in rows]
    except sqlite3.Error as exc:
        print(f"[STORE] Read error: {exc}")
        return []


def get_summary_stats() -> dict:
    """Return counts of alerts grouped by severity, plus a total."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            total    = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            critical = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'").fetchone()[0]
            warning  = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='WARNING'").fetchone()[0]
            info     = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='INFO'").fetchone()[0]
        return {"total": total, "critical": critical, "warning": warning, "info": info}
    except sqlite3.Error as exc:
        print(f"[STORE] Stats error: {exc}")
        return {"total": 0, "critical": 0, "warning": 0, "info": 0}


def get_alerts_over_time() -> list[dict]:
    """Return alert counts grouped by hour for the timeline chart."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute(
                """SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour,
                          COUNT(*) as count
                   FROM alerts
                   GROUP BY hour
                   ORDER BY hour ASC"""
            ).fetchall()
        return [{"hour": r[0], "count": r[1]} for r in rows]
    except sqlite3.Error as exc:
        print(f"[STORE] Timeline error: {exc}")
        return []


def clear_alerts():
    """Delete all alerts (useful for testing)."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM alerts")
            conn.commit()
        print("[STORE] All alerts cleared.")
    except sqlite3.Error as exc:
        print(f"[STORE] Clear error: {exc}")


# Initialise on first import
init_db()
