# ⚡ SIEM Log Analyzer — Mini SOC System

A production-quality **Security Information and Event Management (SIEM)** system
built in Python + Flask. Parses Linux/Windows logs, detects threats with modular
rules, stores alerts in SQLite, and visualises everything on a dark-theme SOC dashboard.

---

## 📸 Features at a Glance

| Feature | Description |
|---|---|
| **Log Parsing** | Parses `auth.log`, `syslog`, and any custom log file |
| **6 Threat Rules** | Brute force, suspicious IPs, off-hours login, activity spike, privilege escalation, invalid user probe |
| **Alert Storage** | SQLite database with severity levels (CRITICAL / WARNING / INFO) |
| **Dashboard** | Dark SOC-themed Flask web UI with Chart.js graphs |
| **File Upload** | Drag-and-drop log upload with auto-analysis |
| **Real-Time Feed** | Server-Sent Events stream simulates live log monitoring |
| **Email Alerts** | Optional SMTP notifications for CRITICAL severity |
| **Modular Rules** | Add new detection rules in one file |

---

## 🗂️ Project Structure

```
siem_analyzer/
│
├── logs/                        # Log files (input)
│   ├── auth.log                 # Sample SSH/auth log
│   └── syslog                   # Sample syslog
│
├── parser/
│   ├── __init__.py
│   └── log_parser.py            # Regex-based log parser
│
├── detection/
│   ├── __init__.py
│   └── engine.py                # Threat detection rules engine
│
├── alerts/
│   ├── __init__.py
│   ├── store.py                 # SQLite alert storage
│   └── email_notifier.py        # Optional SMTP email alerts
│
├── dashboard/
│   ├── app.py                   # Flask web application
│   ├── templates/
│   │   └── index.html           # Main dashboard HTML
│   └── static/
│       ├── css/style.css        # Dark SOC theme stylesheet
│       └── js/app.js            # Dashboard JavaScript
│
├── requirements.txt
└── README.md
```

---

## 🚀 Quick Start (Local)

### 1. Clone / Download

```bash
git clone https://github.com/yourname/siem-analyzer.git
cd siem-analyzer
```

### 2. Create a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the App

```bash
cd dashboard
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

On startup, the app automatically parses the sample log files and pre-loads alerts so the dashboard is ready immediately.

---

## 🔧 Usage Guide

### Analyze Default Logs
Click **"Analyze Logs"** in the top bar or sidebar. This runs the parser and detection engine on `logs/auth.log` and `logs/syslog`.

### Upload Your Own Log File
Drag and drop any `.log` or `.txt` file onto the upload zone. The system auto-detects the log type and runs detection.

### Start Live Feed
Click **"Start Live Feed"** to begin real-time monitoring (simulated events). The dashboard updates automatically.

### Filter Alerts
Use the **Critical / Warning / Info** filter buttons above the table, or type in the search box to filter by IP, username, or alert type.

### Click Any Alert Row
Opens a detail modal with the full alert information and raw log line.

---

## 🛡️ Detection Rules

| Rule | Trigger | Severity |
|---|---|---|
| Brute Force | ≥5 failed logins from same IP | CRITICAL |
| Multiple Failed Logins | 3–4 failures | WARNING |
| Suspicious IP | Activity from known-bad IPs | CRITICAL |
| Off-Hours Login | Successful login 02:00–05:00 | WARNING |
| Activity Spike | Events/minute > 3× average | WARNING |
| Privilege Escalation | sudo / su command detected | WARNING |
| Invalid User Probe | Login with non-existent username | INFO |

### Adding a New Rule

Open `detection/engine.py` and add a function:

```python
def rule_my_custom_rule(events: list) -> list:
    alerts = []
    for ev in events:
        if "some condition" in ev["raw"]:
            alerts.append(_make_alert(
                alert_type = "My Custom Alert",
                severity   = "WARNING",
                ip         = ev["ip"],
                username   = ev["username"],
                detail     = "Custom rule triggered.",
                raw        = ev["raw"],
            ))
    return alerts

# Register it:
RULES.append(rule_my_custom_rule)
```

---

## 📧 Email Alert Configuration

Set these environment variables before running:

```bash
export SIEM_SMTP_HOST="smtp.gmail.com"
export SIEM_SMTP_PORT="587"
export SIEM_SMTP_USER="you@gmail.com"
export SIEM_SMTP_PASS="your_app_password"
export SIEM_ALERT_EMAIL="soc@yourcompany.com"
```

> **Note**: Use a Gmail App Password (not your main password). Go to Google Account → Security → App Passwords.

---

## 🔍 ELK Stack Integration (Optional)

For production scale, replace the SQLite store with Elasticsearch:

1. **Filebeat** watches log files and ships to Logstash
2. **Logstash** applies grok patterns (similar to our regex parser)
3. **Elasticsearch** indexes events
4. **Kibana** visualizes (or use our Flask dashboard querying ES)

To connect to ES, modify `alerts/store.py` to use the `elasticsearch-py` client:

```python
from elasticsearch import Elasticsearch
es = Elasticsearch("http://localhost:9200")
es.index(index="siem-alerts", document=alert)
```

---

## 🛡️ AbuseIPDB Threat Intelligence

```bash
export ABUSEIPDB_KEY="your_api_key_here"
```

Add to `detection/engine.py`:

```python
import requests, os

def check_abuseipdb(ip: str) -> int:
    key = os.getenv("ABUSEIPDB_KEY", "")
    if not key or ip in ("N/A", "localhost"):
        return 0
    resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90}
    )
    return resp.json()["data"]["abuseConfidenceScore"]
```

---

## ☁️ Deployment

### Render (Free Tier)

1. Push your project to GitHub
2. Go to [render.com](https://render.com) → New Web Service
3. Connect your repo
4. Build command: `pip install -r requirements.txt`
5. Start command: `gunicorn dashboard.app:app`
6. Add environment variables in Render's dashboard

### Heroku

```bash
# Install Heroku CLI, then:
heroku create siem-analyzer
git push heroku main
heroku config:set SIEM_SMTP_USER=you@gmail.com
```

Create `Procfile`:
```
web: gunicorn dashboard.app:app
```

---

## 🧪 Running the Test Suite

```bash
python -m pytest tests/ -v
```

---

## 🗺️ Roadmap

- [ ] Windows Event Log support (pywin32)
- [ ] GeoIP mapping of attacking IPs
- [ ] Scheduled reports (daily PDF)
- [ ] Slack/Webhook notifications
- [ ] Multi-user authentication
- [ ] Elasticsearch backend

---

## 📄 License

MIT — free to use and modify for educational and commercial purposes.
