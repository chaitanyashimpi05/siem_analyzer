# Enterprise-Grade Full-Stack SIEM Platform

![SIEM Banner](https://img.shields.io/badge/Security-SIEM%20SOC%20v2.0-blue?style=for-the-badge&logo=shield)
![FastAPI](https://img.shields.io/badge/Backend-FastAPI%20%7C%20Python%203.12-009688?style=for-the-badge&logo=fastapi)
![React](https://img.shields.io/badge/Frontend-React%2018%20%7C%20Vite%20%7C%20Tailwind-61DAFB?style=for-the-badge&logo=react)
![Database](https://img.shields.io/badge/Database-SQLAlchemy%20%7C%20SQLite%20%7C%20PostgreSQL-4169E1?style=for-the-badge&logo=postgresql)

A production-style Security Information and Event Management (SIEM) platform engineered for modern Security Operations Centers (SOC). Reuses and expands core Python threat detection rules into a full-stack platform featuring JWT authentication, FastAPI REST APIs, SQLAlchemy ORM, real-time Watchdog directory monitoring, interactive Chart.js dashboards, Threat Intelligence enrichment (AbuseIPDB/VT/GeoIP), MITRE ATT&CK framework mapping, multi-channel notifications (SMTP Email, Discord, Slack), and automated executive PDF/HTML report generation.

---

## 🏛️ Architecture Overview

```
siem_analyzer/
├── backend/
│   ├── app/
│   │   ├── api/            # REST API endpoints (auth, dashboard, alerts, logs, reports, monitor, health)
│   │   ├── auth/           # JWT token handling & direct bcrypt password hashing
│   │   ├── database/       # SQLAlchemy ORM session factory & engine setup
│   │   ├── detectors/      # Preserved & expanded 16-rule detection engine + MITRE ATT&CK mapping
│   │   ├── models/         # Database ORM models (User, Alert, Log, Report)
│   │   ├── reports/        # Executive PDF (ReportLab) & HTML security report generators
│   │   ├── schemas/        # Pydantic data validation schemas
│   │   ├── services/       # Threat Intel (AbuseIPDB, VT, GeoIP), Notifications, Watchdog Monitor
│   │   ├── utils/          # Multi-format log parsers (auth.log, syslog, apache, evtx, json, generic)
│   │   ├── websocket/      # Live alert feed WebSocket connection manager
│   │   └── main.py         # FastAPI application entry point
├── frontend/
│   ├── src/
│   │   ├── components/     # Navbar, Sidebar, StatCards, SeverityBadge, MitreBadge, ThreatIntelModal
│   │   ├── pages/          # Dashboard, Alerts, AlertDetail, Logs, Monitor, Reports, Login, Register
│   │   └── services/       # Axios API client, AuthContext, WebSocket listener
│   ├── package.json
│   └── vite.config.js
├── logs/                   # Monitored directory for live Watchdog log ingestion
├── uploads/                # Directory for uploaded raw log files
├── reports/                # Output directory for generated PDF & HTML executive reports
├── tests/                  # Pytest unit & integration test suite (parsers, detectors, API)
└── README.md
```

---

## 🔥 Key Features

- 🔒 **Role-Based JWT Authentication**: Secure login & registration (`Admin` vs `Analyst` roles).
- 📊 **Interactive SOC Dashboard**: Real-time KPI stat cards, severity distribution donut charts, attack timeline, top attacker IPs, and live WebSocket threat feed.
- ⚡ **Real-Time Log Monitoring**: Python `Watchdog` service automatically monitors `logs/` directory, parses new files on creation, detects attacks, stores alerts, and broadcasts to dashboard live without manual refresh.
- 🛡️ **16 Modular Security Detectors**:
  - SSH Brute Force (`T1110.001`)
  - Password Spraying (`T1110.003`)
  - SQL Injection (`T1190`)
  - Cross-Site Scripting (XSS) (`T1190`)
  - OS Command Injection (`T1059`)
  - Web Shell Upload (`T1505.003`)
  - Sensitive File Access (`T1083`)
  - Port Scanning (`T1046`)
  - Suspicious User Agent (`T1071.001`)
  - Privilege Escalation (`T1548`)
  - Off-Hours Logins (`T1078`)
  - Activity Volume Spikes (`T1499`)
  - Invalid Username Probes (`T1087`)
  - Impossible Travel (`T1078.004`)
  - Suspicious IP Reputation (`T1071`)
  - IOC Signature Matching (`T1204`)
- 🌐 **Threat Intelligence & GeoIP Enrichment**: Real-time lookup for country, ASN, ISP provider, AbuseIPDB confidence score, and reputation level.
- 🎯 **MITRE ATT&CK Integration**: Every alert is tagged with technique ID, technique name, tactic category, and direct links to MITRE documentation.
- 📄 **Executive PDF & HTML Reporting**: One-click generation of professional security reports with summary metrics, attacker lists, and actionable mitigation recommendations.
- 📢 **Multi-Channel Notifications**: Automated alert dispatches to SMTP Email, Discord webhooks, and Slack webhooks.

---

## 🛠️ Tech Stack

- **Backend**: Python 3.12, FastAPI, SQLAlchemy ORM, Pydantic v2, Pytest, ReportLab, Watchdog, Uvicorn, Jose JWT, Bcrypt.
- **Frontend**: React 18, Vite, Tailwind CSS, Axios, React Router DOM v6, Chart.js, Lucide React Icons.
- **Database**: SQLite (dev default) & PostgreSQL (production ready).

---

## 🚀 Getting Started

### Local Development Setup

#### 1. Backend Setup
```bash
# Install Python dependencies
pip install -r requirements.txt

# Launch FastAPI development server (with live reload)
uvicorn backend.app.main:app --reload --port 8000
```
- API Documentation (Swagger UI): `http://127.0.0.1:8000/docs`
- Health Check: `http://127.0.0.1:8000/api/health`

#### 2. Frontend Setup
```bash
# Navigate to frontend directory
cd frontend

# Install Node dependencies
npm install

# Launch Vite development server
npm run dev
```
- SOC Dashboard UI: `http://localhost:5173`
- Default Login Credentials:
  - **Admin**: `admin` / `admin123`
  - **Analyst**: `analyst` / `analyst123`

---

## 🧪 Testing

Run unit and integration tests across parsers, detectors, and REST APIs:

```bash
pytest
```

---

## 📡 REST API Reference Summary

| Method | Endpoint | Description | Access |
|---|---|---|---|
| `POST` | `/api/auth/login` | Authenticate user & obtain JWT token | Public |
| `POST` | `/api/auth/register` | Register new SOC Analyst / Admin account | Public |
| `GET` | `/api/auth/me` | Retrieve current authenticated user profile | Bearer Token |
| `GET` | `/api/dashboard` | Summary statistics, severity breakdown, top IPs | Bearer Token |
| `GET` | `/api/alerts` | Paginated alerts with search & multi-filters | Bearer Token |
| `PATCH` | `/api/alerts/{id}` | Update alert status, analyst notes, assignment | Bearer Token |
| `GET` | `/api/alerts/export/csv` | Export filtered alerts to CSV file | Bearer Token |
| `POST` | `/api/logs/upload` | Upload and analyze raw log files | Bearer Token |
| `POST` | `/api/reports/generate` | Generate executive PDF or HTML report | Bearer Token |
| `POST` | `/api/monitor/start` | Start real-time Watchdog directory monitor | Bearer Token |
| `GET` | `/api/health` | System health check & database state | Public |
