import os
import sys
import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

load_dotenv()

from backend.app.database.session import Base, engine, SessionLocal
from backend.app.models import User, Alert, Log, Report
from backend.app.auth.jwt import get_password_hash
from backend.app.websocket.manager import ws_manager
from backend.app.utils.log_parsers import parse_log_file
from backend.app.detectors.engine import run_detection

from backend.app.api.auth import router as auth_router
from backend.app.api.dashboard import router as dashboard_router
from backend.app.api.alerts import router as alerts_router
from backend.app.api.logs import router as logs_router
from backend.app.api.reports import router as reports_router
from backend.app.api.monitor import router as monitor_router
from backend.app.api.health import router as health_router

app = FastAPI(
    title="Enterprise SIEM Platform API",
    description="Full-Stack Security Information and Event Management Engine with Real-Time Monitoring & Threat Intel",
    version="2.0.0"
)

# CORS Setup
origins_env = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000")
origins = [o.strip() for o in origins_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Open for local SOC dashboard development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static Files
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(UPLOADS_DIR, exist_ok=True)

app.mount("/static/reports", StaticFiles(directory=REPORTS_DIR), name="reports_static")
app.mount("/static/uploads", StaticFiles(directory=UPLOADS_DIR), name="uploads_static")

# Routers
app.include_router(auth_router, prefix="/api")
app.include_router(dashboard_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(logs_router, prefix="/api")
app.include_router(reports_router, prefix="/api")
app.include_router(monitor_router, prefix="/api")
app.include_router(health_router, prefix="/api")


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Seed default admin user
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            admin_user = User(
                username="admin",
                email="admin@siem.local",
                password_hash=get_password_hash("admin123"),
                role="Admin"
            )
            db.add(admin_user)
            db.commit()
            print("[STARTUP] Initialized default admin account (admin / admin123)")

        # Seed default analyst user
        analyst = db.query(User).filter(User.username == "analyst").first()
        if not analyst:
            analyst_user = User(
                username="analyst",
                email="analyst@siem.local",
                password_hash=get_password_hash("analyst123"),
                role="Analyst"
            )
            db.add(analyst_user)
            db.commit()

        # Seed default log files analysis if database is empty
        if db.query(Alert).count() == 0:
            log_dir = os.path.join(BASE_DIR, "logs")
            all_events = []
            for fname, ltype in [("auth.log", "auth"), ("syslog", "syslog")]:
                fpath = os.path.join(log_dir, fname)
                if os.path.isfile(fpath):
                    all_events.extend(parse_log_file(fpath, ltype))

            if all_events:
                alerts = run_detection(all_events)
                for a in alerts:
                    new_alert = Alert(
                        timestamp=a.get("timestamp"),
                        source_ip=a.get("source_ip"),
                        destination_ip=a.get("destination_ip"),
                        severity=a.get("severity"),
                        attack_type=a.get("attack_type"),
                        description=a.get("description"),
                        log_source=a.get("log_source"),
                        status="OPEN",
                        mitre_technique_id=a.get("mitre_technique_id"),
                        mitre_technique_name=a.get("mitre_technique_name"),
                        mitre_tactic=a.get("mitre_tactic"),
                        recommendation=a.get("recommendation"),
                        raw_log=a.get("raw_log")
                    )
                    db.add(new_alert)
                db.commit()
                print(f"[STARTUP] Pre-loaded {len(alerts)} alerts from default log files.")
    except Exception as exc:
        print(f"[STARTUP] Error during startup seeding: {exc}")
    finally:
        db.close()


@app.websocket("/ws/alerts")
async def websocket_alerts_feed(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
