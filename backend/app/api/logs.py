import os
import shutil
from typing import Optional
from fastapi import APIRouter, Depends, File, UploadFile, HTTPException, Query
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.models.log import Log
from backend.app.models.alert import Alert
from backend.app.utils.log_parsers import parse_log_text, parse_log_file
from backend.app.detectors.engine import run_detection
from backend.app.services.notifications import dispatch_alert_notifications
from backend.app.websocket.manager import ws_manager

router = APIRouter(prefix="/logs", tags=["Logs"])

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "uploads")
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "logs")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)


def _detect_log_type(filename: str) -> str:
    lower = filename.lower()
    if "auth" in lower: return "auth"
    if "syslog" in lower or "sys" in lower: return "syslog"
    if "access" in lower or "apache" in lower: return "apache"
    if "win" in lower or "evtx" in lower: return "windows"
    if lower.endswith(".json"): return "json"
    return "generic"


@router.post("/upload")
async def upload_log_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file uploaded")

    filename = file.filename
    log_type = _detect_log_type(filename)
    contents = await file.read()
    text = contents.decode("utf-8", errors="replace")

    # Save to uploads directory
    save_path = os.path.join(UPLOAD_DIR, filename)
    with open(save_path, "w", encoding="utf-8") as f:
        f.write(text)

    events = parse_log_text(text, log_type)
    alerts = run_detection(events) if events else []

    saved_alerts = 0
    for ev in events:
        log_entry = Log(
            filename=filename,
            event_type=ev.get("event_type", "INFO"),
            raw_log=ev.get("raw", ""),
            timestamp=ev.get("timestamp", "")
        )
        db.add(log_entry)

    for a in alerts:
        existing = db.query(Alert).filter(
            Alert.attack_type == a.get("attack_type"),
            Alert.source_ip == a.get("source_ip"),
            Alert.timestamp == a.get("timestamp")
        ).first()

        if not existing:
            new_alert = Alert(
                timestamp=a.get("timestamp"),
                source_ip=a.get("source_ip"),
                destination_ip=a.get("destination_ip"),
                severity=a.get("severity"),
                attack_type=a.get("attack_type"),
                description=a.get("description"),
                log_source=a.get("log_source", filename),
                status="OPEN",
                mitre_technique_id=a.get("mitre_technique_id"),
                mitre_technique_name=a.get("mitre_technique_name"),
                mitre_tactic=a.get("mitre_tactic"),
                recommendation=a.get("recommendation"),
                raw_log=a.get("raw_log")
            )
            db.add(new_alert)
            saved_alerts += 1
    db.commit()

    if alerts:
        dispatch_alert_notifications(alerts)
        await ws_manager.broadcast({"type": "NEW_ALERTS", "count": len(alerts), "alerts": alerts[:5]})

    severity_counts = {
        "critical": sum(1 for a in alerts if a.get("severity") == "CRITICAL"),
        "high": sum(1 for a in alerts if a.get("severity") == "HIGH"),
        "medium": sum(1 for a in alerts if a.get("severity") == "MEDIUM"),
        "low": sum(1 for a in alerts if a.get("severity") == "LOW"),
    }

    return {
        "status": "ok",
        "filename": filename,
        "log_type": log_type,
        "parsed": len(events),
        "alerts": saved_alerts,
        "severity_breakdown": severity_counts
    }


@router.get("")
def list_logs(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    filename: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Log)
    if filename:
        query = query.filter(Log.filename.ilike(f"%{filename}%"))

    total = query.count()
    logs = query.order_by(Log.id.desc()).offset((page - 1) * per_page).limit(per_page).all()
    return {
        "logs": logs,
        "total": total,
        "page": page,
        "per_page": per_page
    }


@router.post("/analyze")
def analyze_default_logs(db: Session = Depends(get_db)):
    results = {"parsed": 0, "alerts_generated": 0, "files_processed": []}
    files = [("auth.log", "auth"), ("syslog", "syslog")]

    all_events = []
    for fname, ltype in files:
        fpath = os.path.join(LOG_DIR, fname)
        if os.path.isfile(fpath):
            evs = parse_log_file(fpath, ltype)
            all_events.extend(evs)
            results["parsed"] += len(evs)
            results["files_processed"].append(fname)

    if all_events:
        alerts = run_detection(all_events)
        saved = 0
        for a in alerts:
            existing = db.query(Alert).filter(
                Alert.attack_type == a.get("attack_type"),
                Alert.source_ip == a.get("source_ip"),
                Alert.timestamp == a.get("timestamp")
            ).first()

            if not existing:
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
                saved += 1
        db.commit()
        results["alerts_generated"] = saved
        dispatch_alert_notifications(alerts)

    return {"status": "ok", "results": results}
