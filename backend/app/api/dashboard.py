from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.app.database.session import get_db
from backend.app.models.alert import Alert
from backend.app.models.log import Log
from backend.app.services.watchdog_monitor import monitor_service

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("")
def get_dashboard_summary(db: Session = Depends(get_db)):
    total = db.query(Alert).count()
    critical = db.query(Alert).filter(Alert.severity == "CRITICAL").count()
    high = db.query(Alert).filter(Alert.severity == "HIGH").count()
    medium = db.query(Alert).filter(Alert.severity == "MEDIUM").count()
    low = db.query(Alert).filter(Alert.severity == "LOW").count()

    open_count = db.query(Alert).filter(Alert.status == "OPEN").count()
    resolved_count = db.query(Alert).filter(Alert.status == "RESOLVED").count()
    fp_count = db.query(Alert).filter(Alert.status == "FALSE_POSITIVE").count()

    top_ips_query = db.query(
        Alert.source_ip.label("ip"),
        func.count(Alert.id).label("count")
    ).filter(
        Alert.source_ip.isnot(None),
        Alert.source_ip != "N/A",
        Alert.source_ip != "localhost"
    ).group_by(Alert.source_ip).order_by(func.count(Alert.id).desc()).limit(5).all()

    top_ips = [{"ip": r.ip, "count": r.count} for r in top_ips_query]

    recent_alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(10).all()
    total_logs = db.query(Log).count()

    # Category breakdown
    categories_query = db.query(
        Alert.attack_type.label("type"),
        func.count(Alert.id).label("count")
    ).group_by(Alert.attack_type).all()
    event_categories = [{"type": r.type, "count": r.count} for r in categories_query]

    return {
        "stats": {
            "total": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "open": open_count,
            "resolved": resolved_count,
            "false_positive": fp_count,
            "total_logs": total_logs,
            "monitor_active": monitor_service.is_running
        },
        "top_ips": top_ips,
        "recent_alerts": recent_alerts,
        "event_categories": event_categories
    }
