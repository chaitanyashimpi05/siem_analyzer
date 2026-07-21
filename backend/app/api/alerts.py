import io
import csv
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.models.alert import Alert
from backend.app.schemas.alert import AlertResponse, AlertStatusUpdate
from backend.app.services.threat_intel import get_threat_intel

router = APIRouter(prefix="/alerts", tags=["Alerts"])

@router.get("", response_model=dict)
def get_alerts(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    attack_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Alert)

    if severity:
        query = query.filter(Alert.severity == severity.upper())
    if status:
        query = query.filter(Alert.status == status.upper())
    if attack_type:
        query = query.filter(Alert.attack_type.ilike(f"%{attack_type}%"))
    if source_ip:
        query = query.filter(Alert.source_ip == source_ip)
    if search:
        query = query.filter(
            (Alert.description.ilike(f"%{search}%")) |
            (Alert.source_ip.ilike(f"%{search}%")) |
            (Alert.attack_type.ilike(f"%{search}%")) |
            (Alert.mitre_technique_id.ilike(f"%{search}%"))
        )

    total = query.count()
    alerts = query.order_by(Alert.id.desc()).offset((page - 1) * per_page).limit(per_page).all()

    return {
        "alerts": alerts,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": max(1, -(-total // per_page))
    }

@router.get("/export/csv")
def export_alerts_csv(db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(Alert.id.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Timestamp", "Severity", "Attack Type", "Source IP", "Destination IP",
        "Log Source", "Status", "Assigned To", "MITRE Technique ID", "MITRE Technique Name", "Description"
    ])
    for a in alerts:
        writer.writerow([
            a.id, a.timestamp, a.severity, a.attack_type, a.source_ip, a.destination_ip,
            a.log_source, a.status, a.assigned_to, a.mitre_technique_id, a.mitre_technique_name, a.description
        ])
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=siem_alerts_export.csv"}
    )

@router.get("/{alert_id}")
def get_alert_detail(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    threat_intel = get_threat_intel(alert.source_ip)
    return {
        "alert": alert,
        "threat_intel": threat_intel
    }

@router.patch("/{alert_id}", response_model=AlertResponse)
def update_alert_status(alert_id: int, update_data: AlertStatusUpdate, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    if update_data.status:
        alert.status = update_data.status.upper()
    if update_data.assigned_to is not None:
        alert.assigned_to = update_data.assigned_to
    if update_data.analyst_notes is not None:
        alert.analyst_notes = update_data.analyst_notes

    db.commit()
    db.refresh(alert)
    return alert

@router.delete("/{alert_id}")
def delete_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    db.delete(alert)
    db.commit()
    return {"status": "ok", "message": f"Alert {alert_id} deleted."}
