import os
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.app.database.session import get_db
from backend.app.models.alert import Alert
from backend.app.models.report import Report
from backend.app.schemas.log import ReportCreate
from backend.app.reports.report_generator import generate_pdf_report, generate_html_report

router = APIRouter(prefix="/reports", tags=["Reports"])

REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "reports")

@router.post("/generate")
def generate_report(payload: ReportCreate, db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(Alert.id.desc()).all()
    alert_dicts = [{
        "timestamp": a.timestamp,
        "severity": a.severity,
        "attack_type": a.attack_type,
        "source_ip": a.source_ip,
        "mitre_technique_id": a.mitre_technique_id,
        "mitre_technique_name": a.mitre_technique_name,
        "description": a.description
    } for a in alerts]

    stats = {
        "total": len(alerts),
        "critical": sum(1 for a in alerts if a.severity == "CRITICAL"),
        "high": sum(1 for a in alerts if a.severity == "HIGH"),
        "medium": sum(1 for a in alerts if a.severity == "MEDIUM"),
        "low": sum(1 for a in alerts if a.severity == "LOW")
    }

    top_ips_query = db.query(
        Alert.source_ip.label("ip"),
        func.count(Alert.id).label("count")
    ).filter(Alert.source_ip != "N/A").group_by(Alert.source_ip).order_by(func.count(Alert.id).desc()).limit(5).all()

    top_ips = [{"ip": r.ip, "count": r.count} for r in top_ips_query]

    if payload.report_type.upper() == "PDF":
        filename = generate_pdf_report(alert_dicts, stats, top_ips)
    else:
        filename = generate_html_report(alert_dicts, stats, top_ips)

    download_url = f"/api/reports/{filename}/download"
    new_report = Report(
        filename=filename,
        report_type=payload.report_type.upper(),
        download_url=download_url
    )
    db.add(new_report)
    db.commit()
    db.refresh(new_report)

    return new_report

@router.get("")
def list_reports(db: Session = Depends(get_db)):
    reports = db.query(Report).order_by(Report.id.desc()).all()
    return reports

@router.get("/{filename}/download")
def download_report(filename: str):
    fpath = os.path.join(REPORT_DIR, filename)
    if not os.path.isfile(fpath):
        raise HTTPException(status_code=404, detail="Report file not found")
    media_type = "application/pdf" if filename.endswith(".pdf") else "text/html"
    return FileResponse(path=fpath, filename=filename, media_type=media_type)
