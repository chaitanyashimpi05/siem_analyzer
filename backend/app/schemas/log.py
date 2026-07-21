from datetime import datetime
from pydantic import BaseModel
from typing import Optional, List, Dict

class LogResponse(BaseModel):
    id: int
    filename: str
    event_type: str
    raw_log: str
    timestamp: str
    processed: bool
    created_at: datetime

    class Config:
        from_attributes = True

class LogUploadResponse(BaseModel):
    status: str
    filename: str
    log_type: str
    parsed: int
    alerts: int
    severity_breakdown: Dict[str, int]

class ReportCreate(BaseModel):
    report_type: str = "PDF"  # PDF or HTML

class ReportResponse(BaseModel):
    id: int
    filename: str
    generated_at: datetime
    report_type: str
    download_url: str

    class Config:
        from_attributes = True
