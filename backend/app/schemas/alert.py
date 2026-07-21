from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional

class AlertStatusUpdate(BaseModel):
    status: str = Field(..., description="OPEN, RESOLVED, or FALSE_POSITIVE")
    assigned_to: Optional[str] = None
    analyst_notes: Optional[str] = None

class AlertResponse(BaseModel):
    id: int
    timestamp: str
    source_ip: str
    destination_ip: str
    severity: str
    attack_type: str
    description: str
    log_source: str
    status: str
    assigned_to: str
    analyst_notes: str
    mitre_technique_id: str
    mitre_technique_name: str
    mitre_tactic: str
    recommendation: str
    raw_log: str
    created_at: datetime

    class Config:
        from_attributes = True

class AlertStatsResponse(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    resolved: int
    open: int
    false_positive: int
