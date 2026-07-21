from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime
from backend.app.database.session import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String(50), index=True, nullable=False)
    source_ip = Column(String(50), index=True, default="N/A")
    destination_ip = Column(String(50), default="N/A")
    severity = Column(String(20), index=True, nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW
    attack_type = Column(String(100), index=True, nullable=False)
    description = Column(Text, nullable=False)
    log_source = Column(String(100), index=True, default="auth.log")
    status = Column(String(30), default="OPEN", index=True)  # OPEN, RESOLVED, FALSE_POSITIVE
    assigned_to = Column(String(50), default="Unassigned")
    analyst_notes = Column(Text, default="")
    mitre_technique_id = Column(String(50), default="T1110")
    mitre_technique_name = Column(String(100), default="Brute Force")
    mitre_tactic = Column(String(100), default="Credential Access")
    recommendation = Column(Text, default="Investigate source IP and apply firewall rules if necessary.")
    raw_log = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
