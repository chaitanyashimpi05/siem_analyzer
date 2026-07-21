from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime
from backend.app.database.session import Base

class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), index=True, nullable=False)
    event_type = Column(String(100), default="INFO")
    raw_log = Column(Text, nullable=False)
    timestamp = Column(String(50), nullable=False)
    processed = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
