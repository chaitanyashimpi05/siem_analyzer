from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime
from backend.app.database.session import Base

class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    generated_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    report_type = Column(String(20), default="PDF", nullable=False)  # PDF or HTML
    download_url = Column(String(255), nullable=False)
