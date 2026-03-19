import enum
from datetime import datetime, timezone
from sqlalchemy import String, Text, DateTime, Enum, Integer, ForeignKey, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class IntegrationType(str, enum.Enum):
    SAST = "sast"
    DAST = "dast"
    SCA = "sca"
    CONTAINER = "container"
    CLOUD = "cloud"
    INFRASTRUCTURE = "infrastructure"
    SECRET_DETECTION = "secret_detection"
    IAC = "iac"
    API_SECURITY = "api_security"
    ISSUE_TRACKER = "issue_tracker"
    NOTIFICATION = "notification"


class Integration(Base):
    __tablename__ = "integrations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    integration_type: Mapped[IntegrationType] = mapped_column(Enum(IntegrationType), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config: Mapped[str] = mapped_column(Text, nullable=True)  # JSON config
    api_url: Mapped[str] = mapped_column(String(500), nullable=True)
    auth_type: Mapped[str] = mapped_column(String(50), nullable=True)  # api_key, oauth, token
    last_sync: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    sync_interval_minutes: Mapped[int] = mapped_column(Integer, default=60)
    product_id: Mapped[int] = mapped_column(Integer, ForeignKey("products.id"), nullable=True)
    created_by_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class ScanImport(Base):
    __tablename__ = "scan_imports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    filename: Mapped[str] = mapped_column(String(500), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(100), nullable=False)
    scanner: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="processing")  # processing, completed, failed
    findings_created: Mapped[int] = mapped_column(Integer, default=0)
    findings_duplicates: Mapped[int] = mapped_column(Integer, default=0)
    findings_closed: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)
    product_id: Mapped[int] = mapped_column(Integer, ForeignKey("products.id"), nullable=False)
    engagement_id: Mapped[int] = mapped_column(Integer, ForeignKey("engagements.id"), nullable=True)
    test_id: Mapped[int] = mapped_column(Integer, ForeignKey("tests.id"), nullable=True)
    imported_by_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
