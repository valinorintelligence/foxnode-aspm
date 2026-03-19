import enum
from datetime import datetime, timezone
from sqlalchemy import String, Text, DateTime, Enum, Integer, ForeignKey, Float
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class ProductType(str, enum.Enum):
    WEB_APP = "web_application"
    API = "api"
    MOBILE = "mobile"
    INFRASTRUCTURE = "infrastructure"
    CLOUD = "cloud"
    CONTAINER = "container"
    SOURCE_CODE = "source_code"
    IOT = "iot"


class EngagementStatus(str, enum.Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class Product(Base):
    __tablename__ = "products"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    product_type: Mapped[ProductType] = mapped_column(Enum(ProductType), default=ProductType.WEB_APP)
    business_criticality: Mapped[str] = mapped_column(String(50), default="medium")
    team: Mapped[str] = mapped_column(String(255), nullable=True)
    tags: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array stored as text
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    repo_url: Mapped[str] = mapped_column(String(500), nullable=True)
    owner_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    engagements: Mapped[list["Engagement"]] = relationship(back_populates="product", cascade="all, delete-orphan")
    owner: Mapped["User"] = relationship("User", lazy="selectin")


class Engagement(Base):
    __tablename__ = "engagements"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    status: Mapped[EngagementStatus] = mapped_column(
        Enum(EngagementStatus), default=EngagementStatus.NOT_STARTED
    )
    engagement_type: Mapped[str] = mapped_column(String(50), default="CI/CD")
    product_id: Mapped[int] = mapped_column(Integer, ForeignKey("products.id"), nullable=False)
    lead_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    target_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    target_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    product: Mapped["Product"] = relationship(back_populates="engagements")
    tests: Mapped[list["Test"]] = relationship(back_populates="engagement", cascade="all, delete-orphan")
    lead: Mapped["User"] = relationship("User", lazy="selectin")


class Test(Base):
    __tablename__ = "tests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    test_type: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g., "Trivy Scan", "Semgrep"
    scan_type: Mapped[str] = mapped_column(String(100), nullable=True)  # SAST, DAST, SCA, etc.
    engagement_id: Mapped[int] = mapped_column(Integer, ForeignKey("engagements.id"), nullable=False)
    environment: Mapped[str] = mapped_column(String(100), default="Development")
    branch: Mapped[str] = mapped_column(String(255), nullable=True)
    commit_hash: Mapped[str] = mapped_column(String(64), nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    engagement: Mapped["Engagement"] = relationship(back_populates="tests")
    findings: Mapped[list["Finding"]] = relationship(
        "Finding", back_populates="test", cascade="all, delete-orphan"
    )


from app.models.finding import Finding  # noqa: E402
