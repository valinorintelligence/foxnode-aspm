import enum
import hashlib
from datetime import datetime, timezone
from sqlalchemy import String, Text, DateTime, Enum, Integer, ForeignKey, Float, Boolean, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, enum.Enum):
    ACTIVE = "active"
    VERIFIED = "verified"
    MITIGATED = "mitigated"
    FALSE_POSITIVE = "false_positive"
    RISK_ACCEPTED = "risk_accepted"
    OUT_OF_SCOPE = "out_of_scope"
    DUPLICATE = "duplicate"


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_status", "status"),
        Index("ix_findings_hash", "hash_code"),
        Index("ix_findings_product_severity", "product_id", "severity"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    severity: Mapped[FindingSeverity] = mapped_column(Enum(FindingSeverity), nullable=False)
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), default=FindingStatus.ACTIVE)

    # CVSS
    cvss_score: Mapped[float] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str] = mapped_column(String(200), nullable=True)

    # CWE / CVE
    cwe: Mapped[int] = mapped_column(Integer, nullable=True)
    cve: Mapped[str] = mapped_column(String(50), nullable=True, index=True)

    # Source
    scanner: Mapped[str] = mapped_column(String(100), nullable=True)
    scanner_finding_id: Mapped[str] = mapped_column(String(255), nullable=True)
    tool_type: Mapped[str] = mapped_column(String(50), nullable=True)  # SAST, DAST, SCA, etc.

    # Location
    file_path: Mapped[str] = mapped_column(String(1000), nullable=True)
    line_number: Mapped[int] = mapped_column(Integer, nullable=True)
    component: Mapped[str] = mapped_column(String(500), nullable=True)
    component_version: Mapped[str] = mapped_column(String(100), nullable=True)

    # Deduplication
    hash_code: Mapped[str] = mapped_column(String(128), nullable=True)
    unique_id_from_tool: Mapped[str] = mapped_column(String(500), nullable=True)
    duplicate_of_id: Mapped[int] = mapped_column(Integer, ForeignKey("findings.id"), nullable=True)
    is_duplicate: Mapped[bool] = mapped_column(Boolean, default=False)

    # Remediation
    mitigation: Mapped[str] = mapped_column(Text, nullable=True)
    impact: Mapped[str] = mapped_column(Text, nullable=True)
    references: Mapped[str] = mapped_column(Text, nullable=True)
    steps_to_reproduce: Mapped[str] = mapped_column(Text, nullable=True)

    # Relations
    test_id: Mapped[int] = mapped_column(Integer, ForeignKey("tests.id"), nullable=True)
    product_id: Mapped[int] = mapped_column(Integer, ForeignKey("products.id"), nullable=False)
    reporter_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    assignee_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)

    # Timestamps
    date_found: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    date_mitigated: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    sla_deadline: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    test: Mapped["Test"] = relationship("Test", back_populates="findings")
    product: Mapped["Product"] = relationship("Product", lazy="selectin")
    endpoints: Mapped[list["Endpoint"]] = relationship(back_populates="finding", cascade="all, delete-orphan")

    def compute_hash(self) -> str:
        hash_input = f"{self.title}|{self.scanner}|{self.file_path}|{self.line_number}|{self.cwe}|{self.cve}"
        self.hash_code = hashlib.sha256(hash_input.encode()).hexdigest()
        return self.hash_code


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    protocol: Mapped[str] = mapped_column(String(20), nullable=True)
    host: Mapped[str] = mapped_column(String(500), nullable=True)
    port: Mapped[int] = mapped_column(Integer, nullable=True)
    path: Mapped[str] = mapped_column(String(1000), nullable=True)
    query: Mapped[str] = mapped_column(String(1000), nullable=True)
    finding_id: Mapped[int] = mapped_column(Integer, ForeignKey("findings.id"), nullable=False)
    product_id: Mapped[int] = mapped_column(Integer, ForeignKey("products.id"), nullable=True)

    finding: Mapped["Finding"] = relationship(back_populates="endpoints")


from app.models.product import Product, Test  # noqa: E402
