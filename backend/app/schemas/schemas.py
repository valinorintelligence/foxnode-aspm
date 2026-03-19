from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr

from app.models.user import UserRole
from app.models.product import ProductType, EngagementStatus
from app.models.finding import FindingSeverity, FindingStatus
from app.models.integration import IntegrationType


# --- Auth ---
class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# --- User ---
class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str
    full_name: Optional[str] = None
    role: UserRole = UserRole.ANALYST


class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    full_name: Optional[str]
    role: UserRole
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# --- Product ---
class ProductCreate(BaseModel):
    name: str
    description: Optional[str] = None
    product_type: ProductType = ProductType.WEB_APP
    business_criticality: str = "medium"
    team: Optional[str] = None
    tags: Optional[str] = None
    repo_url: Optional[str] = None


class ProductResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    product_type: ProductType
    business_criticality: str
    team: Optional[str]
    risk_score: float
    repo_url: Optional[str]
    created_at: datetime
    finding_counts: Optional[dict] = None

    class Config:
        from_attributes = True


# --- Engagement ---
class EngagementCreate(BaseModel):
    name: str
    description: Optional[str] = None
    engagement_type: str = "CI/CD"
    product_id: int
    target_start: Optional[datetime] = None
    target_end: Optional[datetime] = None


class EngagementResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    status: EngagementStatus
    engagement_type: str
    product_id: int
    created_at: datetime

    class Config:
        from_attributes = True


# --- Finding ---
class FindingCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: FindingSeverity
    cvss_score: Optional[float] = None
    cwe: Optional[int] = None
    cve: Optional[str] = None
    scanner: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    component: Optional[str] = None
    component_version: Optional[str] = None
    mitigation: Optional[str] = None
    impact: Optional[str] = None
    references: Optional[str] = None
    product_id: int
    test_id: Optional[int] = None


class FindingResponse(BaseModel):
    id: int
    title: str
    description: Optional[str]
    severity: FindingSeverity
    status: FindingStatus
    cvss_score: Optional[float]
    cwe: Optional[int]
    cve: Optional[str]
    scanner: Optional[str]
    tool_type: Optional[str]
    file_path: Optional[str]
    line_number: Optional[int]
    component: Optional[str]
    component_version: Optional[str]
    is_duplicate: bool
    mitigation: Optional[str]
    product_id: int
    date_found: datetime
    created_at: datetime

    class Config:
        from_attributes = True


class FindingUpdate(BaseModel):
    status: Optional[FindingStatus] = None
    severity: Optional[FindingSeverity] = None
    assignee_id: Optional[int] = None
    mitigation: Optional[str] = None


class UserUpdate(BaseModel):
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    full_name: Optional[str] = None


# --- Integration ---
class IntegrationCreate(BaseModel):
    name: str
    tool_name: str
    integration_type: IntegrationType
    description: Optional[str] = None
    api_url: Optional[str] = None
    auth_type: Optional[str] = None
    config: Optional[str] = None
    product_id: Optional[int] = None
    sync_interval_minutes: int = 60


class IntegrationResponse(BaseModel):
    id: int
    name: str
    tool_name: str
    integration_type: IntegrationType
    is_enabled: bool
    last_sync: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


# --- Scan Import ---
class ScanImportRequest(BaseModel):
    scanner: str
    product_id: int
    engagement_id: Optional[int] = None


class ScanImportResponse(BaseModel):
    id: int
    filename: str
    scanner: str
    status: str
    findings_created: int
    findings_duplicates: int
    created_at: datetime

    class Config:
        from_attributes = True


# --- Dashboard ---
class DashboardStats(BaseModel):
    total_products: int
    total_findings: int
    open_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    findings_by_severity: dict
    findings_by_status: dict
    findings_by_scanner: dict
    recent_findings: list[FindingResponse]
    risk_trend: list[dict]
    top_vulnerable_products: list[dict]
    mean_time_to_remediate: Optional[float] = None
