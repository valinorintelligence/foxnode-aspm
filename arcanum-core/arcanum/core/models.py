"""Pydantic domain models and enums for Arcanum."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ------------------------------------------------------------------
# Enums
# ------------------------------------------------------------------


class Mode(str, Enum):
    autopilot = "autopilot"
    copilot = "copilot"
    manual = "manual"


class Status(str, Enum):
    created = "created"
    running = "running"
    paused = "paused"
    complete = "complete"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class StashType(str, Enum):
    credential = "credential"
    hash = "hash"
    host = "host"
    range = "range"
    payload = "payload"
    script = "script"
    token = "token"


# ------------------------------------------------------------------
# Embedded value objects
# ------------------------------------------------------------------


class Scope(BaseModel):
    """Defines what is in / out of scope for a session."""

    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)


class Progress(BaseModel):
    """Tracks session progress."""

    phase: str = ""
    percent: float = 0.0
    current_task: str = ""


class Assets(BaseModel):
    """Discovered assets linked to a session."""

    hosts: list[str] = Field(default_factory=list)
    ports: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)


# ------------------------------------------------------------------
# Top-level models
# ------------------------------------------------------------------


class Session(BaseModel):
    """A pentest / recon session."""

    id: str
    name: str
    target: Optional[str] = None
    mode: Mode = Mode.manual
    status: Status = Status.created
    scope: Scope = Field(default_factory=Scope)
    progress: Progress = Field(default_factory=Progress)
    assets: Assets = Field(default_factory=Assets)
    findings_count: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class Finding(BaseModel):
    """A security finding / vulnerability."""

    id: str
    session_id: str
    title: str
    type: Optional[str] = None
    severity: Optional[Severity] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    affected: list[str] = Field(default_factory=list)
    evidence: list[dict] = Field(default_factory=list)
    poc: list[dict] = Field(default_factory=list)
    cve_id: Optional[str] = None
    cwe_ids: list[str] = Field(default_factory=list)
    remediation: Optional[str] = None
    verified: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)


class StashItem(BaseModel):
    """A stashed credential, hash, host, or other artifact."""

    id: str
    type: str  # StashType value as string — DB stores plain strings
    value: str
    note: Optional[str] = None
    session_id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
