"""Pydantic models for ArmourMail API."""

from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, EmailStr, Field


class EmailStatus(str, Enum):
    """Status of an email in the system."""
    PENDING = "pending"
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    QUARANTINED = "quarantined"
    APPROVED = "approved"
    REJECTED = "rejected"


class ThreatLevel(str, Enum):
    """Threat level classification."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanResult(BaseModel):
    """Results from email security scan."""
    threat_level: ThreatLevel = ThreatLevel.NONE
    phishing_score: float = Field(ge=0.0, le=1.0, default=0.0)
    spam_score: float = Field(ge=0.0, le=1.0, default=0.0)
    malware_detected: bool = False
    suspicious_links: list[str] = Field(default_factory=list)
    suspicious_attachments: list[str] = Field(default_factory=list)
    flags: list[str] = Field(default_factory=list)
    scanned_at: datetime = Field(default_factory=datetime.utcnow)


class EmailBase(BaseModel):
    """Base email model with common fields."""
    sender: str
    recipient: str
    subject: str
    body_plain: Optional[str] = None
    body_html: Optional[str] = None


class EmailCreate(EmailBase):
    """Model for creating a new email record."""
    headers: dict = Field(default_factory=dict)
    attachments: list[str] = Field(default_factory=list)
    raw_payload: Optional[dict] = None


class Email(EmailBase):
    """Full email model with all fields."""
    id: UUID = Field(default_factory=uuid4)
    status: EmailStatus = EmailStatus.PENDING
    scan_result: Optional[ScanResult] = None
    received_at: datetime = Field(default_factory=datetime.utcnow)
    processed_at: Optional[datetime] = None
    headers: dict = Field(default_factory=dict)
    attachments: list[str] = Field(default_factory=list)

    class Config:
        from_attributes = True


class EmailSummary(BaseModel):
    """Summary view of email for list endpoints."""
    id: UUID
    sender: str
    recipient: str
    subject: str
    status: EmailStatus
    threat_level: Optional[ThreatLevel] = None
    received_at: datetime


class PaginatedResponse(BaseModel):
    """Generic paginated response wrapper."""
    items: list
    total: int
    page: int
    page_size: int
    total_pages: int


class EmailListResponse(BaseModel):
    """Paginated list of emails."""
    items: list[EmailSummary]
    total: int
    page: int
    page_size: int
    total_pages: int


class QuarantineAction(BaseModel):
    """Action taken on quarantined email."""
    reason: Optional[str] = None
    notify_sender: bool = False


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "healthy"
    version: str = "1.0.0"
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class WebhookResponse(BaseModel):
    """Response for webhook ingestion."""
    id: UUID
    status: EmailStatus
    message: str


class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str
    detail: Optional[str] = None
