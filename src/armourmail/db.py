"""Database configuration and ORM models for ArmourMail."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from .models import EmailStatus, ThreatLevel

DATABASE_URL = os.getenv("DATABASE_URL")


def is_database_configured() -> bool:
    return bool(DATABASE_URL)


class Base(DeclarativeBase):
    pass


class EmailRecord(Base):
    __tablename__ = "emails"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    sender: Mapped[str] = mapped_column(String, nullable=False)
    recipient: Mapped[str] = mapped_column(String, nullable=False)
    subject: Mapped[str] = mapped_column(String, nullable=False)
    body_plain: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    body_html: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[EmailStatus] = mapped_column(
        Enum(EmailStatus), default=EmailStatus.PENDING, nullable=False
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False
    )
    processed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    headers: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    attachments: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    raw_payload: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    threat_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    scan_result: Mapped[Optional["ScanResultRecord"]] = relationship(
        back_populates="email",
        uselist=False,
        cascade="all, delete-orphan",
    )


class ScanResultRecord(Base):
    __tablename__ = "scan_results"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    email_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("emails.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    threat_level: Mapped[ThreatLevel] = mapped_column(
        Enum(ThreatLevel), default=ThreatLevel.NONE, nullable=False
    )
    score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    flags: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False
    )

    email: Mapped[EmailRecord] = relationship(back_populates="scan_result")


engine = (
    create_async_engine(DATABASE_URL, echo=False, future=True)
    if DATABASE_URL
    else None
)

AsyncSessionLocal: Optional[async_sessionmaker[AsyncSession]] = (
    async_sessionmaker(engine, expire_on_commit=False)
    if engine
    else None
)
