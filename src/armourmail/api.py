"""ArmourMail API - Email security service for AI agents."""

import logging
import re
from datetime import datetime
from math import ceil
from pathlib import Path
from typing import Optional
from uuid import UUID

from fastapi import FastAPI, Form, HTTPException, Query, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from .models import (
    Email,
    EmailCreate,
    EmailListResponse,
    EmailStatus,
    EmailSummary,
    ErrorResponse,
    HealthResponse,
    QuarantineAction,
    ScanResult,
    ThreatLevel,
    WebhookResponse,
)
from .db import (
    AsyncSessionLocal,
    Base,
    EmailRecord,
    ScanResultRecord,
    engine,
    is_database_configured,
)

# Detector
from .detector import scan_email_api

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("armourmail")

# Paths
BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# Initialize FastAPI app
app = FastAPI(
    title="ArmourMail API",
    description="Email security service for AI agents. Scans incoming emails for threats and manages quarantine.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Mount static files
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage (fallback for local dev)
email_store: dict[UUID, Email] = {}


def email_record_to_model(record: EmailRecord) -> Email:
    scan_result = None
    if record.scan_result:
        scan_result = ScanResult(
            threat_level=record.scan_result.threat_level,
            score=record.scan_result.score,
            flags=record.scan_result.flags or [],
            scanned_at=record.scan_result.scanned_at,
        )

    return Email(
        id=record.id,
        sender=record.sender,
        recipient=record.recipient,
        subject=record.subject,
        body_plain=record.body_plain,
        body_html=record.body_html,
        status=record.status,
        scan_result=scan_result,
        received_at=record.received_at,
        processed_at=record.processed_at,
        headers=record.headers or {},
        attachments=record.attachments or [],
    )


# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with consistent format."""
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(error=exc.detail).model_dump(),
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions."""
    logger.error(f"Unexpected error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="Internal server error",
            detail=str(exc) if app.debug else None
        ).model_dump(),
    )


# Health check endpoint
@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """
    Health check endpoint.
    
    Returns the service status, version, and current timestamp.
    """
    return HealthResponse()


# Dashboard endpoint
@app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
async def dashboard():
    """
    Serve the ArmourMail dashboard.
    """
    dashboard_path = TEMPLATES_DIR / "dashboard.html"
    if dashboard_path.exists():
        return HTMLResponse(content=dashboard_path.read_text())
    return HTMLResponse(content="<h1>ArmourMail</h1><p>Dashboard not found. Visit <a href='/docs'>/docs</a> for API.</p>")


# Webhook endpoint for SendGrid Inbound Parse
@app.post("/webhook/ingest", response_model=WebhookResponse, tags=["Webhook"])
async def ingest_email(
    request: Request,
    from_: str = Form(None, alias="from"),
    to: str = Form(None),
    subject: str = Form(""),
    text: str = Form(None),
    html: str = Form(None),
    headers: str = Form(None),
    raw_email: str = Form(None, alias="email"),
    attachments: Optional[list[UploadFile]] = File(None),
):
    """
    Receive emails from SendGrid Inbound Parse webhook.
    
    This endpoint processes incoming emails, scans them for threats,
    and stores them in the system. Emails flagged as threats are
    automatically quarantined.
    """
    try:
        # Parse sender and recipient
        sender = from_ or "unknown@unknown.com"
        recipient = to or "unknown@unknown.com"
        
        logger.info(f"Receiving email from {sender} to {recipient}: {subject}")
        
        # Parse headers if provided
        parsed_headers = {}
        if headers:
            try:
                import json
                parsed_headers = json.loads(headers)
            except:
                # Headers might be in different format
                parsed_headers = {"raw": headers}
        
        # Get attachment filenames
        attachment_names = []
        if attachments:
            attachment_names = [a.filename for a in attachments if a.filename]
        
        # Best-effort body extraction (SendGrid Inbound Parse can send `text`, `html`, and/or raw `email`)
        body_plain = text
        body_html = html

        if (not body_plain) and body_html:
            # Fallback: derive a plain-text body from HTML
            body_plain = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body_html)).strip()

        if (not body_plain) and raw_email:
            # Fallback: parse the raw RFC822 email
            try:
                from email import policy
                from email.parser import BytesParser

                msg = BytesParser(policy=policy.default).parsebytes(raw_email.encode("utf-8", errors="ignore"))

                if msg.is_multipart():
                    # Prefer text/plain
                    for part in msg.walk():
                        ctype = part.get_content_type()
                        if ctype == "text/plain":
                            body_plain = part.get_content()
                            break
                    # Then text/html
                    if (not body_plain):
                        for part in msg.walk():
                            if part.get_content_type() == "text/html":
                                body_html = body_html or part.get_content()
                                body_plain = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body_html)).strip()
                                break
                else:
                    ctype = msg.get_content_type()
                    if ctype == "text/plain":
                        body_plain = msg.get_content()
                    elif ctype == "text/html":
                        body_html = body_html or msg.get_content()
                        body_plain = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body_html)).strip()
            except Exception:
                # If parsing fails, keep whatever we have
                pass

        # Create email record
        email_data = EmailCreate(
            sender=sender,
            recipient=recipient,
            subject=subject,
            body_plain=body_plain,
            body_html=body_html,
            headers=parsed_headers,
            attachments=attachment_names,
            raw_payload={
                "from": from_,
                "to": to,
                "subject": subject,
                "has_text": bool(text),
                "has_html": bool(html),
                "has_raw_email": bool(raw_email),
            },
        )
        
        email = Email(**email_data.model_dump())
        
        # Scan email for threats
        try:
            scan_result = await scan_email_api(email)
            email.scan_result = scan_result
            email.processed_at = datetime.utcnow()
            
            # Determine status based on scan results
            if scan_result.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                email.status = EmailStatus.QUARANTINED
                logger.warning(f"Email {email.id} quarantined: {scan_result.threat_level}")
            elif scan_result.threat_level == ThreatLevel.MEDIUM:
                email.status = EmailStatus.SUSPICIOUS
            else:
                email.status = EmailStatus.SAFE
                
        except Exception as e:
            logger.error(f"Scan failed for email {email.id}: {e}")
            email.status = EmailStatus.QUARANTINED  # Fail-safe: quarantine on error
            email.scan_result = ScanResult(
                threat_level=ThreatLevel.MEDIUM,
                flags=["scan_error"]
            )
        
        # Store email
        if is_database_configured() and AsyncSessionLocal:
            async with AsyncSessionLocal() as session:
                email_record = EmailRecord(
                    id=email.id,
                    sender=email.sender,
                    recipient=email.recipient,
                    subject=email.subject,
                    body_plain=email.body_plain,
                    body_html=email.body_html,
                    status=email.status,
                    received_at=email.received_at,
                    processed_at=email.processed_at,
                    headers=email.headers,
                    attachments=email.attachments,
                    raw_payload=email_data.raw_payload,
                    threat_score=email.scan_result.score if email.scan_result else None,
                )
                if email.scan_result:
                    email_record.scan_result = ScanResultRecord(
                        threat_level=email.scan_result.threat_level,
                        score=email.scan_result.score,
                        flags=email.scan_result.flags,
                        scanned_at=email.scan_result.scanned_at,
                    )

                session.add(email_record)
                await session.commit()
        else:
            email_store[email.id] = email
        
        logger.info(f"Email {email.id} processed with status: {email.status}")
        
        return WebhookResponse(
            id=email.id,
            status=email.status,
            message=f"Email processed successfully. Status: {email.status.value}"
        )
        
    except Exception as e:
        logger.error(f"Failed to ingest email: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to process email: {str(e)}")


# Email listing endpoint
@app.get("/emails", response_model=EmailListResponse, tags=["Emails"])
async def list_emails(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    status: Optional[EmailStatus] = Query(None, description="Filter by status"),
    sender: Optional[str] = Query(None, description="Filter by sender"),
):
    """
    List all processed emails with pagination.
    
    Supports filtering by status and sender email address.
    """
    if is_database_configured() and AsyncSessionLocal:
        async with AsyncSessionLocal() as session:
            filters = []
            if status:
                filters.append(EmailRecord.status == status)
            if sender:
                filters.append(EmailRecord.sender.ilike(f"%{sender}%"))

            total = await session.scalar(
                select(func.count()).select_from(EmailRecord).where(*filters)
            )
            total = total or 0
            total_pages = ceil(total / page_size) if total > 0 else 1
            start = (page - 1) * page_size

            stmt = (
                select(EmailRecord)
                .options(selectinload(EmailRecord.scan_result))
                .where(*filters)
                .order_by(EmailRecord.received_at.desc())
                .offset(start)
                .limit(page_size)
            )
            records = (await session.scalars(stmt)).all()

            summaries = [
                EmailSummary(
                    id=record.id,
                    sender=record.sender,
                    recipient=record.recipient,
                    subject=record.subject,
                    status=record.status,
                    threat_level=(
                        record.scan_result.threat_level
                        if record.scan_result
                        else None
                    ),
                    received_at=record.received_at,
                )
                for record in records
            ]

            return EmailListResponse(
                items=summaries,
                total=total,
                page=page,
                page_size=page_size,
                total_pages=total_pages,
            )

    # Fallback: in-memory store
    emails = list(email_store.values())

    if status:
        emails = [e for e in emails if e.status == status]

    if sender:
        emails = [e for e in emails if sender.lower() in e.sender.lower()]

    # Sort by received date (newest first)
    emails.sort(key=lambda e: e.received_at, reverse=True)

    # Paginate
    total = len(emails)
    total_pages = ceil(total / page_size) if total > 0 else 1
    start = (page - 1) * page_size
    end = start + page_size
    page_emails = emails[start:end]

    # Convert to summaries
    summaries = [
        EmailSummary(
            id=e.id,
            sender=e.sender,
            recipient=e.recipient,
            subject=e.subject,
            status=e.status,
            threat_level=e.scan_result.threat_level if e.scan_result else None,
            received_at=e.received_at,
        )
        for e in page_emails
    ]

    return EmailListResponse(
        items=summaries,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


# Get single email
@app.get("/emails/{email_id}", response_model=Email, tags=["Emails"])
async def get_email(email_id: UUID):
    """
    Get a single email by ID with full details and scan results.
    """
    if is_database_configured() and AsyncSessionLocal:
        async with AsyncSessionLocal() as session:
            stmt = (
                select(EmailRecord)
                .options(selectinload(EmailRecord.scan_result))
                .where(EmailRecord.id == email_id)
            )
            record = (await session.scalars(stmt)).first()
            if not record:
                raise HTTPException(status_code=404, detail="Email not found")
            return email_record_to_model(record)

    email = email_store.get(email_id)
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    return email


# Quarantine listing endpoint
@app.get("/quarantine", response_model=EmailListResponse, tags=["Quarantine"])
async def list_quarantined(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
):
    """
    List all quarantined emails awaiting review.
    
    Returns emails with status QUARANTINED that need approval or rejection.
    """
    if is_database_configured() and AsyncSessionLocal:
        async with AsyncSessionLocal() as session:
            filters = [EmailRecord.status == EmailStatus.QUARANTINED]

            total = await session.scalar(
                select(func.count()).select_from(EmailRecord).where(*filters)
            )
            total = total or 0
            total_pages = ceil(total / page_size) if total > 0 else 1
            start = (page - 1) * page_size

            stmt = (
                select(EmailRecord)
                .options(selectinload(EmailRecord.scan_result))
                .where(*filters)
                .order_by(EmailRecord.received_at.asc())
                .offset(start)
                .limit(page_size)
            )
            records = (await session.scalars(stmt)).all()

            summaries = [
                EmailSummary(
                    id=record.id,
                    sender=record.sender,
                    recipient=record.recipient,
                    subject=record.subject,
                    status=record.status,
                    threat_level=(
                        record.scan_result.threat_level
                        if record.scan_result
                        else None
                    ),
                    received_at=record.received_at,
                )
                for record in records
            ]

            return EmailListResponse(
                items=summaries,
                total=total,
                page=page,
                page_size=page_size,
                total_pages=total_pages,
            )

    # Fallback: in-memory store
    quarantined = [e for e in email_store.values() if e.status == EmailStatus.QUARANTINED]

    # Sort by received date (oldest first - FIFO for review)
    quarantined.sort(key=lambda e: e.received_at)

    # Paginate
    total = len(quarantined)
    total_pages = ceil(total / page_size) if total > 0 else 1
    start = (page - 1) * page_size
    end = start + page_size
    page_emails = quarantined[start:end]

    # Convert to summaries
    summaries = [
        EmailSummary(
            id=e.id,
            sender=e.sender,
            recipient=e.recipient,
            subject=e.subject,
            status=e.status,
            threat_level=e.scan_result.threat_level if e.scan_result else None,
            received_at=e.received_at,
        )
        for e in page_emails
    ]

    return EmailListResponse(
        items=summaries,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


# Approve quarantined email
@app.post("/quarantine/{email_id}/approve", response_model=Email, tags=["Quarantine"])
async def approve_email(email_id: UUID, action: QuarantineAction = None):
    """
    Approve and release an email from quarantine.
    
    The email will be marked as APPROVED and can be delivered to the recipient.
    """
    if is_database_configured() and AsyncSessionLocal:
        async with AsyncSessionLocal() as session:
            stmt = (
                select(EmailRecord)
                .options(selectinload(EmailRecord.scan_result))
                .where(EmailRecord.id == email_id)
            )
            record = (await session.scalars(stmt)).first()
            if not record:
                raise HTTPException(status_code=404, detail="Email not found")

            if record.status != EmailStatus.QUARANTINED:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Email is not quarantined. "
                        f"Current status: {record.status.value}"
                    ),
                )

            record.status = EmailStatus.APPROVED
            record.processed_at = datetime.utcnow()
            await session.commit()

            logger.info(f"Email {email_id} approved and released from quarantine")

            if action and action.notify_sender:
                logger.info(f"Notification requested for email {email_id}")

            return email_record_to_model(record)

    email = email_store.get(email_id)
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")

    if email.status != EmailStatus.QUARANTINED:
        raise HTTPException(
            status_code=400,
            detail=f"Email is not quarantined. Current status: {email.status.value}"
        )

    email.status = EmailStatus.APPROVED
    email.processed_at = datetime.utcnow()

    logger.info(f"Email {email_id} approved and released from quarantine")

    # TODO: Trigger delivery to recipient if notify_sender is True
    if action and action.notify_sender:
        logger.info(f"Notification requested for email {email_id}")

    return email


# Reject quarantined email
@app.post("/quarantine/{email_id}/reject", response_model=Email, tags=["Quarantine"])
async def reject_email(email_id: UUID, action: QuarantineAction = None):
    """
    Permanently reject a quarantined email.
    
    The email will be marked as REJECTED and will not be delivered.
    """
    if is_database_configured() and AsyncSessionLocal:
        async with AsyncSessionLocal() as session:
            stmt = (
                select(EmailRecord)
                .options(selectinload(EmailRecord.scan_result))
                .where(EmailRecord.id == email_id)
            )
            record = (await session.scalars(stmt)).first()
            if not record:
                raise HTTPException(status_code=404, detail="Email not found")

            if record.status != EmailStatus.QUARANTINED:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Email is not quarantined. "
                        f"Current status: {record.status.value}"
                    ),
                )

            record.status = EmailStatus.REJECTED
            record.processed_at = datetime.utcnow()
            await session.commit()

            reason = action.reason if action else "No reason provided"
            logger.info(f"Email {email_id} rejected. Reason: {reason}")

            return email_record_to_model(record)

    email = email_store.get(email_id)
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")

    if email.status != EmailStatus.QUARANTINED:
        raise HTTPException(
            status_code=400,
            detail=f"Email is not quarantined. Current status: {email.status.value}"
        )

    email.status = EmailStatus.REJECTED
    email.processed_at = datetime.utcnow()

    reason = action.reason if action else "No reason provided"
    logger.info(f"Email {email_id} rejected. Reason: {reason}")

    return email


# Application startup/shutdown events
@app.on_event("startup")
async def startup_event():
    """Initialize resources on startup."""
    logger.info("ArmourMail API starting up...")
    if is_database_configured() and engine:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup resources on shutdown."""
    logger.info("ArmourMail API shutting down...")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
