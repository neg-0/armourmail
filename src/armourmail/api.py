"""ArmourMail API - Email security service for AI agents."""

import logging
from datetime import datetime
from math import ceil
from typing import Optional
from uuid import UUID

from fastapi import FastAPI, Form, HTTPException, Query, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

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

# Assume detector module exists
from .detector import scan_email

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("armourmail")

# Initialize FastAPI app
app = FastAPI(
    title="ArmourMail API",
    description="Email security service for AI agents. Scans incoming emails for threats and manages quarantine.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage (replace with database in production)
email_store: dict[UUID, Email] = {}


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
        
        # Create email record
        email_data = EmailCreate(
            sender=sender,
            recipient=recipient,
            subject=subject,
            body_plain=text,
            body_html=html,
            headers=parsed_headers,
            attachments=attachment_names,
        )
        
        email = Email(**email_data.model_dump())
        
        # Scan email for threats
        try:
            scan_result = await scan_email(email)
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
    # Filter emails
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
    # Get only quarantined emails
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


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup resources on shutdown."""
    logger.info("ArmourMail API shutting down...")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
