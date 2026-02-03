# ArmourMail

Email security service for AI agents. Scans incoming emails for threats and manages quarantine.

## Features

- **Email Ingestion**: Receive emails via SendGrid Inbound Parse webhook
- **Threat Detection**: Scan emails for phishing, spam, malware, and suspicious content
- **Quarantine Management**: Automatically quarantine threats; approve or reject manually
- **API Access**: RESTful API for email listing and management

## Quick Start

### Installation

```bash
cd armourmail
pip install -r requirements.txt
```

### Running the Server

**Development:**
```bash
uvicorn src.armourmail.api:app --reload --port 8000
```

**Production:**
```bash
gunicorn src.armourmail.api:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000
```

### API Documentation

Once running, visit:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## API Endpoints

### SendGrid Inbound Parse

ArmourMail can ingest emails via SendGrid Inbound Parse:
- `POST /webhook/ingest`

Setup guide: `docs/sendgrid-inbound-parse.md`

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/webhook/ingest` | SendGrid Inbound Parse webhook |
| GET | `/emails` | List all emails (paginated) |
| GET | `/emails/{id}` | Get single email with scan results |
| GET | `/quarantine` | List quarantined emails |
| POST | `/quarantine/{id}/approve` | Release email from quarantine |
| POST | `/quarantine/{id}/reject` | Permanently reject email |

## SendGrid Setup

1. Configure SendGrid Inbound Parse to point to your `/webhook/ingest` endpoint
2. Set the MX record for your domain to point to SendGrid
3. Emails sent to your domain will be forwarded to ArmourMail

## Configuration

Environment variables:
- `ARMOURMAIL_DEBUG`: Enable debug mode (default: false)
- `ARMOURMAIL_LOG_LEVEL`: Logging level (default: INFO)

## Project Structure

```
armourmail/
├── src/
│   └── armourmail/
│       ├── __init__.py
│       ├── api.py          # FastAPI application
│       ├── models.py       # Pydantic models
│       └── detector.py     # Threat detection module
├── requirements.txt
└── README.md
```

## License

MIT
