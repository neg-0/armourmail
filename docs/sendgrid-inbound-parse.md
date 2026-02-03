# SendGrid Inbound Parse → ArmourMail

ArmourMail includes a FastAPI endpoint that can receive inbound emails from SendGrid Inbound Parse and scan them for threats.

## Endpoint

- **URL:** `https://<YOUR_ARMOURMAIL_DOMAIN>/webhook/ingest`
- **Method:** `POST`
- **Content-Type:** `multipart/form-data`

The handler accepts standard SendGrid Inbound Parse fields:
- `from` (mapped to `from_` in FastAPI)
- `to`
- `subject`
- `text`
- `html`
- `headers`
- `attachments` (files)

## SendGrid Setup

1. In SendGrid, go to **Settings → Inbound Parse**
2. Add a Host & URL:
   - Host: whatever domain you’re receiving mail on (e.g. `inbound.yourdomain.com`)
   - URL: `https://<YOUR_ARMOURMAIL_DOMAIN>/webhook/ingest`
3. Configure your DNS MX records per SendGrid instructions for the chosen host.

## Notes

- SendGrid Inbound Parse does **not** provide the same signed webhook verification as the SendGrid Event Webhook. Treat this endpoint as untrusted input.
- Recommended hardening:
  - Put the endpoint behind Cloudflare/WAF
  - Rate limit
  - Allowlist SendGrid IP ranges (optional)
  - Require a shared secret in a custom header via Cloudflare Transform Rules (optional)

## Testing

You can simulate an inbound parse request locally using curl:

```bash
curl -X POST http://localhost:8000/webhook/ingest \
  -F "from=alice@example.com" \
  -F "to=bob@example.com" \
  -F "subject=Test Email" \
  -F "text=Hello from SendGrid Inbound Parse" \
  -F "headers={\"X-Test\":\"1\"}"
```

You should receive a response containing the stored email ID and status.
