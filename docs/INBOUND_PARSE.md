# SendGrid Inbound Parse (ArmourMail)

## Endpoint
- `POST /api/inbound`
- Expects **SendGrid Inbound Parse** `multipart/form-data`
- Attachments handled via `multer` (`upload.any()`)

## Fields we read (v0)
- `from`, `to`, `subject`, `text`, `html`
- `envelope` (JSON string; SendGrid typically provides `{ "to": [...], "from": "..." }`)
- `dkim`, `SPF`

## Guard checks (v0)
- Flags `isAuthentic` if either `dkim` or `SPF` contains `pass`
- Logs inbound metadata to `inbound_log.json` (capped to last 100 entries)

## Routing (v0)
- Loads `config/agents.json` and maps a recipient email address to an agent record.
- Chooses recipient from `envelope.to[0]` if available, else falls back to `to`.
- Current behavior: logs routing decision (no downstream dispatch yet).
