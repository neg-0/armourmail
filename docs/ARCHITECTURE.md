# ArmourMail Architecture

> Email security gateway for AI agents. Intercepts, scans, and quarantines suspicious emails before they reach your agent.

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              EXTERNAL                                        │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐                               │
│  │  Gmail   │    │ Outlook  │    │  Other   │                               │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘                               │
│       │               │               │                                      │
│       └───────────────┼───────────────┘                                      │
│                       ▼                                                      │
│              ┌─────────────────┐                                             │
│              │    SendGrid     │  (Inbound Parse)                            │
│              │   MX Records    │                                             │
│              └────────┬────────┘                                             │
└───────────────────────┼─────────────────────────────────────────────────────┘
                        │ HTTPS POST (webhook)
                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ARMOURMAIL CORE                                    │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                         API Gateway (Hono)                              │ │
│  │  POST /ingest   GET /emails   GET /quarantine   POST /quarantine/:id   │ │
│  └────────────────────────────────┬───────────────────────────────────────┘ │
│                                   │                                          │
│  ┌────────────────────────────────┼───────────────────────────────────────┐ │
│  │                         Processing Pipeline                             │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐               │ │
│  │  │  Parse   │─▶│  Scan    │─▶│ Classify │─▶│  Route   │               │ │
│  │  │  Email   │  │ Content  │  │  Risk    │  │  Email   │               │ │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘               │ │
│  │       │             │             │             │                       │ │
│  │       │        ┌────┴────┐   ┌────┴────┐   ┌────┴────┐                │ │
│  │       │        │ URL     │   │ LLM     │   │ CLEAN   │──▶ emails      │ │
│  │       │        │ Scanner │   │ Detect  │   │ QUEUE   │                │ │
│  │       │        │ Attach  │   │         │   └─────────┘                │ │
│  │       │        │ Scanner │   └─────────┘   ┌─────────┐                │ │
│  │       │        └─────────┘                 │QUARANTINE│──▶ quarantine │ │
│  │       │                                    └─────────┘                │ │
│  └───────┼────────────────────────────────────────────────────────────────┘ │
│          │                                                                   │
│  ┌───────┴────────────────────────────────────────────────────────────────┐ │
│  │                           Storage Layer                                 │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                    │ │
│  │  │   SQLite    │  │    Redis    │  │   S3/R2     │                    │ │
│  │  │  (emails,   │  │  (sessions, │  │ (attachments│                    │ │
│  │  │   scans)    │  │   rate lim) │  │   raw eml)  │                    │ │
│  │  └─────────────┘  └─────────────┘  └─────────────┘                    │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AI AGENT CONSUMERS                                 │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │ OpenClaw │    │ LangChain│    │  Custom  │    │  Human   │              │
│  │  Agent   │    │  Agent   │    │  Agent   │    │ Reviewer │              │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘              │
│       │               │               │               │                     │
│       └───────────────┴───────────────┴───────────────┘                     │
│                              │                                               │
│                    SDK / REST API / Webhook                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## API Endpoints

### Authentication

All endpoints require Bearer token authentication:
```
Authorization: Bearer am_live_xxxxxxxxxxxx
```

Tokens are scoped per-mailbox:
- `am_live_*` — Production tokens
- `am_test_*` — Sandbox tokens (emails stored 24h, no real delivery)

---

### POST /ingest

**Purpose:** Receive incoming emails from SendGrid Inbound Parse webhook.

**Authentication:** Webhook signature verification (not Bearer token)

```http
POST /ingest
Content-Type: multipart/form-data
X-Twilio-Email-Event-Webhook-Signature: <signature>
X-Twilio-Email-Event-Webhook-Timestamp: <timestamp>
```

**SendGrid Payload Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `from` | string | Sender email |
| `to` | string | Recipient email |
| `subject` | string | Email subject |
| `text` | string | Plain text body |
| `html` | string | HTML body |
| `envelope` | JSON string | SMTP envelope |
| `attachments` | integer | Number of attachments |
| `attachment1`, `attachment2`, ... | file | Attachment files |
| `headers` | string | Raw email headers |
| `dkim` | string | DKIM verification result |
| `SPF` | string | SPF verification result |

**Response:**
```json
{
  "id": "em_01HXK3M...",
  "status": "processing",
  "received_at": "2026-02-01T09:00:00Z"
}
```

**Status Codes:**
- `202 Accepted` — Email queued for processing
- `400 Bad Request` — Malformed payload
- `401 Unauthorized` — Invalid webhook signature
- `429 Too Many Requests` — Rate limited

**Processing Flow:**
1. Verify SendGrid webhook signature
2. Parse multipart form data
3. Create `Email` record with status `pending`
4. Queue for async scanning
5. Return immediately (non-blocking)

---

### GET /emails

**Purpose:** Fetch clean, approved emails for agent consumption.

```http
GET /emails?limit=20&after=em_01HXK3M...&status=clean
Authorization: Bearer am_live_xxxxxxxxxxxx
```

**Query Parameters:**
| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | integer | 20 | Max emails to return (1-100) |
| `after` | string | null | Cursor for pagination (email ID) |
| `before` | string | null | Fetch emails before this ID |
| `status` | string | `clean` | Filter: `clean`, `all`, `unread` |
| `from` | string | null | Filter by sender domain/email |
| `since` | ISO8601 | null | Emails received after this time |

**Response:**
```json
{
  "emails": [
    {
      "id": "em_01HXK3M...",
      "from": {
        "email": "alice@example.com",
        "name": "Alice Smith"
      },
      "to": ["agent@armourmail.io"],
      "subject": "Meeting tomorrow",
      "text": "Hi, can we meet at 3pm?",
      "html": "<p>Hi, can we meet at 3pm?</p>",
      "received_at": "2026-02-01T09:00:00Z",
      "scan": {
        "risk_score": 0.12,
        "risk_level": "low",
        "flags": [],
        "scanned_at": "2026-02-01T09:00:02Z"
      },
      "attachments": [
        {
          "id": "att_01HXK...",
          "filename": "agenda.pdf",
          "content_type": "application/pdf",
          "size_bytes": 45231,
          "url": "/attachments/att_01HXK..."
        }
      ],
      "read": false
    }
  ],
  "has_more": true,
  "next_cursor": "em_01HXK3N..."
}
```

**Mark as Read:**
```http
POST /emails/:id/read
```

---

### GET /quarantine

**Purpose:** List emails flagged for human review.

```http
GET /quarantine?limit=20&status=pending
Authorization: Bearer am_live_xxxxxxxxxxxx
```

**Query Parameters:**
| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | integer | 20 | Max items (1-100) |
| `status` | string | `pending` | Filter: `pending`, `approved`, `rejected`, `all` |
| `risk_level` | string | null | Filter: `medium`, `high`, `critical` |
| `after` | string | null | Pagination cursor |

**Response:**
```json
{
  "items": [
    {
      "id": "qr_01HXK3M...",
      "email_id": "em_01HXK3M...",
      "status": "pending",
      "quarantined_at": "2026-02-01T09:00:00Z",
      "email": {
        "from": { "email": "suspicious@phish.com", "name": "Your Bank" },
        "subject": "Urgent: Verify your account",
        "preview": "Click here immediately to verify..."
      },
      "scan": {
        "risk_score": 0.89,
        "risk_level": "high",
        "flags": [
          {
            "type": "prompt_injection",
            "severity": "high",
            "detail": "Contains instruction override attempt",
            "evidence": "Ignore previous instructions and..."
          },
          {
            "type": "suspicious_url",
            "severity": "medium",
            "detail": "URL domain age < 7 days",
            "evidence": "https://verify-bank-now.xyz/login"
          }
        ]
      },
      "expires_at": "2026-02-08T09:00:00Z"
    }
  ],
  "has_more": false,
  "counts": {
    "pending": 3,
    "approved": 12,
    "rejected": 45
  }
}
```

---

### POST /quarantine/:id/approve

**Purpose:** Release email from quarantine to clean queue.

```http
POST /quarantine/qr_01HXK3M.../approve
Authorization: Bearer am_live_xxxxxxxxxxxx
Content-Type: application/json

{
  "reason": "Verified sender is legitimate contact",
  "add_to_allowlist": true
}
```

**Response:**
```json
{
  "id": "qr_01HXK3M...",
  "status": "approved",
  "approved_at": "2026-02-01T10:30:00Z",
  "approved_by": "api_key:am_live_xxx",
  "email_id": "em_01HXK3M..."
}
```

---

### POST /quarantine/:id/reject

**Purpose:** Permanently reject email (delete or archive).

```http
POST /quarantine/qr_01HXK3M.../reject
Authorization: Bearer am_live_xxxxxxxxxxxx
Content-Type: application/json

{
  "reason": "Confirmed phishing attempt",
  "report_spam": true,
  "block_sender": true
}
```

**Response:**
```json
{
  "id": "qr_01HXK3M...",
  "status": "rejected",
  "rejected_at": "2026-02-01T10:30:00Z",
  "actions_taken": ["sender_blocked", "spam_reported"]
}
```

---

## Data Models

### Email

```typescript
interface Email {
  // Identity
  id: string;                    // "em_" + ULID
  mailbox_id: string;            // Owner mailbox
  
  // Envelope
  from: EmailAddress;
  to: EmailAddress[];
  cc: EmailAddress[];
  reply_to: EmailAddress | null;
  
  // Content
  subject: string;
  text: string | null;           // Plain text body
  html: string | null;           // HTML body
  headers: Record<string, string>;
  
  // Attachments (stored separately in S3)
  attachment_ids: string[];
  
  // Raw storage
  raw_eml_url: string;           // S3 URL to original .eml
  
  // Status
  status: 'pending' | 'scanning' | 'clean' | 'quarantined' | 'rejected';
  read: boolean;
  
  // Timestamps
  received_at: Date;             // When we received from SendGrid
  scanned_at: Date | null;
  created_at: Date;
  updated_at: Date;
  
  // Authentication results
  spf: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none';
  dkim: 'pass' | 'fail' | 'none';
  dmarc: 'pass' | 'fail' | 'none';
}

interface EmailAddress {
  email: string;
  name: string | null;
}
```

**SQLite Schema:**
```sql
CREATE TABLE emails (
  id TEXT PRIMARY KEY,
  mailbox_id TEXT NOT NULL,
  
  from_email TEXT NOT NULL,
  from_name TEXT,
  to_addresses TEXT NOT NULL,      -- JSON array
  cc_addresses TEXT,               -- JSON array
  reply_to TEXT,                   -- JSON object
  
  subject TEXT NOT NULL,
  text_body TEXT,
  html_body TEXT,
  headers TEXT,                    -- JSON object
  
  raw_eml_url TEXT,
  
  status TEXT NOT NULL DEFAULT 'pending',
  read INTEGER NOT NULL DEFAULT 0,
  
  spf TEXT,
  dkim TEXT,
  dmarc TEXT,
  
  received_at TEXT NOT NULL,
  scanned_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  
  FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id)
);

CREATE INDEX idx_emails_mailbox_status ON emails(mailbox_id, status);
CREATE INDEX idx_emails_received ON emails(mailbox_id, received_at DESC);
CREATE INDEX idx_emails_from ON emails(from_email);
```

---

### ScanResult

```typescript
interface ScanResult {
  id: string;                    // "scan_" + ULID
  email_id: string;
  
  // Overall risk assessment
  risk_score: number;            // 0.0 - 1.0
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  verdict: 'clean' | 'suspicious' | 'malicious';
  
  // Individual checks
  flags: ScanFlag[];
  
  // Scanner metadata
  scanners_run: string[];        // Which scanners executed
  scan_duration_ms: number;
  
  // LLM analysis (if triggered)
  llm_analysis: {
    model: string;
    prompt_injection_detected: boolean;
    social_engineering_score: number;
    summary: string;
  } | null;
  
  // Timestamps
  started_at: Date;
  completed_at: Date;
}

interface ScanFlag {
  type: ScanFlagType;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  detail: string;
  evidence: string | null;       // Redacted snippet showing issue
}

type ScanFlagType =
  | 'prompt_injection'           // LLM manipulation attempt
  | 'instruction_override'       // "Ignore previous instructions"
  | 'data_exfil_attempt'         // "Send all emails to..."
  | 'suspicious_url'             // Phishing/malware URL
  | 'malicious_attachment'       // Virus/malware in attachment
  | 'spoofed_sender'             // DKIM/SPF fail + display name mismatch
  | 'urgency_manipulation'       // "Act now!" pressure tactics
  | 'impersonation'              // Pretending to be known contact
  | 'executable_content'         // .exe, .js, macros
  | 'homograph_attack'           // Unicode lookalike domains
  | 'new_sender';                // First email from this sender
```

**SQLite Schema:**
```sql
CREATE TABLE scan_results (
  id TEXT PRIMARY KEY,
  email_id TEXT NOT NULL UNIQUE,
  
  risk_score REAL NOT NULL,
  risk_level TEXT NOT NULL,
  verdict TEXT NOT NULL,
  
  flags TEXT NOT NULL,            -- JSON array
  scanners_run TEXT NOT NULL,     -- JSON array
  scan_duration_ms INTEGER,
  
  llm_analysis TEXT,              -- JSON object
  
  started_at TEXT NOT NULL,
  completed_at TEXT NOT NULL,
  
  FOREIGN KEY (email_id) REFERENCES emails(id)
);

CREATE INDEX idx_scans_verdict ON scan_results(verdict);
CREATE INDEX idx_scans_risk ON scan_results(risk_level);
```

---

### QuarantineItem

```typescript
interface QuarantineItem {
  id: string;                    // "qr_" + ULID
  email_id: string;
  mailbox_id: string;
  
  // Status
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  
  // Resolution
  resolved_at: Date | null;
  resolved_by: string | null;    // API key ID or user ID
  resolution_reason: string | null;
  
  // Actions taken on resolution
  actions: QuarantineAction[];
  
  // Auto-expire if not reviewed
  expires_at: Date;              // Default: 7 days
  
  // Timestamps
  quarantined_at: Date;
  created_at: Date;
  updated_at: Date;
}

interface QuarantineAction {
  type: 'sender_blocked' | 'sender_allowlisted' | 'spam_reported' | 'released' | 'deleted';
  executed_at: Date;
}
```

**SQLite Schema:**
```sql
CREATE TABLE quarantine_items (
  id TEXT PRIMARY KEY,
  email_id TEXT NOT NULL UNIQUE,
  mailbox_id TEXT NOT NULL,
  
  status TEXT NOT NULL DEFAULT 'pending',
  
  resolved_at TEXT,
  resolved_by TEXT,
  resolution_reason TEXT,
  actions TEXT,                   -- JSON array
  
  expires_at TEXT NOT NULL,
  quarantined_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  
  FOREIGN KEY (email_id) REFERENCES emails(id),
  FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id)
);

CREATE INDEX idx_quarantine_mailbox_status ON quarantine_items(mailbox_id, status);
CREATE INDEX idx_quarantine_expires ON quarantine_items(expires_at) WHERE status = 'pending';
```

---

## Integration Patterns

### Pattern 1: Polling (Simple)

Best for: Getting started, low-volume, simple agents

```typescript
// Poll every 30 seconds
async function checkEmails() {
  const response = await fetch('https://api.armourmail.io/emails?status=unread', {
    headers: { 'Authorization': `Bearer ${API_KEY}` }
  });
  
  const { emails } = await response.json();
  
  for (const email of emails) {
    await processEmail(email);
    await fetch(`https://api.armourmail.io/emails/${email.id}/read`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${API_KEY}` }
    });
  }
}

setInterval(checkEmails, 30_000);
```

**Pros:** Simple, no infrastructure needed
**Cons:** Latency (up to poll interval), wastes requests when no mail

---

### Pattern 2: Webhook Push (Recommended)

Best for: Real-time processing, production workloads

**Configure webhook in dashboard:**
```json
{
  "webhook_url": "https://your-agent.com/armourmail-events",
  "events": ["email.clean", "email.quarantined"],
  "secret": "whsec_..."
}
```

**Receive events:**
```typescript
app.post('/armourmail-events', async (req, res) => {
  // Verify signature
  const signature = req.headers['x-armourmail-signature'];
  const timestamp = req.headers['x-armourmail-timestamp'];
  
  if (!verifySignature(req.body, signature, timestamp, WEBHOOK_SECRET)) {
    return res.status(401).send('Invalid signature');
  }
  
  const event = req.body;
  
  switch (event.type) {
    case 'email.clean':
      await processCleanEmail(event.data.email);
      break;
    case 'email.quarantined':
      await notifyHumanForReview(event.data.quarantine_item);
      break;
  }
  
  res.status(200).send('OK');
});
```

**Event Types:**
| Event | Description |
|-------|-------------|
| `email.received` | New email received (before scanning) |
| `email.clean` | Email passed all scans |
| `email.quarantined` | Email flagged, awaiting review |
| `quarantine.approved` | Human approved quarantined email |
| `quarantine.rejected` | Human rejected quarantined email |
| `quarantine.expired` | Quarantine item auto-expired |

---

### Pattern 3: SDK (TypeScript)

Best for: Type safety, ergonomic API, complex integrations

```typescript
import { ArmourMail } from '@armourmail/sdk';

const client = new ArmourMail({
  apiKey: process.env.ARMOURMAIL_API_KEY,
});

// Fetch emails
const { emails } = await client.emails.list({
  status: 'unread',
  limit: 10,
});

// Stream new emails (WebSocket)
client.emails.stream({
  onEmail: async (email) => {
    console.log('New email:', email.subject);
    await email.markAsRead();
  },
  onQuarantine: async (item) => {
    console.log('Needs review:', item.email.subject);
  },
});

// Manage quarantine
const { items } = await client.quarantine.list({ status: 'pending' });
await client.quarantine.approve(items[0].id, {
  reason: 'Known sender',
  addToAllowlist: true,
});

// Check scan details
const scan = await client.emails.getScan('em_01HXK...');
console.log('Risk score:', scan.risk_score);
console.log('Flags:', scan.flags);
```

---

### Pattern 4: LangChain/OpenAI Tools

```typescript
const armourmailTool = {
  name: "check_email",
  description: "Check for new emails that have passed security scanning",
  parameters: {
    type: "object",
    properties: {
      limit: { type: "number", description: "Max emails to fetch" }
    }
  },
  execute: async ({ limit = 5 }) => {
    const response = await fetch(
      `https://api.armourmail.io/emails?status=unread&limit=${limit}`,
      { headers: { Authorization: `Bearer ${API_KEY}` } }
    );
    return response.json();
  }
};
```

---

## Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| **Prompt Injection via Email** | LLM-based detection, pattern matching, content isolation |
| **Webhook Spoofing** | Signature verification, timestamp validation, IP allowlist |
| **API Key Theft** | Key rotation, scoped permissions, audit logging |
| **Data Exfiltration** | Email content never in logs, encryption at rest |
| **Denial of Service** | Rate limiting, queue depth limits, webhook retries |
| **Attachment Malware** | Sandbox execution, antivirus scanning, type restrictions |

### Prompt Injection Detection

Multi-layer approach:

```
Layer 1: Pattern Matching (fast, high recall)
├── Known injection patterns ("ignore previous", "system prompt")
├── Instruction-like phrases in unexpected contexts
├── Base64/encoded payloads
└── Unicode obfuscation

Layer 2: LLM Classification (accurate, slower)
├── Dedicated small model fine-tuned on injection examples
├── Only triggered for suspicious emails (score > 0.3)
└── Provides human-readable explanation

Layer 3: Structural Analysis
├── Unusual formatting (hidden text, white-on-white)
├── Role-playing indicators ("You are now...")
└── Context switching attempts
```

### API Security

```typescript
// Rate limits per API key
const RATE_LIMITS = {
  'emails.list': { requests: 100, window: '1m' },
  'emails.read': { requests: 500, window: '1m' },
  'quarantine.list': { requests: 50, window: '1m' },
  'quarantine.approve': { requests: 20, window: '1m' },
  'ingest': { requests: 1000, window: '1m' },  // Per mailbox
};

// API key scopes
type ApiKeyScope = 
  | 'emails:read'
  | 'emails:write'
  | 'quarantine:read'
  | 'quarantine:write'
  | 'admin';
```

### Encryption

- **In Transit:** TLS 1.3 required for all API calls
- **At Rest:** AES-256 for email bodies and attachments in S3
- **Keys:** Managed via AWS KMS / Cloudflare Workers secrets

---

## Scaling Considerations

### Architecture Tiers

**Tier 1: Single Instance (0-10K emails/day)**
```
┌─────────────────────────────────────────┐
│  Single Cloudflare Worker               │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐   │
│  │  API    │ │ Scanner │ │  Queue  │   │
│  └─────────┘ └─────────┘ └─────────┘   │
│                  │                       │
│  ┌─────────────────────────────────┐    │
│  │    Turso (Distributed SQLite)    │   │
│  └─────────────────────────────────┘    │
│  ┌─────────────────────────────────┐    │
│  │    Cloudflare R2 (Attachments)   │   │
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘
```

**Tier 2: Distributed (10K-1M emails/day)**
```
┌─────────────────────────────────────────────────────────────┐
│                    Cloudflare Workers                        │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐             │
│  │ API  │ │ API  │ │ API  │ │ API  │ │ API  │  (global)   │
│  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘             │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────┼─────────────────────────────────┐
│  ┌────────────────────────┴────────────────────────────┐    │
│  │           Cloudflare Queues (Durable)               │    │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐             │    │
│  │  │ ingest  │  │  scan   │  │ webhook │             │    │
│  │  └─────────┘  └─────────┘  └─────────┘             │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  ┌─────────────────┐  ┌─────────────────┐                   │
│  │  Turso Primary  │──│  Turso Replicas │ (multi-region)    │
│  └─────────────────┘  └─────────────────┘                   │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │          Cloudflare R2 (Global Attachments)          │   │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### Queue Design

```typescript
// Ingest queue: High throughput, at-least-once
Queue.send('ingest', {
  emailId: 'em_01HXK...',
  rawPayload: { /* SendGrid data */ }
}, {
  retries: 3,
  backoff: 'exponential',
});

// Scan queue: Medium throughput, exactly-once preferred
Queue.send('scan', {
  emailId: 'em_01HXK...',
}, {
  retries: 3,
  deduplication: { key: 'emailId', window: '1h' },
});

// Webhook queue: Reliable delivery with retries
Queue.send('webhook', {
  mailboxId: 'mb_...',
  event: 'email.clean',
  payload: { /* event data */ }
}, {
  retries: 5,
  backoff: { initial: '1s', max: '5m' },
});
```

### Database Sharding Strategy

For >1M emails/day, shard by `mailbox_id`:

```sql
-- Shard key: mailbox_id
-- Shard count: 16 (can scale to 256)

-- Routing function
SELECT shard_number FROM (
  SELECT (hashtext(mailbox_id) & 0x7FFFFFFF) % 16 AS shard_number
);
```

### Caching Strategy

```typescript
// Cache layers (using Cloudflare KV/Cache API)
const CACHE_TTL = {
  'email:single': 60,           // Single email: 1 min
  'email:list': 10,             // Email list: 10 sec (stale-while-revalidate)
  'quarantine:list': 5,         // Quarantine: 5 sec
  'scan:result': 3600,          // Scan results: 1 hour (immutable)
  'mailbox:settings': 300,      // Mailbox config: 5 min
};
```

---

## Deployment Architecture

### Recommended Stack

| Component | Technology | Reason |
|-----------|------------|--------|
| **API** | Cloudflare Workers + Hono | Global edge, zero cold start |
| **Database** | Turso (libSQL) | Distributed SQLite, simple ops |
| **Queue** | Cloudflare Queues | Native integration, durable |
| **Object Storage** | Cloudflare R2 | S3-compatible, no egress fees |
| **LLM** | Anthropic Claude Haiku | Fast, cheap, good at detection |
| **Secrets** | Workers Secrets | Native, encrypted |

### Environment Configuration

```toml
# wrangler.toml
name = "armourmail-api"
main = "src/index.ts"

[vars]
ENVIRONMENT = "production"
LOG_LEVEL = "info"

[[queues.producers]]
queue = "email-ingest"
binding = "INGEST_QUEUE"

[[queues.producers]]
queue = "email-scan"
binding = "SCAN_QUEUE"

[[queues.consumers]]
queue = "email-ingest"
max_batch_size = 10
max_batch_timeout = 30

[[r2_buckets]]
binding = "ATTACHMENTS"
bucket_name = "armourmail-attachments"

[[ d1_databases ]]
binding = "DB"
database_name = "armourmail"
database_id = "..."
```

---

## Appendix: ID Formats

All IDs use ULID format (sortable, URL-safe):

| Prefix | Entity |
|--------|--------|
| `em_` | Email |
| `scan_` | ScanResult |
| `qr_` | QuarantineItem |
| `mb_` | Mailbox |
| `att_` | Attachment |
| `am_live_` | Production API key |
| `am_test_` | Sandbox API key |
| `whsec_` | Webhook secret |

---

## Next Steps

1. **Phase 1:** Core API + SendGrid integration + basic scanning
2. **Phase 2:** LLM-based prompt injection detection
3. **Phase 3:** SDK + webhook delivery
4. **Phase 4:** Dashboard UI for quarantine management
5. **Phase 5:** Multi-tenant, usage billing
