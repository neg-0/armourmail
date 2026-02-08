# ArmourMail - Sprint Plan

## Target: Working MVP in 2 Weeks

### Week 1: Foundation
| Track | Owner | Deliverable |
|-------|-------|-------------|
| Architecture | Agent | Technical design doc, API spec |
| Core Library | Agent | Prompt injection detection library |
| Infra | Rocket | GitHub repo, CI/CD, SendGrid setup |
| Domain | Dustin | armourmail.dev or similar |

### Week 2: Integration
| Track | Owner | Deliverable |
|-------|-------|-------------|
| API Server | Agent | FastAPI/Express service |
| Dashboard | Agent | Simple quarantine UI |
| Docs | Agent | Integration guide |
| Testing | All | Red team the detector |

### Day 1 (NOW) Parallel Tracks

**Track A: Architecture**
- API design (receive email, fetch clean, quarantine review)
- Data model (emails, scan results, quarantine queue)
- Integration patterns (webhook, polling, SDK)

**Track B: Detection Library**
- Hidden text detection (render vs raw comparison)
- Prompt injection regex patterns
- Known attack pattern database
- Confidence scoring

**Track C: Infrastructure**
- Create GitHub repo: neg-0/armourmail
- Set up Python/TypeScript project
- SendGrid Inbound Parse webhook
- Basic CI/CD

---

## Tech Stack (Proposed)

| Component | Choice | Reason |
|-----------|--------|--------|
| API | FastAPI (Python) | Fast, async, good for ML |
| Detection | Python | NLP libraries, regex |
| Dashboard | Next.js | We know it, fast to build |
| Database | Supabase | Already have it |
| Email Ingest | SendGrid Inbound Parse | Fastest to MVP |
| Hosting | Railway or Vercel | Easy deploys |

---

## Success Criteria (2 weeks)

- [ ] Receive email via SendGrid webhook
- [ ] Scan for hidden text and injection patterns
- [ ] Store results in database
- [ ] API to fetch clean emails
- [ ] Simple dashboard to review quarantine
- [ ] One integration working (OpenClaw dogfooding)
- [ ] README with setup instructions

---

## Stretch Goals

- [ ] ML-based classifier (fine-tuned)
- [ ] PDF attachment scanning
- [ ] Outbound email validation
- [ ] npm/pip SDK package
