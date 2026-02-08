# ArmourMail - AI-Safe Email Infrastructure

## Problem
AI agents are increasingly given email access, but email is a prime vector for prompt injection attacks. Traditional email security focuses on phishing/malware, not LLM-specific attacks.

## Solution
Email infrastructure purpose-built for AI agents with:
- Prompt injection detection
- Hidden text extraction
- Content sanitization
- Human-in-the-loop quarantine
- Audit trails

## Market
- AI agent platforms (OpenClaw, Lindy, AutoGPT, etc.)
- Enterprises deploying AI assistants
- Developers building AI-powered workflows

## Competitive Landscape
| Player | Focus | Gap |
|--------|-------|-----|
| Proofpoint/Mimecast | Phishing, malware | No LLM-specific detection |
| Anthropic/OpenAI guardrails | Model-level | Not email-specific |
| Generic sanitization | XSS, injection | Not prompt-aware |

**No purpose-built solution exists.**

## Business Model
- **SaaS**: Per-mailbox or per-API-call pricing
- **Self-hosted**: Open source core + commercial support
- **Enterprise**: Custom deployment, SLA, compliance

## MVP Scope (2-3 weeks)
1. SendGrid Inbound Parse integration
2. Basic sanitization (strip HTML, detect hidden text)
3. Prompt injection regex patterns
4. REST API for AI agents
5. Simple quarantine dashboard

## Phase 2 (Month 2)
- ML-based injection detection
- Outbound email validation
- Webhook delivery
- Usage analytics
- Open source core release

## Phase 3 (Month 3+)
- Self-hosted deployment option
- Enterprise features (SSO, audit, compliance)
- Custom MX infrastructure option
- Agent framework integrations

## Open Source Strategy
- Core sanitization library: MIT
- Self-hosted server: AGPL
- Cloud service: Proprietary
- Enterprise add-ons: Commercial

## Key Risks
- Email infra is operationally complex
- Prompt injection detection is cat-and-mouse
- Adoption requires trust

## Success Metrics
- Mailboxes protected
- Injection attempts blocked
- False positive rate
- Customer retention

## Next Steps
1. [ ] Validate pain points (talk to AI agent builders)
2. [ ] Competitive deep dive
3. [ ] Technical architecture doc
4. [ ] MVP build
5. [ ] Beta customers
