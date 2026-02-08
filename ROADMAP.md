# ArmourMail Roadmap - Recalibrated (2026-02-08)

## Overview
ArmourMail is evolving from a simple SendGrid handler into a purpose-built **AI-Safe Email Infrastructure**. The primary mission is to protect AI agents from **Indirect Prompt Injection** delivered via email.

## Current State (Post-Recovery)
- ✅ Git Repository Initialized (`neg-0/armourmail`)
- ✅ SendGrid Inbound Parse Handler (`index.js`)
- ✅ Basic Authentication Guard (SPF/DKIM check)
- ✅ Inbound Logging
- ✅ Simulation/Test Script
- ✅ Strategic Documentation (`CONCEPT.md`, `RESEARCH.md`, `SPRINT.md`)

## Phase 1: Injection Detection (The "Armour")
*Target: End of Week 1*

1. **Hidden Text Extraction**: Detect and strip zero-font text, white-on-white text, and other common "hidden instruction" techniques.
2. **Prompt Injection Scanner**: 
    - Implement regex-based scanners for common injection patterns (e.g., "Ignore previous instructions", "System override").
    - Implement semantic analysis using an LLM-based classifier (the "Judge") to detect malicious intent.
3. **Multi-layer Sanitization**:
    - HTML-to-Markdown conversion with strict attribute stripping.
    - URL link validation and proxying.

## Phase 2: Quarantine & Human-in-the-Loop
*Target: Mid-February*

1. **Quarantine Logic**: Flag suspicious emails for review instead of immediate delivery to the agent.
2. **Review API**: Endpoint for a human (or a "High-Trust Agent") to approve/reject quarantined emails.
3. **Dashboard (Alpha)**: Simple Next.js UI to visualize inbound flow and manage quarantine.

## Phase 3: Agent Integration (Dogfooding)
*Target: Late February*

1. **Webhook Delivery**: Route sanitized emails to AI agents via authenticated webhooks.
2. **SDK**: Create a lightweight Python/Node.js SDK for agents to "fetch" sanitized mail from ArmourMail.
3. **OpenClaw Integration**: Use ArmourMail to protect the `rocket` and `warden` agents.

## Phase 4: Expansion
*Target: March 2026*

1. **Attachment Scanning**: Analyze PDFs and images for embedded instructions.
2. **Outbound Guard**: Prevent agents from being tricked into sending sensitive data.
3. **Market Launch**: Open source the core library; launch SaaS for enterprise agents.

## Technical Refinement (Immediate Tasks)
- [ ] Migrate from `index.js` to a more structured FastAPI (Python) or structured Node project to support heavy regex/NLP.
- [ ] Initialize `main` branch and push existing work.
- [ ] Implement `detector.py` (or `.js`) with first set of injection patterns.
