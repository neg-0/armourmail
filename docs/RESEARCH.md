# ArmourMail Market Research
> Research Date: February 1, 2026  
> Prepared for: Go/No-Go Decision on AI Agent Security Product

---

## Executive Summary

The AI agent security market is **real, validated, and well-funded**—but also **crowded with well-capitalized players**. Prompt injection remains the #1 security risk per OWASP. The opportunity exists, but requires a differentiated angle.

---

## 1. Prompt Injection Attack Patterns

### What Is It?
Per OWASP LLM01:2025, prompt injection occurs when user prompts alter LLM behavior in unintended ways. This is the **#1 risk** in the OWASP Top 10 for LLM Applications.

### Attack Types

| Type | Description | Delivery Method |
|------|-------------|-----------------|
| **Direct Injection** | User directly crafts malicious prompts | User input, chat interfaces |
| **Indirect Injection** | Malicious content in external sources (websites, files, emails) | RAG sources, uploaded docs, scraped web content |
| **Jailbreaking** | Bypassing safety guardrails entirely | Crafted prompts with role-play, encoding, etc. |
| **Payload Splitting** | Breaking malicious content across multiple inputs | Resumes, multi-part messages |
| **Adversarial Suffix** | Appending nonsensical strings that manipulate behavior | Automated attack tools |
| **Multilingual/Obfuscation** | Using Base64, emojis, or multiple languages to evade filters | Encoded prompts |
| **Multimodal Injection** | Hiding instructions in images processed with text | Image + text inputs |

### Attack Consequences
- Disclosure of sensitive information
- Revealing system prompts and infrastructure details
- Unauthorized access to LLM-connected tools
- Executing arbitrary commands in connected systems
- Data exfiltration through image links or API calls
- Manipulating decision-making (hiring, financial, medical)

### Key Insight: The "ArmourMail" Angle
**Email is a prime vector for indirect prompt injection attacks.** An AI agent processing emails could receive malicious instructions embedded in:
- Email body text
- PDF attachments (resumes, invoices)
- Linked documents
- Forwarded chains with hidden instructions

---

## 2. OWASP LLM Security Guidance

### OWASP Top 10 for LLM Applications (2025)

| Rank | Vulnerability | Relevance to Email Agents |
|------|---------------|---------------------------|
| **LLM01** | Prompt Injection | ⚠️ **Critical** - emails are untrusted input |
| **LLM02** | Insecure Output Handling | ⚠️ High - agent may execute commands |
| **LLM03** | Training Data Poisoning | Low - model-level concern |
| **LLM04** | Model Denial of Service | Medium - resource exhaustion via email floods |
| **LLM05** | Supply Chain Vulnerabilities | Medium - depends on model providers |
| **LLM06** | Sensitive Information Disclosure | ⚠️ High - email agents access private data |
| **LLM07** | Insecure Plugin Design | ⚠️ High - if agent has email/calendar tools |
| **LLM08** | Excessive Agency | ⚠️ **Critical** - agents taking autonomous actions |
| **LLM09** | Overreliance | Medium - trusting agent decisions |
| **LLM10** | Model Theft | Low - infrastructure concern |

### NEW: OWASP Top 10 for Agentic Applications (2026)
OWASP released a **new framework specifically for agentic AI** in late 2025/2026. This validates market timing—security for autonomous AI agents is now a formal concern.

Key quote from OWASP:
> "The OWASP Top 10 for Agentic Applications 2026 is a globally peer-reviewed framework that identifies the most critical security risks facing autonomous and agentic AI systems."

### OWASP Recommended Mitigations
1. Constrain model behavior via system prompts
2. Define and validate expected output formats
3. Implement input/output filtering (semantic filters, string checks)
4. Enforce privilege control and least-privilege access
5. Require human approval for high-risk actions
6. Segregate and identify external (untrusted) content
7. Conduct adversarial testing/red teaming

---

## 3. Competitive Landscape

### Major Players in AI Agent Security

| Company | Focus | Stage | Notes |
|---------|-------|-------|-------|
| **Lakera** | Prompt injection, jailbreak, guardrails | Series A ($20M+) | Market leader. 1M+ hackers via "Gandalf" game. Sub-50ms latency. Dropbox customer. |
| **HiddenLayer** | Full AI security platform | Series A ($50M+) | Backed by Microsoft M12, IBM Ventures, Capital One. Published APE Taxonomy. |
| **Lasso Security** | Shadow AI discovery, agent security | Series A | 99.8% accuracy claim. "Intent-based" detection. 570x more cost-effective than cloud guardrails (their claim). |
| **Protect AI** | Model security, red teaming | Series B ($60M+) | 17k+ security researchers via huntr. Partnership with Hugging Face. |
| **CalypsoAI** | AI firewall, red teaming, observability | Late stage | **Acquired by F5 (Sep 2025)**. RSAC 2025 Innovation Sandbox finalist. |
| **Arthur AI** | Evals, guardrails, monitoring | Series B | $60/mo Premium tier. SaaS + on-prem. SOC2 compliant. |
| **Securiti AI** | Data + AI security platform | Series D ($150M+) | Enterprise DSPM + AI governance. LLM firewalls. Very broad scope. |
| **PromptArmor** | AI asset visibility, risk assessment | Early stage | OWASP sponsor. Focus on vendor AI risk across 26 risk vectors. |

### HiddenLayer's APE Taxonomy (Key Intelligence)
HiddenLayer published the **industry's first complete taxonomy of adversarial prompt engineering**. This is now a de-facto reference. Key layers:
- **Objectives**: Intent (data theft, reputation harm, task redirection)
- **Tactics**: High-level adversarial groupings (Context Manipulation, etc.)
- **Techniques**: Specific methods (Tool Call Spoofing, Conversation Spoofing, Refusal Suppression)
- **Prompts**: Concrete attack strings

### Notable Acquisitions
- **F5 acquired CalypsoAI** (Sep 2025) - Major validation that established security vendors see value in AI security startups

### Market Positioning
```
                    Broad Platform
                         ↑
                    Securiti AI
                    HiddenLayer
                         |
    Email Focus ←--------+--------→ Generic AI
                         |
                    Lakera
                    Lasso
                    Arthur AI
                         ↓
                    Point Solution
```

**Gap identified**: No one is specifically focused on **email as an attack vector for AI agents**. Everyone is building horizontal platforms.

---

## 4. Pricing Models

### Observed Pricing Structures

| Company | Model | Pricing |
|---------|-------|---------|
| **Arthur AI** | Freemium + tiers | Free → $60/mo → Enterprise custom |
| **Lakera** | Usage-based API | "Start for free" → Enterprise custom (likely per-call) |
| **Lasso** | Enterprise sales | Demo-only, custom pricing |
| **HiddenLayer** | Enterprise sales | Demo-only, custom pricing |
| **Protect AI** | Enterprise sales | Demo-only, custom pricing |

### Typical Security SaaS Pricing Models

1. **Per-API-call / Per-prompt pricing**
   - Common for guardrails/filtering services
   - Example: $0.001-0.01 per prompt scanned
   - Scales with usage, aligns with value

2. **Per-seat / Per-user pricing**
   - Common for observability/monitoring
   - Example: $50-200/user/month
   - Easier to budget, less aligned with actual protection

3. **Tiered feature gates**
   - Free tier → Pro → Enterprise
   - Common pattern: Core features free, advanced (SSO, SLA, custom) gated

4. **Per-agent / Per-application pricing**
   - Example: $X per protected AI agent per month
   - Good for ArmourMail's potential model

### Recommended ArmourMail Pricing (If Built)
- **Free tier**: 10,000 emails/month scanned, basic detection
- **Pro tier**: $99/mo - 100k emails, advanced detection, alerting
- **Enterprise**: Custom - unlimited, SLA, SSO, on-prem

---

## 5. Key Findings & Recommendations

### ✅ Market Validation
1. **OWASP prioritizes this** - Prompt injection is #1 risk in LLM Top 10
2. **Agentic AI specifically addressed** - New OWASP Top 10 for Agentic Applications (2026) shows regulatory/standards momentum
3. **Well-funded competitors** - $200M+ total funding in this space indicates real demand
4. **Enterprise adoption accelerating** - Dropbox, Fortune 500 companies using these solutions
5. **M&A activity** - F5/CalypsoAI acquisition signals market maturity

### ⚠️ Challenges
1. **Crowded market** - At least 8 well-funded competitors
2. **Horizontal focus** - Most are building platforms, not vertical solutions
3. **Latency expectations** - Sub-50ms is the benchmark (Lakera sets this)
4. **Accuracy expectations** - 99%+ with near-zero false positives expected
5. **Enterprise sales cycle** - Security tools require long sales cycles, POCs, compliance

### 🎯 Differentiation Opportunity: "Email Security for AI Agents"

**The gap**: Nobody is specifically focused on **protecting AI agents that process email**. This is a concrete, specific use case with clear attack vectors.

**Why email is special:**
- High volume of untrusted external input
- Attachments (PDFs, images) are multimodal attack vectors
- Email chains can hide injections in forwarded content
- Phishing is already a mature attack category—now extended to AI
- Clear ROI story: "Protect your AI assistant from malicious emails"

**Potential positioning:**
> "ArmourMail: The email firewall for AI agents. Scan incoming emails before your AI assistant processes them. Detect prompt injections, hidden instructions, and adversarial content in email bodies and attachments."

---

## 6. Go/No-Go Assessment

### Arguments FOR Building

| Factor | Assessment |
|--------|------------|
| Market timing | ✅ OWASP Agentic Top 10 just released (2026). Perfect timing. |
| Clear use case | ✅ Email → AI agent is specific and defensible |
| Differentiation | ✅ Vertical focus vs. horizontal platforms |
| Technical feasibility | ✅ Known techniques exist (filtering, semantic analysis) |
| Regulatory tailwind | ✅ AI safety regulations emerging globally |

### Arguments AGAINST Building

| Factor | Assessment |
|--------|------------|
| Competition | ⚠️ Well-funded players could add email features easily |
| Distribution | ⚠️ Need to reach AI agent developers—who are they? |
| Technical moat | ⚠️ Detection techniques are commodity; moat is data/scale |
| Enterprise sales | ⚠️ Long cycles, requires dedicated sales team |

### Verdict: **CONDITIONAL GO**

**Build if:**
- Can ship MVP in <3 months
- Can get 5-10 design partners before heavy investment
- Focus on integration with specific AI agent frameworks (OpenClaw, LangChain, AutoGPT)
- Plan for $0 revenue for 6-12 months (open-source or freemium)

**Don't build if:**
- Expecting quick revenue
- No distribution advantage to AI developers
- Can't commit to the security standards expected (SOC2, etc.)

---

## Appendix: Key Sources

1. OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/
2. OWASP Top 10 for Agentic Applications 2026: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
3. OWASP LLM01 Prompt Injection: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
4. Lakera: https://www.lakera.ai/
5. HiddenLayer APE Taxonomy: https://hiddenlayer.com/innovation-hub/introducing-a-taxonomy-of-adversarial-prompt-engineering/
6. Lasso Security: https://www.lasso.security/
7. Protect AI: https://protectai.com/
8. Arthur AI Pricing: https://www.arthur.ai/pricing
