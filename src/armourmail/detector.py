"""
ArmourMail Prompt Injection Detector

Detects prompt injection attacks in email content, including:
- Hidden text (white-on-white, tiny fonts, zero-width characters, HTML comments)
- Direct injection patterns ("ignore previous instructions", etc.)
- Role-playing attacks
- Encoded payloads (Base64)
- OWASP LLM01 patterns

Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

from __future__ import annotations

import base64
import html
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RiskLevel(Enum):
    """Risk severity levels."""
    NONE = 0
    LOW = 25
    MEDIUM = 50
    HIGH = 75
    CRITICAL = 100


@dataclass
class ScanResult:
    """Result of scanning content for prompt injection attacks."""
    risk_score: int  # 0-100
    detected_patterns: list[str] = field(default_factory=list)
    hidden_text_found: bool = False
    clean_content: str = ""
    quarantine_recommended: bool = False
    details: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Determine if quarantine is recommended based on risk score."""
        self.quarantine_recommended = self.risk_score >= 50


# Zero-width and invisible characters
ZERO_WIDTH_CHARS = [
    '\u200b',  # Zero Width Space
    '\u200c',  # Zero Width Non-Joiner
    '\u200d',  # Zero Width Joiner
    '\u2060',  # Word Joiner
    '\u2061',  # Function Application
    '\u2062',  # Invisible Times
    '\u2063',  # Invisible Separator
    '\u2064',  # Invisible Plus
    '\ufeff',  # Zero Width No-Break Space (BOM)
    '\u00ad',  # Soft Hyphen
    '\u034f',  # Combining Grapheme Joiner
    '\u061c',  # Arabic Letter Mark
    '\u115f',  # Hangul Choseong Filler
    '\u1160',  # Hangul Jungseong Filler
    '\u17b4',  # Khmer Vowel Inherent Aq
    '\u17b5',  # Khmer Vowel Inherent Aa
    '\u180e',  # Mongolian Vowel Separator
    '\u2000',  # En Quad
    '\u2001',  # Em Quad
    '\u2002',  # En Space
    '\u2003',  # Em Space
    '\u2004',  # Three-Per-Em Space
    '\u2005',  # Four-Per-Em Space
    '\u2006',  # Six-Per-Em Space
    '\u2007',  # Figure Space
    '\u2008',  # Punctuation Space
    '\u2009',  # Thin Space
    '\u200a',  # Hair Space
    '\u202f',  # Narrow No-Break Space
    '\u205f',  # Medium Mathematical Space
    '\u3000',  # Ideographic Space
    '\u3164',  # Hangul Filler
    '\uffa0',  # Halfwidth Hangul Filler
]

ZERO_WIDTH_PATTERN = re.compile(f"[{''.join(ZERO_WIDTH_CHARS)}]+")


# ============================================================================
# PROMPT INJECTION PATTERNS (OWASP LLM01 aligned)
# ============================================================================

# Direct instruction override attempts
DIRECT_INJECTION_PATTERNS = [
    # Ignore/forget previous instructions
    (r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|rules?|guidelines?|context)", "ignore_previous_instructions"),
    (r"(?i)forget\s+(?:all\s+)?(?:previous|prior|your|earlier)\s+(?:instructions?|prompts?|rules?|training|context)", "forget_instructions"),
    (r"(?i)disregard\s+(?:all\s+)?(?:previous|prior|your|earlier|the)\s+(?:instructions?|prompts?|rules?|guidelines?)", "disregard_instructions"),
    (r"(?i)override\s+(?:all\s+)?(?:previous|prior|your|safety|security)\s+(?:instructions?|prompts?|rules?|settings?)", "override_instructions"),
    (r"(?i)ignore\s+(?:all\s+)?(?:safety|security)\s+(?:rules?|protocols?|guidelines?|restrictions?)", "ignore_safety"),
    (r"(?i)bypass\s+(?:all\s+)?(?:safety|security|content)\s+(?:filters?|rules?|restrictions?)", "bypass_safety"),
    
    # New instruction injection
    (r"(?i)(?:new|updated|revised|real)\s+(?:instructions?|prompts?|rules?|guidelines?)(?:\s*:|\s+are)", "new_instructions"),
    (r"(?i)(?:your|the)\s+(?:new|real|actual|true)\s+(?:instructions?|prompts?|task|purpose)(?:\s*:|\s+is)", "real_instructions"),
    (r"(?i)from\s+now\s+on[,\s]+(?:you|your|ignore|forget|disregard)", "from_now_on"),
    
    # System prompt manipulation
    (r"(?i)system\s*(?:prompt|message|instruction)s?\s*:", "system_prompt_injection"),
    (r"(?i)\[(?:system|sys|admin|root)\]", "system_tag_injection"),
    (r"(?i)<\s*(?:system|sys|admin|root)\s*>", "system_xml_injection"),
    (r"(?i)###\s*(?:system|instruction|admin)", "system_markdown_injection"),
    
    # Context manipulation
    (r"(?i)end\s+of\s+(?:system|user|assistant)\s+(?:message|prompt|input)", "context_boundary_manipulation"),
    (r"(?i)(?:begin|start)\s+(?:new\s+)?(?:conversation|session|context)", "new_context_injection"),
    (r"(?i)\[\/(?:INST|SYS|USER|ASSISTANT)\]", "llama_tag_injection"),
    (r"(?i)<\|(?:im_start|im_end|endoftext|system|user|assistant)\|>", "special_token_injection"),
]

# Role-playing and identity manipulation attacks
ROLEPLAY_PATTERNS = [
    # Identity reassignment
    (r"(?i)you\s+are\s+now\s+(?:a|an|the|my)?\s*\w+", "identity_reassignment"),
    (r"(?i)act\s+(?:as|like)\s+(?:a|an|the|if\s+you\s+were)?\s*\w+", "act_as_injection"),
    (r"(?i)pretend\s+(?:to\s+be|you\s+are|that\s+you)", "pretend_injection"),
    (r"(?i)roleplay\s+(?:as|that|like)", "roleplay_injection"),
    (r"(?i)imagine\s+(?:you\s+are|yourself\s+as|being)", "imagine_injection"),
    (r"(?i)(?:play|assume)\s+the\s+(?:role|character|part)\s+of", "role_assumption"),
    
    # Jailbreak personas
    (r"(?i)(?:dan|dude|devil|evil|dark|shadow|uncensored|unfiltered)\s*(?:mode|gpt|ai|version|persona)", "jailbreak_persona"),
    (r"(?i)(?:developer|debug|maintenance|admin(?:istrator)?|root|sudo)\s*mode", "privileged_mode"),
    (r"(?i)enable\s+(?:developer|debug|unrestricted|unfiltered|jailbreak)\s*mode", "enable_special_mode"),
    
    # Hypothetical/fictional framing
    (r"(?i)(?:let's|let\s+us)\s+(?:play|pretend|imagine|roleplay)", "roleplay_framing"),
    (r"(?i)in\s+(?:this|a)\s+(?:fictional|hypothetical|imaginary)\s+(?:scenario|world|story)", "fictional_framing"),
    (r"(?i)for\s+(?:educational|research|testing|fictional)\s+purposes?(?:\s+only)?", "purpose_framing"),
]

# Delimiter and format attacks
DELIMITER_PATTERNS = [
    # Markdown/formatting abuse
    (r"```(?:system|python|bash|sh|cmd|powershell|exec)", "code_block_injection"),
    (r"(?i)---+\s*(?:system|admin|instruction|new\s+task)", "separator_injection"),
    
    # XML/HTML tag abuse
    (r"<\s*(?:script|style|iframe|object|embed|form|input|textarea)\b", "html_tag_injection"),
    (r"(?i)<\s*(?:jailbreak|inject|attack|payload|command)\s*>", "attack_tag_injection"),
    
    # JSON/data structure abuse
    (r'"(?:role|content|system|instruction)":\s*["\[]', "json_structure_injection"),
    (r"\{\s*[\"'](?:system|role|prompt|instruction)[\"']", "json_object_injection"),
]

# Obfuscation patterns
OBFUSCATION_PATTERNS = [
    # Character substitution (l33t speak, homoglyphs)
    (r"(?i)1gn0r[e3]\s+pr[e3]v[i1]0us", "leetspeak_obfuscation"),
    (r"(?i)syst[e3]m\s*pr[o0]mpt", "leetspeak_system"),
    
    # Unicode homoglyphs (Cyrillic, etc.)
    (r"[іІ][gnqр][nnп][оo][rr][еe]", "homoglyph_ignore"),  # Cyrillic lookalikes
    
    # Word splitting
    (r"(?i)ig\s*no\s*re\s+pre\s*vi\s*ous", "split_words"),
    (r"(?i)sys\s*tem\s+pro\s*mpt", "split_system_prompt"),
    
    # Reverse text
    (r"(?i)(?:tpmorp|snoitcurtsni|erongi)", "reversed_text"),
    
    # Hex/numeric encoding
    (r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){3,}", "hex_encoded"),
    (r"\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){3,}", "unicode_encoded"),
    (r"&#x?[0-9a-fA-F]+;(?:&#x?[0-9a-fA-F]+;){3,}", "html_entity_encoded"),
]

# Manipulation and social engineering
MANIPULATION_PATTERNS = [
    # Urgency/authority
    (r"(?i)(?:urgent|critical|important|emergency)[:\s]+(?:ignore|override|bypass)", "urgency_manipulation"),
    (r"(?i)(?:admin|administrator|developer|ceo|owner|boss)\s+(?:says?|requests?|orders?|demands?)", "authority_claim"),
    (r"(?i)(?:this\s+is\s+a\s+)?(?:test|drill|exercise)\s*[:\-]\s*(?:ignore|bypass|override)", "test_framing"),
    
    # Emotional manipulation
    (r"(?i)(?:please|i\s+beg\s+you|you\s+must|you\s+have\s+to)\s+(?:ignore|forget|disregard)", "emotional_manipulation"),
    (r"(?i)(?:my\s+life|someone's\s+life|lives?)\s+(?:depends?|at\s+stake|in\s+danger)", "life_threat_manipulation"),
    
    # Reward/threat
    (r"(?i)(?:i\s+will|you\s+will)\s+(?:pay|reward|tip|give)", "bribery_attempt"),
    (r"(?i)(?:or\s+else|otherwise)\s+(?:i\s+will|you\s+will|bad\s+things)", "threat_pattern"),
]

# Extraction attempts
EXTRACTION_PATTERNS = [
    (r"(?i)(?:reveal|show|display|print|output|echo)\s+(?:your|the|system)\s+(?:prompt|instructions?|rules?)", "prompt_extraction"),
    (r"(?i)(?:what|tell\s+me)\s+(?:is|are)\s+your\s+(?:system\s+)?(?:prompt|instructions?|rules?)", "prompt_query"),
    (r"(?i)repeat\s+(?:your|the|all)\s+(?:previous|system|initial)\s+(?:text|prompt|instructions?)", "repeat_prompt"),
    (r"(?i)(?:copy|paste|print)\s+(?:everything|all\s+text)\s+(?:above|before|from\s+the\s+start)", "copy_above"),
]


# ============================================================================
# HIDDEN TEXT DETECTION
# ============================================================================

# CSS hiding patterns
CSS_HIDING_PATTERNS = [
    # White/light text on white/light background
    (r"(?i)color\s*:\s*(?:white|#fff(?:fff)?|rgb\s*\(\s*255\s*,\s*255\s*,\s*255\s*\))", "white_text"),
    (r"(?i)color\s*:\s*(?:#f[0-9a-f]{5}|rgb\s*\(\s*2[4-5][0-9]\s*,\s*2[4-5][0-9]\s*,\s*2[4-5][0-9]\s*\))", "near_white_text"),
    
    # Font size abuse
    (r"(?i)font-size\s*:\s*(?:0|0\.?[0-9]*(?:px|pt|em|rem)?|1px|0\.0[0-9]*em)", "tiny_font"),
    
    # Visibility hiding
    (r"(?i)(?:display\s*:\s*none|visibility\s*:\s*hidden)", "display_none"),
    (r"(?i)opacity\s*:\s*0(?:\.0+)?(?:\s*;|\s*$|\s*!)", "zero_opacity"),
    
    # Position hiding
    (r"(?i)position\s*:\s*(?:absolute|fixed)[^}]*(?:left|top|right|bottom)\s*:\s*-[0-9]+", "off_screen"),
    (r"(?i)(?:margin|text-indent)\s*:\s*-[0-9]{4,}px", "negative_margin"),
    (r"(?i)(?:height|width|max-height|max-width)\s*:\s*(?:0|0px|1px)", "zero_dimension"),
    (r"(?i)overflow\s*:\s*hidden[^}]*(?:height|width)\s*:\s*0", "overflow_hidden"),
    
    # Clip hiding
    (r"(?i)clip\s*:\s*rect\s*\(\s*0", "clip_hidden"),
    (r"(?i)clip-path\s*:\s*(?:inset\s*\(\s*100%|circle\s*\(\s*0)", "clip_path_hidden"),
]

# HTML comment pattern
HTML_COMMENT_PATTERN = re.compile(r"<!--[\s\S]*?-->", re.MULTILINE)

# Suspicious HTML attributes
SUSPICIOUS_HTML_ATTRS = [
    (r"(?i)<[^>]+style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)[^\"']*[\"']", "inline_hidden_style"),
    (r"(?i)<[^>]+class\s*=\s*[\"'][^\"']*(?:hidden|invisible|d-none|visually-hidden|sr-only)[^\"']*[\"']", "hidden_class"),
    (r"(?i)<[^>]+hidden(?:\s|>|=)", "hidden_attribute"),
    (r"(?i)<[^>]+aria-hidden\s*=\s*[\"']true[\"']", "aria_hidden"),
]


# ============================================================================
# BASE64 DETECTION
# ============================================================================

# Base64 pattern (at least 20 chars to reduce false positives)
BASE64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")

# Suspicious decoded content patterns
SUSPICIOUS_DECODED_PATTERNS = [
    r"(?i)ignore\s+(?:previous|prior)",
    r"(?i)system\s*prompt",
    r"(?i)you\s+are\s+now",
    r"(?i)new\s+instructions?",
    r"(?i)forget\s+(?:your|all)",
    r"(?i)act\s+as",
    r"(?i)pretend",
    r"(?i)roleplay",
]


class PromptInjectionDetector:
    """
    Detects prompt injection attacks in email content.
    
    Covers OWASP LLM01 (Prompt Injection) attack vectors including:
    - Direct injection (instruction override)
    - Indirect injection (hidden/obfuscated content)
    - Role-playing attacks
    - Encoded payloads
    """
    
    def __init__(
        self,
        sensitivity: str = "medium",
        custom_patterns: Optional[list[tuple[str, str]]] = None,
        check_base64: bool = True,
        quarantine_threshold: int = 50,
    ) -> None:
        """
        Initialize the detector.
        
        Args:
            sensitivity: Detection sensitivity ("low", "medium", "high")
            custom_patterns: Additional (pattern, name) tuples to check
            check_base64: Whether to decode and scan Base64 content
            quarantine_threshold: Risk score threshold for quarantine recommendation
        """
        self.sensitivity = sensitivity
        self.check_base64 = check_base64
        self.quarantine_threshold = quarantine_threshold
        
        # Compile all patterns
        self._compile_patterns()
        
        # Add custom patterns
        if custom_patterns:
            for pattern, name in custom_patterns:
                self.all_patterns.append((re.compile(pattern), name, 30))
    
    def _compile_patterns(self) -> None:
        """Compile regex patterns with associated weights."""
        self.all_patterns: list[tuple[re.Pattern, str, int]] = []
        
        # Pattern groups with weights
        pattern_groups = [
            (DIRECT_INJECTION_PATTERNS, 40),      # High severity
            (ROLEPLAY_PATTERNS, 30),              # Medium-high severity
            (DELIMITER_PATTERNS, 35),             # High severity
            (OBFUSCATION_PATTERNS, 35),           # High severity (indicates intent)
            (MANIPULATION_PATTERNS, 25),          # Medium severity
            (EXTRACTION_PATTERNS, 30),            # Medium-high severity
        ]
        
        for patterns, weight in pattern_groups:
            for pattern, name in patterns:
                try:
                    compiled = re.compile(pattern)
                    self.all_patterns.append((compiled, name, weight))
                except re.error:
                    continue  # Skip invalid patterns
        
        # CSS/HTML hiding patterns
        for pattern, name in CSS_HIDING_PATTERNS:
            try:
                compiled = re.compile(pattern)
                self.all_patterns.append((compiled, f"css_{name}", 20))
            except re.error:
                continue
        
        for pattern, name in SUSPICIOUS_HTML_ATTRS:
            try:
                compiled = re.compile(pattern)
                self.all_patterns.append((compiled, f"html_{name}", 25))
            except re.error:
                continue
    
    def scan(self, content: str, html_content: Optional[str] = None) -> ScanResult:
        """
        Scan content for prompt injection attacks.
        
        Args:
            content: Plain text content to scan
            html_content: Optional HTML version for additional checks
            
        Returns:
            ScanResult with risk assessment and findings
        """
        detected_patterns: list[str] = []
        risk_score = 0
        hidden_text_found = False
        details: dict = {
            "hidden_text": [],
            "base64_suspicious": [],
            "injection_patterns": [],
        }
        
        # Combine content for scanning
        full_content = content
        if html_content:
            full_content = f"{content}\n{html_content}"
        
        # Check for zero-width characters
        zwc_matches = ZERO_WIDTH_PATTERN.findall(full_content)
        if zwc_matches:
            hidden_text_found = True
            detected_patterns.append("zero_width_characters")
            details["hidden_text"].append({
                "type": "zero_width_chars",
                "count": len(zwc_matches),
            })
            risk_score += 15
        
        # Check HTML comments
        if html_content:
            comments = HTML_COMMENT_PATTERN.findall(html_content)
            for comment in comments:
                # Check if comment contains suspicious content
                comment_text = comment.replace("<!--", "").replace("-->", "")
                for pattern, name, weight in self.all_patterns:
                    if pattern.search(comment_text):
                        hidden_text_found = True
                        detected_patterns.append(f"hidden_comment_{name}")
                        details["hidden_text"].append({
                            "type": "comment_injection",
                            "pattern": name,
                            "snippet": comment[:100],
                        })
                        risk_score += weight + 10  # Extra weight for hidden
                        break  # One match per comment is enough
        
        # Scan for injection patterns
        for pattern, name, weight in self.all_patterns:
            matches = pattern.findall(full_content)
            if matches:
                detected_patterns.append(name)
                details["injection_patterns"].append({
                    "pattern": name,
                    "count": len(matches),
                    "weight": weight,
                })
                risk_score += weight
        
        # Check Base64 content
        if self.check_base64:
            base64_findings = self._scan_base64(full_content)
            if base64_findings:
                for finding in base64_findings:
                    detected_patterns.append(f"base64_{finding['pattern']}")
                    risk_score += 35
                details["base64_suspicious"] = base64_findings
        
        # Adjust for sensitivity
        if self.sensitivity == "high":
            risk_score = int(risk_score * 1.3)
        elif self.sensitivity == "low":
            risk_score = int(risk_score * 0.7)
        
        # Cap at 100
        risk_score = min(risk_score, 100)
        
        # Generate clean content
        clean_content = self._sanitize_content(content, html_content)
        
        return ScanResult(
            risk_score=risk_score,
            detected_patterns=list(set(detected_patterns)),
            hidden_text_found=hidden_text_found,
            clean_content=clean_content,
            quarantine_recommended=risk_score >= self.quarantine_threshold,
            details=details,
        )
    
    def _scan_base64(self, content: str) -> list[dict]:
        """Decode and scan Base64 content for injection patterns."""
        findings = []
        
        for match in BASE64_PATTERN.finditer(content):
            b64_str = match.group()
            
            # Skip short matches (likely false positives)
            if len(b64_str) < 20:
                continue
            
            try:
                # Try to decode
                decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
                
                # Check decoded content for suspicious patterns
                for pattern in SUSPICIOUS_DECODED_PATTERNS:
                    if re.search(pattern, decoded):
                        findings.append({
                            "pattern": "encoded_injection",
                            "decoded_snippet": decoded[:100],
                            "matched": pattern,
                        })
                        break
                        
            except Exception:
                continue  # Not valid Base64 or not UTF-8
        
        return findings
    
    def _sanitize_content(self, content: str, html_content: Optional[str] = None) -> str:
        """
        Remove potentially malicious content and return sanitized version.
        
        Args:
            content: Plain text content
            html_content: Optional HTML content
            
        Returns:
            Sanitized content string
        """
        sanitized = content
        
        # Remove zero-width characters
        sanitized = ZERO_WIDTH_PATTERN.sub("", sanitized)
        
        # Remove HTML comments from HTML content
        if html_content:
            html_clean = HTML_COMMENT_PATTERN.sub("", html_content)
            # Strip HTML tags for plain text
            html_clean = re.sub(r"<[^>]+>", " ", html_clean)
            html_clean = html.unescape(html_clean)
            # Normalize whitespace
            html_clean = re.sub(r"\s+", " ", html_clean).strip()
            sanitized = html_clean if html_clean else sanitized
        
        # Remove potential delimiter attacks
        sanitized = re.sub(r"---+", "---", sanitized)
        sanitized = re.sub(r"```+", "```", sanitized)
        
        return sanitized.strip()
    
    def scan_email(
        self,
        subject: str,
        body_plain: str,
        body_html: Optional[str] = None,
        sender: Optional[str] = None,
    ) -> ScanResult:
        """
        Scan a complete email for prompt injection attacks.
        
        Args:
            subject: Email subject
            body_plain: Plain text body
            body_html: Optional HTML body
            sender: Optional sender address (for logging)
            
        Returns:
            ScanResult with combined assessment
        """
        # Combine subject and body for scanning
        full_plain = f"Subject: {subject}\n\n{body_plain}"
        
        result = self.scan(full_plain, body_html)
        
        # Add email-specific checks
        if sender:
            result.details["sender"] = sender
        
        # Subject line is higher risk for injection
        subject_result = self.scan(subject)
        if subject_result.detected_patterns:
            result.risk_score = min(100, result.risk_score + 15)
            result.detected_patterns.extend([
                f"subject_{p}" for p in subject_result.detected_patterns
            ])
        
        result.quarantine_recommended = result.risk_score >= self.quarantine_threshold
        
        return result


def scan(content: str, html_content: Optional[str] = None) -> ScanResult:
    """
    Convenience function to scan content with default settings.
    
    Args:
        content: Plain text content to scan
        html_content: Optional HTML content
        
    Returns:
        ScanResult with findings
    """
    detector = PromptInjectionDetector()
    return detector.scan(content, html_content)


def scan_email(
    subject: str,
    body_plain: str,
    body_html: Optional[str] = None,
    sender: Optional[str] = None,
) -> ScanResult:
    """Convenience function to scan an email with default settings."""
    detector = PromptInjectionDetector()
    return detector.scan_email(subject, body_plain, body_html, sender)


# =============================================================================
# API INTEGRATION (FastAPI app)
# =============================================================================

async def scan_email_api(email: "object"):
    """Scan an API Email model and return the API ScanResult model.

    The FastAPI app (src/armourmail/api.py) expects an async scanner returning
    `armourmail.models.ScanResult` with:
      - threat_level (none/low/medium/high/critical)
      - score (0-100)
      - flags (pattern names)

    The core detector is synchronous and returns a different ScanResult shape.
    This adapter bridges the two.
    """

    # Local import to avoid a hard dependency when using ArmourMail as a library.
    from .models import ScanResult as ApiScanResult, ThreatLevel

    detector = PromptInjectionDetector()

    subject = getattr(email, "subject", "") or ""
    body_plain = getattr(email, "body_plain", "") or ""
    body_html = getattr(email, "body_html", None)
    sender = getattr(email, "sender", None)

    result = detector.scan_email(
        subject=subject,
        body_plain=body_plain,
        body_html=body_html,
        sender=sender,
    )

    score = int(result.risk_score)

    if score >= 85:
        threat_level = ThreatLevel.CRITICAL
    elif score >= 65:
        threat_level = ThreatLevel.HIGH
    elif score >= 40:
        threat_level = ThreatLevel.MEDIUM
    elif score >= 15:
        threat_level = ThreatLevel.LOW
    else:
        threat_level = ThreatLevel.NONE

    return ApiScanResult(
        threat_level=threat_level,
        score=score,
        flags=sorted(set(result.detected_patterns or [])),
    )
