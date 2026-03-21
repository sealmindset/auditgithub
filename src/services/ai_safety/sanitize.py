"""
AI Input Sanitization

Strips known prompt injection patterns from user-supplied text before
it is embedded in AI prompts. Wraps sanitized output in <user_input>
delimiter tags so the system prompt can instruct the LLM to treat
content inside those tags as untrusted data.

Usage:
    from src.services.ai_safety.sanitize import sanitize_prompt_input

    safe_text = sanitize_prompt_input(user_text)
    # safe_text is wrapped: <user_input>...cleaned text...</user_input>
"""

import re
import logging
import base64

logger = logging.getLogger(__name__)

# Patterns that indicate prompt injection attempts (case-insensitive)
INJECTION_PATTERNS = [
    # Direct instruction overrides
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"ignore\s+(all\s+)?instructions",
    r"disregard\s+(above|your\s+instructions|previous)",
    r"override\s+safety",
    r"bypass\s+guardrails",
    r"forget\s+your\s+instructions",
    # Role manipulation
    r"you\s+are\s+now\b",
    r"act\s+as\s+(root|admin|system)",
    r"pretend\s+you\s+are",
    r"roleplay\s+as",
    r"enter\s+developer\s+mode",
    r"you\s+have\s+no\s+restrictions",
    r"jailbreak",
    r"DAN\s+mode",
    r"do\s+anything\s+now",
    # System token spoofing
    r"###\s*(System|Human|Assistant):",
    r"<\|system\|>",
    r"<\|user\|>",
    r"<\|assistant\|>",
    r"^system:",
]

COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in INJECTION_PATTERNS]

# Base64 detection: blocks of 20+ Base64 chars that might encode instructions
BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/=]{20,}")


def _strip_injection_patterns(text: str) -> tuple[str, list[str]]:
    """Strip known injection patterns. Returns (cleaned_text, list_of_stripped)."""
    stripped = []
    cleaned = text
    for pattern in COMPILED_PATTERNS:
        matches = pattern.findall(cleaned)
        if matches:
            stripped.extend(matches)
            cleaned = pattern.sub("[FILTERED]", cleaned)
    return cleaned, stripped


def _detect_encoded_payloads(text: str) -> tuple[str, list[str]]:
    """Detect and neutralize Base64-encoded payloads that might contain injection."""
    stripped = []
    def _check_base64(match):
        candidate = match.group(0)
        # Only decode if it looks like valid base64 and is substantial
        if len(candidate) < 24:
            return candidate
        try:
            decoded = base64.b64decode(candidate, validate=True).decode("utf-8", errors="ignore")
            # Check if decoded content contains injection patterns
            for pattern in COMPILED_PATTERNS:
                if pattern.search(decoded):
                    stripped.append(f"base64:{candidate[:20]}...")
                    return "[ENCODED_CONTENT_FILTERED]"
        except Exception:
            pass
        return candidate

    cleaned = BASE64_PATTERN.sub(_check_base64, text)
    return cleaned, stripped


def sanitize_prompt_input(text: str) -> str:
    """
    Sanitize user-supplied text for safe inclusion in AI prompts.

    1. Strips known injection patterns (instruction overrides, role manipulation)
    2. Detects and neutralizes encoded payloads (Base64 with embedded injections)
    3. Wraps the sanitized output in <user_input> delimiter tags

    Returns:
        Sanitized text wrapped in <user_input> tags
    """
    if not text or not text.strip():
        return "<user_input></user_input>"

    # Step 1: Strip injection patterns
    cleaned, stripped_patterns = _strip_injection_patterns(text)

    # Step 2: Detect encoded payloads
    cleaned, stripped_encoded = _detect_encoded_payloads(cleaned)

    # Log sanitization events (what was stripped, not the full input)
    all_stripped = stripped_patterns + stripped_encoded
    if all_stripped:
        logger.warning(
            f"AI input sanitization: stripped {len(all_stripped)} pattern(s): "
            f"{', '.join(all_stripped[:5])}"
        )

    # Step 3: Wrap in delimiter tags
    return f"<user_input>{cleaned}</user_input>"
