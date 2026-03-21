"""
PII Masking for AI Submissions

Replaces personally identifiable information (names, emails, phones, etc.)
with pseudonyms before sending data to external AI providers. Stores
a mapping so responses can be de-pseudonymized afterward.

Usage:
    from src.services.ai_safety.pii_masker import mask_pii, unmask_pii

    masked_text, mappings = mask_pii(original_text)
    # Send masked_text to AI provider
    # ...
    unmasked = unmask_pii(ai_response, mappings)
"""

import re
import logging
from typing import Dict, Tuple

logger = logging.getLogger(__name__)

# Email pattern
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")

# Phone patterns (US-centric but catches common formats)
PHONE_RE = re.compile(
    r"(?:\+?1[-.\s]?)?"
    r"(?:\(?\d{3}\)?[-.\s]?)"
    r"\d{3}[-.\s]?\d{4}"
)

# SSN pattern
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

# IP address
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# AWS access key pattern
AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")

# Generic API key / token patterns (long hex or base64 strings)
TOKEN_RE = re.compile(r"\b(?:ghp_|gho_|sk-|sk-ant-)[A-Za-z0-9_-]{20,}\b")


def mask_pii(text: str) -> Tuple[str, Dict[str, str]]:
    """
    Mask PII in text before sending to AI providers.

    Returns:
        (masked_text, mappings) where mappings maps pseudonyms back to originals
    """
    if not text:
        return text, {}

    mappings = {}
    masked = text
    counter = {"email": 0, "phone": 0, "ssn": 0, "ip": 0, "key": 0, "token": 0}

    # Mask tokens/keys first (most specific)
    for match in TOKEN_RE.finditer(masked):
        original = match.group(0)
        if original not in mappings.values():
            counter["token"] += 1
            pseudo = f"[TOKEN-{counter['token']}]"
            mappings[pseudo] = original
            masked = masked.replace(original, pseudo, 1)

    for match in AWS_KEY_RE.finditer(masked):
        original = match.group(0)
        if original not in mappings.values():
            counter["key"] += 1
            pseudo = f"[AWS-KEY-{counter['key']}]"
            mappings[pseudo] = original
            masked = masked.replace(original, pseudo, 1)

    # Mask SSNs
    for match in SSN_RE.finditer(masked):
        original = match.group(0)
        if original not in mappings.values():
            counter["ssn"] += 1
            pseudo = f"[SSN-{counter['ssn']}]"
            mappings[pseudo] = original
            masked = masked.replace(original, pseudo, 1)

    # Mask emails
    for match in EMAIL_RE.finditer(masked):
        original = match.group(0)
        if original not in mappings.values():
            counter["email"] += 1
            pseudo = f"[EMAIL-{counter['email']}]"
            mappings[pseudo] = original
            masked = masked.replace(original, pseudo, 1)

    # Mask phone numbers
    for match in PHONE_RE.finditer(masked):
        original = match.group(0)
        if original not in mappings.values():
            counter["phone"] += 1
            pseudo = f"[PHONE-{counter['phone']}]"
            mappings[pseudo] = original
            masked = masked.replace(original, pseudo, 1)

    # Mask IPs
    for match in IP_RE.finditer(masked):
        original = match.group(0)
        # Skip common non-PII IPs
        if original in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
            continue
        if original not in mappings.values():
            counter["ip"] += 1
            pseudo = f"[IP-{counter['ip']}]"
            mappings[pseudo] = original
            masked = masked.replace(original, pseudo, 1)

    if mappings:
        logger.info(f"PII masking: replaced {len(mappings)} item(s)")

    return masked, mappings


def unmask_pii(text: str, mappings: Dict[str, str]) -> str:
    """
    Restore masked PII in AI response using the mapping from mask_pii().
    """
    if not mappings or not text:
        return text

    result = text
    for pseudo, original in mappings.items():
        result = result.replace(pseudo, original)

    return result
