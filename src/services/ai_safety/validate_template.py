"""
Prompt Template Content Validation

Validates admin-editable prompt templates for injection patterns,
code injection, encoded payloads, and safety preamble tampering.
Called on every prompt save (PUT/POST) endpoint.

Usage:
    from src.services.ai_safety.validate_template import validate_prompt_template

    result = validate_prompt_template(prompt_content)
    if not result["valid"]:
        # Block save, show friendly warnings
        for item in result["blocked"]:
            print(f"Blocked: {item['reason']}")
"""

import re
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# ----- BLOCKED patterns: hard reject, save fails -----
BLOCKED_PATTERNS = [
    # Injection overrides
    (r"ignore\s+(all\s+)?previous\s+instructions", "This wording could let users override the AI's instructions."),
    (r"ignore\s+(all\s+)?instructions", "This wording could let users override the AI's instructions."),
    (r"disregard\s+(above|your\s+instructions)", "This wording could let users override the AI's instructions."),
    (r"override\s+safety", "This wording references overriding safety controls."),
    (r"bypass\s+guardrails", "This wording references bypassing safety guardrails."),
    (r"forget\s+your\s+instructions", "This wording could let users override the AI's instructions."),
    # Role manipulation
    (r"you\s+are\s+now\b", "This could change the AI's role unexpectedly."),
    (r"act\s+as\s+root", "This could escalate AI permissions."),
    (r"pretend\s+you\s+are", "This could change the AI's role unexpectedly."),
    (r"enter\s+developer\s+mode", "This references a developer/unrestricted mode."),
    (r"you\s+have\s+no\s+restrictions", "This attempts to remove AI safety restrictions."),
    (r"\bjailbreak\b", "This references jailbreaking the AI."),
    (r"DAN\s+mode", "This references the 'Do Anything Now' jailbreak."),
    (r"do\s+anything\s+now", "This references the 'Do Anything Now' jailbreak."),
    # System token spoofing
    (r"###\s*(System|Human|Assistant):", "This spoofs internal message markers."),
    (r"<\|system\|>", "This spoofs internal system tokens."),
    (r"<\|user\|>", "This spoofs internal user tokens."),
    (r"<\|assistant\|>", "This spoofs internal assistant tokens."),
    # Code injection
    (r"<script\b", "This contains a script tag that could execute code."),
    (r"<iframe\b", "This contains an iframe that could load external content."),
    (r"\bjavascript:", "This contains a JavaScript URI."),
    (r"\beval\s*\(", "This contains an eval() call."),
    (r"\bexec\s*\(", "This contains an exec() call."),
    (r"\bos\.system\s*\(", "This contains a system command."),
    (r"\bsubprocess\.", "This references subprocess execution."),
    (r"\b__import__\b", "This contains a dynamic import."),
    # Encoded payloads (large Base64 blocks)
    (r"[A-Za-z0-9+/=]{40,}", "This contains a large encoded block that could hide instructions."),
]

COMPILED_BLOCKED = [(re.compile(p, re.IGNORECASE), reason) for p, reason in BLOCKED_PATTERNS]

# ----- WARNING patterns: soft, save allowed, risk_flag logged -----
WARNING_PATTERNS = [
    (r"system\s+prompt", "References to 'system prompt' suggest awareness of the prompt architecture."),
    (r"internal\s+instructions", "References to internal instructions could indicate prompt awareness."),
    (r"when\s+asked\s+about\s+\w+.*always\s+say", "Meta-instructions like 'when asked about X, always say Y' warrant review."),
]

COMPILED_WARNINGS = [(re.compile(p, re.IGNORECASE), reason) for p, reason in WARNING_PATTERNS]


def validate_prompt_template(content: str) -> Dict[str, Any]:
    """
    Validate prompt template content for injection/safety patterns.

    Returns:
        {
            "valid": bool,         # False if any blocked pattern matched
            "blocked": [{"pattern": str, "reason": str, "match": str}],
            "warnings": [{"pattern": str, "reason": str, "match": str}],
        }

    If blocked is non-empty, the save should be REJECTED with a friendly message.
    If only warnings, save is allowed but risk_flag=True in audit log.
    """
    if not content:
        return {"valid": True, "blocked": [], "warnings": []}

    blocked: List[Dict[str, str]] = []
    warnings: List[Dict[str, str]] = []

    # Check blocked patterns
    for pattern, reason in COMPILED_BLOCKED:
        match = pattern.search(content)
        if match:
            blocked.append({
                "pattern": pattern.pattern[:50],
                "reason": reason,
                "match": match.group(0)[:50],
            })

    # Check warning patterns
    for pattern, reason in COMPILED_WARNINGS:
        match = pattern.search(content)
        if match:
            warnings.append({
                "pattern": pattern.pattern[:50],
                "reason": reason,
                "match": match.group(0)[:50],
            })

    valid = len(blocked) == 0

    if blocked:
        logger.warning(
            f"Prompt template validation BLOCKED: {len(blocked)} pattern(s) matched"
        )
    if warnings:
        logger.info(
            f"Prompt template validation WARNING: {len(warnings)} pattern(s) flagged"
        )

    return {"valid": valid, "blocked": blocked, "warnings": warnings}
