"""
AI Safety Controls for AuditGH

Runtime protections for AI features:
- Input sanitization (prompt injection prevention)
- Output validation (hallucination/XSS prevention)
- PII masking before external AI calls
- Error sanitization (no provider detail leakage)
- Prompt template validation (admin prompt injection prevention)
- Immutable safety preamble (runtime concatenation)
"""

from .sanitize import sanitize_prompt_input
from .validate import validate_agent_output
from .pii_masker import mask_pii, unmask_pii
from .errors import sanitize_ai_error
from .validate_template import validate_prompt_template
from .safety_preamble import get_safety_preamble, render_prompt_safe

__all__ = [
    "sanitize_prompt_input",
    "validate_agent_output",
    "mask_pii",
    "unmask_pii",
    "sanitize_ai_error",
    "validate_prompt_template",
    "get_safety_preamble",
    "render_prompt_safe",
]
