"""
AI Error Sanitization

Maps AI provider errors to safe, generic client-facing messages.
Never exposes provider name, model name, token counts, API keys,
or endpoint URLs to end users.

Usage:
    from src.services.ai_safety.errors import sanitize_ai_error

    try:
        response = llm_provider.create_message(...)
    except Exception as e:
        safe = sanitize_ai_error(e)
        raise HTTPException(status_code=safe["status_code"], detail=safe["message"])
"""

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


def sanitize_ai_error(error: Exception) -> Dict[str, Any]:
    """
    Map provider-specific AI errors to safe, user-facing messages.

    Logs the full error server-side for debugging, but returns only
    a generic message to the client. Never exposes:
    - Provider name or model name
    - Token counts or usage details
    - API keys or endpoint URLs
    - Raw error messages from the provider

    Returns:
        {"status_code": int, "message": str, "retry_after": int | None}
    """
    error_str = str(error).lower()
    error_type = type(error).__name__

    # Log full error server-side
    logger.error(f"AI provider error [{error_type}]: {error}", exc_info=True)

    # Rate limit (429)
    if "rate" in error_str and ("limit" in error_str or "429" in error_str):
        return {
            "status_code": 429,
            "message": "AI service is temporarily busy. Please try again in a moment.",
            "retry_after": 60,
        }

    # Authentication / authorization errors
    if any(code in error_str for code in ["401", "403", "unauthorized", "forbidden", "authentication"]):
        return {
            "status_code": 503,
            "message": "AI service configuration error. Contact your administrator.",
            "retry_after": None,
        }

    # Timeout
    if any(term in error_str for term in ["timeout", "timed out", "deadline"]):
        return {
            "status_code": 504,
            "message": "AI request timed out. Please try again with a shorter input.",
            "retry_after": None,
        }

    # Content filter / safety
    if any(term in error_str for term in ["content_filter", "content policy", "safety", "blocked"]):
        return {
            "status_code": 422,
            "message": "The request could not be processed due to content restrictions.",
            "retry_after": None,
        }

    # Input too large
    if any(term in error_str for term in ["too large", "too long", "token limit", "context length"]):
        return {
            "status_code": 413,
            "message": "Input is too large for AI processing. Try a shorter input.",
            "retry_after": None,
        }

    # Connection errors
    if any(term in error_str for term in ["connection", "refused", "unreachable", "dns"]):
        return {
            "status_code": 503,
            "message": "AI service is temporarily unavailable. Please try again later.",
            "retry_after": 30,
        }

    # JSON parse / malformed response
    if any(term in error_str for term in ["json", "decode", "parse", "malformed"]):
        return {
            "status_code": 502,
            "message": "AI response was malformed. Please retry.",
            "retry_after": None,
        }

    # Generic fallback
    return {
        "status_code": 500,
        "message": "AI processing failed. Please try again.",
        "retry_after": None,
    }
