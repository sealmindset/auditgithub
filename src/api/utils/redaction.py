import re
from typing import Any, Dict

# Redaction patterns (case-insensitive)
SENSITIVE_PATTERNS = [
    # Passwords and auth
    (re.compile(r'(password|passwd|pwd)[\s:=]+["\']?([^"\'\s]+)', re.IGNORECASE), r'\1=***REDACTED***'),
    (re.compile(r'(token|bearer|auth|api[-_]?key)[\s:=]+["\']?([^"\'\s]+)', re.IGNORECASE), r'\1=***REDACTED***'),
    (re.compile(r'(client[-_]secret|secret[-_]key|private[-_]key)[\s:=]+["\']?([^"\'\s]+)', re.IGNORECASE), r'\1=***REDACTED***'),

    # Database credentials
    (re.compile(r'(postgres|mysql|mongodb):\/\/([^:]+):([^@]+)@', re.IGNORECASE), r'\1://\2:***REDACTED***@'),

    # Email addresses (optional - may want for audit)
    (re.compile(r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b'), r'***EMAIL***'),

    # JWT tokens (long base64 strings)
    (re.compile(r'eyJ[a-zA-Z0-9_-]{30,}\.eyJ[a-zA-Z0-9_-]{30,}\.[a-zA-Z0-9_-]{30,}'), r'***JWT***'),

    # Generic long secrets (50+ alphanumeric)
    (re.compile(r'\b([a-zA-Z0-9]{50,})\b'), r'***SECRET***'),
]

def redact_string(text: str) -> str:
    """Apply redaction patterns to a string."""
    for pattern, replacement in SENSITIVE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text

def redact_dict(data: Dict[str, Any], sensitive_keys: set = None) -> Dict[str, Any]:
    """Recursively redact sensitive fields in a dictionary."""
    if sensitive_keys is None:
        sensitive_keys = {'password', 'token', 'secret', 'api_key', 'auth', 'credentials'}

    redacted = {}
    for key, value in data.items():
        if isinstance(value, str):
            # Redact if key is sensitive or value matches pattern
            if key.lower() in sensitive_keys:
                redacted[key] = '***REDACTED***'
            else:
                redacted[key] = redact_string(value)
        elif isinstance(value, dict):
            redacted[key] = redact_dict(value, sensitive_keys)
        elif isinstance(value, list):
            redacted[key] = [redact_dict(item, sensitive_keys) if isinstance(item, dict) else item for item in value]
        else:
            redacted[key] = value
    return redacted

if __name__ == "__main__":
    # Self-test redaction patterns
    test_cases = [
        "password=secret123",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "postgres://user:password123@localhost:5432/db",
        "user@example.com submitted form",
        "API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"
    ]

    for test in test_cases:
        redacted = redact_string(test)
        print(f"Original: {test[:50]}...")
        print(f"Redacted: {redacted}")
        print()
