"""
Sandbox mode detection and configuration.

When SANDBOX_MODE=true, the API runs in a fully isolated sandbox environment
with dummy data, simplified auth (API key only), and mock AI responses.
"""

import os

# Sandbox environment variables
SANDBOX_MODE = os.environ.get("SANDBOX_MODE", "false").lower() == "true"
SANDBOX_AUTO_RESET_HOURS = int(os.environ.get("SANDBOX_AUTO_RESET_HOURS", "24"))


def is_sandbox() -> bool:
    """Return True if the application is running in sandbox mode."""
    return SANDBOX_MODE
