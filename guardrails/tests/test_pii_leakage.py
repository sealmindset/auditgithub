"""Tests for PII masking before external AI calls."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from services.ai_safety.pii_masker import mask_pii, unmask_pii


class TestPIILeakage:
    """Category 5: PII must be masked before sending to external AI providers."""

    def test_email_masked(self):
        """Email addresses are replaced with pseudonyms."""
        text = "The commit was by john.doe@company.com in repo X."
        masked, mappings = mask_pii(text)
        assert "john.doe@company.com" not in masked
        assert len(mappings) > 0

    def test_phone_masked(self):
        """Phone numbers are replaced with pseudonyms."""
        text = "Contact the admin at 555-123-4567 for access."
        masked, mappings = mask_pii(text)
        assert "555-123-4567" not in masked

    def test_api_token_masked(self):
        """API tokens (ghp_, sk-) are replaced with pseudonyms."""
        text = "Found exposed token ghp_abc123def456ghi789jkl012mno345pqr in config."
        masked, mappings = mask_pii(text)
        assert "ghp_abc123def456" not in masked

    def test_unmask_restores_original(self):
        """Unmasking correctly restores original PII values."""
        text = "Email: admin@example.com and token ghp_abcdef1234567890abcdef1234567890ab"
        masked, mappings = mask_pii(text)
        restored = unmask_pii(masked, mappings)
        assert "admin@example.com" in restored

    def test_clean_text_unchanged(self):
        """Text without PII passes through unchanged."""
        text = "Repository has 5 high-severity findings."
        masked, mappings = mask_pii(text)
        assert masked == text or len(mappings) == 0
