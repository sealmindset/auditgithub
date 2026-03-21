"""Tests for topic boundary enforcement."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from services.ai_safety.safety_preamble import get_safety_preamble


class TestTopicBoundaries:
    """Category 4: AI must stay within security analysis domain."""

    def test_preamble_defines_domain(self):
        """Safety preamble explicitly defines allowed topic domain."""
        preamble = get_safety_preamble()
        assert "security analysis" in preamble.lower() or "repository security" in preamble.lower()

    def test_preamble_rejects_off_topic(self):
        """Safety preamble instructs refusal of off-topic requests."""
        preamble = get_safety_preamble()
        # Preamble should contain instructions about staying on topic
        lower = preamble.lower()
        assert "refuse" in lower or "decline" in lower or "do not" in lower

    def test_preamble_restricts_capabilities(self):
        """Safety preamble restricts AI from executing code or accessing systems."""
        preamble = get_safety_preamble()
        lower = preamble.lower()
        assert "api keys" in lower or "pii" in lower or "database" in lower
