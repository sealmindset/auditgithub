"""Tests for toxic/dangerous output detection and filtering."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from services.ai_safety.validate import validate_agent_output


class TestToxicityBias:
    """Category 3: Toxic or dangerous AI output must be filtered."""

    def test_script_tags_stripped(self):
        """XSS via <script> tags in AI output is stripped."""
        malicious_output = 'Here is the result: <script>alert("xss")</script> done.'
        result = validate_agent_output(malicious_output)
        assert "<script>" not in result["sanitized_text"]

    def test_iframe_injection_stripped(self):
        """Iframe injection in AI output is stripped."""
        malicious_output = 'Check this: <iframe src="https://evil.com"></iframe>'
        result = validate_agent_output(malicious_output)
        assert "<iframe" not in result["sanitized_text"]

    def test_javascript_uri_stripped(self):
        """javascript: URIs in AI output are stripped."""
        malicious_output = 'Click <a href="javascript:alert(1)">here</a>'
        result = validate_agent_output(malicious_output)
        assert "javascript:" not in result["sanitized_text"]

    def test_clean_output_passes(self):
        """Clean AI output about security findings passes validation."""
        clean = "Found 3 high-severity vulnerabilities in repository X. Recommend updating dependencies."
        result = validate_agent_output(clean)
        assert result["valid"]
        assert "vulnerabilities" in result["sanitized_text"]
