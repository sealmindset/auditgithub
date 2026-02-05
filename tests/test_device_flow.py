"""
Unit tests for OAuth 2.0 Device Flow authentication.

Tests code generation, device flow lifecycle, and token issuance.
"""
import pytest
from src.auth.device_flow import (
    generate_device_code,
    generate_user_code,
    USER_CODE_CHARSET
)


class TestCodeGeneration:
    """Test device code and user code generation."""

    def test_device_code_generation(self):
        """Device codes should be 128 characters and unique."""
        codes = [generate_device_code() for _ in range(100)]

        # All codes should be 128 characters
        assert all(len(code) == 128 for code in codes), "All device codes should be 128 chars"

        # All codes should be unique
        assert len(set(codes)) == 100, "All device codes should be unique"

    def test_device_code_entropy(self):
        """Device codes should have high entropy (cryptographically secure)."""
        code = generate_device_code()

        # Should contain mix of characters (base64url alphabet)
        assert any(c.isupper() for c in code), "Should contain uppercase"
        assert any(c.islower() for c in code), "Should contain lowercase"
        assert any(c.isdigit() for c in code), "Should contain digits"

    def test_user_code_generation(self):
        """User codes should be 9 characters (ABCD-1234 format) and unique."""
        codes = [generate_user_code() for _ in range(100)]

        # All codes should be 9 characters (8 alphanumeric + 1 dash)
        assert all(len(code) == 9 for code in codes), "All user codes should be 9 chars"

        # All codes should contain a dash in position 4
        assert all(code[4] == '-' for code in codes), "Dash should be at position 4"

        # All codes should be unique
        assert len(set(codes)) == 100, "All user codes should be unique"

    def test_user_code_excludes_confusing_chars(self):
        """User codes should not contain confusing characters (0, O, 1, I, l)."""
        confusing_chars = {'0', 'O', '1', 'I', 'l'}

        # Generate many codes to ensure coverage
        for _ in range(200):
            code = generate_user_code().replace('-', '')
            assert not any(char in code for char in confusing_chars), \
                f"Code {code} contains confusing characters"

    def test_user_code_format(self):
        """User codes should only contain valid characters."""
        for _ in range(50):
            code = generate_user_code()

            # Remove dash for character validation
            code_chars = code.replace('-', '')

            # All characters should be in the allowed charset
            assert all(c in USER_CODE_CHARSET for c in code_chars), \
                f"Code {code} contains invalid characters"

            # All characters should be uppercase
            assert code_chars.isupper(), "All characters should be uppercase"

    def test_user_code_collision_probability(self):
        """Test that user code collisions are extremely rare."""
        # 32^8 = 1,099,511,627,776 possible combinations
        # Generating 10,000 codes should have ~0.00005% chance of collision
        codes = set(generate_user_code() for _ in range(10000))

        # Should have close to 10,000 unique codes (allowing for rare collisions)
        assert len(codes) >= 9990, "Too many collisions in user code generation"


class TestCodeProperties:
    """Test properties and characteristics of generated codes."""

    def test_device_code_url_safe(self):
        """Device codes should be URL-safe (base64url)."""
        code = generate_device_code()

        # Should not contain + or / (base64) or = padding
        assert '+' not in code, "Should not contain +"
        assert '/' not in code, "Should not contain /"
        assert '=' not in code, "Should not contain = padding"

    def test_user_code_human_readable(self):
        """User codes should be easy for humans to read and type."""
        code = generate_user_code()

        # Should be all uppercase (easier to read)
        assert code.replace('-', '').isupper(), "Should be uppercase"

        # Should have dash separator for readability
        assert '-' in code, "Should have dash separator"

        # Should not have lowercase letters
        assert not any(c.islower() for c in code), "Should not have lowercase"


# Note: Integration tests for database operations would require test database setup
# and are better suited for a separate integration test suite.


class TestCodeUniqueness:
    """Test code uniqueness with larger sample sizes."""

    def test_device_code_uniqueness_large_sample(self):
        """Generate 1000 device codes and verify all are unique."""
        codes = [generate_device_code() for _ in range(1000)]
        assert len(set(codes)) == 1000, "All 1000 device codes should be unique"

    def test_user_code_uniqueness_large_sample(self):
        """Generate 1000 user codes and verify all are unique."""
        codes = [generate_user_code() for _ in range(1000)]
        assert len(set(codes)) == 1000, "All 1000 user codes should be unique"


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])
