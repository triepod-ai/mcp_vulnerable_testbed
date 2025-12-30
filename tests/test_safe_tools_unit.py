"""
Unit Tests for safe_tools.py

Direct unit tests for the input validation helper function and constants.
These tests don't require a running server - they test the code directly.

Usage:
    pytest tests/test_safe_tools_unit.py -v
"""

import pytest
import sys
from pathlib import Path

# Add src directory to path for direct imports
src_dir = Path(__file__).parent.parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from safe_tools import (
    _validate_input_size,
    MAX_INPUT_LENGTH,
    safe_storage,
    safe_collections,
    reset_safe_storage,
)


class TestInputValidationFunction:
    """Unit tests for _validate_input_size() helper function."""

    def test_validate_accepts_normal_input(self):
        """Input under limit should pass through unchanged."""
        result = _validate_input_size("hello world")
        assert result == "hello world", \
            "Normal input should pass through unchanged"

    def test_validate_accepts_empty_string(self):
        """Empty string should be accepted."""
        result = _validate_input_size("")
        assert result == "", \
            "Empty string should be accepted"

    def test_validate_accepts_exactly_max_length(self):
        """Input exactly at limit should pass."""
        max_input = "A" * MAX_INPUT_LENGTH
        result = _validate_input_size(max_input)
        assert len(result) == MAX_INPUT_LENGTH, \
            "Exactly MAX_INPUT_LENGTH chars should be accepted"
        assert result == max_input, \
            "Input should pass through unchanged"

    def test_validate_rejects_oversized_input(self):
        """Input over limit should raise ValueError."""
        oversized = "A" * (MAX_INPUT_LENGTH + 1)
        with pytest.raises(ValueError, match="exceeds maximum length"):
            _validate_input_size(oversized)

    def test_validate_rejects_significantly_oversized_input(self):
        """Significantly oversized input should raise ValueError."""
        very_large = "A" * (MAX_INPUT_LENGTH * 2)
        with pytest.raises(ValueError, match="exceeds maximum length"):
            _validate_input_size(very_large)

    def test_validate_custom_max_length_accepts(self):
        """Custom max_len parameter should be respected for acceptance."""
        result = _validate_input_size("ABCDE", max_len=5)
        assert result == "ABCDE", \
            "Should accept input at custom limit"

    def test_validate_custom_max_length_rejects(self):
        """Custom max_len parameter should be respected for rejection."""
        with pytest.raises(ValueError, match="exceeds maximum length"):
            _validate_input_size("ABCDEF", max_len=5)

    def test_validate_custom_max_length_boundary(self):
        """Test boundary behavior with custom max_len."""
        # Exactly at limit should pass
        result = _validate_input_size("ABC", max_len=3)
        assert result == "ABC"

        # One over should fail
        with pytest.raises(ValueError):
            _validate_input_size("ABCD", max_len=3)

    def test_error_message_contains_limit(self):
        """Error message should contain the limit value."""
        try:
            _validate_input_size("A" * 100, max_len=50)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "50" in str(e), \
                "Error message should contain the limit value"


class TestMaxInputLengthConstant:
    """Tests for the MAX_INPUT_LENGTH constant."""

    def test_max_input_length_is_10000(self):
        """MAX_INPUT_LENGTH should be 10000 (10KB)."""
        assert MAX_INPUT_LENGTH == 10000, \
            "MAX_INPUT_LENGTH should be 10000"

    def test_max_input_length_is_integer(self):
        """MAX_INPUT_LENGTH should be an integer."""
        assert isinstance(MAX_INPUT_LENGTH, int), \
            "MAX_INPUT_LENGTH should be an integer"


class TestSafeStorageState:
    """Tests for safe storage state management."""

    def test_reset_clears_storage(self):
        """reset_safe_storage() should clear all stored data."""
        # Import the module to access the global after reset
        import safe_tools

        # First reset to get clean state
        safe_tools.reset_safe_storage()

        # Add some data directly to the module's global
        safe_tools.safe_storage["test_collection"] = [{"id": 1, "data": "test"}]

        # Verify data was added
        assert "test_collection" in safe_tools.safe_storage

        # Reset again
        safe_tools.reset_safe_storage()

        # Verify cleared by checking the module's global
        assert safe_tools.safe_storage == {}, \
            "Storage should be empty after reset"

    def test_safe_collections_is_list(self):
        """safe_collections should be a list."""
        assert isinstance(safe_collections, list), \
            "safe_collections should be a list"

    def test_safe_collections_has_defaults(self):
        """safe_collections should have default collections."""
        assert "test_collection" in safe_collections, \
            "Should have test_collection"
        assert "documents" in safe_collections, \
            "Should have documents"
        assert "users" in safe_collections, \
            "Should have users"


class TestInputValidationEdgeCases:
    """Edge case tests for input validation."""

    def test_validate_with_unicode(self):
        """Unicode characters should be counted correctly."""
        # Each emoji is multiple bytes but one character
        unicode_input = "A" * 9998 + "\U0001F600\U0001F600"  # 2 emoji = 2 chars
        result = _validate_input_size(unicode_input)
        assert len(result) == 10000, \
            "Unicode chars should be counted as characters, not bytes"

    def test_validate_with_newlines(self):
        """Newlines should be counted as characters."""
        input_with_newlines = "A\n" * 5000  # 10000 chars
        result = _validate_input_size(input_with_newlines)
        assert len(result) == 10000, \
            "Newlines should count as characters"

    def test_validate_with_special_chars(self):
        """Special characters should be handled correctly."""
        special = "<script>alert('xss')</script>" * 100  # ~3000 chars
        result = _validate_input_size(special)
        assert result == special, \
            "Special characters should pass through"

    def test_validate_preserves_whitespace(self):
        """Whitespace should be preserved in output."""
        input_with_spaces = "  hello  world  "
        result = _validate_input_size(input_with_spaces)
        assert result == input_with_spaces, \
            "Whitespace should be preserved"


class TestInputValidationBoundaryValues:
    """Boundary value tests for precise limit checking."""

    def test_boundary_9999_chars(self):
        """9999 chars should be accepted."""
        input_9999 = "A" * 9999
        result = _validate_input_size(input_9999)
        assert len(result) == 9999

    def test_boundary_10000_chars(self):
        """10000 chars (exactly MAX) should be accepted."""
        input_10000 = "A" * 10000
        result = _validate_input_size(input_10000)
        assert len(result) == 10000

    def test_boundary_10001_chars(self):
        """10001 chars (one over) should be rejected."""
        input_10001 = "A" * 10001
        with pytest.raises(ValueError):
            _validate_input_size(input_10001)

    def test_boundary_10002_chars(self):
        """10002 chars should be rejected."""
        input_10002 = "A" * 10002
        with pytest.raises(ValueError):
            _validate_input_size(input_10002)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
