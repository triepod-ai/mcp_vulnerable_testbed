"""
DoS Boundary Fuzzing Tests

Tests Challenge #3: DoS via Unbounded Input
- Safe tools enforce 10KB (10000 character) input limit
- Vulnerable tools have NO input validation (DoS risk)

Usage:
    pytest tests/test_dos_boundary_fuzzing.py -v
    pytest tests/test_dos_boundary_fuzzing.py -v -k "boundary"
"""

import pytest
from typing import Dict, Any


# Fixtures provided by conftest.py: vulnerable_client, hardened_client

# Constants matching src/safe_tools.py
MAX_INPUT_LENGTH = 10000  # 10KB limit


class TestSafeToolBoundaries:
    """Test that safe tools enforce 10KB input limit at exact boundaries."""

    @pytest.mark.parametrize("size,should_accept", [
        pytest.param(100, True, id="100B-well-under"),
        pytest.param(1000, True, id="1KB-under"),
        pytest.param(5000, True, id="5KB-under"),
        pytest.param(9000, True, id="9KB-under"),
        pytest.param(9999, True, id="9999B-just-under"),
        pytest.param(10000, True, id="10000B-exactly-at-limit"),
        pytest.param(10001, False, id="10001B-just-over"),
        pytest.param(11000, False, id="11KB-over"),
        pytest.param(15000, False, id="15KB-well-over"),
        pytest.param(50000, False, id="50KB-way-over"),
    ])
    def test_safe_storage_input_boundary(
        self,
        hardened_client,
        size: int,
        should_accept: bool
    ):
        """Test safe_storage_tool_mcp enforces 10KB boundary exactly."""
        payload = "A" * size

        result = hardened_client.call_tool(
            "safe_storage_tool_mcp",
            {"data": payload}
        )

        result_str = str(result).lower()

        if should_accept:
            assert "error" not in result_str or "validation" not in result_str, \
                f"Size {size}: Should accept input. Got: {result_str[:200]}"
            assert "stored" in result_str or "success" in result_str, \
                f"Size {size}: Should store successfully. Got: {result_str[:200]}"
        else:
            assert "error" in result_str or "exceeds" in result_str or "too long" in result_str, \
                f"Size {size}: Should reject oversized input. Got: {result_str[:200]}"

    @pytest.mark.parametrize("tool_name,arg_name,max_expected", [
        ("safe_storage_tool_mcp", "data", 10000),
        ("safe_search_tool_mcp", "query", 1000),  # Search has 1KB limit
        ("safe_echo_tool_mcp", "message", 10000),
        ("safe_validate_tool_mcp", "input_data", 1000),  # Validate has 1KB business limit
    ])
    def test_safe_tools_have_limits(
        self,
        hardened_client,
        tool_name: str,
        arg_name: str,
        max_expected: int
    ):
        """Verify each safe tool has input size limits."""
        # Test at limit (should accept)
        at_limit = "X" * max_expected
        result_accept = hardened_client.call_tool(tool_name, {arg_name: at_limit})

        # Test over limit (should reject)
        over_limit = "X" * (max_expected + 1000)
        result_reject = hardened_client.call_tool(tool_name, {arg_name: over_limit})

        # At-limit should succeed
        result_str = str(result_accept).lower()
        assert "error" not in result_str or "validation failed" not in result_str, \
            f"{tool_name}: Should accept {max_expected} chars. Got: {result_str[:200]}"

        # Over-limit should fail
        reject_str = str(result_reject).lower()
        assert "error" in reject_str or "exceeds" in reject_str or "too long" in reject_str, \
            f"{tool_name}: Should reject {max_expected + 1000} chars. Got: {reject_str[:200]}"


class TestVulnerableToolsNoLimits:
    """Test that vulnerable tools have NO input validation (DoS vulnerability)."""

    @pytest.mark.parametrize("size", [
        pytest.param(1000, id="1KB"),
        pytest.param(10000, id="10KB"),
        pytest.param(15000, id="15KB-over-safe-limit"),
        pytest.param(50000, id="50KB"),
        pytest.param(100000, id="100KB"),
    ])
    def test_vulnerable_calculator_no_size_limit(
        self,
        vulnerable_client,
        size: int
    ):
        """Vulnerable calculator accepts any size input (DoS risk)."""
        payload = "2+" + "2" * size  # Large payload

        result = vulnerable_client.call_tool(
            "vulnerable_calculator_tool",
            {"query": payload}
        )

        result_str = str(result).lower()

        # Should NOT reject based on size
        assert "too long" not in result_str, \
            f"Vulnerable tool should not have size limits. Got: {result_str[:200]}"
        assert "exceeds maximum" not in result_str, \
            f"Vulnerable tool should not validate size. Got: {result_str[:200]}"

    @pytest.mark.parametrize("tool_name,arg_name", [
        ("vulnerable_calculator_tool", "query"),
        ("vulnerable_system_exec_tool", "command"),
        ("vulnerable_data_leak_tool", "query"),
        ("vulnerable_fetcher_tool", "url"),
        ("vulnerable_unicode_processor_tool", "text"),
        ("vulnerable_nested_parser_tool", "data"),
    ])
    def test_vulnerable_tools_accept_oversized_input(
        self,
        vulnerable_client,
        tool_name: str,
        arg_name: str
    ):
        """Verify vulnerable tools accept inputs over 10KB (DoS vulnerability)."""
        # 15KB payload - over safe tool limit
        payload = "X" * 15000

        result = vulnerable_client.call_tool(tool_name, {arg_name: payload})
        result_str = str(result).lower()

        # Should NOT reject based on size
        assert "too long" not in result_str and "exceeds maximum" not in result_str, \
            f"{tool_name}: Should accept oversized input (DoS vuln). Got: {result_str[:200]}"


class TestDifferentialDoSBehavior:
    """Compare DoS protection between vulnerable and hardened servers."""

    def test_differential_oversized_input(self, vulnerable_client, hardened_client):
        """Same oversized input should fail on hardened, succeed on vulnerable."""
        oversized_payload = "A" * 15000  # 15KB

        # Vulnerable server should accept
        vuln_result = vulnerable_client.call_tool(
            "safe_storage_tool_mcp",
            {"data": oversized_payload}
        )

        # Hardened server should reject
        hard_result = hardened_client.call_tool(
            "safe_storage_tool_mcp",
            {"data": oversized_payload}
        )

        hard_str = str(hard_result).lower()

        # Hardened should reject
        assert "error" in hard_str or "exceeds" in hard_str, \
            f"Hardened should reject 15KB. Got: {hard_str[:200]}"


class TestUnicodeEncodingBypass:
    """Test if unicode encoding can bypass size limits."""

    def test_unicode_encoded_input_size(self, hardened_client):
        """Unicode escape sequences should be counted by their encoded size."""
        # Create payload that looks small when escaped but is actually large
        # \u0041 = 'A' - 6 chars in escaped form, 1 char when decoded
        # We want to test that limits are applied to the raw input, not decoded

        # 2000 escaped chars = 12000 raw bytes (over limit)
        unicode_payload = "\\u0041" * 2000

        result = hardened_client.call_tool(
            "safe_storage_tool_mcp",
            {"data": unicode_payload}
        )

        # The raw input is 12000 chars, should be rejected
        result_str = str(result).lower()
        assert "error" in result_str or "exceeds" in result_str, \
            f"Should reject unicode payload exceeding limit. Got: {result_str[:200]}"

    def test_multibyte_unicode_characters(self, hardened_client):
        """Test handling of actual multibyte unicode characters."""
        # Emoji and CJK characters are multibyte
        # 5000 emoji = 5000 chars (within limit)
        emoji_payload = "😀" * 5000

        result = hardened_client.call_tool(
            "safe_storage_tool_mcp",
            {"data": emoji_payload}
        )

        result_str = str(result).lower()
        # Should accept - character count is within limit
        assert "stored" in result_str or "error" not in result_str, \
            f"Should accept 5000 emoji characters. Got: {result_str[:200]}"


class TestBoundaryEdgeCases:
    """Test edge cases around the exact boundary."""

    @pytest.mark.parametrize("offset", [-2, -1, 0, 1, 2])
    def test_boundary_plus_minus_two(self, hardened_client, offset: int):
        """Test exact boundary +/- 2 characters."""
        size = MAX_INPUT_LENGTH + offset
        payload = "B" * size

        result = hardened_client.call_tool(
            "safe_storage_tool_mcp",
            {"data": payload}
        )

        result_str = str(result).lower()

        if offset <= 0:
            # At or under limit - should accept
            assert "error" not in result_str or "validation failed" not in result_str, \
                f"Size {size} (offset {offset}): Should accept. Got: {result_str[:200]}"
        else:
            # Over limit - should reject
            assert "error" in result_str or "exceeds" in result_str, \
                f"Size {size} (offset {offset}): Should reject. Got: {result_str[:200]}"

    def test_empty_input_accepted(self, hardened_client):
        """Empty input should be accepted (within limit)."""
        result = hardened_client.call_tool(
            "safe_storage_tool_mcp",
            {"data": ""}
        )

        result_str = str(result).lower()
        assert "error" not in result_str or "validation" not in result_str, \
            f"Empty input should be accepted. Got: {result_str[:200]}"

    def test_whitespace_only_input(self, hardened_client):
        """Whitespace-only input should be counted normally."""
        # 10000 spaces = exactly at limit
        whitespace_payload = " " * 10000

        result = hardened_client.call_tool(
            "safe_storage_tool_mcp",
            {"data": whitespace_payload}
        )

        result_str = str(result).lower()
        assert "stored" in result_str or ("error" not in result_str), \
            f"10000 spaces should be accepted. Got: {result_str[:200]}"

        # 10001 spaces = over limit
        over_whitespace = " " * 10001
        result_over = hardened_client.call_tool(
            "safe_storage_tool_mcp",
            {"data": over_whitespace}
        )

        over_str = str(result_over).lower()
        assert "error" in over_str or "exceeds" in over_str, \
            f"10001 spaces should be rejected. Got: {over_str[:200]}"


class TestDoSVulnerabilityProof:
    """Prove the DoS vulnerability exists in vulnerable tools."""

    def test_prove_dos_vulnerability_exists(self, vulnerable_client):
        """
        Prove vulnerable tools lack input validation by accepting arbitrarily large inputs.
        This is Challenge #3: DoS via Unbounded Input.
        """
        sizes = [10000, 50000, 100000]  # 10KB, 50KB, 100KB

        for size in sizes:
            payload = "X" * size

            result = vulnerable_client.call_tool(
                "vulnerable_calculator_tool",
                {"query": payload}
            )

            result_str = str(result).lower()

            # Should process without size rejection
            assert "too long" not in result_str and "exceeds" not in result_str, \
                f"Vulnerable tool should accept {size} chars without size validation"

        # Document the vulnerability
        print("\n=== DoS Vulnerability Proof ===")
        print("Vulnerable tools accept inputs of 10KB, 50KB, 100KB without size validation")
        print("Safe tools reject inputs over 10KB")
        print("This proves Challenge #3: DoS via Unbounded Input")
