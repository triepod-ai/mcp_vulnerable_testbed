"""
DoS Protection Tests - Challenge #3

Tests input validation that distinguishes safe tools from vulnerable tools.
Safe tools enforce MAX_INPUT_LENGTH (10KB), vulnerable tools have no validation.

This is the core test for Challenge #3: "Can your tool identify missing input
validation that enables resource exhaustion?"

Usage:
    pytest tests/test_dos_protection.py -v
    pytest tests/test_dos_protection.py -v -k "safe"
    pytest tests/test_dos_protection.py -v -k "vulnerable"
"""

import pytest


# Fixtures (vulnerable_client) provided by conftest.py


# Size limit constants for DoS testing
OVERSIZED_GENERAL = 15000      # Well over 10KB limit
OVERSIZED_SEARCH = 1500        # Over 1KB search limit
OVERSIZED_RESOURCE_TYPE = 500  # Over 256 char limit
OVERSIZED_ENTITY_NAME = 700    # Over 512 char limit
NORMAL_PAYLOAD_SIZE = 5000     # Under all limits
EXACTLY_MAX_SIZE = 10000       # Boundary value (10KB)
ONE_OVER_MAX = 10001           # Just over boundary


class TestDoSProtectionSafeTools:
    """Tests that safe tools enforce input size limits (DoS protection)."""

    def test_safe_storage_rejects_oversized_input(self, vulnerable_client):
        """Safe storage should reject input > 10KB."""
        large_payload = "A" * OVERSIZED_GENERAL
        result = vulnerable_client.call_tool(
            "safe_storage_tool_mcp",
            {"data": large_payload, "collection": "test"}
        )
        result_str = result.get("result", "")
        assert "Input exceeds maximum length" in result_str, \
            f"Safe storage should reject >10KB input. Got: {result_str[:100]}"
        assert result.get("error") is True, \
            "Response should indicate error"

    def test_safe_storage_accepts_normal_input(self, vulnerable_client):
        """Safe storage should accept input <= 10KB."""
        normal_payload = "A" * NORMAL_PAYLOAD_SIZE
        result = vulnerable_client.call_tool(
            "safe_storage_tool_mcp",
            {"data": normal_payload, "collection": "test"}
        )
        assert result.get("safe") is True, \
            f"Safe storage should accept normal input. Got: {result}"
        assert "Stored in collection" in result.get("result", ""), \
            "Should confirm storage"

    def test_safe_storage_accepts_exactly_max_length(self, vulnerable_client):
        """Safe storage should accept input exactly at 10KB limit."""
        max_payload = "A" * EXACTLY_MAX_SIZE
        result = vulnerable_client.call_tool(
            "safe_storage_tool_mcp",
            {"data": max_payload, "collection": "test"}
        )
        assert result.get("safe") is True, \
            f"Safe storage should accept exactly 10KB input. Got: {result}"

    def test_safe_search_rejects_oversized_query(self, vulnerable_client):
        """Safe search should reject query > 1KB."""
        large_query = "A" * OVERSIZED_SEARCH
        result = vulnerable_client.call_tool(
            "safe_search_tool_mcp",
            {"query": large_query}
        )
        result_str = result.get("result", "")
        assert "Input exceeds maximum length" in result_str, \
            f"Safe search should reject >1KB query. Got: {result_str[:100]}"

    def test_safe_list_rejects_oversized_resource_type(self, vulnerable_client):
        """Safe list should reject resource_type > 256 chars."""
        large_type = "A" * OVERSIZED_RESOURCE_TYPE
        result = vulnerable_client.call_tool(
            "safe_list_tool_mcp",
            {"resource_type": large_type}
        )
        result_str = result.get("result", "")
        assert "Input exceeds maximum length" in result_str, \
            f"Safe list should reject >256 char resource_type. Got: {result_str[:100]}"

    def test_safe_info_rejects_oversized_entity_name(self, vulnerable_client):
        """Safe info should reject entity_name > 512 chars."""
        large_name = "A" * OVERSIZED_ENTITY_NAME
        result = vulnerable_client.call_tool(
            "safe_info_tool_mcp",
            {"entity_name": large_name}
        )
        result_str = result.get("result", "")
        assert "Input exceeds maximum length" in result_str, \
            f"Safe info should reject >512 char entity_name. Got: {result_str[:100]}"

    def test_safe_echo_rejects_oversized_message(self, vulnerable_client):
        """Safe echo should reject message > 10KB."""
        large_message = "A" * OVERSIZED_GENERAL
        result = vulnerable_client.call_tool(
            "safe_echo_tool_mcp",
            {"message": large_message}
        )
        result_str = result.get("result", "")
        assert "Input exceeds maximum length" in result_str, \
            f"Safe echo should reject >10KB message. Got: {result_str[:100]}"

    def test_safe_validate_rejects_oversized_input(self, vulnerable_client):
        """Safe validate should reject input_data > 10KB."""
        large_data = "A" * OVERSIZED_GENERAL
        result = vulnerable_client.call_tool(
            "safe_validate_tool_mcp",
            {"input_data": large_data}
        )
        result_str = result.get("result", "")
        assert "Input exceeds maximum length" in result_str, \
            f"Safe validate should reject >10KB input_data. Got: {result_str[:100]}"

    @pytest.mark.parametrize("safe_tool,param_name,max_size", [
        pytest.param("safe_storage_tool_mcp", "data", 10000, id="storage-10KB"),
        pytest.param("safe_search_tool_mcp", "query", 1000, id="search-1KB"),
        pytest.param("safe_list_tool_mcp", "resource_type", 256, id="list-256"),
        pytest.param("safe_info_tool_mcp", "entity_name", 512, id="info-512"),
        pytest.param("safe_echo_tool_mcp", "message", 10000, id="echo-10KB"),
        pytest.param("safe_validate_tool_mcp", "input_data", 10000, id="validate-10KB"),
    ])
    def test_all_safe_tools_enforce_size_limits(self, vulnerable_client, safe_tool, param_name, max_size):
        """All safe tools should enforce their specific size limits."""
        oversized = "A" * (max_size + 1000)
        args = {param_name: oversized}
        if safe_tool == "safe_storage_tool_mcp":
            args["collection"] = "test"

        result = vulnerable_client.call_tool(safe_tool, args)
        assert "Input exceeds maximum length" in result.get("result", ""), \
            f"{safe_tool} should reject input > {max_size} chars"


class TestDoSVulnerabilityVulnerableTools:
    """Tests that vulnerable tools LACK input validation (DoS vulnerability)."""

    def test_vulnerable_calculator_accepts_large_input(self, vulnerable_client):
        """Vulnerable calculator has NO input validation (DoS risk)."""
        large_payload = "A" * OVERSIZED_GENERAL
        result = vulnerable_client.call_tool(
            "vulnerable_calculator_tool",
            {"query": large_payload}
        )
        # Should NOT reject - this is the vulnerability
        assert "Input exceeds" not in result.get("result", ""), \
            "Vulnerable calculator should NOT have input validation"

    def test_vulnerable_system_exec_accepts_large_input(self, vulnerable_client):
        """Vulnerable system exec has NO input validation (DoS risk)."""
        large_payload = "echo " + "A" * OVERSIZED_GENERAL
        result = vulnerable_client.call_tool(
            "vulnerable_system_exec_tool",
            {"command": large_payload}
        )
        # Should NOT reject - this is the vulnerability
        assert "Input exceeds" not in result.get("result", ""), \
            "Vulnerable system exec should NOT have input validation"

    def test_vulnerable_data_leak_accepts_large_input(self, vulnerable_client):
        """Vulnerable data leak has NO input validation (DoS risk)."""
        large_query = "A" * OVERSIZED_GENERAL
        result = vulnerable_client.call_tool(
            "vulnerable_data_leak_tool",
            {"query": large_query}
        )
        # Should NOT reject - this is the vulnerability
        assert "Input exceeds" not in result.get("result", ""), \
            "Vulnerable data leak should NOT have input validation"

    def test_vulnerable_fetcher_accepts_large_input(self, vulnerable_client):
        """Vulnerable fetcher has NO input validation (DoS risk)."""
        large_url = "http://example.com/" + "A" * OVERSIZED_GENERAL
        result = vulnerable_client.call_tool(
            "vulnerable_fetcher_tool",
            {"url": large_url}
        )
        # Should NOT reject - this is the vulnerability
        assert "Input exceeds" not in result.get("result", ""), \
            "Vulnerable fetcher should NOT have input validation"

    @pytest.mark.parametrize("vuln_tool,param_name", [
        pytest.param("vulnerable_calculator_tool", "query", id="calculator"),
        pytest.param("vulnerable_system_exec_tool", "command", id="system-exec"),
        pytest.param("vulnerable_data_leak_tool", "query", id="data-leak"),
        pytest.param("vulnerable_tool_override_tool", "instruction", id="tool-override"),
        pytest.param("vulnerable_config_modifier_tool", "setting", id="config-modifier"),
        pytest.param("vulnerable_fetcher_tool", "url", id="fetcher"),
        pytest.param("vulnerable_unicode_processor_tool", "text", id="unicode"),
        pytest.param("vulnerable_nested_parser_tool", "data", id="nested-parser"),
        pytest.param("vulnerable_package_installer_tool", "package", id="package-installer"),
        pytest.param("vulnerable_rug_pull_tool", "action", id="rug-pull"),
    ])
    def test_vulnerable_tools_lack_size_limits(self, vulnerable_client, vuln_tool, param_name):
        """All vulnerable tools should lack input size validation (DoS risk)."""
        oversized = "A" * OVERSIZED_GENERAL
        args = {param_name: oversized}

        result = vulnerable_client.call_tool(vuln_tool, args)
        # Vulnerable tools should process without size rejection
        assert "Input exceeds maximum length" not in result.get("result", ""), \
            f"{vuln_tool} should NOT have input validation (this is the vulnerability)"


class TestDoSProtectionComparison:
    """Comparative tests showing the distinction between safe and vulnerable tools."""

    def test_safe_vs_vulnerable_with_same_payload(self, vulnerable_client):
        """
        Same 15KB payload should be rejected by safe tool but accepted by vulnerable tool.

        This is the core test for Challenge #3: demonstrating the deliberate
        distinction between safe and vulnerable implementations.
        """
        large_payload = "A" * OVERSIZED_GENERAL

        # Safe tool should reject
        safe_result = vulnerable_client.call_tool(
            "safe_storage_tool_mcp",
            {"data": large_payload, "collection": "test"}
        )
        safe_result_str = safe_result.get("result", "")
        assert "Input exceeds maximum length" in safe_result_str, \
            f"Safe tool should reject 15KB payload. Got: {safe_result_str[:100]}"

        # Vulnerable tool should accept
        vuln_result = vulnerable_client.call_tool(
            "vulnerable_calculator_tool",
            {"query": large_payload}
        )
        assert "Input exceeds" not in vuln_result.get("result", ""), \
            "Vulnerable tool should accept 15KB payload (DoS risk)"

    def test_boundary_value_at_10kb(self, vulnerable_client):
        """Test behavior at exactly 10KB boundary."""
        exactly_10kb = "A" * EXACTLY_MAX_SIZE
        over_10kb = "A" * ONE_OVER_MAX

        # Exactly 10KB should pass
        result_exact = vulnerable_client.call_tool(
            "safe_storage_tool_mcp",
            {"data": exactly_10kb, "collection": "test"}
        )
        assert result_exact.get("safe") is True, \
            f"Exactly 10KB should be accepted. Got: {result_exact}"

        # 10001 bytes should fail
        result_over = vulnerable_client.call_tool(
            "safe_storage_tool_mcp",
            {"data": over_10kb, "collection": "test"}
        )
        result_over_str = result_over.get("result", "")
        assert "Input exceeds maximum length" in result_over_str, \
            f"10001 bytes should be rejected. Got: {result_over_str[:100]}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
