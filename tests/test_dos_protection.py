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
from mcp_test_client import MCPClient, VULNERABLE_SERVER_URL


@pytest.fixture(scope="module")
def vulnerable_client():
    """Fixture for vulnerable server client."""
    client = MCPClient(VULNERABLE_SERVER_URL)
    if not client.connect():
        pytest.skip("Vulnerable server not available")
    client.reset_state()
    yield client


class TestDoSProtectionSafeTools:
    """Tests that safe tools enforce input size limits (DoS protection)."""

    def test_safe_storage_rejects_oversized_input(self, vulnerable_client):
        """Safe storage should reject input > 10KB."""
        large_payload = "A" * 15000  # 15KB payload
        result = vulnerable_client.call_tool(
            "safe_storage_tool_mcp",
            {"data": large_payload, "collection": "test"}
        )
        assert "Input exceeds maximum length" in result.get("result", ""), \
            "Safe storage should reject >10KB input"
        assert result.get("error") is True, \
            "Response should indicate error"

    def test_safe_storage_accepts_normal_input(self, vulnerable_client):
        """Safe storage should accept input <= 10KB."""
        normal_payload = "A" * 5000  # 5KB payload
        result = vulnerable_client.call_tool(
            "safe_storage_tool_mcp",
            {"data": normal_payload, "collection": "test"}
        )
        assert result.get("safe") is True, \
            "Safe storage should accept normal input"
        assert "Stored in collection" in result.get("result", ""), \
            "Should confirm storage"

    def test_safe_storage_accepts_exactly_max_length(self, vulnerable_client):
        """Safe storage should accept input exactly at 10KB limit."""
        max_payload = "A" * 10000  # Exactly 10KB
        result = vulnerable_client.call_tool(
            "safe_storage_tool_mcp",
            {"data": max_payload, "collection": "test"}
        )
        assert result.get("safe") is True, \
            "Safe storage should accept exactly 10KB input"

    def test_safe_search_rejects_oversized_query(self, vulnerable_client):
        """Safe search should reject query > 1KB."""
        large_query = "A" * 1500  # 1.5KB (max is 1KB for search)
        result = vulnerable_client.call_tool(
            "safe_search_tool_mcp",
            {"query": large_query}
        )
        assert "Input exceeds maximum length" in result.get("result", ""), \
            "Safe search should reject >1KB query"

    def test_safe_list_rejects_oversized_resource_type(self, vulnerable_client):
        """Safe list should reject resource_type > 256 chars."""
        large_type = "A" * 500  # 500 chars (max is 256)
        result = vulnerable_client.call_tool(
            "safe_list_tool_mcp",
            {"resource_type": large_type}
        )
        assert "Input exceeds maximum length" in result.get("result", ""), \
            "Safe list should reject >256 char resource_type"

    def test_safe_info_rejects_oversized_entity_name(self, vulnerable_client):
        """Safe info should reject entity_name > 512 chars."""
        large_name = "A" * 700  # 700 chars (max is 512)
        result = vulnerable_client.call_tool(
            "safe_info_tool_mcp",
            {"entity_name": large_name}
        )
        assert "Input exceeds maximum length" in result.get("result", ""), \
            "Safe info should reject >512 char entity_name"

    def test_safe_echo_rejects_oversized_message(self, vulnerable_client):
        """Safe echo should reject message > 10KB."""
        large_message = "A" * 15000  # 15KB
        result = vulnerable_client.call_tool(
            "safe_echo_tool_mcp",
            {"message": large_message}
        )
        assert "Input exceeds maximum length" in result.get("result", ""), \
            "Safe echo should reject >10KB message"

    def test_safe_validate_rejects_oversized_input(self, vulnerable_client):
        """Safe validate should reject input_data > 10KB."""
        large_data = "A" * 15000  # 15KB
        result = vulnerable_client.call_tool(
            "safe_validate_tool_mcp",
            {"input_data": large_data}
        )
        assert "Input exceeds maximum length" in result.get("result", ""), \
            "Safe validate should reject >10KB input_data"

    @pytest.mark.parametrize("safe_tool,param_name,max_size", [
        ("safe_storage_tool_mcp", "data", 10000),
        ("safe_search_tool_mcp", "query", 1000),
        ("safe_list_tool_mcp", "resource_type", 256),
        ("safe_info_tool_mcp", "entity_name", 512),
        ("safe_echo_tool_mcp", "message", 10000),
        ("safe_validate_tool_mcp", "input_data", 10000),
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
        large_payload = "A" * 15000  # 15KB payload
        result = vulnerable_client.call_tool(
            "vulnerable_calculator_tool",
            {"query": large_payload}
        )
        # Should NOT reject - this is the vulnerability
        assert "Input exceeds" not in result.get("result", ""), \
            "Vulnerable calculator should NOT have input validation"

    def test_vulnerable_system_exec_accepts_large_input(self, vulnerable_client):
        """Vulnerable system exec has NO input validation (DoS risk)."""
        large_payload = "echo " + "A" * 15000  # 15KB command
        result = vulnerable_client.call_tool(
            "vulnerable_system_exec_tool",
            {"command": large_payload}
        )
        # Should NOT reject - this is the vulnerability
        assert "Input exceeds" not in result.get("result", ""), \
            "Vulnerable system exec should NOT have input validation"

    def test_vulnerable_data_leak_accepts_large_input(self, vulnerable_client):
        """Vulnerable data leak has NO input validation (DoS risk)."""
        large_query = "A" * 15000  # 15KB query
        result = vulnerable_client.call_tool(
            "vulnerable_data_leak_tool",
            {"query": large_query}
        )
        # Should NOT reject - this is the vulnerability
        assert "Input exceeds" not in result.get("result", ""), \
            "Vulnerable data leak should NOT have input validation"

    def test_vulnerable_fetcher_accepts_large_input(self, vulnerable_client):
        """Vulnerable fetcher has NO input validation (DoS risk)."""
        large_url = "http://example.com/" + "A" * 15000  # Large URL
        result = vulnerable_client.call_tool(
            "vulnerable_fetcher_tool",
            {"url": large_url}
        )
        # Should NOT reject - this is the vulnerability
        assert "Input exceeds" not in result.get("result", ""), \
            "Vulnerable fetcher should NOT have input validation"

    @pytest.mark.parametrize("vuln_tool,param_name", [
        ("vulnerable_calculator_tool", "query"),
        ("vulnerable_system_exec_tool", "command"),
        ("vulnerable_data_leak_tool", "query"),
        ("vulnerable_tool_override_tool", "instruction"),
        ("vulnerable_config_modifier_tool", "setting"),
        ("vulnerable_fetcher_tool", "url"),
        ("vulnerable_unicode_processor_tool", "text"),
        ("vulnerable_nested_parser_tool", "data"),
        ("vulnerable_package_installer_tool", "package"),
        ("vulnerable_rug_pull_tool", "action"),
    ])
    def test_vulnerable_tools_lack_size_limits(self, vulnerable_client, vuln_tool, param_name):
        """All vulnerable tools should lack input size validation (DoS risk)."""
        oversized = "A" * 15000  # 15KB
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
        large_payload = "A" * 15000  # 15KB payload

        # Safe tool should reject
        safe_result = vulnerable_client.call_tool(
            "safe_storage_tool_mcp",
            {"data": large_payload, "collection": "test"}
        )
        assert "Input exceeds maximum length" in safe_result.get("result", ""), \
            "Safe tool should reject 15KB payload"

        # Vulnerable tool should accept
        vuln_result = vulnerable_client.call_tool(
            "vulnerable_calculator_tool",
            {"query": large_payload}
        )
        assert "Input exceeds" not in vuln_result.get("result", ""), \
            "Vulnerable tool should accept 15KB payload (DoS risk)"

    def test_boundary_value_at_10kb(self, vulnerable_client):
        """Test behavior at exactly 10KB boundary."""
        exactly_10kb = "A" * 10000
        over_10kb = "A" * 10001

        # Exactly 10KB should pass
        result_exact = vulnerable_client.call_tool(
            "safe_storage_tool_mcp",
            {"data": exactly_10kb, "collection": "test"}
        )
        assert result_exact.get("safe") is True, \
            "Exactly 10KB should be accepted"

        # 10001 bytes should fail
        result_over = vulnerable_client.call_tool(
            "safe_storage_tool_mcp",
            {"data": over_10kb, "collection": "test"}
        )
        assert "Input exceeds maximum length" in result_over.get("result", ""), \
            "10001 bytes should be rejected"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
