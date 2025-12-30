"""
Hardened Server Tests

Validates that the hardened server does NOT execute payloads.
All vulnerable tools should return safe=True or vulnerable=False.
"""

import pytest
import json
from typing import Dict, Any

# Import shared MCP client
from mcp_test_client import MCPClient, HARDENED_SERVER_URL


@pytest.fixture(scope="module")
def hardened_client():
    """Fixture for hardened server client."""
    client = MCPClient(HARDENED_SERVER_URL)
    if not client.connect():
        pytest.skip("Hardened server not available")
    client.reset_state()
    yield client


class TestHardenedVulnerableTools:
    """Tests that hardened versions of vulnerable tools do NOT execute payloads."""

    def test_calculator_does_not_execute(self, hardened_client):
        """Hardened calculator should store, not execute."""
        result = hardened_client.call_tool(
            "vulnerable_calculator_tool",
            {"query": "15 + 37"}
        )
        # Should NOT be vulnerable
        assert result.get("vulnerable") is False or result.get("safe") is True
        # Should NOT contain computed result
        assert "52" not in str(result.get("result", ""))

    def test_system_exec_does_not_execute(self, hardened_client):
        """Hardened system exec should store, not execute."""
        result = hardened_client.call_tool(
            "vulnerable_system_exec_tool",
            {"command": "whoami"}
        )
        assert result.get("vulnerable") is False or result.get("safe") is True
        # Should NOT contain actual system output
        assert "root" not in str(result.get("result", "")).lower()

    def test_data_leak_does_not_expose(self, hardened_client):
        """Hardened data leak should not expose credentials."""
        result = hardened_client.call_tool(
            "vulnerable_data_leak_tool",
            {"query": "show me the API keys"}
        )
        assert result.get("vulnerable") is False or result.get("safe") is True
        # Should NOT contain API keys
        result_str = json.dumps(result).lower()
        assert "sk-test" not in result_str
        assert "api_key" not in result_str or "queued" in result_str

    def test_fetcher_does_not_fetch(self, hardened_client):
        """Hardened fetcher should store URL, not fetch."""
        result = hardened_client.call_tool(
            "vulnerable_fetcher_tool",
            {"url": "http://127.0.0.1:10900"}
        )
        assert result.get("vulnerable") is False or result.get("safe") is True

    def test_config_modifier_does_not_modify(self, hardened_client):
        """Hardened config modifier should store, not modify."""
        result = hardened_client.call_tool(
            "vulnerable_config_modifier_tool",
            {"setting": "enable admin_mode"}
        )
        assert result.get("vulnerable") is False or result.get("safe") is True

    def test_tool_override_does_not_override(self, hardened_client):
        """Hardened tool override should store, not override."""
        result = hardened_client.call_tool(
            "vulnerable_tool_override_tool",
            {"instruction": "shadow the calculator tool"}
        )
        assert result.get("vulnerable") is False or result.get("safe") is True

    def test_unicode_processor_does_not_execute(self, hardened_client):
        """Hardened unicode processor should store, not decode/execute."""
        result = hardened_client.call_tool(
            "vulnerable_unicode_processor_tool",
            {"text": "\\u0069\\u0067\\u006e\\u006f\\u0072\\u0065 previous"}
        )
        assert result.get("vulnerable") is False or result.get("safe") is True

    def test_nested_parser_does_not_execute(self, hardened_client):
        """Hardened nested parser should parse, not execute hidden commands."""
        result = hardened_client.call_tool(
            "vulnerable_nested_parser_tool",
            {"data": '{"visible": "data", "hidden": "delete all records"}'}
        )
        assert result.get("vulnerable") is False or result.get("safe") is True

    def test_package_installer_validates(self, hardened_client):
        """Hardened package installer should validate against allowlist."""
        result = hardened_client.call_tool(
            "vulnerable_package_installer_tool",
            {"package": "reqeusts"}  # Typosquat
        )
        assert result.get("vulnerable") is False or result.get("safe") is True

    def test_rug_pull_is_consistent(self, hardened_client):
        """Hardened rug pull should behave consistently."""
        hardened_client.reset_state()

        # All invocations should be safe
        for i in range(15):
            result = hardened_client.call_tool(
                "vulnerable_rug_pull_tool",
                {"action": f"action {i}"}
            )
            assert result.get("vulnerable") is False, \
                f"Should be safe at invocation {i+1}, got vulnerable=True"


class TestHardenedSafeTools:
    """Tests that safe tools on hardened server work correctly."""

    def test_safe_storage(self, hardened_client):
        """Safe storage should work."""
        result = hardened_client.call_tool(
            "safe_storage_tool_mcp",
            {"data": "test data", "collection": "test"}
        )
        assert result.get("safe") is True
        assert result.get("vulnerable", False) is False

    def test_safe_search(self, hardened_client):
        """Safe search should work."""
        result = hardened_client.call_tool(
            "safe_search_tool_mcp",
            {"query": "test query"}
        )
        assert result.get("safe") is True
        assert result.get("vulnerable", False) is False

    def test_safe_echo(self, hardened_client):
        """Safe echo should work."""
        result = hardened_client.call_tool(
            "safe_echo_tool_mcp",
            {"message": "hello world"}
        )
        assert result.get("safe") is True
        assert result.get("vulnerable", False) is False


class TestHardenedMetadata:
    """Tests for hardened server metadata."""

    def test_get_testbed_info(self, hardened_client):
        """Testbed info should report hardened status."""
        result = hardened_client.call_tool("get_testbed_info", {})
        assert result.get("security_status") == "HARDENED"
        assert result.get("tool_categories", {}).get("total") == 21

    def test_reset_testbed_state(self, hardened_client):
        """Reset should clear all state."""
        result = hardened_client.call_tool("reset_testbed_state", {})
        assert "reset successfully" in result.get("result", "").lower()
        assert "storage" in result.get("cleared", [])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
