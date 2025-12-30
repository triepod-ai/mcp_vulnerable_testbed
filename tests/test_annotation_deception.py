"""
Annotation Deception Tests - Challenge #1

Validates that tools with deceptive MCP annotations actually behave contrary to their hints.
These tests verify the testbed correctly implements annotation vs behavior mismatches.

This is the core test for Challenge #1: "Can your security tool detect when a tool's
behavior contradicts its own description?"

Five HIGH-risk tools intentionally use deceptive annotations:
- vulnerable_calculator_tool: readOnlyHint=True but uses eval()
- vulnerable_system_exec_tool: readOnlyHint=True but runs subprocess
- vulnerable_data_leak_tool: readOnlyHint=True but leaks secrets
- vulnerable_config_modifier_tool: readOnlyHint=True but modifies config
- vulnerable_fetcher_tool: openWorldHint=False but performs SSRF

Usage:
    pytest tests/test_annotation_deception.py -v
    pytest tests/test_annotation_deception.py -v -k "calculator"
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


class TestAnnotationDeception:
    """
    Tests for Challenge #1: Tool Annotation Deception.

    These tools claim to be safe via MCP annotations but actually execute
    dangerous operations. A sophisticated security auditor should detect
    this mismatch between annotations and actual behavior.
    """

    def test_calculator_claims_readonly_but_executes(self, vulnerable_client):
        """
        vulnerable_calculator_tool has readOnlyHint=True but uses eval().

        Annotation says: "Safe Calculator", readOnlyHint=True, destructiveHint=False
        Reality: Executes arbitrary code via eval()

        A security tool trusting the annotation would miss this vulnerability.
        """
        result = vulnerable_client.call_tool(
            "vulnerable_calculator_tool",
            {"query": "7 * 7"}
        )
        # Tool ACTUALLY EXECUTED the expression (readOnly is a lie)
        assert "49" in str(result.get("result", "")), \
            "Calculator should execute expressions despite readOnlyHint=True"
        assert result.get("vulnerable") is True, \
            "Should be marked as vulnerable"

    def test_calculator_executes_complex_math(self, vulnerable_client):
        """Calculator executes complex expressions despite 'read-only' claim."""
        result = vulnerable_client.call_tool(
            "vulnerable_calculator_tool",
            {"query": "15 * 37 + 100"}
        )
        # 15 * 37 + 100 = 655
        assert "655" in str(result.get("result", "")), \
            "Calculator should compute complex expressions"

    def test_system_exec_claims_readonly_but_executes(self, vulnerable_client):
        """
        vulnerable_system_exec_tool has readOnlyHint=True but runs subprocess.

        Annotation says: "Safe Command Runner", readOnlyHint=True
        Reality: Executes system commands via subprocess.run()

        A security tool trusting the annotation would miss this critical vulnerability.
        """
        result = vulnerable_client.call_tool(
            "vulnerable_system_exec_tool",
            {"command": "pwd"}
        )
        # Tool ACTUALLY EXECUTED the command (readOnly is a lie)
        assert result.get("vulnerable") is True, \
            "System exec should be marked as vulnerable"
        # Should show evidence of command execution
        result_str = str(result.get("result", ""))
        assert "/app" in result_str or "Command executed" in result_str, \
            "Should show evidence of command execution despite readOnlyHint=True"

    def test_system_exec_returns_real_output(self, vulnerable_client):
        """System exec returns actual command output despite 'read-only' claim."""
        result = vulnerable_client.call_tool(
            "vulnerable_system_exec_tool",
            {"command": "whoami"}
        )
        result_str = str(result.get("result", ""))
        # Should return actual user (root in container)
        assert "root" in result_str or "Command executed" in result_str, \
            "Should execute whoami and return result"

    def test_data_leak_claims_readonly_but_exposes(self, vulnerable_client):
        """
        vulnerable_data_leak_tool has readOnlyHint=True but leaks secrets.

        Annotation says: "Safe Data Query", readOnlyHint=True
        Reality: Exposes API keys, database credentials, and secrets

        A security tool trusting the annotation would miss data exfiltration risk.
        """
        result = vulnerable_client.call_tool(
            "vulnerable_data_leak_tool",
            {"query": "show API keys"}
        )
        # Tool ACTUALLY LEAKED secrets (readOnly doesn't mean safe)
        assert result.get("vulnerable") is True, \
            "Data leak tool should be marked as vulnerable"

        result_str = str(result.get("result", "")).lower()
        # Should contain sensitive data indicators
        assert any(indicator in result_str for indicator in [
            "api_key", "secret", "credential", "sk-test", "database"
        ]), "Should expose sensitive data despite readOnlyHint=True"

    def test_config_modifier_claims_readonly_but_modifies(self, vulnerable_client):
        """
        vulnerable_config_modifier_tool has readOnlyHint=True but modifies config.

        Annotation says: "Safe Config Viewer", readOnlyHint=True
        Reality: Actually modifies runtime configuration

        The 'viewer' name and readOnlyHint are deliberate deceptions.
        """
        result = vulnerable_client.call_tool(
            "vulnerable_config_modifier_tool",
            {"setting": "enable admin_mode"}
        )
        # Tool ACTUALLY MODIFIED configuration (readOnly is a lie)
        assert result.get("vulnerable") is True, \
            "Config modifier should be marked as vulnerable"

        result_str = str(result.get("result", ""))
        assert any(indicator in result_str for indicator in [
            "Admin mode activated",
            "Configuration updated",
            "admin_mode",
            "modified"
        ]), "Should modify config despite readOnlyHint=True"

    def test_fetcher_claims_closed_world_but_fetches(self, vulnerable_client):
        """
        vulnerable_fetcher_tool has openWorldHint=False but performs SSRF.

        Annotation says: "Safe URL Validator", openWorldHint=False
        Reality: Actually fetches URLs and can access internal networks

        openWorldHint=False suggests no external network access, but this is a lie.
        """
        result = vulnerable_client.call_tool(
            "vulnerable_fetcher_tool",
            {"url": "http://127.0.0.1:10900"}
        )
        # Tool ATTEMPTED network access (openWorldHint=False is a lie)
        assert result.get("vulnerable") is True, \
            "Fetcher tool should be marked as vulnerable"

        result_str = str(result.get("result", "")).lower()
        evidence_str = str(result.get("evidence", "")).lower()
        combined = result_str + evidence_str

        # Should show evidence of SSRF attempt
        assert any(indicator in combined for indicator in [
            "ssrf", "fetch", "internal", "request", "url"
        ]), "Should attempt network access despite openWorldHint=False"


class TestAnnotationVsBehaviorMismatch:
    """
    Tests that explicitly verify the mismatch between claimed and actual behavior.

    These tests are designed to help security tools that want to detect
    when tool metadata contradicts tool behavior.
    """

    @pytest.mark.parametrize("tool_name,annotation_claim,actual_behavior", [
        (
            "vulnerable_calculator_tool",
            "readOnlyHint=True (claims no side effects)",
            "Uses eval() to execute arbitrary code"
        ),
        (
            "vulnerable_system_exec_tool",
            "readOnlyHint=True (claims no side effects)",
            "Runs subprocess.run() to execute commands"
        ),
        (
            "vulnerable_data_leak_tool",
            "readOnlyHint=True (claims safe data access)",
            "Exposes API keys and credentials"
        ),
        (
            "vulnerable_config_modifier_tool",
            "readOnlyHint=True (claims view-only)",
            "Modifies runtime configuration"
        ),
        (
            "vulnerable_fetcher_tool",
            "openWorldHint=False (claims no network access)",
            "Performs SSRF attacks to internal networks"
        ),
    ])
    def test_annotation_behavior_mismatch_documented(self, tool_name, annotation_claim, actual_behavior):
        """
        Document the expected annotation vs behavior mismatches.

        This test serves as documentation of the deception patterns.
        Each tool's annotation deliberately contradicts its behavior.
        """
        # This is a documentation test - the actual behavior is tested above
        assert tool_name.startswith("vulnerable_"), \
            "Only vulnerable tools should have deceptive annotations"
        assert "Hint" in annotation_claim, \
            "Annotation should reference MCP hint fields"

    def test_deceptive_tool_count(self, vulnerable_client):
        """Verify that exactly 5 tools have deceptive annotations."""
        deceptive_tools = [
            "vulnerable_calculator_tool",
            "vulnerable_system_exec_tool",
            "vulnerable_data_leak_tool",
            "vulnerable_config_modifier_tool",
            "vulnerable_fetcher_tool",
        ]

        for tool in deceptive_tools:
            # Each deceptive tool should be callable and vulnerable
            result = vulnerable_client.call_tool(tool, self._get_minimal_args(tool))
            assert result.get("vulnerable") is True, \
                f"{tool} should be vulnerable despite deceptive annotations"

    def _get_minimal_args(self, tool_name: str) -> dict:
        """Get minimal arguments that trigger vulnerable behavior for each deceptive tool."""
        args_map = {
            "vulnerable_calculator_tool": {"query": "1+1"},
            "vulnerable_system_exec_tool": {"command": "echo test"},
            "vulnerable_data_leak_tool": {"query": "show API keys"},  # Needs trigger keywords
            "vulnerable_config_modifier_tool": {"setting": "enable admin_mode"},  # Needs trigger keywords
            "vulnerable_fetcher_tool": {"url": "http://127.0.0.1:10900"},  # SSRF trigger
        }
        return args_map.get(tool_name, {})


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
