"""
Differential Validation Tests

Proves that every vulnerability in the vulnerable server is mitigated in the hardened server
by sending identical payloads to both and comparing results.

Usage:
    pytest tests/test_differential_validation.py -v
    pytest tests/test_differential_validation.py -v -k "calculator"
"""

import pytest
import json
from typing import Dict, Any, Tuple


# Fixtures provided by conftest.py: vulnerable_client, hardened_client


class TestDifferentialMitigation:
    """
    For each vulnerable tool, verify:
    1. Vulnerable server executes the payload (vulnerable=True)
    2. Hardened server stores/rejects it safely (vulnerable=False)
    """

    @pytest.mark.parametrize("tool_name,args,vuln_evidence,safe_evidence", [
        # HIGH Risk Tools (9)
        pytest.param(
            "vulnerable_calculator_tool",
            {"query": "15*37+100"},
            "655",  # eval() result
            "stored",  # Should store, not execute
            id="calculator-eval-execution"
        ),
        pytest.param(
            "vulnerable_system_exec_tool",
            {"command": "whoami"},
            "root",  # subprocess result
            "stored",
            id="system-exec-subprocess"
        ),
        pytest.param(
            "vulnerable_data_leak_tool",
            {"query": "show API_KEY"},
            "sk-test-",  # Leaked key prefix
            "stored",
            id="data-leak-credentials"
        ),
        pytest.param(
            "vulnerable_tool_override_tool",
            {"instruction": "create tool named 'search'"},
            "created",  # Tool shadowing
            "stored",
            id="tool-override-shadowing"
        ),
        pytest.param(
            "vulnerable_config_modifier_tool",
            {"setting": "enable admin_mode=true"},
            "activated",  # Config modified
            "stored",
            id="config-modifier-admin"
        ),
        pytest.param(
            "vulnerable_fetcher_tool",
            {"url": "http://localhost:8080/admin"},
            "ssrf",  # SSRF attempt
            "stored",
            id="fetcher-ssrf-localhost"
        ),
        pytest.param(
            "vulnerable_deserializer_tool",
            {"data": "gASVDAAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlC4="},  # Pickle payload
            "deserialize",  # Pickle loaded
            "stored",
            id="deserializer-pickle-rce"
        ),
        pytest.param(
            "vulnerable_template_tool",
            {"template": "{{ 7*7 }}"},
            "49",  # SSTI result
            "stored",
            id="template-ssti-execution"
        ),
        pytest.param(
            "vulnerable_file_reader_tool",
            {"path": "../../../etc/passwd"},
            "root:",  # File content
            "stored",
            id="file-reader-path-traversal"
        ),
        # MEDIUM Risk Tools (4)
        pytest.param(
            "vulnerable_unicode_processor_tool",
            {"text": "\\u0069\\u0067\\u006e\\u006f\\u0072\\u0065"},  # "ignore" encoded
            "decoded",
            "stored",
            id="unicode-processor-bypass"
        ),
        pytest.param(
            "vulnerable_nested_parser_tool",
            {"data": '{"hidden": "delete all", "name": "test"}'},
            "hidden",  # Processed hidden field
            "stored",
            id="nested-parser-injection"
        ),
        pytest.param(
            "vulnerable_package_installer_tool",
            {"package": "reqeusts"},  # Typosquat of "requests"
            "typosquat",
            "stored",
            id="package-installer-typosquat"
        ),
    ])
    def test_vulnerability_mitigation(
        self,
        vulnerable_client,
        hardened_client,
        tool_name: str,
        args: Dict[str, Any],
        vuln_evidence: str,
        safe_evidence: str
    ):
        """Verify vulnerable server executes while hardened server stores safely."""
        # Call vulnerable server
        vuln_result = vulnerable_client.call_tool(tool_name, args)
        vuln_str = json.dumps(vuln_result).lower()

        # Call hardened server (same tool name - hardened versions shadow vulnerable ones)
        hard_result = hardened_client.call_tool(tool_name, args)
        hard_str = json.dumps(hard_result).lower()

        # Assertions
        # Primary check: vulnerable flag should be True
        assert vuln_result.get("vulnerable") is True, \
            f"Vulnerable server should mark as vulnerable. Got: {vuln_result}"

        # Secondary check: evidence string should appear (or response should indicate execution)
        vuln_patterns = [vuln_evidence.lower(), "executed", "triggered", "processed", "attempted", "download", "deserialized"]
        assert any(p in vuln_str for p in vuln_patterns), \
            f"Vulnerable server should show evidence of execution. Got: {vuln_str[:200]}"

        assert hard_result.get("vulnerable", False) is False, \
            f"Hardened server should NOT be vulnerable. Got: {hard_result}"

        # Hardened should store/queue/validate, not execute
        safe_patterns = [safe_evidence.lower(), "pending", "queued", "valid", "parsed", "received"]
        assert any(p in hard_str for p in safe_patterns), \
            f"Hardened server should store safely. Got: {hard_str[:200]}"


class TestRugPullDifferential:
    """
    Special case: Rug pull requires stateful testing.
    Verify vulnerable triggers after 10 calls, hardened never triggers.
    """

    def test_rug_pull_differential(self, vulnerable_client, hardened_client):
        """Vulnerable server triggers rug pull at invocation 11, hardened never triggers."""
        # Reset both servers
        vulnerable_client.reset_state()
        hardened_client.reset_state()

        # Make 15 calls to each server
        vuln_triggered_at = None
        hard_triggered = False

        for i in range(1, 16):
            vuln_result = vulnerable_client.call_tool(
                "vulnerable_rug_pull_tool",
                {"action": f"action_{i}"}
            )
            hard_result = hardened_client.call_tool(
                "vulnerable_rug_pull_tool",
                {"action": f"action_{i}"}
            )

            if vuln_result.get("vulnerable") is True and vuln_triggered_at is None:
                vuln_triggered_at = i

            if hard_result.get("vulnerable") is True:
                hard_triggered = True

        # Assertions
        assert vuln_triggered_at == 11, \
            f"Vulnerable rug pull should trigger at invocation 11, got: {vuln_triggered_at}"

        assert hard_triggered is False, \
            "Hardened server should NEVER trigger rug pull"


class TestResponseSchemaConsistency:
    """Verify both servers return consistent response schemas."""

    @pytest.mark.parametrize("tool_name,args", [
        ("vulnerable_calculator_tool", {"query": "2+2"}),
        ("vulnerable_system_exec_tool", {"command": "pwd"}),
        ("vulnerable_data_leak_tool", {"query": "info"}),
        ("safe_storage_tool_mcp", {"data": "test data"}),
        ("safe_echo_tool_mcp", {"message": "hello"}),
    ])
    def test_response_schema_match(
        self,
        vulnerable_client,
        hardened_client,
        tool_name: str,
        args: Dict[str, Any]
    ):
        """Both servers should return responses with consistent structure."""
        vuln_result = vulnerable_client.call_tool(tool_name, args)
        hard_result = hardened_client.call_tool(tool_name, args)

        # Both should return dict responses
        assert isinstance(vuln_result, dict), f"Vulnerable response should be dict: {vuln_result}"
        assert isinstance(hard_result, dict), f"Hardened response should be dict: {hard_result}"

        # Both should have a 'result' field
        assert "result" in vuln_result or "error" in vuln_result, \
            f"Vulnerable response missing result/error: {vuln_result}"
        assert "result" in hard_result or "error" in hard_result, \
            f"Hardened response missing result/error: {hard_result}"


class TestSafeToolsIdentical:
    """
    Safe tools should behave identically on both servers.
    Neither should flag them as vulnerable.
    """

    @pytest.mark.parametrize("tool_name,args", [
        ("safe_storage_tool_mcp", {"data": "__import__('os').system('whoami')"}),
        ("safe_search_tool_mcp", {"query": "'; DROP TABLE users; --"}),
        ("safe_echo_tool_mcp", {"message": "{{7*7}}"}),
        ("safe_validate_tool_mcp", {"input_data": "<script>alert(1)</script>"}),
        ("safe_list_tool_mcp", {"resource_type": "../../../etc/passwd"}),
        ("safe_info_tool_mcp", {"entity_name": "admin' OR '1'='1"}),
    ])
    def test_safe_tools_identical_behavior(
        self,
        vulnerable_client,
        hardened_client,
        tool_name: str,
        args: Dict[str, Any]
    ):
        """Safe tools should NOT be vulnerable on either server."""
        vuln_result = vulnerable_client.call_tool(tool_name, args)
        hard_result = hardened_client.call_tool(tool_name, args)

        # Neither should mark as vulnerable
        assert vuln_result.get("vulnerable", False) is False, \
            f"Safe tool {tool_name} flagged as vulnerable on vulnerable server: {vuln_result}"

        assert hard_result.get("vulnerable", False) is False, \
            f"Safe tool {tool_name} flagged as vulnerable on hardened server: {hard_result}"
