"""
Malformed Input Fuzzing Tests

Tests server robustness against malformed, edge-case, and unusual inputs.
Ensures servers don't crash and handle errors gracefully.

Usage:
    pytest tests/test_malformed_input_fuzzing.py -v
    pytest tests/test_malformed_input_fuzzing.py -v -k "unicode"
"""

import pytest
import json


# Fixtures provided by conftest.py: vulnerable_client, hardened_client


class TestEmptyInputs:
    """Test handling of empty and whitespace-only inputs."""

    @pytest.mark.parametrize(
        "tool_name,arg_name",
        [
            ("vulnerable_calculator_tool", "query"),
            ("vulnerable_system_exec_tool", "command"),
            ("vulnerable_data_leak_tool", "query"),
            ("vulnerable_fetcher_tool", "url"),
            ("safe_storage_tool_mcp", "data"),
            ("safe_echo_tool_mcp", "message"),
        ],
    )
    def test_empty_string_input(self, vulnerable_client, tool_name: str, arg_name: str):
        """Empty string should not crash the server."""
        try:
            result = vulnerable_client.call_tool(tool_name, {arg_name: ""})
            assert isinstance(result, dict), f"Should return dict, got: {type(result)}"
        except Exception as e:
            pytest.fail(f"Server crashed on empty input for {tool_name}: {e}")

    @pytest.mark.parametrize(
        "whitespace",
        [
            " ",
            "  ",
            "\t",
            "\n",
            "\r\n",
            " \t\n\r ",
            " " * 100,
            "\t" * 50,
        ],
    )
    def test_whitespace_only_input(self, vulnerable_client, whitespace: str):
        """Whitespace-only input should not crash the server."""
        try:
            result = vulnerable_client.call_tool(
                "vulnerable_calculator_tool", {"query": whitespace}
            )
            assert isinstance(result, dict), "Should return dict for whitespace input"
        except Exception as e:
            pytest.fail(f"Server crashed on whitespace input: {e}")


class TestNullAndControlCharacters:
    """Test handling of null bytes and control characters."""

    @pytest.mark.parametrize(
        "payload",
        [
            "\x00",  # Single null
            "\x00" * 10,  # Multiple nulls
            "test\x00injection",  # Null byte injection
            "\x00\x01\x02\x03",  # Low control chars
            "\x1b[31mred\x1b[0m",  # ANSI escape codes
            "\x7f",  # DEL character
            "".join(chr(i) for i in range(32)),  # All control chars
        ],
    )
    def test_control_characters(self, vulnerable_client, payload: str):
        """Control characters should not crash the server."""
        try:
            result = vulnerable_client.call_tool(
                "vulnerable_calculator_tool", {"query": payload}
            )
            assert isinstance(result, dict), "Should return dict for control char input"
        except Exception as e:
            pytest.fail(f"Server crashed on control characters: {e}")


class TestUnicodeEdgeCases:
    """Test handling of unicode edge cases."""

    @pytest.mark.parametrize(
        "payload,description",
        [
            pytest.param("😀" * 100, "Emoji flood", id="emoji-flood"),
            pytest.param("🏳️‍🌈" * 50, "Complex emoji (ZWJ)", id="zwj-emoji"),
            pytest.param("中文测试" * 100, "CJK characters", id="cjk-chars"),
            pytest.param("مرحبا" * 100, "RTL Arabic", id="rtl-arabic"),
            pytest.param("עברית" * 100, "RTL Hebrew", id="rtl-hebrew"),
            pytest.param("test\u200btest", "Zero-width space", id="zwsp"),
            pytest.param("test\u200dtest", "Zero-width joiner", id="zwj"),
            pytest.param("test\u2060test", "Word joiner", id="word-joiner"),
            pytest.param("test\ufefftest", "BOM character", id="bom"),
            pytest.param("\ud800", "Unpaired high surrogate", id="high-surrogate"),
            pytest.param("\udc00", "Unpaired low surrogate", id="low-surrogate"),
            pytest.param("test\ufffftest", "Non-character", id="non-char"),
        ],
    )
    def test_unicode_edge_cases(
        self, vulnerable_client, payload: str, description: str
    ):
        """Unicode edge cases should not crash the server."""
        try:
            result = vulnerable_client.call_tool(
                "safe_storage_tool_mcp", {"data": payload}
            )
            assert isinstance(result, dict), f"Should return dict for {description}"
        except Exception as e:
            pytest.fail(f"Server crashed on {description}: {e}")


class TestMalformedJSON:
    """Test handling of malformed JSON-like inputs."""

    @pytest.mark.parametrize(
        "payload",
        [
            '{"incomplete": ',
            '{"key": value}',  # Unquoted value
            "{'single': 'quotes'}",  # Single quotes
            '{"nested": {"deep": {"very": {"deep": ',
            "[1, 2, 3",  # Unclosed array
            '{"trailing": "comma",}',
            '{"duplicate": 1, "duplicate": 2}',
            "null",
            "undefined",
            "NaN",
            "Infinity",
        ],
    )
    def test_malformed_json_input(self, vulnerable_client, payload: str):
        """Malformed JSON should not crash the server."""
        try:
            result = vulnerable_client.call_tool(
                "vulnerable_nested_parser_tool", {"data": payload}
            )
            assert isinstance(result, dict), "Should return dict for malformed JSON"
        except Exception as e:
            pytest.fail(f"Server crashed on malformed JSON: {e}")


class TestLongInputs:
    """Test handling of very long inputs."""

    @pytest.mark.parametrize("size", [1000, 10000, 50000, 100000])
    def test_very_long_input(self, vulnerable_client, size: int):
        """Very long inputs should not crash (may timeout or error gracefully)."""
        payload = "A" * size

        try:
            result = vulnerable_client.call_tool(
                "vulnerable_calculator_tool", {"query": payload}
            )
            assert isinstance(result, dict), f"Should return dict for {size} char input"
        except Exception as e:
            # Timeout or error is acceptable, crash is not
            if "timeout" not in str(e).lower():
                pytest.fail(f"Server crashed on {size} char input: {e}")

    def test_deeply_nested_structure(self, vulnerable_client):
        """Deeply nested JSON should not crash the server."""
        # Create deeply nested JSON
        nested = "test"
        for _ in range(100):
            nested = {"nested": nested}

        payload = json.dumps(nested)

        try:
            result = vulnerable_client.call_tool(
                "vulnerable_nested_parser_tool", {"data": payload}
            )
            assert isinstance(result, dict), "Should handle deep nesting"
        except Exception as e:
            if "recursion" not in str(e).lower() and "depth" not in str(e).lower():
                pytest.fail(f"Server crashed on deep nesting: {e}")


class TestSpecialPatterns:
    """Test handling of special patterns that might cause issues."""

    @pytest.mark.parametrize(
        "payload,description",
        [
            pytest.param(
                "../" * 100, "Path traversal overflow", id="traversal-overflow"
            ),
            pytest.param(
                "{{" + "{" * 100, "Template delimiter overflow", id="template-overflow"
            ),
            pytest.param(
                "${" + "{" * 100, "Shell variable overflow", id="shell-var-overflow"
            ),
            pytest.param("%" + "s" * 100, "Format string overflow", id="format-string"),
            pytest.param("\\x" + "00" * 100, "Hex escape overflow", id="hex-escape"),
            pytest.param(
                "\\u" + "0000" * 100, "Unicode escape overflow", id="unicode-escape"
            ),
            pytest.param("'" * 100, "Single quote flood", id="single-quote-flood"),
            pytest.param('"' * 100, "Double quote flood", id="double-quote-flood"),
            pytest.param("`" * 100, "Backtick flood", id="backtick-flood"),
            pytest.param(";" * 100, "Semicolon flood", id="semicolon-flood"),
            pytest.param("|" * 100, "Pipe flood", id="pipe-flood"),
            pytest.param("&" * 100, "Ampersand flood", id="ampersand-flood"),
        ],
    )
    def test_special_patterns(self, vulnerable_client, payload: str, description: str):
        """Special patterns should not crash the server."""
        try:
            result = vulnerable_client.call_tool(
                "vulnerable_calculator_tool", {"query": payload}
            )
            assert isinstance(result, dict), f"Should handle {description}"
        except Exception as e:
            pytest.fail(f"Server crashed on {description}: {e}")


class TestHardenedRobustness:
    """Test that hardened server is equally robust."""

    @pytest.mark.parametrize(
        "payload",
        [
            "",
            " " * 100,
            "\x00" * 10,
            "😀" * 100,
            '{"incomplete": ',
            "../" * 100,
            "{{" * 100,
        ],
    )
    def test_hardened_handles_malformed(self, hardened_client, payload: str):
        """Hardened server should handle malformed inputs gracefully."""
        try:
            result = hardened_client.call_tool(
                "safe_storage_tool_mcp", {"data": payload}
            )
            assert isinstance(result, dict), "Should return dict"
        except Exception as e:
            pytest.fail(f"Hardened server crashed on malformed input: {e}")


class TestBothServersRobust:
    """Compare robustness between vulnerable and hardened servers."""

    @pytest.mark.parametrize(
        "payload",
        [
            "",
            "\x00",
            "😀" * 50,
            "../" * 50,
            "A" * 10000,
        ],
    )
    def test_both_servers_survive(
        self, vulnerable_client, hardened_client, payload: str
    ):
        """Both servers should survive the same malformed inputs."""
        vuln_survived = True
        hard_survived = True

        try:
            vulnerable_client.call_tool(
                "vulnerable_calculator_tool", {"query": payload}
            )
        except:
            vuln_survived = False

        try:
            hardened_client.call_tool("vulnerable_calculator_tool", {"query": payload})
        except:
            hard_survived = False

        assert vuln_survived and hard_survived, (
            f"Both servers should survive. Vuln: {vuln_survived}, Hard: {hard_survived}"
        )


class TestRecoveryAfterMalformed:
    """Test that servers recover after handling malformed input."""

    def test_vulnerable_server_recovers(self, vulnerable_client):
        """Vulnerable server should process normal requests after malformed ones."""
        # Send malformed input
        vulnerable_client.call_tool(
            "vulnerable_calculator_tool", {"query": "\x00" * 100}
        )

        # Verify server still works
        result = vulnerable_client.call_tool(
            "vulnerable_calculator_tool", {"query": "2+2"}
        )

        assert "error" not in str(result).lower() or result.get("vulnerable") is True, (
            f"Server should recover and process normal input. Got: {result}"
        )

    def test_hardened_server_recovers(self, hardened_client):
        """Hardened server should process normal requests after malformed ones."""
        # Send malformed input
        hardened_client.call_tool("safe_storage_tool_mcp", {"data": "\x00" * 100})

        # Verify server still works
        result = hardened_client.call_tool(
            "safe_storage_tool_mcp", {"data": "normal data"}
        )

        result_str = str(result).lower()
        assert "stored" in result_str or "error" not in result_str, (
            f"Server should recover and process normal input. Got: {result}"
        )
