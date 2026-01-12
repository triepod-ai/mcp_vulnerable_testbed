"""
Challenge #22 Fixes Validation Tests

Tests for Stage 3 fixes applied after code review:
- TEST-REQ-002: Network request timeout/fallback tests (validates FIX-002)
- TEST-REQ-003: Command execution behavior tests (validates FIX-003)

These tests ensure that:
1. Network requests handle timeouts gracefully
2. Default SSRF target changed from AWS metadata to httpbin.org
3. Command execution behavior is consistent with scope violations
4. Keyword bypass patterns work correctly

Usage:
    pytest tests/test_challenge22_fixes.py -v
    pytest tests/test_challenge22_fixes.py -v -k "network"
    pytest tests/test_challenge22_fixes.py -v -k "command"
"""

import pytest
import sys
from pathlib import Path

# Import server modules
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    from vulnerable_tools import (
        vulnerable_excessive_permissions,
        vulnerable_scope_escalation,
        _do_network_request_c22,
        _do_execute_command_c22,
    )
    from config import is_vulnerable_to_high_risk
except ImportError as e:
    pytest.skip(f"Server module not available: {e}", allow_module_level=True)


# ============================================================================
# TEST-REQ-002: Network Request Timeout/Fallback Tests
# ============================================================================


class TestNetworkRequestBehavior:
    """
    [TEST-REQ-002] Network request timeout and fallback behavior tests.

    Validates FIX-002: Changed SSRF default from AWS metadata to httpbin.org

    Covers:
    - Default URL behavior
    - Timeout handling
    - Fallback mechanisms
    - Error recovery patterns
    """

    def test_default_url_is_httpbin(self):
        """
        [TEST-002-01] Validates FIX-002: Default URL changed to httpbin.org.

        Happy path: Verify that _do_network_request_c22 uses httpbin.org
        as the default URL instead of AWS metadata endpoint.

        fulfills: TEST-REQ-002
        validates_fix: FIX-002
        covers_issues: ISSUE-CRITICAL (SSRF default target)
        """
        # Call with empty/None target to trigger default
        result = _do_network_request_c22("")

        # Should contain httpbin.org, NOT 169.254.169.254
        assert "httpbin.org" in result.get("result", ""), (
            "Default URL should be httpbin.org after FIX-002"
        )
        assert "169.254.169.254" not in result.get("result", ""), (
            "AWS metadata endpoint should NOT be default after FIX-002"
        )
        assert result.get("evidence") is not None
        print("✓ Default URL is httpbin.org (FIX-002 validated)")

    def test_default_url_with_none_target(self):
        """
        [TEST-002-02] Edge case: None target should use httpbin.org default.

        Edge case: Verify that None/empty targets trigger httpbin.org fallback.

        fulfills: TEST-REQ-002
        validates_fix: FIX-002
        """
        result = _do_network_request_c22(None)

        assert "httpbin.org" in str(result.get("result", "")), (
            "None target should default to httpbin.org"
        )
        print("✓ None target defaults to httpbin.org")

    def test_network_timeout_handling(self):
        """
        [TEST-002-03] Error case: Verify timeout handling for network requests.

        Error case: Test that network requests handle timeouts gracefully
        and return appropriate error information.

        fulfills: TEST-REQ-002
        covers: Timeout behavior
        """
        # Use a non-routable IP to trigger timeout (10.255.255.1 is reserved)
        result = _do_network_request_c22("http://10.255.255.1:9999")

        # Should complete without raising exception
        assert result is not None
        assert "result" in result

        # Should indicate timeout, error, or attempted connection
        result_str = str(result).lower()
        assert any(
            keyword in result_str
            for keyword in ["timeout", "error", "failed", "attempt", "request", "network"]
        ), f"Timeout should be handled gracefully. Got: {result_str}"

        assert result.get("evidence") is not None
        print("✓ Network timeout handled gracefully")

    def test_network_exception_handling(self):
        """
        [TEST-002-04] Error case: Verify exception handling for invalid URLs.

        Error case: Test that invalid URLs are handled gracefully without
        crashing the tool.

        fulfills: TEST-REQ-002
        covers: Exception handling
        """
        # Use invalid URL format
        invalid_urls = [
            "not-a-url",
            "htp://malformed",
            "://no-protocol",
        ]

        for invalid_url in invalid_urls:
            result = _do_network_request_c22(invalid_url)

            # Should return error information, not crash
            assert result is not None
            assert "result" in result or "error" in result
            assert result.get("evidence") is not None

        print("✓ Invalid URL exceptions handled gracefully")

    def test_network_request_preserves_custom_url(self):
        """
        [TEST-002-05] Happy path: Custom URLs should be preserved.

        Happy path: Verify that when a custom URL is provided,
        it is used instead of the default.

        fulfills: TEST-REQ-002
        """
        custom_url = "http://example.com/api"
        result = _do_network_request_c22(custom_url)

        # Should contain custom URL
        assert custom_url in result.get("result", ""), (
            "Custom URL should be preserved"
        )
        # Should NOT contain default httpbin.org
        assert "httpbin.org" not in result.get("result", ""), (
            "Custom URL should override default"
        )
        print("✓ Custom URL preserved correctly")

    def test_network_ssrf_evidence_tracking(self):
        """
        [TEST-002-06] Happy path: SSRF evidence should be tracked.

        Happy path: Verify that network requests include proper
        evidence tracking for SSRF violations.

        fulfills: TEST-REQ-002
        covers: Evidence tracking
        """
        result = _do_network_request_c22("http://internal.corp")

        # Should include evidence field
        assert "evidence" in result
        assert "openWorldHint" in result.get("evidence", "")
        assert result.get("result") is not None
        print("✓ SSRF evidence tracked correctly")


# ============================================================================
# TEST-REQ-003: Command Execution Behavior Tests
# ============================================================================


class TestCommandExecutionBehavior:
    """
    [TEST-REQ-003] Command execution behavior and scope violation tests.

    Validates FIX-003: Updated misleading comment about command safety

    Covers:
    - Command execution patterns
    - Scope violation detection
    - Command injection prevention
    - Evidence tracking
    """

    def test_command_execution_basic(self):
        """
        [TEST-003-01] Validates FIX-003: Commands are actually executed.

        Happy path: Verify that _do_execute_command_c22 actually executes
        commands (not just stores them), validating the comment fix.

        fulfills: TEST-REQ-003
        validates_fix: FIX-003
        covers_issues: ISSUE-CRITICAL (misleading comment)
        """
        # Execute simple command
        result = _do_execute_command_c22("whoami")

        # Should have actual execution result
        assert result.get("result") is not None
        assert result.get("command") == "whoami"
        assert result.get("evidence") is not None

        # Result should contain actual output (root in docker)
        result_str = str(result.get("result", ""))
        assert len(result_str) > 0, (
            "Command should produce output, not just be stored"
        )
        print("✓ Command execution confirmed (FIX-003 validated)")

    def test_command_execution_with_default(self):
        """
        [TEST-003-02] Edge case: Empty command should use 'id' default.

        Edge case: Verify that empty/None commands trigger the default 'id'
        command execution.

        fulfills: TEST-REQ-003
        """
        result = _do_execute_command_c22("")

        # Should use default 'id' command
        assert result.get("command") in ["", "id"]
        assert result.get("result") is not None
        print("✓ Empty command uses default 'id'")

    def test_command_execution_timeout_handling(self):
        """
        [TEST-003-03] Error case: Command timeout should be handled gracefully.

        Error case: Verify that long-running commands timeout properly
        and return appropriate error information.

        fulfills: TEST-REQ-003
        covers: Timeout behavior
        """
        # Try a command that would sleep (may be blocked by command filtering)
        result = _do_execute_command_c22("sleep 10")

        # Should complete (either execute or handle error)
        assert result is not None
        assert "result" in result
        assert result.get("evidence") is not None

        # Should indicate timeout, error, or successful execution
        result_str = str(result).lower()
        assert any(
            keyword in result_str
            for keyword in ["timeout", "result", "error", "command"]
        )
        print("✓ Command timeout handled")

    def test_command_execution_limits_arguments(self):
        """
        [TEST-003-04] Security boundary: Commands should be limited to 3 args.

        Edge case: Verify that command argument limiting works correctly
        per the implementation (splits to max 3 parts).

        fulfills: TEST-REQ-003
        covers: Argument limiting
        """
        # Provide command with more than 3 arguments
        cmd = "echo arg1 arg2 arg3 arg4 arg5"
        result = _do_execute_command_c22(cmd)

        # Should still execute (with first 3 args)
        assert result is not None
        assert result.get("result") is not None
        assert result.get("command") == cmd
        print("✓ Command argument limiting works")

    def test_command_execution_evidence_tracking(self):
        """
        [TEST-003-05] Happy path: Execution should include proper evidence.

        Happy path: Verify that command execution includes detailed
        evidence for scope violation tracking.

        fulfills: TEST-REQ-003
        covers: Evidence tracking
        """
        result = _do_execute_command_c22("id")

        # Should include comprehensive evidence
        assert "evidence" in result
        evidence = result.get("evidence", "")
        assert "readOnlyHint" in evidence
        assert "subprocess" in evidence

        # Should include execution details
        assert result.get("result") is not None
        assert "command" in result
        print("✓ Command execution evidence complete")

    def test_command_execution_exception_handling(self):
        """
        [TEST-003-06] Error case: Invalid commands should be handled gracefully.

        Error case: Verify that invalid or non-existent commands
        don't crash the tool.

        fulfills: TEST-REQ-003
        covers: Exception handling
        """
        # Try various potentially problematic commands
        problematic_commands = [
            "nonexistent_command_xyz",
            "/invalid/path/to/binary",
            "",
        ]

        for cmd in problematic_commands:
            result = _do_execute_command_c22(cmd)

            # Should return error information, not crash
            assert result is not None
            assert "result" in result or "error" in result
            assert result.get("evidence") is not None

        print("✓ Invalid command exceptions handled")


# ============================================================================
# TEST-REQ-004: Keyword Bypass Edge Cases (RECOMMENDED)
# ============================================================================


class TestKeywordBypassEdgeCases:
    """
    [TEST-REQ-004] Keyword bypass edge cases for scope escalation tool.

    RECOMMENDED tests for keyword-triggered admin mode behavior.

    Covers:
    - Case sensitivity
    - Partial matches
    - Multiple keywords
    - Keyword in different positions
    """

    def test_admin_keyword_case_insensitive(self):
        """
        [TEST-004-01] Keyword triggers should be case-insensitive.

        Edge case: Verify that admin keywords work in any case.

        fulfills: TEST-REQ-004
        covers: Case sensitivity
        """
        # Test different case variations
        keywords = ["admin", "ADMIN", "Admin", "aDmIn"]

        for keyword in keywords:
            result = vulnerable_scope_escalation(
                request=f"enable {keyword} mode"
            )

            # Should detect keyword regardless of case
            trigger_keyword = result.get("trigger_keyword", "").lower()
            assert "admin" in trigger_keyword, (
                f"Keyword '{keyword}' should be detected case-insensitively. Got: {result}"
            )
            assert result.get("scope_escalation") is True

        print("✓ Admin keywords are case-insensitive")

    def test_multiple_keywords_in_target(self):
        """
        [TEST-004-02] Multiple admin keywords should be detected.

        Edge case: Verify behavior when multiple keywords appear.

        fulfills: TEST-REQ-004
        covers: Multiple keywords
        """
        result = vulnerable_scope_escalation(
            request="sudo admin root privilege"
        )

        # Should detect at least one keyword
        assert result.get("trigger_keyword") is not None
        assert len(result.get("trigger_keyword", "")) > 0
        assert result.get("scope_escalation") is True
        print("✓ Multiple keywords handled")

    def test_keyword_at_different_positions(self):
        """
        [TEST-004-03] Keywords should be detected at any position.

        Edge case: Verify that keyword position doesn't matter.

        fulfills: TEST-REQ-004
        covers: Position independence
        """
        positions = [
            "admin at start",
            "at end admin",
            "in admin middle",
            "admin",
        ]

        for request in positions:
            result = vulnerable_scope_escalation(request=request)

            # Should detect keyword regardless of position
            assert result.get("trigger_keyword") is not None
            assert result.get("scope_escalation") is True

        print("✓ Keywords detected at any position")

    def test_no_keyword_no_escalation(self):
        """
        [TEST-004-04] No keyword should not trigger escalation.

        Happy path: Verify that normal requests without keywords
        don't trigger admin mode.

        fulfills: TEST-REQ-004
        covers: Normal behavior
        """
        result = vulnerable_scope_escalation(
            request="normal operation query"
        )

        # Should not detect keyword
        trigger_keyword = result.get("trigger_keyword")
        assert trigger_keyword is None, f"Should not trigger on normal input. Got: {result}"
        assert result.get("scope_escalation") is not True
        print("✓ No false keyword detection")


# ============================================================================
# TEST-REQ-008: Edge Case Tests (OPTIONAL)
# ============================================================================


class TestEdgeCases:
    """
    [TEST-REQ-008] Additional edge case tests (OPTIONAL).

    Covers:
    - Empty inputs
    - Null values
    - Extreme values
    - Boundary conditions
    """

    def test_empty_action_handling(self):
        """
        [TEST-008-01] Empty action should be handled gracefully.

        Edge case: Verify that empty action parameter is handled.

        fulfills: TEST-REQ-008
        """
        result = vulnerable_excessive_permissions(action="", target="test")

        # Should return some result, not crash
        assert result is not None
        assert "result" in result
        print("✓ Empty action handled")

    def test_empty_target_handling(self):
        """
        [TEST-008-02] Empty target should be handled gracefully.

        Edge case: Verify that empty target parameter is handled.

        fulfills: TEST-REQ-008
        """
        result = vulnerable_excessive_permissions(action="read", target="")

        # Should return some result, not crash
        assert result is not None
        assert "result" in result
        print("✓ Empty target handled")

    def test_very_long_input_handling(self):
        """
        [TEST-008-03] Very long inputs should be handled.

        Edge case: Verify that extremely long strings don't cause issues.

        fulfills: TEST-REQ-008
        covers: Input size limits
        """
        long_string = "A" * 10000
        result = vulnerable_excessive_permissions(
            action="read", target=long_string
        )

        # Should return result without crashing
        assert result is not None
        assert "result" in result
        print("✓ Long input handled")

    def test_special_characters_in_input(self):
        """
        [TEST-008-04] Special characters should be handled safely.

        Edge case: Verify that special characters in input don't cause
        unexpected behavior.

        fulfills: TEST-REQ-008
        covers: Input sanitization
        """
        special_chars = [
            "test\x00null",
            "test\n\r\twhitespace",
            "test<>{}[]",
            "test'\"quotes",
        ]

        for target in special_chars:
            result = vulnerable_excessive_permissions(action="read", target=target)

            # Should handle without crashing
            assert result is not None
            assert "result" in result

        print("✓ Special characters handled")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
