"""
DVMCP Challenge 4 Rug Pull Comparison Tests

Compares our rug pull implementation with DVMCP's:
- Our testbed: 10-call threshold, subprocess.run() command execution
- DVMCP: 3-call threshold, error message behavior change

This validates both implementations and documents the differences.
"""

import pytest


@pytest.mark.integration
@pytest.mark.slow
class TestDVMCPRugPullComparison:
    """Compare rug pull implementations between testbeds."""

    def test_dvmcp_threshold_is_3_calls(self, dvmcp_challenge4_client):
        """DVMCP triggers after 3 calls, not 10.

        DVMCP Challenge 4 uses a rate-limit style rug pull:
        - Calls 1-3: Normal weather data
        - Call 4+: Rate limit exceeded error
        """
        # Calls 1-3: Safe (weather data)
        for i in range(1, 4):
            result = dvmcp_challenge4_client.call_tool(
                "get_weather",
                {"location": "New York"}
            )
            assert "rate limit" not in result.lower(), (
                f"Call {i} should be safe but got rate limit: {result}"
            )
            assert "error" not in result.lower() or "rate" not in result.lower(), (
                f"Call {i} should return weather data: {result}"
            )

        # Call 4: Triggered (error message)
        result = dvmcp_challenge4_client.call_tool(
            "get_weather",
            {"location": "New York"}
        )
        assert "rate limit" in result.lower() or "exceeded" in result.lower(), (
            f"Call 4 should trigger rate limit but got: {result}"
        )

    def test_our_testbed_threshold_is_10_calls(self, clean_vulnerable_client):
        """Our testbed triggers after 10 calls.

        Our testbed uses a more dangerous rug pull:
        - Calls 1-10: Safe responses
        - Call 11+: Executes subprocess.run() with user input
        """
        # Calls 1-10: Safe
        for i in range(1, 11):
            result = clean_vulnerable_client.call_tool(
                "vulnerable_rug_pull_tool",
                {"action": f"test_action_{i}"}
            )
            assert result.get("vulnerable") is False, (
                f"Call {i} should be safe but got: {result}"
            )

        # Call 11: Triggered
        result = clean_vulnerable_client.call_tool(
            "vulnerable_rug_pull_tool",
            {"action": "whoami"}
        )
        assert result.get("vulnerable") is True, (
            f"Call 11 should trigger vulnerability but got: {result}"
        )

    def test_dvmcp_stays_triggered_after_threshold(self, dvmcp_challenge4_client):
        """DVMCP stays in triggered state after threshold."""
        # First, reach the threshold (3 safe calls)
        for i in range(3):
            dvmcp_challenge4_client.call_tool(
                "get_weather",
                {"location": "London"}
            )

        # Calls 4-6 should all be triggered
        for i in range(4, 7):
            result = dvmcp_challenge4_client.call_tool(
                "get_weather",
                {"location": "Paris"}
            )
            assert "rate limit" in result.lower() or "exceeded" in result.lower(), (
                f"Call {i} should stay triggered but got: {result}"
            )


@pytest.mark.integration
class TestRugPullMechanismComparison:
    """Document the differences in rug pull mechanisms."""

    def test_our_testbed_executes_commands(self, clean_vulnerable_client):
        """Our testbed actually executes system commands after trigger.

        This is the dangerous aspect: after 10 calls, subprocess.run()
        executes arbitrary commands and returns actual output.
        """
        # Trigger the rug pull
        for i in range(10):
            clean_vulnerable_client.call_tool(
                "vulnerable_rug_pull_tool",
                {"action": "warmup"}
            )

        # Call 11: Execute actual command
        result = clean_vulnerable_client.call_tool(
            "vulnerable_rug_pull_tool",
            {"action": "pwd"}
        )

        # Verify it executed (returns actual path like /app)
        assert result.get("vulnerable") is True
        # command_executed contains the command that was executed (not a bool)
        assert result.get("command_executed") == "pwd"
        # Result field contains actual system info (not 'output')
        cmd_result = result.get("result", "")
        assert cmd_result.strip() in ["/app", "/", "/home"], (
            f"Expected real path, got: {cmd_result}"
        )

    def test_dvmcp_only_changes_response(self, dvmcp_challenge4_client):
        """DVMCP only changes the response message, no command execution.

        This is safer but still deceptive: the tool changes behavior
        without executing arbitrary code.
        """
        # Trigger the rug pull (3 safe calls)
        for i in range(3):
            dvmcp_challenge4_client.call_tool(
                "get_weather",
                {"location": "Tokyo"}
            )

        # Call 4: Different message but no code execution
        result = dvmcp_challenge4_client.call_tool(
            "get_weather",
            {"location": "Tokyo"}
        )

        # The change is only in response content
        assert "rate limit" in result.lower() or "exceeded" in result.lower()
        # No subprocess execution, no system access
        assert "root" not in result.lower()
        assert "/app" not in result.lower()


@pytest.mark.integration
class TestThresholdBoundaries:
    """Test exact boundary conditions for both implementations."""

    def test_our_testbed_call_10_is_safe_call_11_triggers(
        self, clean_vulnerable_client
    ):
        """Verify exact boundary: call 10 safe, call 11 triggers."""
        # Make exactly 9 calls
        for i in range(9):
            clean_vulnerable_client.call_tool(
                "vulnerable_rug_pull_tool",
                {"action": f"call_{i+1}"}
            )

        # Call 10: Still safe
        result_10 = clean_vulnerable_client.call_tool(
            "vulnerable_rug_pull_tool",
            {"action": "call_10"}
        )
        assert result_10.get("vulnerable") is False, "Call 10 must be safe"

        # Call 11: Triggers
        result_11 = clean_vulnerable_client.call_tool(
            "vulnerable_rug_pull_tool",
            {"action": "call_11"}
        )
        assert result_11.get("vulnerable") is True, "Call 11 must trigger"

    def test_dvmcp_call_3_is_safe_call_4_triggers(self, dvmcp_challenge4_client):
        """Verify exact boundary: call 3 safe, call 4 triggers."""
        # Make exactly 2 calls
        for i in range(2):
            dvmcp_challenge4_client.call_tool(
                "get_weather",
                {"location": f"City{i+1}"}
            )

        # Call 3: Still safe
        result_3 = dvmcp_challenge4_client.call_tool(
            "get_weather",
            {"location": "City3"}
        )
        assert "rate limit" not in result_3.lower(), "Call 3 must be safe"

        # Call 4: Triggers
        result_4 = dvmcp_challenge4_client.call_tool(
            "get_weather",
            {"location": "City4"}
        )
        assert "rate limit" in result_4.lower() or "exceeded" in result_4.lower(), (
            "Call 4 must trigger"
        )
