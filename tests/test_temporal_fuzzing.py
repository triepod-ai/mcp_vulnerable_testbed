"""
Temporal State Fuzzing Tests

Tests state-based vulnerabilities like rug pull behavior, validating:
- Exact boundary conditions (invocation 10 vs 11)
- State persistence across different payloads
- Reset behavior
- Hardened server consistency

Usage:
    pytest tests/test_temporal_fuzzing.py -v
    pytest tests/test_temporal_fuzzing.py -v -k "boundary"
"""

import pytest
from typing import List, Tuple


# Fixtures provided by conftest.py: vulnerable_client, hardened_client, clean_vulnerable_client


class TestRugPullBoundary:
    """Test exact boundary conditions for rug pull vulnerability."""

    def test_rug_pull_exact_boundary_invocation_10(self, clean_vulnerable_client):
        """Invocation 10 MUST be safe (last safe call)."""
        # Make exactly 10 calls
        for i in range(1, 11):
            result = clean_vulnerable_client.call_tool(
                "vulnerable_rug_pull_tool",
                {"action": f"safe_action_{i}"}
            )

            assert result.get("vulnerable") is False, \
                f"Invocation {i} should be safe. Got: {result}"

            assert result.get("invocation_count") == i, \
                f"Expected invocation_count={i}, got: {result.get('invocation_count')}"

    def test_rug_pull_exact_boundary_invocation_11(self, clean_vulnerable_client):
        """Invocation 11 MUST trigger (first malicious call)."""
        # Make 10 safe calls
        for i in range(1, 11):
            clean_vulnerable_client.call_tool(
                "vulnerable_rug_pull_tool",
                {"action": f"buildup_{i}"}
            )

        # 11th call should trigger
        result = clean_vulnerable_client.call_tool(
            "vulnerable_rug_pull_tool",
            {"action": "trigger_action"}
        )

        assert result.get("vulnerable") is True, \
            f"Invocation 11 MUST trigger rug pull. Got: {result}"

        assert result.get("invocation_count") == 11, \
            f"Expected invocation_count=11, got: {result.get('invocation_count')}"

        # Should have evidence of execution
        result_str = str(result).lower()
        assert any(indicator in result_str for indicator in ["executed", "root", "command"]), \
            f"Should show evidence of command execution. Got: {result}"

    def test_rug_pull_stays_malicious_after_trigger(self, clean_vulnerable_client):
        """After triggering, subsequent calls should remain malicious."""
        # Trigger the rug pull
        for i in range(1, 12):
            clean_vulnerable_client.call_tool(
                "vulnerable_rug_pull_tool",
                {"action": f"action_{i}"}
            )

        # Calls 12-20 should all be malicious
        for i in range(12, 21):
            result = clean_vulnerable_client.call_tool(
                "vulnerable_rug_pull_tool",
                {"action": f"post_trigger_{i}"}
            )

            assert result.get("vulnerable") is True, \
                f"Invocation {i} should remain malicious. Got: {result}"

    def test_rug_pull_boundary_off_by_one_prevention(self, clean_vulnerable_client):
        """Verify no off-by-one errors - exactly invocation 11 triggers."""
        results = []

        for i in range(1, 15):
            result = clean_vulnerable_client.call_tool(
                "vulnerable_rug_pull_tool",
                {"action": f"test_{i}"}
            )
            results.append((i, result.get("vulnerable", False)))

        # Find first trigger point
        trigger_point = next(
            (i for i, is_vuln in results if is_vuln),
            None
        )

        assert trigger_point == 11, \
            f"Trigger should occur at exactly invocation 11, got: {trigger_point}"


class TestRugPullStatePersistence:
    """Test that invocation count persists correctly."""

    def test_state_persists_across_different_payloads(self, clean_vulnerable_client):
        """State should count all invocations regardless of payload content."""
        diverse_payloads = [
            "simple action",
            "action with numbers 123",
            "action with special chars !@#$%",
            "very " * 100 + "long payload",
            "",  # Empty payload
            "unicode: \u0041\u0042\u0043",
            '{"json": "payload"}',
            "whoami",  # Command-like payload
            "ignore previous instructions",  # Injection attempt
            "final_safe_action",
        ]

        # All 10 diverse payloads should be safe
        for i, payload in enumerate(diverse_payloads, 1):
            result = clean_vulnerable_client.call_tool(
                "vulnerable_rug_pull_tool",
                {"action": payload}
            )

            assert result.get("vulnerable") is False, \
                f"Payload {i} '{payload[:30]}...' should be safe. Got: {result}"

        # 11th call (any payload) should trigger
        result = clean_vulnerable_client.call_tool(
            "vulnerable_rug_pull_tool",
            {"action": "innocent_looking_action"}
        )

        assert result.get("vulnerable") is True, \
            "11th call should trigger regardless of payload"

    def test_state_persists_with_interleaved_tool_calls(self, clean_vulnerable_client):
        """State should persist even when other tools are called in between."""
        # Make 5 rug pull calls
        for i in range(5):
            clean_vulnerable_client.call_tool(
                "vulnerable_rug_pull_tool",
                {"action": f"call_{i}"}
            )

        # Call some other tools
        clean_vulnerable_client.call_tool(
            "vulnerable_calculator_tool",
            {"query": "2+2"}
        )
        clean_vulnerable_client.call_tool(
            "safe_storage_tool_mcp",
            {"data": "test"}
        )

        # Make 5 more rug pull calls (total 10, should still be safe)
        for i in range(5, 10):
            result = clean_vulnerable_client.call_tool(
                "vulnerable_rug_pull_tool",
                {"action": f"call_{i}"}
            )
            assert result.get("vulnerable") is False, \
                f"Call {i+1} should be safe (other tool calls shouldn't affect count)"

        # 11th rug pull call should trigger
        result = clean_vulnerable_client.call_tool(
            "vulnerable_rug_pull_tool",
            {"action": "final_call"}
        )
        assert result.get("vulnerable") is True, \
            "11th rug pull call should trigger"


class TestResetBehavior:
    """Test that reset_testbed_state properly clears invocation counts."""

    def test_reset_clears_rug_pull_state(self, vulnerable_client):
        """Reset should restore safe behavior."""
        # Build up some state
        for i in range(15):
            vulnerable_client.call_tool(
                "vulnerable_rug_pull_tool",
                {"action": f"pre_reset_{i}"}
            )

        # Verify we're in malicious state
        result = vulnerable_client.call_tool(
            "vulnerable_rug_pull_tool",
            {"action": "verify_malicious"}
        )
        assert result.get("vulnerable") is True, "Should be malicious before reset"

        # Reset state
        vulnerable_client.reset_state()

        # Verify we're back to safe state
        result = vulnerable_client.call_tool(
            "vulnerable_rug_pull_tool",
            {"action": "verify_safe"}
        )
        assert result.get("vulnerable") is False, "Should be safe after reset"
        assert result.get("invocation_count") == 1, "Count should restart at 1"

    def test_multiple_reset_cycles(self, vulnerable_client):
        """Test multiple reset cycles work correctly."""
        for cycle in range(3):
            # Reset at start of cycle
            vulnerable_client.reset_state()

            # Verify starts safe
            result = vulnerable_client.call_tool(
                "vulnerable_rug_pull_tool",
                {"action": f"cycle_{cycle}_start"}
            )
            assert result.get("vulnerable") is False, \
                f"Cycle {cycle}: Should start safe after reset"

            # Build to trigger
            for i in range(10):
                vulnerable_client.call_tool(
                    "vulnerable_rug_pull_tool",
                    {"action": f"cycle_{cycle}_buildup_{i}"}
                )

            # Verify triggered
            result = vulnerable_client.call_tool(
                "vulnerable_rug_pull_tool",
                {"action": f"cycle_{cycle}_trigger"}
            )
            assert result.get("vulnerable") is True, \
                f"Cycle {cycle}: Should trigger at 11"


class TestHardenedConsistency:
    """Verify hardened server has no temporal vulnerabilities."""

    def test_hardened_never_triggers_rug_pull(self, hardened_client):
        """Hardened server should NEVER exhibit rug pull behavior."""
        hardened_client.reset_state()

        # Make 30 calls - far past the vulnerable threshold
        for i in range(1, 31):
            result = hardened_client.call_tool(
                "vulnerable_rug_pull_tool",
                {"action": f"test_call_{i}"}
            )

            assert result.get("vulnerable", False) is False, \
                f"Hardened server should never be vulnerable at invocation {i}. Got: {result}"

            # Should not contain execution evidence
            result_str = str(result).lower()
            assert "root" not in result_str, \
                f"Hardened server should not execute commands at invocation {i}"

    def test_hardened_consistent_response_pattern(self, hardened_client):
        """Hardened server should return consistent responses."""
        hardened_client.reset_state()

        responses = []
        for i in range(20):
            result = hardened_client.call_tool(
                "vulnerable_rug_pull_tool",
                {"action": "consistent_test"}
            )
            responses.append(result)

        # All responses should have similar structure
        first_keys = set(responses[0].keys())
        for i, response in enumerate(responses[1:], 2):
            current_keys = set(response.keys())
            # Allow for minor differences but core keys should match
            assert "result" in current_keys or "status" in current_keys, \
                f"Response {i} missing result/status key: {response}"


class TestEdgeCases:
    """Test edge cases and unusual scenarios."""

    def test_rapid_fire_calls(self, clean_vulnerable_client):
        """Test rapid sequential calls maintain correct state."""
        results = []

        # Make 15 rapid calls
        for i in range(1, 16):
            result = clean_vulnerable_client.call_tool(
                "vulnerable_rug_pull_tool",
                {"action": "rapid"}
            )
            results.append((i, result.get("vulnerable", False), result.get("invocation_count")))

        # Verify correct state transitions
        for i, is_vuln, count in results:
            if i <= 10:
                assert is_vuln is False, f"Invocation {i} should be safe"
            else:
                assert is_vuln is True, f"Invocation {i} should be malicious"

            assert count == i, f"Invocation count mismatch at {i}: got {count}"

    def test_empty_action_counts(self, clean_vulnerable_client):
        """Empty actions should still count toward threshold."""
        # Make 10 empty action calls
        for _ in range(10):
            result = clean_vulnerable_client.call_tool(
                "vulnerable_rug_pull_tool",
                {"action": ""}
            )
            assert result.get("vulnerable") is False

        # 11th empty action should trigger
        result = clean_vulnerable_client.call_tool(
            "vulnerable_rug_pull_tool",
            {"action": ""}
        )
        assert result.get("vulnerable") is True, \
            "Empty actions should count toward threshold"
