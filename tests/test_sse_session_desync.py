"""
SSE Session Desync Vulnerability Tests (Challenge #19)

Tests for 4 SSE session management weaknesses:
1. CWE-330: Predictable Event IDs (sequential integers)
2. CWE-287: No Event ID Validation (accepts any Last-Event-ID)
3. CWE-384: Session Scope Bypass (events not bound to sessions)
4. CWE-613: No Event Expiration (events never expire)

Usage:
    pytest tests/test_sse_session_desync.py -v
    pytest tests/test_sse_session_desync.py -v -k "predictable"
    pytest tests/test_sse_session_desync.py -v -k "replay"
"""

import inspect
import pytest


class TestDocumentationAndDesignDecisions:
    """Tests for documentation clarity and intentional design decisions."""

    def test_challenge3_design_decision_documented(self):
        """Validates FIX-001: Documentation clarifies intentional Challenge #3 design decision.

        Covers ISSUE-002: Missing documentation explaining why event_data lacks input validation.
        This test verifies that the function docstring explicitly documents the intentional
        lack of input validation as part of Challenge #3 (DoS via Unbounded Input).
        """
        # Read the source file directly to check docstring
        from pathlib import Path

        src_file = Path(__file__).parent.parent / "src" / "vulnerable_tools.py"
        source_code = src_file.read_text()

        # Find the vulnerable_sse_reconnect function docstring
        # Look for the function definition and its docstring
        func_start = source_code.find("def vulnerable_sse_reconnect(")
        assert func_start > 0, "Function vulnerable_sse_reconnect should exist"

        # Extract docstring (between triple quotes after function def)
        docstring_start = source_code.find('"""', func_start)
        docstring_end = source_code.find('"""', docstring_start + 3)
        docstring = source_code[docstring_start + 3:docstring_end]

        assert docstring is not None and len(docstring) > 0, "Function should have docstring"

        # Verify Challenge #3 is explicitly mentioned
        assert "Challenge #3" in docstring, (
            "Docstring should reference Challenge #3"
        )

        # Verify unbounded input explanation
        assert "unbounded input" in docstring.lower(), (
            "Docstring should explain unbounded input vulnerability"
        )

        # Verify it mentions event_data parameter specifically
        assert "event_data" in docstring, (
            "Docstring should mention event_data parameter"
        )

        # Verify it clarifies this is intentional, not an oversight
        assert "intentionally" in docstring.lower() or "intentional" in docstring.lower(), (
            "Docstring should clarify this is an intentional design decision"
        )

        # Verify comparison to safe tools
        assert "safe tools" in docstring.lower(), (
            "Docstring should compare to safe tools' behavior"
        )

        # Verify mention of 10KB limit (what safe tools enforce)
        assert "10kb" in docstring.lower() or "10 kb" in docstring.lower(), (
            "Docstring should mention the 10KB limit that safe tools enforce"
        )


class TestPredictableEventIDs:
    """Tests for CWE-330: Predictable event ID pattern."""

    def test_sequential_event_id_pattern(self, clean_vulnerable_client):
        """CWE-330: Event IDs are sequential integers."""
        # Generate first event
        result1 = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "generate_event", "session_id": "session_a"},
        )
        assert result1.get("vulnerable") is True
        event_id_1 = result1.get("event_id")

        # Generate second event
        result2 = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "generate_event", "session_id": "session_a"},
        )
        event_id_2 = result2.get("event_id")

        # Verify sequential pattern
        assert int(event_id_2) == int(event_id_1) + 1, (
            f"Event IDs should be sequential: {event_id_1} -> {event_id_2}"
        )
        assert "CWE-330" in str(result1.get("cwe_ids", []))

    def test_event_id_prediction_attack(self, clean_vulnerable_client):
        """Event ID can be predicted from previous IDs."""
        result = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "generate_event", "session_id": "session_a"},
        )
        assert result.get("vulnerable") is True

        # Tool leaks the next expected ID
        next_expected = result.get("next_expected_id")
        current_id = result.get("event_id")

        assert next_expected is not None, "Tool should leak next expected ID"
        assert int(next_expected) == int(current_id) + 1

    def test_event_pattern_exposed(self, clean_vulnerable_client):
        """Event ID pattern is explicitly exposed in response."""
        result = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "generate_event", "session_id": "session_a"},
        )
        assert result.get("vulnerable") is True
        assert result.get("event_pattern") == "sequential_integer", (
            "Tool should expose the predictable pattern"
        )

    def test_multiple_events_all_sequential(self, clean_vulnerable_client):
        """Multiple events are all sequential integers."""
        event_ids = []
        for i in range(5):
            result = clean_vulnerable_client.call_tool(
                "vulnerable_sse_reconnect_tool",
                {"action": "generate_event", "session_id": "session_a"},
            )
            event_ids.append(int(result.get("event_id")))

        # All IDs should be sequential
        for i in range(1, len(event_ids)):
            assert event_ids[i] == event_ids[i - 1] + 1, (
                f"Event IDs must be sequential: {event_ids}"
            )

    def test_counter_increments_globally(self, clean_vulnerable_client):
        """Event counter is global, not session-scoped."""
        # Session A creates event
        result_a = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "generate_event", "session_id": "session_a"},
        )
        id_a = int(result_a.get("event_id"))

        # Session B creates event - ID should continue from session A
        result_b = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "generate_event", "session_id": "session_b"},
        )
        id_b = int(result_b.get("event_id"))

        assert id_b == id_a + 1, (
            "Event counter should be global (vulnerability)"
        )


class TestEventReplayAttack:
    """Tests for CWE-287: Event replay without validation."""

    def test_reconnect_returns_events(self, clean_vulnerable_client):
        """Reconnect returns all events after Last-Event-ID."""
        # Generate some events
        for i in range(3):
            clean_vulnerable_client.call_tool(
                "vulnerable_sse_reconnect_tool",
                {"action": "generate_event", "session_id": "session_a"},
            )

        # Reconnect from event 1
        result = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "reconnect", "last_event_id": "1", "session_id": "session_a"},
        )
        assert result.get("vulnerable") is True
        assert result.get("event_count") >= 2, "Should return events after ID 1"

    def test_no_session_validation_on_reconnect(self, clean_vulnerable_client):
        """Reconnect doesn't validate session ownership."""
        # Session A creates sensitive event
        clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {
                "action": "generate_sensitive_event",
                "session_id": "session_a",
            },
        )

        # Session B reconnects and gets session A's events
        result = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "reconnect", "session_id": "session_b"},
        )

        assert result.get("vulnerable") is True
        assert result.get("session_validated") is False, (
            "Session should NOT be validated (vulnerability)"
        )

    def test_cross_session_replay_attack(self, clean_vulnerable_client):
        """Session B can access session A's events via replay."""
        # Session A creates events
        result_a = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "generate_event", "session_id": "session_a"},
        )
        event_id_a = result_a.get("event_id")

        # Session B reconnects with ID 0 to get all events
        result_b = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "reconnect", "last_event_id": "0", "session_id": "session_b"},
        )

        assert result_b.get("vulnerable") is True
        # Check if session A's event is in session B's replay
        replayed = result_b.get("replayed_events", [])
        session_a_ids = [e["event_id"] for e in replayed if e.get("session_id") == "session_a"]
        assert event_id_a in session_a_ids, (
            "Session B should be able to replay session A's events (vulnerability)"
        )

    def test_sensitive_event_replay(self, clean_vulnerable_client):
        """Sensitive events can be replayed by other sessions."""
        # Create sensitive event with credentials
        create_result = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "generate_sensitive_event", "session_id": "session_a"},
        )
        assert create_result.get("contains_credentials") is True

        # Different session replays and gets credentials
        replay_result = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "reconnect", "session_id": "session_b"},
        )

        assert replay_result.get("vulnerable") is True
        assert replay_result.get("sensitive_data_exposed") is True, (
            "Sensitive data should be exposed via replay (vulnerability)"
        )

    def test_cwe_287_evidence(self, clean_vulnerable_client):
        """CWE-287 should be in evidence."""
        clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "generate_event", "session_id": "session_a"},
        )

        result = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "reconnect", "last_event_id": "0", "session_id": "session_b"},
        )

        assert "CWE-287" in str(result.get("cwe_ids", []))


class TestSessionScopeBypass:
    """Tests for CWE-384: Events not bound to sessions."""

    def test_events_not_bound_to_session(self, clean_vulnerable_client):
        """Events lack proper session binding."""
        result = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "generate_event", "session_id": "session_a"},
        )
        assert result.get("vulnerable") is True
        assert "CWE-384" in str(result.get("cwe_ids", []))

    def test_session_id_not_enforced(self, clean_vulnerable_client):
        """Session ID parameter is stored but not enforced on retrieval."""
        # Create event with session A
        clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "generate_event", "session_id": "session_a"},
        )

        # List events (no session filter)
        list_result = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "list_events"},
        )

        # All events visible regardless of session
        events = list_result.get("events", [])
        assert len(events) > 0
        # Session A's events are visible globally
        session_a_events = [e for e in events if e.get("session_id") == "session_a"]
        assert len(session_a_events) > 0, (
            "Session A events should be globally visible (vulnerability)"
        )

    def test_attacker_accesses_victim_events(self, clean_vulnerable_client):
        """Attacker session can access victim session's events."""
        # Victim creates sensitive event
        victim_result = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "generate_sensitive_event", "session_id": "victim_session"},
        )
        victim_event_id = victim_result.get("event_id")

        # Attacker reconnects and gets victim's events
        attacker_result = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "reconnect", "session_id": "attacker_session"},
        )

        assert attacker_result.get("cross_session_access") is True, (
            "Attacker should have cross-session access (vulnerability)"
        )


class TestNoEventExpiration:
    """Tests for CWE-613: Events never expire."""

    def test_events_never_expire(self, clean_vulnerable_client):
        """Generated events have no expiration time."""
        result = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "generate_event", "session_id": "session_a"},
        )
        assert result.get("vulnerable") is True
        assert result.get("expires_at") is None, (
            "Events should have no expiration (vulnerability)"
        )
        assert "CWE-613" in str(result.get("cwe_ids", []))

    def test_old_events_still_accessible(self, clean_vulnerable_client):
        """Old events remain accessible indefinitely."""
        # Create event
        create_result = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "generate_event", "session_id": "session_a"},
        )
        event_id = create_result.get("event_id")

        # Create more events
        for _ in range(5):
            clean_vulnerable_client.call_tool(
                "vulnerable_sse_reconnect_tool",
                {"action": "generate_event", "session_id": "session_a"},
            )

        # Old event should still be accessible
        list_result = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "list_events"},
        )
        event_ids = [e["event_id"] for e in list_result.get("events", [])]
        assert event_id in event_ids, "Old events should persist indefinitely"


class TestHardenedSSEReconnection:
    """Tests for hardened SSE reconnection tool - should NOT be vulnerable."""

    def test_safe_flag_set(self, hardened_client):
        """Hardened tool should return safe=True."""
        result = hardened_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "generate_event", "session_id": "session_a"},
        )
        assert result.get("safe") is True
        assert result.get("vulnerable", False) is False

    def test_security_measures_present(self, hardened_client):
        """Hardened tool should document security measures."""
        result = hardened_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "generate_event", "session_id": "session_a"},
        )
        security = result.get("security_measures", {})
        assert security.get("event_id_secure") is True
        assert security.get("session_bound") is True
        assert security.get("expiration_enforced") is True
        assert security.get("hmac_signed") is True

    def test_no_actual_events_created(self, hardened_client):
        """Hardened tool should store request, not create vulnerable events."""
        result = hardened_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "generate_event", "session_id": "session_a"},
        )
        assert result.get("event_created") is False
        assert result.get("status") == "pending_review"

    def test_reconnect_replay_blocked(self, hardened_client):
        """Hardened tool should block cross-session replay."""
        result = hardened_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "reconnect", "session_id": "session_a"},
        )
        assert result.get("replay_blocked") is True
        assert result.get("cwe_287_mitigated") is True
        assert result.get("cwe_384_mitigated") is True

    def test_sensitive_event_credentials_not_stored(self, hardened_client):
        """Hardened tool should not store credentials in events."""
        result = hardened_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "generate_sensitive_event", "session_id": "session_a"},
        )
        assert result.get("credentials_stored") is False
        assert result.get("cwe_200_mitigated") is True

    def test_cross_session_listing_blocked(self, hardened_client):
        """Hardened tool should block cross-session event listing."""
        result = hardened_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "list_events"},
        )
        assert result.get("cross_session_listing_blocked") is True


class TestEdgeCases:
    """Edge case tests for SSE reconnection tool."""

    def test_invalid_action_error(self, vulnerable_client):
        """Unknown action should return error."""
        result = vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "invalid_action"},
        )
        assert "error" in result or "Unknown action" in result.get("error", "")
        assert result.get("vulnerable", True) is False  # Error case not vulnerable

    def test_empty_session_id(self, clean_vulnerable_client):
        """Empty session ID should default to 'anonymous'."""
        result = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "generate_event"},
        )
        assert result.get("session_id") == "anonymous"

    def test_invalid_last_event_id_format(self, clean_vulnerable_client):
        """Invalid Last-Event-ID format should return error with hint."""
        # First create an event so the store isn't empty
        clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "generate_event"},
        )

        # Try invalid format
        result = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "reconnect", "last_event_id": "not_a_number"},
        )
        # Error message should leak valid ID range (vulnerability)
        assert result.get("vulnerable") is True
        assert "hint" in result or "Valid IDs" in str(result.get("hint", ""))

    def test_invalid_last_event_id_cwe_reporting(self, clean_vulnerable_client):
        """TEST-REQ-001: Invalid Last-Event-ID error path includes CWE-200 in cwe_ids array.

        Validates FIX-002: Added cwe_ids: ["CWE-200"] to error path at lines 3243-3253.
        Covers ISSUE-003: Missing cwe_ids array in invalid Last-Event-ID error path.
        """
        # First create an event so the store isn't empty
        clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "generate_event"},
        )

        # Try invalid format - should trigger error path with CWE-200
        result = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "reconnect", "last_event_id": "invalid_format_xyz"},
        )

        # Verify error response structure
        assert "error" in result, "Should return error for invalid format"
        assert result.get("vulnerable") is True, "Error path should be marked as vulnerable"

        # KEY TEST: Verify cwe_ids array is present and contains CWE-200
        cwe_ids = result.get("cwe_ids", [])
        assert isinstance(cwe_ids, list), "cwe_ids should be a list"
        assert "CWE-200" in cwe_ids, "CWE-200 (Information Exposure) should be in cwe_ids array"

        # Verify evidence field exists (consistent with other vulnerable paths)
        assert "evidence" in result, "Should include evidence field"
        assert "Information disclosure" in result.get("evidence", ""), (
            "Evidence should describe information disclosure vulnerability"
        )

    def test_empty_event_store_reconnect(self, clean_vulnerable_client):
        """TEST-REQ-002: Edge case when sse_event_store is empty.

        Tests reconnect behavior when no events exist in the store.
        Covers ISSUE-008: Empty event store edge case not covered in test suite.
        """
        # Ensure clean state with no events
        # (clean_vulnerable_client fixture already resets state)

        # Test 1: Reconnect when no events exist should return empty list without error
        result = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "reconnect"},
        )
        assert result.get("vulnerable") is True, "Should still be marked vulnerable"
        assert result.get("event_count") == 0, "Should return zero events"
        assert isinstance(result.get("replayed_events", []), list), "Should return empty list"
        assert len(result.get("replayed_events", [])) == 0, "replayed_events should be empty"

        # Test 2: Reconnect with last_event_id on empty store should handle gracefully
        result2 = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "reconnect", "last_event_id": "5"},
        )
        assert result2.get("vulnerable") is True
        assert result2.get("event_count") == 0, "Should return zero events even with last_event_id"

        # Test 3: List events on empty store should return valid empty response
        result3 = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "list_events"},
        )
        assert "events" in result3, "Should have events field"
        assert isinstance(result3.get("events", []), list), "events should be a list"
        assert len(result3.get("events", [])) == 0, "events list should be empty"
        assert result3.get("event_count") == 0, "event_count should be zero"

    def test_reconnect_without_last_event_id(self, clean_vulnerable_client):
        """Reconnect without Last-Event-ID returns all events."""
        # Create events
        for _ in range(3):
            clean_vulnerable_client.call_tool(
                "vulnerable_sse_reconnect_tool",
                {"action": "generate_event"},
            )

        # Reconnect without last_event_id
        result = clean_vulnerable_client.call_tool(
            "vulnerable_sse_reconnect_tool",
            {"action": "reconnect"},
        )
        assert result.get("vulnerable") is True
        assert result.get("event_count") >= 3
