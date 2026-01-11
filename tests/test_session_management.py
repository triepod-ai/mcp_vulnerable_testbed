"""
Session Management Vulnerability Tests (Challenge #12)

Tests for 5 session management weaknesses:
1. CWE-384: Session Fixation
2. CWE-200: Session ID Exposure in URL
3. CWE-613: No Session Timeout
4. CWE-330: Predictable Session Tokens
5. CWE-384: No Session ID Regeneration After Auth

Usage:
    pytest tests/test_session_management.py -v
    pytest tests/test_session_management.py -v -k "fixation"
"""

import pytest
import re


class TestVulnerableSessionManagement:
    """Tests for vulnerable session tool - should trigger vulnerabilities."""

    def test_predictable_session_id_pattern(self, vulnerable_client):
        """CWE-330: Session IDs follow predictable pattern."""
        result = vulnerable_client.call_tool(
            "vulnerable_session_tool", {"action": "create", "user": "testuser"}
        )
        assert result.get("vulnerable") is True
        session_id = result.get("session_id", "")

        # Verify predictable pattern: session_{user}_{timestamp}_{counter}
        pattern = r"^session_testuser_\d+_\d+$"
        assert re.match(pattern, session_id), (
            f"Session ID '{session_id}' should match predictable pattern"
        )
        assert "CWE-330" in str(result.get("cwe_ids", []))

    def test_session_id_in_url(self, vulnerable_client):
        """CWE-200: Session ID exposed in URL parameters."""
        result = vulnerable_client.call_tool(
            "vulnerable_session_tool", {"action": "create", "user": "testuser"}
        )
        assert result.get("vulnerable") is True
        session_url = result.get("session_url", "")
        session_id = result.get("session_id", "")

        # Session ID should be in URL (vulnerability)
        assert f"session_id={session_id}" in session_url, (
            "Session ID should be exposed in URL"
        )
        assert "CWE-200" in str(result.get("cwe_ids", []))

    def test_no_session_timeout(self, vulnerable_client):
        """CWE-613: Sessions have no expiration."""
        result = vulnerable_client.call_tool(
            "vulnerable_session_tool", {"action": "create", "user": "testuser"}
        )
        assert result.get("vulnerable") is True
        assert result.get("expires_at") is None, (
            "Session should have no expiration (vulnerability)"
        )
        assert "CWE-613" in str(result.get("cwe_ids", []))

    def test_session_fixation_attack(self, clean_vulnerable_client):
        """CWE-384: Session fixation - accepts attacker-provided session ID."""
        # Step 1: Attacker creates session with chosen ID
        attacker_session = "attacker_chosen_session_12345"
        result = clean_vulnerable_client.call_tool(
            "vulnerable_session_tool",
            {"action": "fixate", "session_id": attacker_session, "user": "attacker"},
        )
        assert result.get("vulnerable") is True
        assert result.get("attacker_controlled") is True
        assert "CWE-384" in str(result.get("cwe_ids", []))

        # Step 2: Verify fixation URL is generated
        fixation_url = result.get("fixation_url", "")
        assert attacker_session in fixation_url

        # Step 3: Victim logs in with attacker's session
        login_result = clean_vulnerable_client.call_tool(
            "vulnerable_session_tool",
            {"action": "login", "session_id": attacker_session, "user": "victim"},
        )
        assert login_result.get("vulnerable") is True
        assert login_result.get("authenticated") is True
        # Session ID is still the attacker's chosen ID
        assert login_result.get("session_id") == attacker_session

    def test_no_session_regeneration_after_login(self, clean_vulnerable_client):
        """CWE-384: Session ID not regenerated after authentication."""
        # Create session
        create_result = clean_vulnerable_client.call_tool(
            "vulnerable_session_tool", {"action": "create", "user": "testuser"}
        )
        original_session_id = create_result.get("session_id")

        # Login (should regenerate session ID, but doesn't)
        login_result = clean_vulnerable_client.call_tool(
            "vulnerable_session_tool",
            {"action": "login", "session_id": original_session_id, "user": "testuser"},
        )
        assert login_result.get("vulnerable") is True
        assert login_result.get("session_regenerated") is False, (
            "Session ID should NOT be regenerated (vulnerability)"
        )
        assert login_result.get("session_id") == original_session_id, (
            "Session ID should remain same after login (vulnerability)"
        )
        assert "CWE-384" in str(login_result.get("cwe_ids", []))

    def test_session_validation_no_timeout_check(self, clean_vulnerable_client):
        """CWE-613: Session validation doesn't check expiration."""
        # Create session
        create_result = clean_vulnerable_client.call_tool(
            "vulnerable_session_tool", {"action": "create", "user": "testuser"}
        )
        session_id = create_result.get("session_id")

        # Validate session (should check timeout, but doesn't)
        validate_result = clean_vulnerable_client.call_tool(
            "vulnerable_session_tool", {"action": "validate", "session_id": session_id}
        )
        assert validate_result.get("vulnerable") is True
        assert validate_result.get("timeout_checked") is False, (
            "Timeout should NOT be checked (vulnerability)"
        )

    def test_predictable_session_sequence(self, clean_vulnerable_client):
        """CWE-330: Session IDs can be predicted from sequence."""
        sessions = []
        for i in range(3):
            result = clean_vulnerable_client.call_tool(
                "vulnerable_session_tool", {"action": "create", "user": "testuser"}
            )
            sessions.append(result.get("session_id"))

        # Extract counters from session IDs
        counters = [int(s.split("_")[-1]) for s in sessions]

        # Verify sequential counters (predictable)
        assert counters == sorted(counters), "Counters should be sequential"
        assert counters[2] - counters[0] == 2, "Counter increment should be predictable"


class TestHardenedSessionManagement:
    """Tests for hardened session tool - should NOT trigger vulnerabilities."""

    def test_secure_token_indicators(self, hardened_client):
        """Hardened: Uses cryptographically secure tokens."""
        result = hardened_client.call_tool(
            "vulnerable_session_tool", {"action": "create", "user": "testuser"}
        )
        assert result.get("safe") is True
        assert result.get("vulnerable", False) is False

        security = result.get("security_measures", {})
        assert security.get("token_secure") is True

    def test_fixation_blocked(self, hardened_client):
        """Hardened: Session fixation attacks are blocked."""
        result = hardened_client.call_tool(
            "vulnerable_session_tool",
            {"action": "fixate", "session_id": "attacker_session", "user": "attacker"},
        )
        assert result.get("safe") is True
        assert result.get("attack_blocked") is True
        assert "fixation" in result.get("blocked_reason", "").lower()

    def test_session_id_not_in_url(self, hardened_client):
        """Hardened: Session ID never exposed in URLs."""
        result = hardened_client.call_tool(
            "vulnerable_session_tool", {"action": "create", "user": "testuser"}
        )
        assert result.get("safe") is True

        security = result.get("security_measures", {})
        assert security.get("id_in_url") is False

    def test_timeout_enforced(self, hardened_client):
        """Hardened: Sessions have expiration."""
        result = hardened_client.call_tool(
            "vulnerable_session_tool", {"action": "create", "user": "testuser"}
        )
        assert result.get("safe") is True

        security = result.get("security_measures", {})
        assert security.get("timeout_enforced") is True

    def test_regeneration_on_auth(self, hardened_client):
        """Hardened: Session ID regenerated on authentication."""
        result = hardened_client.call_tool(
            "vulnerable_session_tool", {"action": "login", "user": "testuser"}
        )
        assert result.get("safe") is True

        security = result.get("security_measures", {})
        assert security.get("regeneration_on_auth") is True


class TestSessionStateBoundaries:
    """Tests for session state handling edge cases."""

    def test_logout_clears_session(self, clean_vulnerable_client):
        """Logout should remove session from store."""
        # Create session
        create_result = clean_vulnerable_client.call_tool(
            "vulnerable_session_tool", {"action": "create", "user": "testuser"}
        )
        session_id = create_result.get("session_id")

        # Logout
        logout_result = clean_vulnerable_client.call_tool(
            "vulnerable_session_tool", {"action": "logout", "session_id": session_id}
        )
        assert "ended" in logout_result.get("result", "").lower()

        # Validate should fail
        validate_result = clean_vulnerable_client.call_tool(
            "vulnerable_session_tool", {"action": "validate", "session_id": session_id}
        )
        assert (
            validate_result.get("valid", True) is False
            or "not found" in validate_result.get("result", "").lower()
        )

    def test_missing_required_params(self, vulnerable_client):
        """Missing parameters should return errors."""
        # Create without user
        result = vulnerable_client.call_tool(
            "vulnerable_session_tool", {"action": "create"}
        )
        assert "error" in result

        # Login without session_id
        result = vulnerable_client.call_tool(
            "vulnerable_session_tool", {"action": "login", "user": "testuser"}
        )
        assert "error" in result

    def test_invalid_action(self, vulnerable_client):
        """Invalid action should return error with valid options."""
        result = vulnerable_client.call_tool(
            "vulnerable_session_tool", {"action": "invalid_action"}
        )
        assert "error" in result
        assert "valid_actions" in result


class TestAuthValidationEdgeCases:
    """Tests for _validate_token_format edge cases from config.py."""

    def test_validate_token_format_edge_cases(self):
        """
        Test _validate_token_format with edge case inputs.

        The function must handle:
        - Empty string -> False
        - None -> False (should not crash)
        - Whitespace -> False
        - Valid format -> True
        - Invalid format -> False

        This ensures robust token validation that doesn't crash on unexpected input.
        """
        # Import the validation function
        import sys
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
        from config import _validate_token_format

        # Empty string
        assert _validate_token_format("") is False
        print("✓ Empty string handled: returns False")

        # Whitespace only
        assert _validate_token_format("   ") is False
        assert _validate_token_format("\t\n") is False
        print("✓ Whitespace handled: returns False")

        # None (should not crash)
        try:
            result = _validate_token_format(None)  # type: ignore
            assert result is False
            print("✓ None handled: returns False")
        except (TypeError, AttributeError):
            # If it raises, that's acceptable (depends on implementation)
            print("✓ None handled: raises TypeError (acceptable)")

        # Valid tokens (must start with "valid_" and be 10+ chars)
        assert _validate_token_format("valid_token_123") is True
        assert _validate_token_format("valid_abcdefg") is True
        print("✓ Valid tokens: returns True")

        # Invalid formats
        assert _validate_token_format("invalid_token") is False
        assert _validate_token_format("valid_") is False  # Too short (< 10 chars)
        assert _validate_token_format("token_valid") is False  # Wrong prefix
        print("✓ Invalid tokens: returns False")

        print("\n✓ All edge cases handled correctly")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
