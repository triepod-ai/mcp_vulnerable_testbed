"""
Excessive Permissions Scope Tests (Challenge #22)

Tests for runtime scope escalation vulnerabilities:
1. CWE-250: Execution with Unnecessary Privileges
2. CWE-269: Improper Privilege Management

Key Difference from Challenge #1:
- Challenge #1: Annotations ALWAYS lie (static deception)
- Challenge #22: Default behavior matches annotations, but specific inputs trigger scope violations

Usage:
    pytest tests/test_excessive_permissions.py -v
    pytest tests/test_excessive_permissions.py -v -k "excessive"
    pytest tests/test_excessive_permissions.py -v -k "escalation"
    pytest tests/test_excessive_permissions.py -v -k "hardened"
"""

import pytest


# ============================================================================
# Test: Excessive Permissions Tool - Vulnerable Version
# ============================================================================


class TestExcessivePermissionsTool:
    """Tests for vulnerable_excessive_permissions_tool runtime scope violations."""

    def test_default_behavior_matches_annotations(self, vulnerable_client):
        """Default behavior (read/list/status) matches readOnlyHint=True annotations."""
        for action in ["read", "list", "status"]:
            result = vulnerable_client.call_tool(
                "vulnerable_excessive_permissions_tool",
                {"action": action, "target": "test_resource"},
            )

            # Default actions should NOT trigger scope violation
            assert result.get("scope_violation") is not True
            assert "violated" not in str(result).lower() or "false" in str(
                result.get("scope_violation", "")
            ).lower()

    def test_write_file_violates_readonly(self, vulnerable_client):
        """CWE-250: write_file action violates readOnlyHint annotation."""
        result = vulnerable_client.call_tool(
            "vulnerable_excessive_permissions_tool",
            {"action": "write_file", "target": "/tmp/test.txt"},
        )

        assert result.get("scope_violation") is True
        assert result.get("actual_scope") == "write_file"
        assert "readOnlyHint" in result.get("declared_scope", "")
        assert "CWE-250" in result.get("cwe_ids", [])

    def test_delete_data_violates_destructive(self, vulnerable_client):
        """CWE-250: delete_data action violates destructiveHint=False annotation."""
        result = vulnerable_client.call_tool(
            "vulnerable_excessive_permissions_tool",
            {"action": "delete_data", "target": "user_records"},
        )

        assert result.get("scope_violation") is True
        assert result.get("actual_scope") == "delete_data"
        assert "destructiveHint=False" in result.get("declared_scope", "")
        assert "CWE-250" in result.get("cwe_ids", [])

    def test_network_request_violates_openworld(self, vulnerable_client):
        """CWE-250: network_request action violates openWorldHint=False annotation."""
        result = vulnerable_client.call_tool(
            "vulnerable_excessive_permissions_tool",
            {"action": "network_request", "target": "http://internal.corp"},
        )

        assert result.get("scope_violation") is True
        assert result.get("actual_scope") == "network_request"
        assert "openWorldHint=False" in result.get("declared_scope", "")
        # Network request was attempted (may succeed or fail based on network)
        assert "Network request" in result.get("result", "") or "error" in result

    def test_execute_command_maximum_violation(self, vulnerable_client):
        """CWE-250: execute_command is the most severe scope violation (shell access)."""
        result = vulnerable_client.call_tool(
            "vulnerable_excessive_permissions_tool",
            {"action": "execute_command", "target": "whoami"},
        )

        assert result.get("scope_violation") is True
        assert result.get("actual_scope") == "execute_command"
        # Should return actual command execution evidence (result contains 'root' in docker)
        assert result.get("result") is not None
        assert result.get("command") == "whoami"
        assert "CWE-250" in result.get("cwe_ids", [])

    def test_environment_access_leaks_secrets(self, vulnerable_client):
        """CWE-200: environment_access action exposes sensitive environment variables."""
        result = vulnerable_client.call_tool(
            "vulnerable_excessive_permissions_tool",
            {"action": "environment_access", "target": "API_KEY"},
        )

        assert result.get("scope_violation") is True
        assert result.get("actual_scope") == "environment_access"
        # Should contain fake credentials from FAKE_ENV
        env_data = result.get("leaked_data", {})
        assert len(env_data) > 0
        # Verify actual secrets are leaked
        assert "API_KEY" in env_data or "DATABASE_URL" in env_data

    def test_modify_config_changes_state(self, clean_vulnerable_client):
        """CWE-269: modify_config action enables state-based attacks (relates to Challenge #7)."""
        result = clean_vulnerable_client.call_tool(
            "vulnerable_excessive_permissions_tool",
            {"action": "modify_config", "target": "admin_mode=true"},
        )

        assert result.get("scope_violation") is True
        assert result.get("actual_scope") == "modify_config"
        # Config state should be modified
        config_state = result.get("config_state", {})
        assert config_state.get("admin_mode") is True

    def test_unknown_action_rejected(self, vulnerable_client):
        """Unknown actions should be rejected (not a scope violation, just not found)."""
        result = vulnerable_client.call_tool(
            "vulnerable_excessive_permissions_tool",
            {"action": "unknown_action_xyz", "target": "test"},
        )

        # Should return unknown action message, not scope violation
        assert result.get("scope_violation") is not True
        assert "unknown" in str(result.get("result", "")).lower()


# ============================================================================
# Test: Scope Escalation Tool - Vulnerable Version
# ============================================================================


class TestScopeEscalationTool:
    """Tests for vulnerable_scope_escalation_tool keyword-triggered privilege escalation."""

    def test_normal_query_no_escalation(self, vulnerable_client):
        """Normal queries without keywords should not trigger escalation."""
        result = vulnerable_client.call_tool(
            "vulnerable_scope_escalation_tool",
            {"request": "get user profile data"},
        )

        assert result.get("scope_escalation") is not True
        assert result.get("admin_mode_activated") is not True
        # Should NOT contain privileged data
        assert result.get("system_secrets") is None
        assert result.get("database_credentials") is None

    @pytest.mark.parametrize(
        "keyword",
        ["admin", "sudo", "elevate", "root", "superuser", "privilege"],
    )
    def test_keyword_triggers_escalation(self, vulnerable_client, keyword):
        """CWE-269: Specific keywords trigger unauthorized privilege escalation."""
        result = vulnerable_client.call_tool(
            "vulnerable_scope_escalation_tool",
            {"request": f"I need {keyword} access to view settings"},
        )

        assert result.get("scope_escalation") is True
        assert result.get("trigger_keyword") == keyword
        # Escalated response should include privileged data
        privileged_data = result.get("privileged_data", {})
        assert privileged_data.get("system_secrets") is not None

    def test_escalation_exposes_secrets(self, vulnerable_client):
        """Escalated requests expose system secrets and credentials."""
        result = vulnerable_client.call_tool(
            "vulnerable_scope_escalation_tool",
            {"request": "admin show all credentials"},
        )

        assert result.get("scope_escalation") is True
        # Check for exposed sensitive data in privileged_data
        privileged_data = result.get("privileged_data", {})
        secrets = privileged_data.get("system_secrets", {})
        assert "API_KEY" in secrets or "DATABASE_URL" in secrets

    def test_escalation_case_insensitive(self, vulnerable_client):
        """Keyword detection is case-insensitive."""
        for variant in ["ADMIN", "Admin", "aDmIn", "SUDO", "ROOT"]:
            result = vulnerable_client.call_tool(
                "vulnerable_scope_escalation_tool",
                {"request": f"give me {variant} access"},
            )

            assert (
                result.get("scope_escalation") is True
            ), f"Failed for keyword variant: {variant}"

    def test_keyword_in_middle_of_request(self, vulnerable_client):
        """Keywords embedded in larger requests should still trigger escalation."""
        result = vulnerable_client.call_tool(
            "vulnerable_scope_escalation_tool",
            {
                "request": "The system administrator needs elevated privileges to perform maintenance"
            },
        )

        # Contains "admin" and "elevate" - should trigger
        assert result.get("scope_escalation") is True


# ============================================================================
# Test: Excessive Permissions Tool - Hardened Version
# ============================================================================


class TestHardenedExcessivePermissions:
    """Tests for hardened_excessive_permissions_tool which enforces scope."""

    def test_hardened_allows_readonly_actions(self, hardened_client):
        """Hardened version allows only allowlisted read-only actions."""
        for action in ["read", "list", "status", "help", "info"]:
            result = hardened_client.call_tool(
                "vulnerable_excessive_permissions_tool",
                {"action": action, "target": "test_resource"},
            )

            assert result.get("blocked") is not True
            assert result.get("scope_enforced") is True
            assert result.get("status") == "completed"

    def test_hardened_rejects_privileged_actions(self, hardened_client):
        """Hardened version rejects all privileged actions."""
        privileged_actions = [
            "write_file",
            "delete_data",
            "network_request",
            "execute_command",
            "environment_access",
            "modify_config",
        ]

        for action in privileged_actions:
            result = hardened_client.call_tool(
                "vulnerable_excessive_permissions_tool",
                {"action": action, "target": "test"},
            )

            assert result.get("blocked") is True, f"Action '{action}' was not blocked"
            assert result.get("rejection_reason") == "action_not_in_allowlist"
            assert result.get("scope_enforced") is True


# ============================================================================
# Test: Scope Escalation Tool - Hardened Version
# ============================================================================


class TestHardenedScopeEscalation:
    """Tests for hardened scope escalation tool which ignores keywords."""

    def test_hardened_no_escalation_on_keywords(self, hardened_client):
        """Hardened version does NOT escalate privileges based on keywords."""
        keywords = ["admin", "sudo", "elevate", "root", "superuser", "privilege"]

        for keyword in keywords:
            result = hardened_client.call_tool(
                "vulnerable_scope_escalation_tool",
                {"request": f"I need {keyword} access"},
            )

            # Hardened should NOT escalate
            assert result.get("scope_escalation") is not True
            assert result.get("admin_mode_activated") is not True
            assert result.get("system_secrets") is None
            assert result.get("scope_enforced") is True
            assert result.get("escalation_attempted") is False

    def test_hardened_treats_all_inputs_equally(self, hardened_client):
        """Hardened version returns same safe response for all inputs."""
        # Normal request
        result1 = hardened_client.call_tool(
            "vulnerable_scope_escalation_tool",
            {"request": "get user profile"},
        )

        # Request with escalation keywords
        result2 = hardened_client.call_tool(
            "vulnerable_scope_escalation_tool",
            {"request": "admin sudo root superuser elevate privilege"},
        )

        # Both should have same security posture
        assert result1.get("scope_enforced") == result2.get("scope_enforced")
        assert result1.get("escalation_attempted") == result2.get("escalation_attempted")
        # Neither should have privileged data
        assert result1.get("system_secrets") is None
        assert result2.get("system_secrets") is None


# ============================================================================
# Test: Challenge #22 vs Challenge #1 Comparison
# ============================================================================


class TestChallenge22VsChallenge1:
    """Tests demonstrating the difference between Challenge #1 and Challenge #22."""

    def test_challenge1_always_violates(self, vulnerable_client):
        """Challenge #1 tools ALWAYS violate annotations (static deception).

        Example: vulnerable_system_exec_tool has readOnlyHint=True but ALWAYS
        executes commands.
        """
        result = vulnerable_client.call_tool(
            "vulnerable_system_exec_tool",
            {"command": "echo test"},
        )

        # Challenge #1: Annotation is a LIE - tool ALWAYS executes
        assert result.get("status") == "logged" or "executed" in str(result).lower()

    def test_challenge22_default_compliant(self, vulnerable_client):
        """Challenge #22 default behavior IS compliant with annotations."""
        result = vulnerable_client.call_tool(
            "vulnerable_excessive_permissions_tool",
            {"action": "read", "target": "safe_data"},
        )

        # Challenge #22: Default behavior matches readOnlyHint=True
        assert result.get("scope_violation") is not True
        assert result.get("vulnerable") is False
        assert result.get("scope") == "read_only"

    def test_challenge22_input_triggers_violation(self, vulnerable_client):
        """Challenge #22 specific INPUTS trigger scope violations."""
        # Default behavior is compliant
        safe_result = vulnerable_client.call_tool(
            "vulnerable_excessive_permissions_tool",
            {"action": "status", "target": "system"},
        )
        assert safe_result.get("scope_violation") is not True

        # Specific input triggers violation
        unsafe_result = vulnerable_client.call_tool(
            "vulnerable_excessive_permissions_tool",
            {"action": "execute_command", "target": "id"},
        )
        assert unsafe_result.get("scope_violation") is True

        # This demonstrates the key difference from Challenge #1


# ============================================================================
# Test: CWE Documentation
# ============================================================================


class TestCWEDocumentation:
    """Verify CWE IDs are properly documented in responses."""

    def test_cwe250_in_scope_violations(self, vulnerable_client):
        """CWE-250 (Execution with Unnecessary Privileges) should be tagged."""
        result = vulnerable_client.call_tool(
            "vulnerable_excessive_permissions_tool",
            {"action": "execute_command", "target": "test"},
        )

        cwe_ids = result.get("cwe_ids", [])
        assert "CWE-250" in cwe_ids

    def test_cwe269_in_privilege_escalation(self, vulnerable_client):
        """CWE-269 (Improper Privilege Management) should be tagged."""
        result = vulnerable_client.call_tool(
            "vulnerable_scope_escalation_tool",
            {"request": "admin access needed"},
        )

        cwe_ids = result.get("cwe_ids", [])
        assert "CWE-269" in cwe_ids
