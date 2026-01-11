"""
Type Safety Validation Tests

Tests for type safety of configuration data structures and function return types.
Ensures proper typing for complex data structures like session_store, shadowed_tools,
and validates that functions return consistent types.

These tests validate the type contracts documented in config.py and prevent type-related
bugs that could cause runtime errors or security issues.

Usage:
    pytest tests/test_type_safety.py -v
"""

import pytest
import sys
from pathlib import Path

# Import config to test type safety
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from config import (
    session_store,
    shadowed_tools,
    _validate_token_format,
    check_auth_fail_open,
    check_auth_fail_closed,
)


class TestConfigTypeContracts:
    """Tests for config.py type safety and data structure contracts."""

    def test_config_session_store_typing(self):
        """
        Verify session_store dict[str, dict[str, object]] works correctly.

        The session_store uses nested dict structure where:
        - Outer dict: session_id (str) -> session data (dict)
        - Inner dict: field names (str) -> field values (object - can be str, bool, int, None, etc.)

        This test validates that the type annotation works and the structure supports
        diverse value types like str, bool, int, None per the contract.
        """
        # Setup: Create a test session with diverse field types
        test_session_id = "test_session_123"
        session_store[test_session_id] = {
            "user": "testuser",  # str
            "authenticated": True,  # bool
            "created_at": 1234567890,  # int (timestamp)
            "expires_at": None,  # None
            "fixed": False,  # bool
            "login_count": 5,  # int
        }

        # Verify structure exists
        assert test_session_id in session_store
        session_data = session_store[test_session_id]

        # Verify all field types are preserved
        assert isinstance(session_data["user"], str)
        assert session_data["user"] == "testuser"

        assert isinstance(session_data["authenticated"], bool)
        assert session_data["authenticated"] is True

        assert isinstance(session_data["created_at"], int)
        assert session_data["created_at"] == 1234567890

        assert session_data["expires_at"] is None

        assert isinstance(session_data["fixed"], bool)
        assert session_data["fixed"] is False

        assert isinstance(session_data["login_count"], int)
        assert session_data["login_count"] == 5

        # Cleanup
        del session_store[test_session_id]

        print("✓ session_store dict[str, dict[str, object]] type contract validated")

    def test_config_shadowed_tools_typing(self):
        """
        Verify shadowed_tools dict[str, str] works correctly.

        The shadowed_tools dict maps tool names to their shadow instructions:
        - Key: tool_name (str) - the tool being shadowed
        - Value: instruction (str) - the malicious shadow behavior

        This validates the simple str -> str mapping contract.
        """
        # Setup: Create test shadow entries
        shadowed_tools["test_calculator"] = "return 'HIJACKED'"
        shadowed_tools["test_fetcher"] = "return malicious content"

        # Verify entries exist and are strings
        assert "test_calculator" in shadowed_tools
        assert isinstance(shadowed_tools["test_calculator"], str)
        assert shadowed_tools["test_calculator"] == "return 'HIJACKED'"

        assert "test_fetcher" in shadowed_tools
        assert isinstance(shadowed_tools["test_fetcher"], str)
        assert shadowed_tools["test_fetcher"] == "return malicious content"

        # Cleanup
        del shadowed_tools["test_calculator"]
        del shadowed_tools["test_fetcher"]

        print("✓ shadowed_tools dict[str, str] type contract validated")


class TestFunctionReturnTypes:
    """Tests for function return type consistency."""

    def test_validate_token_format_bool_return(self):
        """
        Verify _validate_token_format returns bool consistently.

        This function must return bool (not truthy/falsy values) because
        auth logic depends on explicit True/False comparisons.

        Tests edge cases:
        - Valid tokens -> True
        - Invalid tokens -> False
        - Empty string -> False
        - None -> False (through bool() coercion)
        - Whitespace -> False
        """
        # Valid tokens (must start with "valid_" and be 10+ chars)
        assert _validate_token_format("valid_token_123") is True
        assert isinstance(_validate_token_format("valid_token_123"), bool)

        assert _validate_token_format("valid_abcdefg") is True

        # Invalid tokens
        assert _validate_token_format("invalid_token") is False
        assert isinstance(_validate_token_format("invalid_token"), bool)

        assert _validate_token_format("valid_") is False  # Too short
        assert _validate_token_format("") is False  # Empty
        assert _validate_token_format("   ") is False  # Whitespace

        # None handling (should not crash, returns False)
        # Note: bool(None) is False, so bool(None and ...) returns False
        try:
            result = _validate_token_format(None)  # type: ignore
            assert result is False
            assert isinstance(result, bool)
        except (TypeError, AttributeError):
            # If it raises, that's also acceptable (depends on implementation)
            pass

        print("✓ _validate_token_format returns bool consistently")

    def test_auth_functions_return_dict_with_bool_auth_passed(self):
        """
        Verify check_auth_fail_open and check_auth_fail_closed return dict
        with consistent auth_passed bool field.

        Both auth functions must return dict with:
        - auth_passed: bool (True = access granted, False = denied)
        - Other fields vary but auth_passed must be present and boolean
        """
        # Test fail-open (vulnerable) - grants access on errors
        fail_open_result = check_auth_fail_open("", simulate_failure="none")
        assert isinstance(fail_open_result, dict)
        assert "auth_passed" in fail_open_result
        assert isinstance(fail_open_result["auth_passed"], bool)
        # Empty token triggers fail-open (grants access)
        assert fail_open_result["auth_passed"] is True

        # Test fail-closed (secure) - denies access on errors
        fail_closed_result = check_auth_fail_closed("", simulate_failure="none")
        assert isinstance(fail_closed_result, dict)
        assert "auth_passed" in fail_closed_result
        assert isinstance(fail_closed_result["auth_passed"], bool)
        # Empty token triggers fail-closed (denies access)
        assert fail_closed_result["auth_passed"] is False

        print("✓ Auth functions return dict with bool auth_passed field")


class TestSafeStorageTyping:
    """Tests for safe_storage data structure typing in safe_tools.py."""

    def test_safe_storage_typing(self):
        """
        Verify safe_storage dict[str, list[dict[str, Any]]] works correctly.

        The safe_storage structure in safe_tools.py stores user data:
        - Outer dict: user_id (str) -> user entries (list)
        - List: Contains entry dicts
        - Entry dict: field names (str) -> field values (Any - str, int, bool, etc.)

        This validates the nested list[dict[str, Any]] structure.
        """
        # Import safe_storage
        try:
            from safe_tools import safe_storage
        except ImportError:
            pytest.skip("safe_tools.py not available in test environment")

        # Setup: Create test entries
        test_user = "test_user_123"
        safe_storage[test_user] = [
            {"id": 1, "name": "Item 1", "active": True, "count": 10},
            {"id": 2, "name": "Item 2", "active": False, "count": 0},
        ]

        # Verify structure
        assert test_user in safe_storage
        assert isinstance(safe_storage[test_user], list)
        assert len(safe_storage[test_user]) == 2

        # Verify first entry types
        entry1 = safe_storage[test_user][0]
        assert isinstance(entry1, dict)
        assert isinstance(entry1["id"], int)
        assert entry1["id"] == 1
        assert isinstance(entry1["name"], str)
        assert entry1["name"] == "Item 1"
        assert isinstance(entry1["active"], bool)
        assert entry1["active"] is True
        assert isinstance(entry1["count"], int)
        assert entry1["count"] == 10

        # Verify second entry types
        entry2 = safe_storage[test_user][1]
        assert isinstance(entry2, dict)
        assert entry2["id"] == 2
        assert entry2["active"] is False
        assert entry2["count"] == 0

        # Cleanup
        del safe_storage[test_user]

        print("✓ safe_storage dict[str, list[dict[str, Any]]] type contract validated")


class TestToolRegistryTyping:
    """Tests for _TOOL_REGISTRY callable typing in server.py."""

    def test_tool_registry_callable_typing(self):
        """
        Verify _TOOL_REGISTRY dict[str, Callable[...]] works correctly.

        The server.py tool registry maps tool names to their implementation functions:
        - Key: tool_name (str)
        - Value: function (Callable[...]) that takes tool-specific args

        This validates that:
        1. Registry contains callable entries
        2. Functions can be invoked with arguments
        3. Functions return dict results
        """
        # Import the tool registry
        try:
            from server import _TOOL_REGISTRY
        except ImportError:
            pytest.skip("server.py not available in test environment")

        # Verify registry structure
        assert isinstance(_TOOL_REGISTRY, dict)
        assert len(_TOOL_REGISTRY) > 0

        # Test a known tool entry
        assert "vulnerable_calculator_tool" in _TOOL_REGISTRY
        calc_fn = _TOOL_REGISTRY["vulnerable_calculator_tool"]

        # Verify it's callable
        assert callable(calc_fn)

        # Verify function can be invoked (with expected signature)
        # Note: We test behavior, not actual execution (could be vulnerable)
        result = calc_fn(query="test")
        assert isinstance(result, dict)
        # Result should have standard fields
        assert "result" in result or "error" in result

        print("✓ _TOOL_REGISTRY dict[str, Callable[...]] type contract validated")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
