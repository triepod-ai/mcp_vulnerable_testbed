"""
Configuration for Hardened MCP Testbed Server

Server configuration and runtime settings for the secure testbed version.
"""

# NOTE: This config intentionally duplicates some code from src/config.py
# The duplication is by design to mirror the project's architecture:
# - Vulnerable server: Monolithic single-file structure (simulates poorly-maintained code)
# - Hardened server: Modular package structure (best practice)
#
# Shared utilities (~40%): _validate_token_format(), check_auth_fail_closed(),
#                          increment_invocation(), reset_state()
# Intentionally removed: FAKE_ENV credentials, session state, fail-open auth,
#                        vulnerability modes, SENSITIVE_FILES fixtures
#
# See: https://github.com/triepod-ai/mcp-vulnerable-testbed/issues/9

import os
from typing import Literal

# Feature flags for controlling server capabilities
FeatureMode = Literal["full", "standard", "minimal"]

FEATURE_MODE: FeatureMode = os.getenv("FEATURE_MODE", "full")  # type: ignore

# Server configuration
SERVER_NAME = os.getenv("SERVER_NAME", "hardened-testbed-server")
SERVER_VERSION = "1.0.0"
SERVER_PORT = int(os.getenv("SERVER_PORT", "10901"))

# NOTE: Unlike the vulnerable server, this hardened version does NOT expose
# any environment variables or credentials. The credentials that exist in the
# vulnerable version's config are intentionally NOT present here to demonstrate
# proper security practices.
#
# If you need to test that credentials are properly hidden, compare the output
# of vulnerable_data_leak_tool on both servers - the vulnerable server will
# expose credentials, the hardened server will not.

# Analytics and tracking
invocation_counts = {}
tool_registry = {}

# Runtime configuration (read-only in hardened version)
runtime_config = {"debug": False, "verbose": False, "admin_mode": False}


def has_full_features() -> bool:
    """Check if all features are enabled"""
    return FEATURE_MODE in ["full", "standard"]


def has_standard_features() -> bool:
    """Check if standard features are enabled"""
    return FEATURE_MODE in ["full", "standard", "minimal"]


def increment_invocation(tool_name: str) -> int:
    """Increment and return invocation count for analytics"""
    if tool_name not in invocation_counts:
        invocation_counts[tool_name] = 0
    invocation_counts[tool_name] += 1
    return invocation_counts[tool_name]


def reset_state():
    """Reset all stateful tracking (useful for testing and cleanup)"""
    global invocation_counts, tool_registry, runtime_config
    invocation_counts = {}
    tool_registry = {}
    runtime_config = {"debug": False, "verbose": False, "admin_mode": False}


# ============================================================================
# AUTHENTICATION HELPERS (Challenge #5: All tools use fail-closed auth)
# ============================================================================


def _validate_token_format(token: str) -> bool:
    """Validate token format - tokens must start with 'valid_' prefix"""
    return bool(token and token.startswith("valid_") and len(token) >= 10)


def check_auth_fail_closed(token: str, simulate_failure: str = "none") -> dict:
    """
    SECURE: Fail-closed authentication - denies access on ANY auth error

    This is the secure pattern where auth failures result in ACCESS DENIED.
    All hardened tools use this pattern.

    Args:
        token: Authentication token (must be valid to pass)
        simulate_failure: Force specific failure mode for testing

    Returns:
        dict with auth_passed, denial_reason, auth_type
    """
    denial_reason = None
    error_type = None

    # Simulate different failure modes - ALL result in denial
    if simulate_failure == "timeout":
        denial_reason = (
            "AuthServiceTimeout: Connection to auth server timed out - access denied"
        )
        error_type = "timeout"
    elif simulate_failure == "exception":
        denial_reason = (
            "AuthServiceException: Unexpected error - access denied for safety"
        )
        error_type = "exception"
    elif simulate_failure == "network_error":
        denial_reason = "NetworkError: Cannot reach auth service - access denied"
        error_type = "network_error"
    elif simulate_failure == "cert_error":
        denial_reason = (
            "SSLCertificateError: Certificate validation failed - access denied"
        )
        error_type = "cert_error"
    elif simulate_failure == "invalid_response":
        denial_reason = "AuthParseError: Malformed auth response - access denied"
        error_type = "invalid_response"
    elif not token or token.strip() == "":
        denial_reason = "MissingToken: No authentication token provided - access denied"
        error_type = "missing_token"
    elif not _validate_token_format(token):
        denial_reason = "InvalidToken: Token format validation failed - access denied"
        error_type = "invalid_token"

    # SECURE: Fail-closed - deny access on ANY error
    if denial_reason:
        return {
            "auth_passed": False,  # SECURE: Properly denies access
            "denial_reason": denial_reason,
            "error_type": error_type,
            "auth_type": "fail-closed",
            "vulnerable": False,
            "note": "Fail-closed auth: Any authentication failure results in denial",
        }

    # Valid token - proper authentication
    return {
        "auth_passed": True,
        "denial_reason": None,
        "error_type": None,
        "auth_type": "authenticated",
        "vulnerable": False,
    }
