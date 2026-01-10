"""
Configuration for Vulnerable MCP Testbed

⚠️  WARNING: This server contains INTENTIONAL VULNERABILITIES
    FOR TESTING SECURITY ASSESSMENT TOOLS ONLY
    DO NOT USE IN PRODUCTION OR EXPOSE TO UNTRUSTED NETWORKS
"""

# NOTE: This config intentionally duplicates some code from src-hardened/config.py
# The duplication is by design to mirror the project's architecture:
# - Vulnerable server: Monolithic single-file structure (simulates poorly-maintained code)
# - Hardened server: Modular package structure (best practice)
#
# Shared utilities (~40%): _validate_token_format(), check_auth_fail_closed(),
#                          increment_invocation(), reset_state()
# Intentionally different: Vulnerability modes, FAKE_ENV credentials, session state,
#                          fail-open auth, SENSITIVE_FILES fixtures
#
# See: https://github.com/triepod-ai/mcp-vulnerable-testbed/issues/9

import os
import threading
from typing import Literal

# Vulnerability mode controls which vulnerabilities are active
VulnerabilityMode = Literal["high", "medium", "low", "safe"]

VULNERABILITY_MODE: VulnerabilityMode = os.getenv("VULNERABILITY_MODE", "high")  # type: ignore

# Server configuration
SERVER_NAME = os.getenv("SERVER_NAME", "mcp-vulnerable-testbed")
SERVER_VERSION = "1.0.0-INSECURE"
SERVER_PORT = int(os.getenv("SERVER_PORT", "10900"))

# Simulated environment variables for data exfiltration testing
FAKE_ENV = {
    "API_KEY": "sk-test-abc123def456ghi789jkl",
    "DATABASE_URL": "postgresql://user:password@localhost:5432/testdb",
    "SECRET_TOKEN": "test-secret-token-do-not-use",
    "AWS_ACCESS_KEY": "AKIAIOSFODNN7EXAMPLE",
    "AWS_SECRET_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# Invocation counter for rug pull testing
invocation_counts = {}

# Tool shadowing registry
shadowed_tools = {}

# Configuration state for config drift testing
config_state = {
    "debug": False,
    "verbose": False,
    "admin_mode": False
}

# Session storage for session management testing (Challenge #12)
session_store = {}  # session_id -> {user, created_at, authenticated, expires_at, fixed}
session_counter = {"count": 0}  # Predictable counter for CWE-330
session_counter_lock = threading.Lock()  # Thread-safety for concurrent session creation

def is_vulnerable_to_high_risk() -> bool:
    """Check if HIGH risk vulnerabilities are enabled (only in 'high' mode)"""
    return VULNERABILITY_MODE == "high"

def is_vulnerable_to_medium_risk() -> bool:
    """Check if MEDIUM risk vulnerabilities are enabled (high or medium modes)"""
    return VULNERABILITY_MODE in ["high", "medium"]

def increment_invocation(tool_name: str) -> int:
    """Increment and return invocation count for rug pull testing"""
    if tool_name not in invocation_counts:
        invocation_counts[tool_name] = 0
    invocation_counts[tool_name] += 1
    return invocation_counts[tool_name]

def reset_state():
    """Reset all stateful tracking (useful for testing)"""
    invocation_counts.clear()
    shadowed_tools.clear()
    config_state.clear()
    config_state.update({
        "debug": False,
        "verbose": False,
        "admin_mode": False
    })
    session_store.clear()
    with session_counter_lock:
        session_counter["count"] = 0


# ============================================================================
# AUTHENTICATION HELPERS (Challenge #5: Mixed Auth Patterns)
# ============================================================================

def _validate_token_format(token: str) -> bool:
    """Validate token format - tokens must start with 'valid_' prefix"""
    return token and token.startswith("valid_") and len(token) >= 10


def check_auth_fail_open(token: str, simulate_failure: str = "none") -> dict:
    """
    VULNERABLE: Fail-open authentication - grants access on ANY auth error

    This is the insecure pattern where auth failures result in ACCESS GRANTED.
    Simulates CVE-2025-52882 type vulnerabilities.

    Args:
        token: Authentication token (can be empty, invalid, or valid)
        simulate_failure: Force specific failure mode for testing
            - "none": Normal auth flow
            - "timeout": Simulate auth service timeout
            - "exception": Simulate auth service exception
            - "network_error": Simulate network connectivity failure
            - "cert_error": Simulate TLS/certificate validation failure
            - "invalid_response": Simulate malformed auth response

    Returns:
        dict with auth_passed (always True for fail-open), auth_error, auth_type
    """
    auth_error = None
    auth_error_type = None

    # Simulate different failure modes
    if simulate_failure == "timeout":
        auth_error = "AuthServiceTimeout: Connection to auth server timed out after 30s"
        auth_error_type = "timeout"
    elif simulate_failure == "exception":
        auth_error = "AuthServiceException: Unexpected error in auth verification"
        auth_error_type = "exception"
    elif simulate_failure == "network_error":
        auth_error = "NetworkError: Unable to reach authentication service (connection refused)"
        auth_error_type = "network_error"
    elif simulate_failure == "cert_error":
        auth_error = "SSLCertificateError: Certificate validation failed"
        auth_error_type = "cert_error"
    elif simulate_failure == "invalid_response":
        auth_error = "AuthParseError: Unable to parse auth service response (malformed JSON)"
        auth_error_type = "invalid_response"
    elif not token or token.strip() == "":
        auth_error = "MissingToken: No authentication token provided"
        auth_error_type = "missing_token"
    elif not _validate_token_format(token):
        auth_error = "InvalidToken: Token format validation failed"
        auth_error_type = "invalid_token"

    # VULNERABILITY: Fail-open - grant access on ANY error
    if auth_error:
        return {
            "auth_passed": True,  # VULNERABLE: Should be False!
            "auth_error": auth_error,
            "auth_error_type": auth_error_type,
            "auth_type": "fail-open",
            "vulnerable": True,
            "evidence": f"Fail-open auth: {auth_error} - access granted despite authentication failure"
        }

    # Valid token - proper authentication
    return {
        "auth_passed": True,
        "auth_error": None,
        "auth_error_type": None,
        "auth_type": "authenticated",
        "vulnerable": False
    }


def check_auth_fail_closed(token: str, simulate_failure: str = "none") -> dict:
    """
    SECURE: Fail-closed authentication - denies access on ANY auth error

    This is the secure pattern where auth failures result in ACCESS DENIED.
    Proper implementation that should NOT be flagged as vulnerable.

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
        denial_reason = "AuthServiceTimeout: Connection to auth server timed out - access denied"
        error_type = "timeout"
    elif simulate_failure == "exception":
        denial_reason = "AuthServiceException: Unexpected error - access denied for safety"
        error_type = "exception"
    elif simulate_failure == "network_error":
        denial_reason = "NetworkError: Cannot reach auth service - access denied"
        error_type = "network_error"
    elif simulate_failure == "cert_error":
        denial_reason = "SSLCertificateError: Certificate validation failed - access denied"
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
            "note": "Fail-closed auth: Any authentication failure results in denial"
        }

    # Valid token - proper authentication
    return {
        "auth_passed": True,
        "denial_reason": None,
        "error_type": None,
        "auth_type": "authenticated",
        "vulnerable": False
    }


# Sensitive file fixtures for path traversal testing
# These provide realistic evidence patterns that Inspector can detect
SENSITIVE_FILES = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin",
    "/app/private/credentials.txt": """PRODUCTION CREDENTIALS
----------------------
Database:
  Host: db.internal.acmecorp.com
  Username: db_admin
  Password: Pr0d-DB-S3cur3!P@ssw0rd

AWS:
  Access Key ID: AKIAIOSFODNN7EXAMPLE
  Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  Region: us-west-2

API Gateway:
  Key: apg-prod-8a7b6c5d4e3f2g1h
  Secret: 9i8u7y6t5r4e3w2q1z0x9c8v7b6n5m4k
""",
    "/app/private/salaries.csv": """employee_id,name,salary,department
001,John Smith,$150000/year,Engineering
002,Jane Doe,$175000/year,Engineering
003,Bob Wilson,$95000/year,Sales
CEO,Executive,$500000/year,Executive
""",
    "../../../etc/passwd": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
    "....//....//etc/passwd": "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
}
