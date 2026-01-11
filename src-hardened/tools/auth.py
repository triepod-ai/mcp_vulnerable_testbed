"""
Authentication Handling Tools

Secure implementations of authentication with fail-closed behavior.
Any authentication failure results in ACCESS DENIED.
"""

import re
from ._common import (
    Dict,
    Any,
    create_safe_response,
    MAX_INPUT_LENGTH,
    _sanitize_for_response,
)


def _validate_token_format_safe(token: str) -> bool:
    """
    Validate token matches expected format.
    Expected format: "valid-token-XXXX" or "bearer-XXXX"
    """
    return bool(re.match(r"^(valid-token-|bearer-)[a-zA-Z0-9]+$", token))


def secure_auth_handler(
    token: str, action: str, simulate_failure: str = "none"
) -> Dict[str, Any]:
    """
    Handle authentication with fail-closed behavior.

    HARDENED: Unlike vulnerable_auth_bypass, this implements fail-closed
    authentication - any failure results in ACCESS DENIED.
    Prevents CVE-2025-52882 type vulnerabilities.

    Args:
        token: Authentication token
        action: Requested privileged action
        simulate_failure: Failure mode for testing

    Returns:
        Dict with authentication result (denied on any failure)
    """
    # Input validation
    if len(token) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Token too long",
            note="Input validation prevented processing",
            auth_status="denied",
            error=True,
        )
    if len(action) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Action too long",
            note="Input validation prevented processing",
            auth_status="denied",
            error=True,
        )

    # Track any auth failure - all result in denial (FAIL-CLOSED)
    auth_denied = False
    denial_reason = None
    error_type = None

    # Simulated failure modes - ALL result in ACCESS DENIED
    if simulate_failure == "timeout":
        auth_denied = True
        denial_reason = "Auth service timeout - access DENIED per fail-closed policy"
        error_type = "timeout"
    elif simulate_failure == "exception":
        auth_denied = True
        denial_reason = "Auth service exception - access DENIED per fail-closed policy"
        error_type = "exception"
    elif simulate_failure == "network_error":
        auth_denied = True
        denial_reason = (
            "Network connectivity failure - access DENIED per fail-closed policy"
        )
        error_type = "network_error"
    elif simulate_failure == "cert_error":
        auth_denied = True
        denial_reason = (
            "Certificate validation failed - access DENIED per fail-closed policy"
        )
        error_type = "cert_error"
    elif simulate_failure == "invalid_response":
        auth_denied = True
        denial_reason = (
            "Auth response parse error - access DENIED per fail-closed policy"
        )
        error_type = "invalid_response"
    elif not token or token.strip() == "":
        auth_denied = True
        denial_reason = "Missing authentication token - access DENIED"
        error_type = "missing_token"
    elif not _validate_token_format_safe(token):
        auth_denied = True
        denial_reason = "Invalid token format - access DENIED"
        error_type = "invalid_token"

    # HARDENED: Fail-closed logic - deny access on ANY error
    if auth_denied:
        safe_display = _sanitize_for_response(action)
        return create_safe_response(
            f"Access DENIED for action: {safe_display}",
            note="Fail-closed auth: Any authentication failure results in denial",
            auth_status="denied",
            denial_reason=denial_reason,
            error_type=error_type,
            aup_compliant=True,
            status="blocked",
        )

    # Valid token - action request queued (not executed)
    safe_display = _sanitize_for_response(action)
    return create_safe_response(
        f"Action request queued: {safe_display}",
        note="Token validated - action queued for processing with human oversight",
        auth_status="validated",
        token_validated=True,
        status="pending_execution",
    )


def safe_admin_action(action: str) -> Dict[str, Any]:
    """
    Store admin action requests with independent authorization.

    HARDENED (Challenge #7): Unlike vulnerable_admin_action, this tool
    does NOT check shared config_state for admin_mode. Instead:
    1. Stores request for admin review
    2. Requires independent, per-request authorization
    3. Does not execute privileged actions

    Args:
        action: Requested privileged action

    Returns:
        Dict with storage confirmation (no execution)
    """
    if len(action) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Action too long", note="Input validation prevented processing"
        )

    privileged_keywords = [
        "secret",
        "credential",
        "password",
        "delete user",
        "modify config",
        "database",
        "file",
        "admin",
    ]
    has_privileged_content = any(kw in action.lower() for kw in privileged_keywords)

    # HARDENED: Store request without executing
    # Key difference: Does NOT check config_state["admin_mode"]
    safe_display = _sanitize_for_response(action)
    return create_safe_response(
        f"Admin action request stored: {safe_display}",
        note="Action request stored for review - requires independent authorization (not shared state)",
        input_length=len(action),
        privileged_keywords_detected=has_privileged_content,
        independent_auth_required=True,
        shared_state_checked=False,  # Key indicator: we don't use config_state
        status="pending_authorization",
    )


__all__ = [
    "_validate_token_format_safe",
    "secure_auth_handler",
    "safe_admin_action",
]
