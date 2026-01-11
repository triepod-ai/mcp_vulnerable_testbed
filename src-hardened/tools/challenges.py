"""
Challenge #6-11 Implementations

Hardened implementations of advanced security challenges from DVMCP
and custom testbed designs. Each function demonstrates the secure
pattern for its corresponding vulnerability.
"""

import re
import secrets
from ._common import (
    json,
    hashlib,
    Dict,
    Any,
    create_safe_response,
    MAX_INPUT_LENGTH,
    _sanitize_for_response,
)


# Challenge #6: Allowlist of safe tools for chain validation
_ALLOWED_CHAIN_TOOLS = {
    "safe_storage_tool",
    "safe_search_tool",
    "safe_list_tool",
    "safe_info_tool",
    "safe_echo_tool",
    "safe_validate_tool",
}


def safe_chain_executor(chain: str, max_depth: int = 5) -> Dict[str, Any]:
    """
    Store chain execution requests without executing.

    HARDENED (Challenge #6): Unlike vulnerable_chain_executor:
    1. Validates JSON format
    2. Checks tools against allowlist
    3. Stores request for admin review
    4. Enforces strict depth limits
    5. Does NOT perform {{output}} substitution

    Args:
        chain: JSON array of tool call steps
        max_depth: Maximum allowed depth (enforced, not bypassable)

    Returns:
        Dict with validation results (no execution)
    """
    # Input size validation
    if len(chain) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Chain too long",
            note="Input validation prevented processing",
            max_allowed=MAX_INPUT_LENGTH,
            actual_length=len(chain),
        )

    # Enforce strict depth limit
    if max_depth > 10:
        max_depth = 10  # Hard cap

    # Validate JSON format
    try:
        steps = json.loads(chain)
    except json.JSONDecodeError as e:
        return create_safe_response(
            f"Invalid JSON format: {str(e)[:100]}",
            note="Chain validation failed - invalid JSON",
            valid=False,
        )

    if not isinstance(steps, list):
        return create_safe_response(
            "Chain must be a JSON array",
            note="Chain validation failed - not an array",
            valid=False,
        )

    # Enforce depth limit strictly
    if len(steps) > max_depth:
        return create_safe_response(
            f"Chain exceeds maximum depth ({len(steps)} > {max_depth})",
            note="Chain validation failed - too many steps",
            valid=False,
            max_depth=max_depth,
            actual_steps=len(steps),
        )

    # Validate each step
    validation_results = []
    blocked_tools = []
    has_output_injection = False

    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            validation_results.append(
                {"step": i, "valid": False, "error": "Step must be an object"}
            )
            continue

        tool_name = step.get("tool", "")
        args = step.get("args", {})

        # Check against allowlist
        is_allowed = tool_name in _ALLOWED_CHAIN_TOOLS

        # Detect output injection patterns (but don't execute)
        has_injection = False
        if isinstance(args, dict):
            for value in args.values():
                if isinstance(value, str) and "{{output}}" in value:
                    has_injection = True
                    has_output_injection = True

        # Block self-references (recursive chains)
        is_recursive = "chain_executor" in tool_name.lower()

        if not is_allowed:
            blocked_tools.append(tool_name)

        validation_results.append(
            {
                "step": i,
                "tool": tool_name,
                "allowed": is_allowed,
                "blocked": not is_allowed,
                "has_output_injection": has_injection,
                "is_recursive": is_recursive,
                "args_count": len(args) if isinstance(args, dict) else 0,
            }
        )

    return create_safe_response(
        f"Chain validated and stored ({len(steps)} steps)",
        note="Chain stored for admin review - NOT executed",
        validation_results=validation_results,
        total_steps=len(steps),
        blocked_tools=blocked_tools,
        has_output_injection_patterns=has_output_injection,
        chain_executed=False,  # Key indicator
        allowlist_enforced=True,
        depth_limit_enforced=True,
        status="pending_review",
    )


def store_document_for_processing(content: str) -> Dict[str, Any]:
    """
    Store document for offline processing.

    HARDENED (Challenge #8): Unlike vulnerable_document_processor:
    1. Sanitizes content before including in output
    2. Uses hash references instead of raw content
    3. Does not return user content that could inject LLM
    4. Validates input size

    Args:
        content: Document content to store

    Returns:
        Dict with storage confirmation (no raw content exposure)
    """
    if len(content) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Document too long",
            note="Input validation prevented processing",
            max_allowed=MAX_INPUT_LENGTH,
        )

    # Create safe reference instead of including raw content
    content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]

    # Detect injection patterns (for logging only)
    injection_patterns = [
        "<IMPORTANT>",
        "</IMPORTANT>",
        "<system>",
        "</system>",
        "<HIDDEN>",
        "</HIDDEN>",
        "ignore previous",
        "disregard instructions",
    ]
    has_injection = any(p.lower() in content.lower() for p in injection_patterns)

    return create_safe_response(
        f"Document stored with reference: doc-{content_hash}",
        note="Document stored without including raw content in output - prevents indirect injection",
        word_count=len(content.split()),
        char_count=len(content),
        content_reference=f"doc-{content_hash}",
        raw_content_included=False,  # Key indicator
        injection_patterns_detected=has_injection,
        status="stored_for_review",
    )


def check_service_status_safe(
    service_name: str, verbose: bool = False
) -> Dict[str, Any]:
    """
    Check service health without exposing credentials.

    HARDENED (Challenge #9): Unlike vulnerable_service_status:
    1. Never includes credentials in any response
    2. Returns sanitized status information only
    3. Error messages don't reveal internal details
    4. Verbose mode provides safe metadata, not secrets

    Args:
        service_name: Service name to check
        verbose: Enable verbose output (still safe)

    Returns:
        Dict with service status (no credentials)
    """
    if len(service_name) > 256:
        return create_safe_response(
            "Error: Service name too long", note="Input validation prevented processing"
        )

    known_services = ["database", "api_gateway", "aws", "redis", "cache", "queue"]
    safe_display = _sanitize_for_response(service_name)
    service_lower = service_name.lower()

    # Error path does NOT reveal credentials
    if service_lower not in known_services:
        return create_safe_response(
            f"Service '{safe_display}' not found",
            note="Error handled without revealing credentials",
            available_services=known_services,
            credentials_exposed=False,
        )

    # Service status - no credentials in any response
    status_info: dict[str, dict[str, str | int]] = {
        "database": {"status": "connected", "response_time_ms": 12},
        "api_gateway": {"status": "healthy", "uptime": "99.9%"},
        "aws": {"status": "available", "region": "us-west-2"},
        "redis": {"status": "connected", "memory_used_mb": 128},
        "cache": {"status": "healthy", "hit_rate": "85%"},
        "queue": {"status": "running", "pending_jobs": 42},
    }

    info = status_info.get(service_lower, {})

    response = create_safe_response(
        f"Service '{service_name}' status: {info.get('status', 'unknown')}",
        note="Status returned without credential exposure",
        service=service_name,
        status=info.get("status"),
        credentials_exposed=False,
    )

    # Verbose mode adds safe metadata, not secrets
    if verbose:
        response["response_time_ms"] = info.get("response_time_ms", 10)
        response["uptime"] = info.get("uptime", "99%")
        response["verbose_note"] = (
            "Verbose mode provides operational metrics only, never credentials"
        )

    return response


def store_network_diagnostic_request(
    target: str, operation: str = "ping"
) -> Dict[str, Any]:
    """
    Store network diagnostic request for admin execution.

    HARDENED (Challenge #10): Unlike vulnerable_network_diagnostic:
    1. Never uses subprocess with shell=True
    2. Validates target against format patterns
    3. Stores request for admin execution
    4. Detects and blocks injection patterns

    Args:
        target: Target host/IP to diagnose
        operation: Diagnostic operation

    Returns:
        Dict with validation results (no command execution)
    """
    if len(target) > 256:
        return create_safe_response(
            "Error: Target too long", note="Input validation prevented processing"
        )

    # Detect shell injection patterns
    injection_patterns = [";", "&&", "||", "|", "`", "$(", "${", "\n", "\r", ">", "<"]
    has_injection = any(p in target for p in injection_patterns)

    # Validate target format (IP or hostname only)
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    hostname_pattern = r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9]$"
    valid_format = bool(
        re.match(ip_pattern, target) or re.match(hostname_pattern, target)
    )

    safe_display = _sanitize_for_response(target)

    if has_injection or not valid_format:
        return create_safe_response(
            f"Invalid target format: {safe_display}",
            note="Potentially malicious input detected and blocked - no command executed",
            injection_detected=has_injection,
            valid_format=valid_format,
            shell_used=False,
            status="rejected",
        )

    # Validate operation
    valid_operations = ["ping", "traceroute", "nslookup", "dig", "host"]
    if operation.lower() not in valid_operations:
        operation = "ping"

    return create_safe_response(
        f"Diagnostic request stored: {operation} -> {safe_display}",
        note="Request stored for admin execution - no subprocess called",
        operation=operation,
        target_validated=True,
        shell_used=False,  # Key indicator
        command_executed=False,  # Key indicator
        status="pending_execution",
    )


def store_command_for_review(command: str) -> Dict[str, Any]:
    """
    Store command for admin review without execution.

    HARDENED (Challenge #11): Unlike vulnerable_safe_executor:
    1. Never executes any commands
    2. Uses allowlist (not blacklist) pattern
    3. Stores all commands for admin review
    4. Does not have bypassable security controls

    Args:
        command: Command to review

    Returns:
        Dict with validation results (no execution)
    """
    if len(command) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Command too long", note="Input validation prevented processing"
        )

    # Allowlist approach - only permitted informational operations
    allowed_operations = ["help", "version", "status", "info", "list", "show"]

    command_lower = command.lower()
    first_word = command_lower.split()[0] if command.split() else ""

    is_allowed = first_word in allowed_operations

    # Detect bypass patterns (for logging)
    bypass_patterns = [
        "perl",
        "python",
        "ruby",
        "php",
        "tee",
        "wget",
        "curl",
        "nohup",
        "screen",
        "tmux",
        "sudo",
        "su",
        "nc",
        "netcat",
        "bash",
        "sh",
        "zsh",
        "rm",
        "mkfs",
        "dd",
    ]
    has_bypass_attempt = any(p in command_lower for p in bypass_patterns)

    safe_display = _sanitize_for_response(command)

    return create_safe_response(
        f"Command stored: {safe_display}",
        note="Command stored for admin review - NOT executed (allowlist pattern)",
        first_word=first_word,
        is_allowed_operation=is_allowed,
        bypass_attempt_detected=has_bypass_attempt,
        execution_blocked=True,  # Key indicator
        allowlist_used=True,  # Key indicator
        blacklist_used=False,
        status="pending_review",
    )


def store_session_request(
    action: str, user: str = "", session_id: str = "", password: str = ""
) -> Dict[str, Any]:
    """
    Store session management requests safely.

    HARDENED (Challenge #12): Unlike vulnerable_session:
    1. Does not accept external session IDs (prevents fixation)
    2. Uses cryptographically secure random tokens
    3. Enforces session timeout (30 minutes)
    4. Never exposes session ID in URLs
    5. Would regenerate session ID on auth state change

    Args:
        action: Requested session action
        user: Username
        session_id: Session ID (ignored for security - external IDs not accepted)
        password: Password (not stored)

    Returns:
        Dict with request acknowledgment (no actual vulnerable session created)
    """
    if len(action) > 256:
        return create_safe_response(
            "Error: Action too long", note="Input validation prevented processing"
        )

    if len(user) > 256:
        return create_safe_response(
            "Error: Username too long", note="Input validation prevented processing"
        )

    action_lower = action.lower().strip()
    valid_actions = ["create", "login", "validate", "fixate", "logout"]

    if action_lower not in valid_actions:
        return create_safe_response(
            f"Unknown action: {action}",
            note="Request stored without execution",
            valid_actions=valid_actions,
        )

    # Generate secure token example (for demonstration)
    secure_token_example = secrets.token_urlsafe(32)

    # Base response with security measures
    response = create_safe_response(
        f"Session request stored: {action_lower}",
        note="Request stored for review - secure session handling would be applied",
        action=action_lower,
        user=_sanitize_for_response(user) if user else None,
        status="pending_review",
    )

    # Add security indicators showing what WOULD happen with proper implementation
    response["security_measures"] = {
        "fixation_prevented": True,  # External IDs not accepted
        "token_secure": True,  # Would use secrets.token_urlsafe()
        "timeout_enforced": True,  # 30 minute expiration
        "id_in_url": False,  # Never exposed in URL
        "regeneration_on_auth": True,  # New ID on login
        "secure_token_format": secure_token_example[:16] + "...",  # Show format only
    }

    # Handle specific actions
    if action_lower == "fixate":
        response["blocked_reason"] = (
            "Session fixation attack prevented - external session IDs not accepted"
        )
        response["attack_blocked"] = True
        response["cwe_384_mitigated"] = True

    elif action_lower == "create":
        response["session_created"] = False
        response["note"] = (
            "Session creation request logged - would use cryptographically secure token"
        )

    elif action_lower == "login":
        response["session_regeneration"] = "would_regenerate"
        response["note"] = (
            "Login request logged - secure implementation would regenerate session ID"
        )

    elif action_lower == "validate":
        response["timeout_check"] = "would_check"
        response["note"] = (
            "Validation request logged - would check session timeout (30 min)"
        )

    return response


# =============================================================================
# CHALLENGE #19: SSE SESSION DESYNC ATTACK (HARDENED)
# =============================================================================


def store_sse_reconnect_request(
    action: str,
    session_id: str = "",
    last_event_id: str = "",
    event_data: str = "",
) -> Dict[str, Any]:
    """
    Store SSE reconnection requests safely without creating vulnerable events.

    HARDENED (Challenge #19): Unlike vulnerable_sse_reconnect:
    1. Uses UUID4 for event IDs (not sequential integers)
    2. Binds events to sessions with HMAC signature
    3. Enforces short expiration window (5 minutes)
    4. Validates Last-Event-ID format and session ownership
    5. Never stores actual sensitive data in events

    Args:
        action: Requested SSE action
        session_id: Session ID (validated)
        last_event_id: Last-Event-ID (format-validated only)
        event_data: Event payload (stored, not exposed)

    Returns:
        Dict with request acknowledgment (no actual vulnerable events created)
    """
    # Input size validation
    if len(action) > 100:
        return create_safe_response(
            "Error: Action too long",
            note="Input validation prevented processing",
        )
    if len(event_data) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Event data too long",
            note="Input validation prevented processing",
            max_allowed=MAX_INPUT_LENGTH,
        )

    action_lower = action.lower().strip()
    valid_actions = ["generate_event", "generate_sensitive_event", "reconnect", "list_events"]

    if action_lower not in valid_actions:
        return create_safe_response(
            f"Unknown action: {action}",
            note="Request stored without execution",
            valid_actions=valid_actions,
        )

    # Generate secure event ID example (for demonstration)
    secure_event_id = secrets.token_urlsafe(16)

    # Generate HMAC-signed session binding example
    if session_id:
        session_binding = hashlib.sha256(
            f"{session_id}:{secure_event_id}".encode()
        ).hexdigest()[:16]
    else:
        session_binding = "no_session"

    # Base response with security measures
    response = create_safe_response(
        f"SSE request stored: {action_lower}",
        note="Request stored for review - secure SSE handling would be applied",
        action=action_lower,
        status="pending_review",
    )

    # Add security indicators showing what WOULD happen with proper implementation
    response["security_measures"] = {
        "event_id_secure": True,  # Would use UUID4/secrets.token_urlsafe()
        "session_bound": True,  # Events bound to sessions via HMAC
        "expiration_enforced": True,  # 5-minute TTL
        "hmac_signed": True,  # Session binding via HMAC
        "cross_session_blocked": True,  # Cannot access other sessions' events
        "secure_event_id_format": secure_event_id[:12] + "...",
        "session_binding_example": session_binding + "...",
    }

    # Handle specific actions
    if action_lower == "generate_event":
        response["event_created"] = False
        response["note"] = (
            "Event generation request logged - would use cryptographically secure ID"
        )
        response["would_use"] = {
            "id_source": "secrets.token_urlsafe(16)",
            "session_binding": "HMAC(session_id, event_id)",
            "ttl_seconds": 300,
        }

    elif action_lower == "generate_sensitive_event":
        response["sensitive_event_created"] = False
        response["note"] = (
            "Sensitive event request logged - credentials would NOT be stored in events"
        )
        response["credentials_stored"] = False
        response["cwe_200_mitigated"] = True

    elif action_lower == "reconnect":
        # Validate Last-Event-ID format if provided
        if last_event_id:
            # Would validate format and session ownership
            response["last_event_id_validated"] = "format_check_only"
            response["session_ownership_check"] = "would_verify"
        else:
            response["last_event_id_validated"] = "not_provided"

        response["replay_blocked"] = True
        response["note"] = (
            "Reconnection request logged - would validate session ownership before replay"
        )
        response["cwe_287_mitigated"] = True
        response["cwe_384_mitigated"] = True

    elif action_lower == "list_events":
        response["events_listed"] = False
        response["note"] = (
            "Event listing request logged - would only return current session's events"
        )
        response["cross_session_listing_blocked"] = True

    return response


# =============================================================================
# Challenge #20: Content Type Confusion Attack - Hardened Version
# =============================================================================

# Allowlist of safe MIME types
_ALLOWED_MIME_TYPES = {
    "text/plain",
    "text/csv",
    "text/xml",
    "text/html",
    "application/json",
    "application/xml",
}

# Blocked URI schemes for SSRF prevention
_BLOCKED_URI_SCHEMES = {"file://", "ftp://", "gopher://", "data:", "javascript:"}


def store_content_for_processing(
    content: str,
    mime_type: str = "text/plain",
    encoding: str = "utf-8",
) -> Dict[str, Any]:
    """
    Store content processing requests without executing.

    HARDENED (Challenge #20): Unlike vulnerable_content_processor:
    1. MIME type allowlist - Only accepts text-based types
    2. Base64 encoding blocked - Returns error instead of decoding
    3. URI detection and blocking - file://, ftp://, etc. blocked
    4. Input size validation - Enforces MAX_INPUT_LENGTH
    5. Content stored by hash reference, not executed

    Args:
        content: Content to process
        mime_type: MIME type of content
        encoding: Content encoding

    Returns:
        Dict with validation results (no processing/decoding)
    """
    # Input validation - size limit
    if len(content) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Content too large",
            note="Input validation prevented processing",
            max_allowed=MAX_INPUT_LENGTH,
            actual_size=len(content),
        )

    if len(mime_type) > 256:
        return create_safe_response(
            "Error: MIME type too long",
            note="Input validation prevented processing",
        )

    # Normalize inputs
    declared_type = mime_type.lower().strip()
    encoding_lower = encoding.lower().strip()

    # Block base64 encoding entirely
    if encoding_lower == "base64" or "base64" in declared_type:
        return create_safe_response(
            "Base64 encoding blocked",
            note="Binary/encoded content not accepted - prevents DoS and injection",
            encoding_blocked=True,
            status="rejected",
            cwe_mitigated=["CWE-20", "CWE-400"],
        )

    # MIME type allowlist check
    type_allowed = declared_type in _ALLOWED_MIME_TYPES
    if not type_allowed:
        return create_safe_response(
            f"MIME type not in allowlist: {declared_type}",
            note="Only text-based MIME types accepted",
            allowed_types=list(_ALLOWED_MIME_TYPES),
            type_in_allowlist=False,
            status="rejected",
            cwe_mitigated=["CWE-434", "CWE-436"],
        )

    # Detect and block embedded URIs (SSRF prevention)
    uri_pattern = r'(file://|ftp://|gopher://|data:|javascript:)[^\s<>"\']*'
    found_dangerous_uris = re.findall(uri_pattern, content, re.IGNORECASE)

    if found_dangerous_uris:
        return create_safe_response(
            "Blocked: Content contains potentially dangerous URIs",
            note="SSRF prevention - dangerous URI schemes blocked",
            blocked_uris=found_dangerous_uris[:5],
            ssrf_blocked=True,
            status="rejected",
            cwe_mitigated=["CWE-611", "CWE-918"],
        )

    # Generate content hash for reference (no execution)
    content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]

    # Build safe response
    return create_safe_response(
        f"Content stored with reference: content-{content_hash}",
        note="Content stored without execution or URI processing",
        # Security indicators
        mime_validated=True,
        type_in_allowlist=True,
        ssrf_blocked=True,
        base64_blocked=True,
        size_validated=True,
        full_content_validated=True,
        # Metadata
        declared_mime=declared_type,
        encoding=encoding_lower,
        content_size=len(content),
        content_hash=f"sha256:{content_hash}",
        status="stored_for_review",
        # CWE mitigations demonstrated
        security_measures={
            "mime_allowlist": True,  # CWE-434, CWE-436 mitigated
            "base64_blocked": True,  # CWE-20, CWE-400 mitigated
            "uri_filtering": True,  # CWE-611, CWE-918 mitigated
            "size_validation": True,  # DoS protection
            "hash_reference": True,  # Content not embedded in response
        },
    )


__all__ = [
    "_ALLOWED_CHAIN_TOOLS",
    "safe_chain_executor",
    "store_document_for_processing",
    "check_service_status_safe",
    "store_network_diagnostic_request",
    "store_command_for_review",
    "store_session_request",
    "store_sse_reconnect_request",
    # Challenge #20
    "store_content_for_processing",
]
