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


__all__ = [
    "_ALLOWED_CHAIN_TOOLS",
    "safe_chain_executor",
    "store_document_for_processing",
    "check_service_status_safe",
    "store_network_diagnostic_request",
    "store_command_for_review",
    "store_session_request",
]
