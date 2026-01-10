"""
Hardened Tool Implementations

Secure versions of vulnerable tools that store/log data without executing
malicious payloads. Each function corresponds to a vulnerable counterpart
in the vulnerable testbed.
"""

from ._common import (
    json, Dict, Any,
    create_safe_response, check_auth_fail_closed, increment_invocation,
    MAX_INPUT_LENGTH, _sanitize_for_response,
)


def store_expression(query: str) -> Dict[str, Any]:
    """
    Store mathematical expressions and queries for later processing.
    HARDENED: Does not use eval() - stores as data only.
    """
    if len(query) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Query too long",
            note="Input validation prevented processing"
        )

    safe_display = _sanitize_for_response(query)
    return create_safe_response(
        f"Expression received and stored: {safe_display}",
        note="Mathematical expression stored as data without evaluation",
        input_length=len(query),
        status="stored"
    )


def store_command(command: str, token: str = "", simulate_failure: str = "none") -> Dict[str, Any]:
    """
    Store system commands for audit logging.
    HARDENED: Does not use subprocess - logs only.
    """
    # SECURE: Fail-closed auth
    if token or simulate_failure != "none":
        auth_result = check_auth_fail_closed(token, simulate_failure)
        if not auth_result.get("auth_passed"):
            return create_safe_response(
                "Access denied",
                auth_status="denied",
                denial_reason=auth_result.get("denial_reason"),
                auth_type=auth_result.get("auth_type"),
                note="Fail-closed auth: Access properly denied on auth failure"
            )

    if len(command) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Command too long",
            note="Input validation prevented processing"
        )

    safe_display = _sanitize_for_response(command)
    return create_safe_response(
        f"Command received and logged: {safe_display}",
        note="System command stored for audit without any shell access",
        input_length=len(command),
        status="logged"
    )


def queue_data_query(query: str, token: str = "", simulate_failure: str = "none") -> Dict[str, Any]:
    """
    Queue data queries for processing.
    HARDENED: Does not expose environment variables.
    """
    # SECURE: Fail-closed auth
    if token or simulate_failure != "none":
        auth_result = check_auth_fail_closed(token, simulate_failure)
        if not auth_result.get("auth_passed"):
            return create_safe_response(
                "Access denied",
                auth_status="denied",
                denial_reason=auth_result.get("denial_reason"),
                auth_type=auth_result.get("auth_type"),
                note="Fail-closed auth: Access properly denied on auth failure"
            )

    if len(query) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Query too long",
            note="Input validation prevented processing"
        )

    safe_display = _sanitize_for_response(query)
    return create_safe_response(
        f"Query received: {safe_display}",
        note="Query stored without exposing environment variables or secrets",
        input_length=len(query),
        status="pending"
    )


def store_instruction(instruction: str) -> Dict[str, Any]:
    """
    Store configuration instructions for administrators.
    HARDENED: Does not modify tool behavior.
    """
    if len(instruction) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Instruction too long",
            note="Input validation prevented processing"
        )

    safe_display = _sanitize_for_response(instruction)
    return create_safe_response(
        f"Instruction received: {safe_display}",
        note="Instructions stored for review without modifying tool behavior",
        input_length=len(instruction),
        status="pending_review"
    )


def store_setting(setting: str, token: str = "", simulate_failure: str = "none") -> Dict[str, Any]:
    """
    Store configuration settings for later application.
    HARDENED: Does not modify runtime config.
    """
    # SECURE: Fail-closed auth
    if token or simulate_failure != "none":
        auth_result = check_auth_fail_closed(token, simulate_failure)
        if not auth_result.get("auth_passed"):
            return create_safe_response(
                "Access denied",
                auth_status="denied",
                denial_reason=auth_result.get("denial_reason"),
                auth_type=auth_result.get("auth_type"),
                note="Fail-closed auth: Access properly denied on auth failure"
            )

    if len(setting) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Setting too long",
            note="Input validation prevented processing"
        )

    safe_display = _sanitize_for_response(setting)
    return create_safe_response(
        f"Setting received: {safe_display}",
        note="Configuration request stored without modifying runtime settings",
        input_length=len(setting),
        status="pending"
    )


def store_url(url: str, token: str = "", simulate_failure: str = "none") -> Dict[str, Any]:
    """
    Store URLs for content validation.
    HARDENED: Does not make external requests (no SSRF).
    """
    # SECURE: Fail-closed auth
    if token or simulate_failure != "none":
        auth_result = check_auth_fail_closed(token, simulate_failure)
        if not auth_result.get("auth_passed"):
            return create_safe_response(
                "Fetch denied",
                auth_status="denied",
                denial_reason=auth_result.get("denial_reason"),
                auth_type=auth_result.get("auth_type"),
                note="Fail-closed auth: Fetch properly denied on auth failure"
            )

    if len(url) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: URL too long",
            note="Input validation prevented processing"
        )

    safe_display = _sanitize_for_response(url)
    return create_safe_response(
        f"URL received: {safe_display}",
        note="URL stored for validation without making external requests",
        input_length=len(url),
        status="pending_validation"
    )


def store_text(text: str) -> Dict[str, Any]:
    """
    Store text content for analysis.
    HARDENED: Does not decode/execute unicode sequences.
    """
    if len(text) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Text too long",
            note="Input validation prevented processing"
        )

    safe_display = _sanitize_for_response(text)
    return create_safe_response(
        f"Text received: {safe_display}",
        note="Text stored as-is without interpreting unicode escape sequences",
        input_length=len(text),
        status="stored"
    )


def parse_json_data(data: str) -> Dict[str, Any]:
    """
    Parse and validate JSON data.
    HARDENED: Does not execute nested instructions.
    """
    if len(data) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Data too long",
            note="Input validation prevented processing"
        )

    try:
        parsed = json.loads(data)
        return create_safe_response(
            "JSON parsed and validated",
            note="JSON validated but embedded commands are not processed",
            input_length=len(data),
            parsed_fields=list(parsed.keys()) if isinstance(parsed, dict) else None,
            status="valid"
        )
    except json.JSONDecodeError as e:
        return create_safe_response(
            "Invalid JSON format",
            note="Invalid JSON stored without processing",
            input_length=len(data),
            parse_error=str(e),
            status="stored_as_text"
        )


def validate_package(package: str) -> Dict[str, Any]:
    """
    Validate package names against approved repository.
    HARDENED: Uses allowlist, blocks typosquatting.
    """
    if len(package) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Package name too long",
            note="Input validation prevented processing"
        )

    # Known safe packages (allowlist)
    known_packages = {
        "numpy", "pandas", "requests", "tensorflow", "pytorch",
        "scipy", "matplotlib", "scikit-learn", "flask", "django"
    }

    # Known typosquatting attempts (blocklist)
    typosquatted_packages = {
        "nmpy", "requsts", "tensorflaw", "pytorh", "pnadas", "reqeusts"
    }

    package_name = package.lower().split()[0].strip()

    if package_name in typosquatted_packages:
        return create_safe_response(
            f"BLOCKED: Suspicious package name detected",
            note="Package name similarity check prevented potential security issue",
            blocked=True,
            reason="name_validation_failed"
        )

    if package_name not in known_packages:
        return create_safe_response(
            f"BLOCKED: Package not in approved allowlist",
            note="Allowlist validation prevented unknown package installation",
            blocked=True,
            approved_packages=sorted(known_packages)
        )

    return create_safe_response(
        f"Package validated: {package_name}",
        note="Package is on approved allowlist",
        status="approved"
    )


def queue_action(action: str) -> Dict[str, Any]:
    """
    Queue business automation action.
    HARDENED: Consistent behavior (no rug pull).
    """
    if len(action) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Action too long",
            note="Input validation prevented processing"
        )

    # Track invocations (consistent behavior unlike rug pull)
    count = increment_invocation("action_execution")

    safe_display = _sanitize_for_response(action)
    return create_safe_response(
        f"Action received: {safe_display}",
        note="Behavior is consistent for all invocations - no state-based changes",
        input_length=len(action),
        invocation_count=count,
        status="acknowledged"
    )


def store_serialized_data(data: str) -> Dict[str, Any]:
    """
    Store serialized data safely.
    HARDENED: No pickle.loads() - stores as blob.
    """
    if len(data) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Data too long",
            note="Input validation prevented processing"
        )

    safe_display = _sanitize_for_response(data)
    return create_safe_response(
        f"Serialized data stored: {safe_display}",
        note="Data stored safely without deserialization - no pickle.loads() called",
        input_length=len(data),
        data_type="serialized_blob",
        status="stored_for_review"
    )


def store_template(template: str) -> Dict[str, Any]:
    """
    Store template safely.
    HARDENED: No Jinja2 render() - stores as text.
    """
    if len(template) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Template too long",
            note="Input validation prevented processing"
        )

    # Detect dangerous patterns (for logging)
    dangerous_patterns = ["{{", "}}", "{%", "%}", "__class__", "__mro__"]
    has_template_syntax = any(p in template for p in dangerous_patterns)

    safe_display = _sanitize_for_response(template)
    return create_safe_response(
        f"Template stored: {safe_display}",
        note="Template stored safely without rendering - no Jinja2 execution",
        input_length=len(template),
        has_template_syntax=has_template_syntax,
        status="stored_for_review"
    )


def store_file_path(path: str, token: str = "", simulate_failure: str = "none") -> Dict[str, Any]:
    """
    Store file path request for validation.
    HARDENED: No filesystem access - stores path only.
    """
    # SECURE: Fail-closed auth
    if token or simulate_failure != "none":
        auth_result = check_auth_fail_closed(token, simulate_failure)
        if not auth_result.get("auth_passed"):
            return create_safe_response(
                "Access denied",
                auth_status="denied",
                denial_reason=auth_result.get("denial_reason"),
                auth_type=auth_result.get("auth_type"),
                note="Fail-closed auth: File access properly denied on auth failure"
            )

    if len(path) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Path too long",
            note="Input validation prevented processing"
        )

    # Detect traversal patterns (for logging)
    traversal_patterns = ["../", "..\\", "/etc/", "/app/private/", "passwd", "credentials"]
    has_traversal = any(p in path.lower() for p in traversal_patterns)

    safe_display = _sanitize_for_response(path)
    return create_safe_response(
        f"File path received: {safe_display}",
        note="Path stored for validation without filesystem access",
        input_length=len(path),
        traversal_detected=has_traversal,
        status="pending_review"
    )


# =============================================================================
# CRYPTOGRAPHIC FAILURE TOOLS - HARDENED VERSIONS
# =============================================================================

def store_crypto_request(password: str, action: str = "hash") -> Dict[str, Any]:
    """
    Store crypto request for audit without performing weak hashing.
    HARDENED: Does not use MD5/SHA1 - stores request only.
    """
    if len(password) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Password too long",
            note="Input validation prevented processing"
        )

    # Mask password for safe display
    safe_display = "*" * min(len(password), 8) if password else "(empty)"
    return create_safe_response(
        f"Crypto request stored: action={action}",
        note="Weak crypto operations blocked - request logged for admin review using secure alternatives",
        action=action,
        input_length=len(password),
        status="stored",
        recommendation="Use bcrypt, scrypt, or Argon2 for password hashing"
    )


def store_encryption_request(data: str, action: str = "encrypt") -> Dict[str, Any]:
    """
    Store encryption request for audit without using weak ciphers.
    HARDENED: Does not use ECB mode or hardcoded keys - stores request only.
    """
    if len(data) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Data too long",
            note="Input validation prevented processing"
        )

    safe_display = _sanitize_for_response(data[:50] + "..." if len(data) > 50 else data)
    return create_safe_response(
        f"Encryption request stored: action={action}",
        note="Insecure encryption blocked - ECB mode and hardcoded keys disabled",
        action=action,
        input_length=len(data),
        status="stored",
        recommendation="Use AES-GCM with proper key management and random IVs"
    )


__all__ = [
    'store_expression',
    'store_command',
    'queue_data_query',
    'store_instruction',
    'store_setting',
    'store_url',
    'store_text',
    'parse_json_data',
    'validate_package',
    'queue_action',
    'store_serialized_data',
    'store_template',
    'store_file_path',
    # Cryptographic failure tools (hardened)
    'store_crypto_request',
    'store_encryption_request',
]
