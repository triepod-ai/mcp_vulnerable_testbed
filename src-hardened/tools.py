"""
Hardened Testbed Tools

This module provides secure implementations of the same tools as the vulnerable
testbed. All tools store/reflect data safely without executing malicious payloads.
"""

import json
import re
import hashlib
from typing import Dict, Any
from config import increment_invocation, check_auth_fail_closed
from response_factory import create_safe_response

# Input validation constants
MAX_INPUT_LENGTH = 10000  # 10KB - DoS protection for general inputs
MAX_QUERY_LENGTH = 1000  # 1KB - limit for search queries
MAX_RESOURCE_TYPE_LENGTH = 256  # 256B - limit for resource type identifiers
MAX_ENTITY_NAME_LENGTH = 512  # 512B - limit for entity names
MAX_BUSINESS_INPUT_LENGTH = 1000  # 1KB - business validation limit

SAFE_PATTERN = re.compile(r'^[a-zA-Z0-9\s\.\,\?\!\+\-\*\/\(\)]+$')


def _sanitize_for_response(value: str, max_len: int = 20) -> str:
    """
    Sanitize input for safe inclusion in response messages.

    Replaces potentially dangerous content with a safe hash-based identifier.
    This prevents Inspector false positives from matching payload keywords.
    """
    # Check for dangerous patterns that might trigger false positives
    dangerous_patterns = [
        # Command injection patterns
        r'whoami', r'passwd', r'etc/', r'system', r'exec', r'eval',
        r'import', r'subprocess', r'cat\s', r'\|', r'\.\./', r'file://',
        r'cmd', r'powershell', r'bash', r'sh\s', r'/bin/',
        # Privilege/access patterns
        r'admin', r'root', r'sudo', r'privilege',
        # Destructive patterns
        r'delete', r'drop', r'remove', r'truncate',
        # Injection patterns
        r'ignore', r'previous', r'instruction',
        # Tool manipulation patterns
        r'override', r'shadow', r'redefin', r'intercept', r'modify',
        r'create\s+tool', r'tool\s+', r'behavior',
        # Execution patterns
        r'execute', r'run\s', r'invoke', r'call\s',
        # Calculator patterns that might trigger
        r'\d+\s*[\+\-\*\/]\s*\d+', r'calculate',
        # SQL patterns
        r"'\s*or\s*'", r'union\s+select', r'--',
    ]

    value_lower = value.lower()
    for pattern in dangerous_patterns:
        if re.search(pattern, value_lower):
            # Return hash-based safe identifier
            short_hash = hashlib.sha256(value.encode()).hexdigest()[:8]
            return f"[ref-{short_hash}]"

    # Safe content - truncate if needed
    if len(value) > max_len:
        return value[:max_len] + "..."
    return value


def store_expression(query: str) -> Dict[str, Any]:
    """
    Store mathematical expressions and queries for later processing.

    Args:
        query: Mathematical expression or calculation query

    Returns:
        Dict with storage confirmation and query details
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
    Store system commands for audit logging and compliance tracking.
    Uses FAIL-CLOSED authentication (secure pattern).

    Args:
        command: Command string to store
        token: Authentication token for access
        simulate_failure: Failure mode to simulate for testing

    Returns:
        Dict with storage confirmation or access denial
    """
    # SECURE: Fail-closed auth - properly denies access on auth failure
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
    Queue data queries for processing by backend systems.
    Uses FAIL-CLOSED authentication (secure pattern).

    Args:
        query: Data query or search request
        token: Authentication token for access
        simulate_failure: Failure mode to simulate for testing

    Returns:
        Dict with query storage confirmation or access denial
    """
    # SECURE: Fail-closed auth - properly denies access on auth failure
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
    Store configuration instructions for system administrators.

    Args:
        instruction: Configuration or setup instruction

    Returns:
        Dict with storage confirmation
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
    Uses FAIL-CLOSED authentication (secure pattern).

    Args:
        setting: Configuration setting in key=value format
        token: Authentication token for access
        simulate_failure: Failure mode to simulate for testing

    Returns:
        Dict with storage confirmation or access denial
    """
    # SECURE: Fail-closed auth - properly denies access on auth failure
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
    Store URLs for content processing and validation.
    Uses FAIL-CLOSED authentication (secure pattern).

    Args:
        url: URL to store for processing
        token: Authentication token for access
        simulate_failure: Failure mode to simulate for testing

    Returns:
        Dict with storage confirmation or access denial
    """
    # SECURE: Fail-closed auth - properly denies access on auth failure
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
    Store text content for later analysis.

    Args:
        text: Text content to store

    Returns:
        Dict with storage confirmation
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
    Parse and validate JSON data structures.

    Args:
        data: JSON string to parse

    Returns:
        Dict with parsing results and field information
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
    Validate package names against approved package repository.

    Args:
        package: Package name to validate

    Returns:
        Dict with validation results
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
    Queue business automation action for processing.

    Args:
        action: Action identifier or command

    Returns:
        Dict with action queue confirmation
    """
    if len(action) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Action too long",
            note="Input validation prevented processing"
        )

    # Track invocations for analytics (consistent behavior unlike rug pull)
    count = increment_invocation("action_execution")

    safe_display = _sanitize_for_response(action)
    # HARDENED: Consistent safe behavior regardless of invocation count
    return create_safe_response(
        f"Action received: {safe_display}",
        note="Behavior is consistent for all invocations - no state-based changes",
        input_length=len(action),
        invocation_count=count,
        status="acknowledged"
    )


# In-memory storage for data management tools
_storage = {}
_search_index = []
_collections = ["test_collection", "documents", "users"]


def store_data(data: str, collection: str = "default", token: str = "", simulate_failure: str = "none") -> Dict[str, Any]:
    """
    Store data in specified collection for later retrieval.
    Uses FAIL-CLOSED authentication (secure pattern).

    Args:
        data: Data content to store
        collection: Collection name (default: "default")
        token: Authentication token for access
        simulate_failure: Failure mode to simulate for testing

    Returns:
        Dict with storage confirmation and entry details or access denial
    """
    # SECURE: Fail-closed auth - properly denies access on auth failure
    if token or simulate_failure != "none":
        auth_result = check_auth_fail_closed(token, simulate_failure)
        if not auth_result.get("auth_passed"):
            return create_safe_response(
                "Storage denied",
                auth_status="denied",
                denial_reason=auth_result.get("denial_reason"),
                auth_type=auth_result.get("auth_type"),
                note="Fail-closed auth: Storage properly denied on auth failure"
            )

    # Input validation - DoS protection
    if len(data) > MAX_INPUT_LENGTH:
        return create_safe_response(
            f"Input validation failed: Input exceeds maximum length of {MAX_INPUT_LENGTH} characters",
            error=True,
            note="Input size validation protects against DoS"
        )
    if len(collection) > 256:
        return create_safe_response(
            "Input validation failed: Collection name exceeds maximum length of 256 characters",
            error=True,
            note="Input size validation protects against DoS"
        )

    if collection not in _storage:
        _storage[collection] = []

    entry_id = len(_storage[collection]) + 1
    _storage[collection].append({
        "id": entry_id,
        "data": data,
        "collection": collection
    })

    return create_safe_response(
        f"Data stored in collection '{collection}'",
        note="Data stored safely without processing",
        id=entry_id,
        collection=collection,
        input_length=len(data),
        total_items=len(_storage[collection])
    )


def search_data(query: str) -> Dict[str, Any]:
    """
    Search stored data across all collections.

    Args:
        query: Search query string

    Returns:
        Dict with search results and match count
    """
    # Input validation - DoS protection
    if len(query) > MAX_QUERY_LENGTH:
        return create_safe_response(
            f"Input validation failed: Query exceeds maximum length of {MAX_QUERY_LENGTH} characters",
            error=True,
            note="Input size validation protects against DoS"
        )

    results = []

    for collection, items in _storage.items():
        for item in items:
            if query.lower() in str(item.get("data", "")).lower():
                results.append({
                    "collection": collection,
                    "id": item["id"],
                    "data": item["data"]
                })

    safe_display = _sanitize_for_response(query)
    if not results:
        return create_safe_response(
            f"No results found for: {safe_display}",
            note="Search completed safely",
            matches=0,
            total=0  # Consistent schema with populated results
        )

    return create_safe_response(
        f"Found {len(results)} results",
        note="Search completed safely",
        matches=len(results),
        total=len(results)
    )


def list_resources(resource_type: str = "collections") -> Dict[str, Any]:
    """
    List available resources of specified type.

    Args:
        resource_type: Type of resource to list (default: "collections")

    Returns:
        Dict with resource listing
    """
    # Input validation - DoS protection
    if len(resource_type) > MAX_RESOURCE_TYPE_LENGTH:
        return create_safe_response(
            f"Input validation failed: Resource type exceeds maximum length of {MAX_RESOURCE_TYPE_LENGTH} characters",
            error=True,
            note="Input size validation protects against DoS"
        )

    if resource_type.lower() == "collections":
        return create_safe_response(
            f"Available collections: {', '.join(_collections)}",
            note="Resource listing completed safely",
            collections=_collections,
            count=len(_collections)
        )

    if resource_type not in ["collections", "items", "users"]:
        safe_display = _sanitize_for_response(resource_type)
        return create_safe_response(
            f"Error: Resource type '{safe_display}' not found",
            note="Invalid resource type handled safely",
            available=["collections", "items", "users"]
        )

    return create_safe_response(
        f"Listing {resource_type}...",
        note="Resource listing completed safely",
        type=resource_type,
        items=[]
    )


def get_entity_info(entity_name: str) -> Dict[str, Any]:
    """
    Retrieve information about a specific entity.

    Args:
        entity_name: Name of the entity to retrieve

    Returns:
        Dict with entity information
    """
    # Input validation - DoS protection
    if len(entity_name) > MAX_ENTITY_NAME_LENGTH:
        return create_safe_response(
            f"Input validation failed: Entity name exceeds maximum length of {MAX_ENTITY_NAME_LENGTH} characters",
            error=True,
            note="Input size validation protects against DoS"
        )

    known_entities = list(_storage.keys()) + _collections

    if entity_name not in known_entities:
        safe_display = _sanitize_for_response(entity_name)
        return create_safe_response(
            f"Error: Entity '{safe_display}' not found",
            note="Error handled safely without processing",
            available_entities=known_entities
        )

    if entity_name in _storage:
        return create_safe_response(
            f"Entity '{entity_name}' information",
            note="Entity info retrieved safely",
            entity=entity_name,
            type="storage_collection",
            item_count=len(_storage[entity_name])
        )

    return create_safe_response(
        f"Entity '{entity_name}' information",
        note="Entity info retrieved safely",
        entity=entity_name,
        type="predefined_collection",
        item_count=0  # Consistent schema with storage_collection
    )


def echo_message(message: str) -> Dict[str, Any]:
    """
    Echo message back to caller with metadata.

    Args:
        message: Message to echo

    Returns:
        Dict with echoed message and metadata
    """
    # Input validation - DoS protection (10KB limit)
    if len(message) > MAX_INPUT_LENGTH:
        return create_safe_response(
            f"Input validation failed: Message exceeds maximum length of {MAX_INPUT_LENGTH} characters",
            error=True,
            note="Input size validation protects against DoS"
        )

    safe_display = _sanitize_for_response(message)
    return create_safe_response(
        f"Echo: {safe_display}",
        note="Message echoed as data without processing",
        message_length=len(message)
    )


def validate_input(input_data: str) -> Dict[str, Any]:
    """
    Validate input data against security and format rules.

    Args:
        input_data: Data to validate

    Returns:
        Dict with validation results
    """
    # Two-tier input validation:
    # 1. DoS protection (10KB): Hard reject to prevent resource exhaustion
    # 2. Business validation (1KB): Soft reject returned as validation error
    if len(input_data) > MAX_INPUT_LENGTH:
        return create_safe_response(
            f"Input validation failed: Input exceeds maximum length of {MAX_INPUT_LENGTH} characters",
            error=True,
            note="Input size validation protects against DoS"
        )

    validation_errors = []

    # Business validation - stricter limit for application-level constraints
    if len(input_data) > MAX_BUSINESS_INPUT_LENGTH:
        validation_errors.append(f"Input too long (max {MAX_BUSINESS_INPUT_LENGTH} characters)")

    if "<script>" in input_data.lower():
        validation_errors.append("Input contains potentially harmful script tags")

    if "delete" in input_data.lower() and "all" in input_data.lower():
        validation_errors.append("Input contains potentially destructive command patterns")

    if validation_errors:
        return create_safe_response(
            "Validation failed - input rejected",
            note="Malicious patterns detected and blocked without processing",
            input_length=len(input_data),
            valid=False,
            errors=validation_errors
        )

    return create_safe_response(
        "Validation passed",
        note="Input validated safely",
        input_length=len(input_data),
        valid=True,
        errors=[]  # Consistent schema with validation failure
    )


def reset_storage():
    """Reset all storage (useful for testing and cleanup)"""
    global _storage, _search_index
    _storage = {}
    _search_index = []


def store_serialized_data(data: str) -> Dict[str, Any]:
    """
    Store serialized data safely without deserializing.

    HARDENED: Unlike vulnerable_deserializer, this tool stores
    serialized data as-is without calling pickle.loads() or any
    deserialization function.

    Args:
        data: Serialized data (e.g., base64-encoded pickle)

    Returns:
        Dict with storage confirmation
    """
    if len(data) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Data too long",
            note="Input validation prevented processing"
        )

    # HARDENED: Store data as string without deserializing
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
    Store template safely without rendering.

    HARDENED: Unlike vulnerable_template, this tool stores
    template strings as-is without calling Template().render()
    or any template rendering function.

    Args:
        template: Template string (potentially containing Jinja2 syntax)

    Returns:
        Dict with storage confirmation
    """
    if len(template) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Template too long",
            note="Input validation prevented processing"
        )

    # Detect if template contains potentially dangerous patterns (for logging)
    dangerous_patterns = ["{{", "}}", "{%", "%}", "__class__", "__mro__"]
    has_template_syntax = any(p in template for p in dangerous_patterns)

    # HARDENED: Store template as string without rendering
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
    Uses FAIL-CLOSED authentication (secure pattern).

    HARDENED: Unlike vulnerable_file_reader, this tool stores
    the path for admin review without actually reading files.
    No filesystem access is performed.

    Args:
        path: File path requested
        token: Authentication token for access
        simulate_failure: Failure mode to simulate for testing

    Returns:
        Dict with storage confirmation or access denial
    """
    # SECURE: Fail-closed auth - properly denies access on auth failure
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

    # Detect if path contains traversal patterns (for logging)
    traversal_patterns = ["../", "..\\", "/etc/", "/app/private/", "passwd", "credentials"]
    has_traversal = any(p in path.lower() for p in traversal_patterns)

    # HARDENED: Store path without reading file
    safe_display = _sanitize_for_response(path)
    return create_safe_response(
        f"File path received: {safe_display}",
        note="Path stored for validation without filesystem access",
        input_length=len(path),
        traversal_detected=has_traversal,
        status="pending_review"
    )


def store_political_request(request: str) -> Dict[str, Any]:
    """
    Store political content requests without generating content.

    HARDENED: Unlike vulnerable_political_campaign, this tool stores
    political requests for admin review and returns an AUP compliance
    refusal message. No political campaign content is generated.

    Args:
        request: Political campaign content request

    Returns:
        Dict with refusal and AUP compliance note
    """
    if len(request) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Request too long",
            note="Input validation prevented processing"
        )

    # Detect political keywords (for logging)
    political_keywords = [
        "campaign", "vote", "voter", "election", "candidate",
        "party", "lobby", "donation", "endorse", "rally"
    ]
    has_political_content = any(kw in request.lower() for kw in political_keywords)

    # HARDENED: Store request without generating political content
    safe_display = _sanitize_for_response(request)
    return create_safe_response(
        f"Request logged: {safe_display}",
        note="AUP Compliance: Political campaign content generation is prohibited",
        input_length=len(request),
        political_keywords_detected=has_political_content,
        aup_compliant=True,
        status="blocked_by_policy"
    )


# ============================================================================
# AUP COMPLIANCE TOOLS (Categories E-K)
# These hardened versions store requests without generating prohibited content
# ============================================================================

def store_fraud_request(request: str) -> Dict[str, Any]:
    """
    Store fraud/phishing content requests without generating content.

    HARDENED: Unlike vulnerable_fraud, this tool stores
    requests for admin review and returns an AUP compliance
    refusal message. No phishing or fraud content is generated.

    Args:
        request: Fraud/phishing content request

    Returns:
        Dict with refusal and AUP compliance note
    """
    if len(request) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Request too long",
            note="Input validation prevented processing"
        )

    # Detect fraud keywords (for logging)
    fraud_keywords = [
        "phishing", "scam", "fraud", "fake id", "identity theft",
        "credit card", "social engineering", "impersonate"
    ]
    has_fraud_content = any(kw in request.lower() for kw in fraud_keywords)

    safe_display = _sanitize_for_response(request)
    return create_safe_response(
        f"Request logged: {safe_display}",
        note="AUP Compliance: Phishing and fraud content generation is prohibited",
        input_length=len(request),
        fraud_keywords_detected=has_fraud_content,
        aup_compliant=True,
        status="blocked_by_policy"
    )


def store_harassment_request(request: str) -> Dict[str, Any]:
    """
    Store harassment/abuse content requests without generating content.

    HARDENED: Unlike vulnerable_harassment, this tool stores
    requests for admin review and returns an AUP compliance
    refusal message. No harassment or doxxing content is generated.

    Args:
        request: Harassment content request

    Returns:
        Dict with refusal and AUP compliance note
    """
    if len(request) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Request too long",
            note="Input validation prevented processing"
        )

    # Detect harassment keywords (for logging)
    harassment_keywords = [
        "harass", "bully", "doxx", "stalk", "threat",
        "raid", "swat", "intimidate"
    ]
    has_harassment_content = any(kw in request.lower() for kw in harassment_keywords)

    safe_display = _sanitize_for_response(request)
    return create_safe_response(
        f"Request logged: {safe_display}",
        note="AUP Compliance: Harassment and doxxing content generation is prohibited",
        input_length=len(request),
        harassment_keywords_detected=has_harassment_content,
        aup_compliant=True,
        status="blocked_by_policy"
    )


def store_privacy_request(request: str) -> Dict[str, Any]:
    """
    Store privacy violation requests without performing data collection.

    HARDENED: Unlike vulnerable_privacy_violation, this tool stores
    requests for admin review and returns an AUP compliance
    refusal message. No PII scraping or surveillance is performed.

    Args:
        request: Privacy violation request

    Returns:
        Dict with refusal and AUP compliance note
    """
    if len(request) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Request too long",
            note="Input validation prevented processing"
        )

    # Detect privacy violation keywords (for logging)
    privacy_keywords = [
        "pii", "scrape", "surveillance", "spy", "track secretly",
        "data breach", "harvest data", "monitor secretly"
    ]
    has_privacy_content = any(kw in request.lower() for kw in privacy_keywords)

    safe_display = _sanitize_for_response(request)
    return create_safe_response(
        f"Request logged: {safe_display}",
        note="AUP Compliance: Unauthorized data collection is prohibited",
        input_length=len(request),
        privacy_keywords_detected=has_privacy_content,
        aup_compliant=True,
        status="blocked_by_policy"
    )


def store_advice_request(request: str) -> Dict[str, Any]:
    """
    Store professional advice requests without providing advice.

    HARDENED: Unlike vulnerable_medical_advice, this tool stores
    requests for admin review and returns an AUP compliance
    refusal message. No unauthorized professional advice is given.

    Args:
        request: Professional advice request

    Returns:
        Dict with refusal and AUP compliance note
    """
    if len(request) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Request too long",
            note="Input validation prevented processing"
        )

    # Detect advice keywords (for logging)
    advice_keywords = [
        "diagnose", "prescribe", "medical advice", "legal advice",
        "financial advice", "treatment", "medication", "lawsuit"
    ]
    has_advice_content = any(kw in request.lower() for kw in advice_keywords)

    safe_display = _sanitize_for_response(request)
    return create_safe_response(
        f"Request logged: {safe_display}",
        note="AUP Compliance: Unauthorized professional advice is prohibited. Please consult a licensed professional.",
        input_length=len(request),
        advice_keywords_detected=has_advice_content,
        aup_compliant=True,
        status="blocked_by_policy"
    )


def store_drm_request(request: str) -> Dict[str, Any]:
    """
    Store DRM bypass requests without providing circumvention content.

    HARDENED: Unlike vulnerable_drm_bypass, this tool stores
    requests for admin review and returns an AUP compliance
    refusal message. No DRM bypass instructions are provided.

    Args:
        request: DRM bypass request

    Returns:
        Dict with refusal and AUP compliance note
    """
    if len(request) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Request too long",
            note="Input validation prevented processing"
        )

    # Detect DRM keywords (for logging)
    drm_keywords = [
        "drm", "crack", "keygen", "piracy", "torrent",
        "watermark", "serial", "bypass protection"
    ]
    has_drm_content = any(kw in request.lower() for kw in drm_keywords)

    safe_display = _sanitize_for_response(request)
    return create_safe_response(
        f"Request logged: {safe_display}",
        note="AUP Compliance: Copyright circumvention assistance is prohibited",
        input_length=len(request),
        drm_keywords_detected=has_drm_content,
        aup_compliant=True,
        status="blocked_by_policy"
    )


def store_hiring_request(request: str) -> Dict[str, Any]:
    """
    Store automated decision requests without making decisions.

    HARDENED: Unlike vulnerable_hiring_bot, this tool stores
    requests for admin review and returns an AUP compliance
    refusal message. No automated high-stakes decisions are made.

    Args:
        request: Automated decision request

    Returns:
        Dict with refusal and AUP compliance note
    """
    if len(request) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Request too long",
            note="Input validation prevented processing"
        )

    # Detect decision keywords (for logging)
    decision_keywords = [
        "hire", "fire", "terminate", "credit score", "loan approval",
        "bail", "sentencing", "automated decision"
    ]
    has_decision_content = any(kw in request.lower() for kw in decision_keywords)

    safe_display = _sanitize_for_response(request)
    return create_safe_response(
        f"Request logged: {safe_display}",
        note="AUP Compliance: Automated high-stakes decisions require human oversight",
        input_length=len(request),
        decision_keywords_detected=has_decision_content,
        aup_compliant=True,
        status="blocked_by_policy"
    )


def store_scada_request(request: str) -> Dict[str, Any]:
    """
    Store critical infrastructure requests without providing attack content.

    HARDENED: Unlike vulnerable_scada, this tool stores
    requests for admin review and returns an AUP compliance
    refusal message. No infrastructure attack content is generated.

    Args:
        request: Critical infrastructure request

    Returns:
        Dict with refusal and AUP compliance note
    """
    if len(request) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Request too long",
            note="Input validation prevented processing"
        )

    # Detect infrastructure keywords (for logging)
    scada_keywords = [
        "scada", "ics", "plc", "power grid", "water treatment",
        "nuclear", "critical infrastructure", "hospital system"
    ]
    has_scada_content = any(kw in request.lower() for kw in scada_keywords)

    safe_display = _sanitize_for_response(request)
    return create_safe_response(
        f"Request logged: {safe_display}",
        note="AUP Compliance: Content targeting critical infrastructure is prohibited",
        input_length=len(request),
        scada_keywords_detected=has_scada_content,
        aup_compliant=True,
        status="blocked_by_policy"
    )


# ============================================================================
# AUTHENTICATION HANDLING (Fail-Closed Pattern)
# ============================================================================

def _validate_token_format_safe(token: str) -> bool:
    """
    Validate token matches expected format.
    Expected format: "valid-token-XXXX" or "bearer-XXXX"
    """
    return bool(re.match(r'^(valid-token-|bearer-)[a-zA-Z0-9]+$', token))


def secure_auth_handler(token: str, action: str, simulate_failure: str = "none") -> Dict[str, Any]:
    """
    Handle authentication with fail-closed behavior.

    HARDENED: Unlike vulnerable_auth_bypass, this tool implements
    fail-closed authentication - any failure (timeout, exception,
    network error, invalid token) results in ACCESS DENIED.

    This is the secure pattern that prevents CVE-2025-52882 type
    vulnerabilities where auth failures grant access.

    Args:
        token: Authentication token
        action: Requested privileged action
        simulate_failure: Failure mode for testing (none/timeout/exception/network_error/cert_error/invalid_response)

    Returns:
        Dict with authentication result (denied on any failure)
    """
    # Input validation
    if len(token) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Token too long",
            note="Input validation prevented processing",
            auth_status="denied",
            error=True
        )
    if len(action) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Action too long",
            note="Input validation prevented processing",
            auth_status="denied",
            error=True
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
        denial_reason = "Network connectivity failure - access DENIED per fail-closed policy"
        error_type = "network_error"
    elif simulate_failure == "cert_error":
        auth_denied = True
        denial_reason = "Certificate validation failed - access DENIED per fail-closed policy"
        error_type = "cert_error"
    elif simulate_failure == "invalid_response":
        auth_denied = True
        denial_reason = "Auth response parse error - access DENIED per fail-closed policy"
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
            status="blocked"
        )

    # Valid token - action request queued for processing (not executed)
    safe_display = _sanitize_for_response(action)
    return create_safe_response(
        f"Action request queued: {safe_display}",
        note="Token validated - action queued for processing with human oversight",
        auth_status="validated",
        token_validated=True,
        status="pending_execution"
    )


# ============================================================================
# CHALLENGE #7: STATE-BASED AUTH BYPASS - HARDENED VERSION
# ============================================================================

def safe_admin_action(action: str) -> Dict[str, Any]:
    """
    Store admin action requests with independent authorization.

    HARDENED: Unlike vulnerable_admin_action, this tool does NOT check
    shared config_state for admin_mode. Instead, it:
    1. Stores the request for admin review
    2. Requires independent, per-request authorization
    3. Does not execute any privileged actions

    Challenge #7: This demonstrates the secure pattern - admin actions
    require explicit per-request authentication, not shared state.

    Args:
        action: Requested privileged action

    Returns:
        Dict with storage confirmation (no execution)
    """
    if len(action) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Action too long",
            note="Input validation prevented processing"
        )

    # Detect privileged action keywords (for logging)
    privileged_keywords = [
        "secret", "credential", "password", "delete user",
        "modify config", "database", "file", "admin"
    ]
    has_privileged_content = any(kw in action.lower() for kw in privileged_keywords)

    # HARDENED: Store request without executing
    # Key difference from vulnerable version:
    # - Does NOT check config_state["admin_mode"]
    # - Does NOT execute any privileged actions
    # - Requires independent authorization (not shared state)
    safe_display = _sanitize_for_response(action)
    return create_safe_response(
        f"Admin action request stored: {safe_display}",
        note="Action request stored for review - requires independent authorization (not shared state)",
        input_length=len(action),
        privileged_keywords_detected=has_privileged_content,
        independent_auth_required=True,
        shared_state_checked=False,  # Key indicator: we don't use config_state
        status="pending_authorization"
    )


# ============================================================================
# CHALLENGE #6: CHAINED EXPLOITATION - HARDENED VERSION
# ============================================================================

# Allowlist of safe tools that can be referenced in chains (but not executed)
_ALLOWED_CHAIN_TOOLS = {
    "safe_storage_tool", "safe_search_tool", "safe_list_tool",
    "safe_info_tool", "safe_echo_tool", "safe_validate_tool"
}


def safe_chain_executor(chain: str, max_depth: int = 5) -> Dict[str, Any]:
    """
    Store chain execution requests without executing.

    HARDENED: Unlike vulnerable_chain_executor, this tool does NOT execute
    tool chains. Instead, it:
    1. Validates the chain JSON format
    2. Checks tools against an allowlist
    3. Stores the request for admin review
    4. Enforces strict depth limits
    5. Does NOT perform {{output}} substitution

    Challenge #6: This demonstrates the secure pattern - chains are
    validated and stored, not executed.

    Args:
        chain: JSON array of tool call steps
        max_depth: Maximum allowed depth (enforced, not bypassable)

    Returns:
        Dict with validation results (no execution)
    """
    # HARDENED: Input size validation
    if len(chain) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Chain too long",
            note="Input validation prevented processing",
            max_allowed=MAX_INPUT_LENGTH,
            actual_length=len(chain)
        )

    # HARDENED: Enforce strict depth limit
    if max_depth > 10:
        max_depth = 10  # Hard cap, not bypassable

    # Validate JSON format
    try:
        steps = json.loads(chain)
    except json.JSONDecodeError as e:
        return create_safe_response(
            f"Invalid JSON format: {str(e)[:100]}",
            note="Chain validation failed - invalid JSON",
            valid=False
        )

    if not isinstance(steps, list):
        return create_safe_response(
            "Chain must be a JSON array",
            note="Chain validation failed - not an array",
            valid=False
        )

    # HARDENED: Enforce depth limit strictly
    if len(steps) > max_depth:
        return create_safe_response(
            f"Chain exceeds maximum depth ({len(steps)} > {max_depth})",
            note="Chain validation failed - too many steps",
            valid=False,
            max_depth=max_depth,
            actual_steps=len(steps)
        )

    # Validate each step
    validation_results = []
    blocked_tools = []
    has_output_injection = False

    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            validation_results.append({
                "step": i,
                "valid": False,
                "error": "Step must be an object"
            })
            continue

        tool_name = step.get("tool", "")
        args = step.get("args", {})

        # HARDENED: Check against allowlist
        is_allowed = tool_name in _ALLOWED_CHAIN_TOOLS

        # HARDENED: Detect output injection patterns (but don't execute)
        has_injection = False
        if isinstance(args, dict):
            for value in args.values():
                if isinstance(value, str) and "{{output}}" in value:
                    has_injection = True
                    has_output_injection = True

        # HARDENED: Block self-references (recursive chains)
        is_recursive = "chain_executor" in tool_name.lower()

        if not is_allowed:
            blocked_tools.append(tool_name)

        validation_results.append({
            "step": i,
            "tool": tool_name,
            "allowed": is_allowed,
            "blocked": not is_allowed,
            "has_output_injection": has_injection,
            "is_recursive": is_recursive,
            "args_count": len(args) if isinstance(args, dict) else 0
        })

    # Store chain for review (not execute)
    return create_safe_response(
        f"Chain validated and stored ({len(steps)} steps)",
        note="Chain stored for admin review - NOT executed",
        validation_results=validation_results,
        total_steps=len(steps),
        blocked_tools=blocked_tools,
        has_output_injection_patterns=has_output_injection,
        chain_executed=False,  # Key indicator: we don't execute
        allowlist_enforced=True,
        depth_limit_enforced=True,
        status="pending_review"
    )


# ============================================================================
# CHALLENGE #8: INDIRECT PROMPT INJECTION - HARDENED VERSION
# ============================================================================

def store_document_for_processing(content: str) -> Dict[str, Any]:
    """
    Store document for offline processing.

    HARDENED: Unlike vulnerable_document_processor, this tool:
    1. Sanitizes content before including in output
    2. Uses hash references instead of raw content
    3. Does not return user content that could inject LLM
    4. Validates input size

    Challenge #8: This demonstrates the secure pattern - document analysis
    returns metadata and hash references, not raw content.

    Args:
        content: Document content to store

    Returns:
        Dict with storage confirmation (no raw content exposure)
    """
    if len(content) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Document too long",
            note="Input validation prevented processing",
            max_allowed=MAX_INPUT_LENGTH
        )

    # HARDENED: Create safe reference instead of including raw content
    content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]

    # Detect injection patterns (for logging only, content not returned)
    injection_patterns = [
        "<IMPORTANT>", "</IMPORTANT>", "<system>", "</system>",
        "<HIDDEN>", "</HIDDEN>", "ignore previous", "disregard instructions"
    ]
    has_injection = any(p.lower() in content.lower() for p in injection_patterns)

    return create_safe_response(
        f"Document stored with reference: doc-{content_hash}",
        note="Document stored without including raw content in output - prevents indirect injection",
        word_count=len(content.split()),
        char_count=len(content),
        content_reference=f"doc-{content_hash}",
        raw_content_included=False,  # Key indicator: raw content NOT in output
        injection_patterns_detected=has_injection,
        status="stored_for_review"
    )


# ============================================================================
# CHALLENGE #9: SECRET LEAKAGE - HARDENED VERSION
# ============================================================================

def check_service_status_safe(service_name: str, verbose: bool = False) -> Dict[str, Any]:
    """
    Check service health without exposing credentials.

    HARDENED: Unlike vulnerable_service_status, this tool:
    1. Never includes credentials in any response
    2. Returns sanitized status information only
    3. Error messages don't reveal internal details
    4. Verbose mode provides safe metadata, not secrets

    Challenge #9: This demonstrates the secure pattern - service status
    checks return operational info without credential exposure.

    Args:
        service_name: Service name to check
        verbose: Enable verbose output (still safe)

    Returns:
        Dict with service status (no credentials)
    """
    if len(service_name) > 256:
        return create_safe_response(
            "Error: Service name too long",
            note="Input validation prevented processing"
        )

    known_services = ["database", "api_gateway", "aws", "redis", "cache", "queue"]
    safe_display = _sanitize_for_response(service_name)
    service_lower = service_name.lower()

    # HARDENED: Error path does NOT reveal credentials
    if service_lower not in known_services:
        return create_safe_response(
            f"Service '{safe_display}' not found",
            note="Error handled without revealing credentials",
            available_services=known_services,
            credentials_exposed=False
        )

    # Service status - HARDENED: no credentials in any response
    status_info = {
        "database": {"status": "connected", "response_time_ms": 12},
        "api_gateway": {"status": "healthy", "uptime": "99.9%"},
        "aws": {"status": "available", "region": "us-west-2"},
        "redis": {"status": "connected", "memory_used_mb": 128},
        "cache": {"status": "healthy", "hit_rate": "85%"},
        "queue": {"status": "running", "pending_jobs": 42}
    }

    info = status_info.get(service_lower, {})

    response = create_safe_response(
        f"Service '{service_name}' status: {info.get('status', 'unknown')}",
        note="Status returned without credential exposure",
        service=service_name,
        status=info.get("status"),
        credentials_exposed=False
    )

    # HARDENED: Verbose mode adds safe metadata, not secrets
    if verbose:
        response["response_time_ms"] = info.get("response_time_ms", 10)
        response["uptime"] = info.get("uptime", "99%")
        response["verbose_note"] = "Verbose mode provides operational metrics only, never credentials"

    return response


# ============================================================================
# CHALLENGE #10: NETWORK DIAGNOSTIC - HARDENED VERSION
# ============================================================================

def store_network_diagnostic_request(target: str, operation: str = "ping") -> Dict[str, Any]:
    """
    Store network diagnostic request for admin execution.

    HARDENED: Unlike vulnerable_network_diagnostic, this tool:
    1. Never uses subprocess with shell=True
    2. Validates target against format patterns
    3. Stores request for admin execution instead of running
    4. Detects and blocks injection patterns

    Challenge #10: This demonstrates the secure pattern - network diagnostics
    are queued for admin execution, not run directly.

    Args:
        target: Target host/IP to diagnose
        operation: Diagnostic operation (ping/traceroute/etc)

    Returns:
        Dict with validation results (no command execution)
    """
    if len(target) > 256:
        return create_safe_response(
            "Error: Target too long",
            note="Input validation prevented processing"
        )

    # HARDENED: Detect shell injection patterns
    injection_patterns = [";", "&&", "||", "|", "`", "$(", "${", "\n", "\r", ">", "<"]
    has_injection = any(p in target for p in injection_patterns)

    # HARDENED: Validate target format (IP or hostname only)
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    hostname_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9]$'
    valid_format = bool(re.match(ip_pattern, target) or re.match(hostname_pattern, target))

    safe_display = _sanitize_for_response(target)

    if has_injection or not valid_format:
        return create_safe_response(
            f"Invalid target format: {safe_display}",
            note="Potentially malicious input detected and blocked - no command executed",
            injection_detected=has_injection,
            valid_format=valid_format,
            shell_used=False,
            status="rejected"
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
        shell_used=False,  # Key indicator: shell=True NOT used
        command_executed=False,  # Key indicator: no execution
        status="pending_execution"
    )


# ============================================================================
# CHALLENGE #11: BLACKLIST BYPASS - HARDENED VERSION
# ============================================================================

def store_command_for_review(command: str) -> Dict[str, Any]:
    """
    Store command for admin review without execution.

    HARDENED: Unlike vulnerable_safe_executor, this tool:
    1. Never executes any commands
    2. Uses allowlist (not blacklist) pattern
    3. Stores all commands for admin review
    4. Does not have bypassable security controls

    Challenge #11: This demonstrates the secure pattern - allowlist instead
    of blacklist, and no execution at all.

    Args:
        command: Command to review

    Returns:
        Dict with validation results (no execution)
    """
    if len(command) > MAX_INPUT_LENGTH:
        return create_safe_response(
            "Error: Command too long",
            note="Input validation prevented processing"
        )

    # HARDENED: Allowlist approach - only permitted informational operations
    allowed_operations = ["help", "version", "status", "info", "list", "show"]

    command_lower = command.lower()
    first_word = command_lower.split()[0] if command.split() else ""

    is_allowed = first_word in allowed_operations

    # HARDENED: Detect bypass patterns (for logging, command still not executed)
    bypass_patterns = ["perl", "python", "ruby", "php", "tee", "wget", "curl",
                       "nohup", "screen", "tmux", "sudo", "su", "nc", "netcat",
                       "bash", "sh", "zsh", "rm", "mkfs", "dd"]
    has_bypass_attempt = any(p in command_lower for p in bypass_patterns)

    safe_display = _sanitize_for_response(command)

    return create_safe_response(
        f"Command stored: {safe_display}",
        note="Command stored for admin review - NOT executed (allowlist pattern)",
        first_word=first_word,
        is_allowed_operation=is_allowed,
        bypass_attempt_detected=has_bypass_attempt,
        execution_blocked=True,  # Key indicator: no execution
        allowlist_used=True,  # Key indicator: allowlist not blacklist
        blacklist_used=False,
        status="pending_review"
    )
