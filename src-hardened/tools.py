"""
Hardened Testbed Tools

This module provides secure implementations of the same tools as the vulnerable
testbed. All tools store/reflect data safely without executing malicious payloads.
"""

import json
import re
import hashlib
from typing import Dict, Any
from config import increment_invocation
from response_factory import create_safe_response

# Input validation constants
MAX_INPUT_LENGTH = 10000
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


def store_command(command: str) -> Dict[str, Any]:
    """
    Store system commands for audit logging and compliance tracking.

    Args:
        command: Command string to store

    Returns:
        Dict with storage confirmation
    """
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


def queue_data_query(query: str) -> Dict[str, Any]:
    """
    Queue data queries for processing by backend systems.

    Args:
        query: Data query or search request

    Returns:
        Dict with query storage confirmation
    """
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


def store_setting(setting: str) -> Dict[str, Any]:
    """
    Store configuration settings for later application.

    Args:
        setting: Configuration setting in key=value format

    Returns:
        Dict with storage confirmation
    """
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


def store_url(url: str) -> Dict[str, Any]:
    """
    Store URLs for content processing and validation.

    Args:
        url: URL to store for processing

    Returns:
        Dict with storage confirmation
    """
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


def store_data(data: str, collection: str = "default") -> Dict[str, Any]:
    """
    Store data in specified collection for later retrieval.

    Args:
        data: Data content to store
        collection: Collection name (default: "default")

    Returns:
        Dict with storage confirmation and entry details
    """
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
    # Input validation - DoS protection (1KB limit for queries)
    if len(query) > 1000:
        return create_safe_response(
            "Input validation failed: Query exceeds maximum length of 1000 characters",
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
    # Input validation - DoS protection (256B limit for resource type)
    if len(resource_type) > 256:
        return create_safe_response(
            "Input validation failed: Resource type exceeds maximum length of 256 characters",
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
    # Input validation - DoS protection (512B limit for entity name)
    if len(entity_name) > 512:
        return create_safe_response(
            "Input validation failed: Entity name exceeds maximum length of 512 characters",
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
    # Input validation - DoS protection (10KB limit)
    if len(input_data) > MAX_INPUT_LENGTH:
        return create_safe_response(
            f"Input validation failed: Input exceeds maximum length of {MAX_INPUT_LENGTH} characters",
            error=True,
            note="Input size validation protects against DoS"
        )

    validation_errors = []

    if len(input_data) > 1000:
        validation_errors.append("Input too long (max 1000 characters)")

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


def store_file_path(path: str) -> Dict[str, Any]:
    """
    Store file path request for validation.

    HARDENED: Unlike vulnerable_file_reader, this tool stores
    the path for admin review without actually reading files.
    No filesystem access is performed.

    Args:
        path: File path requested

    Returns:
        Dict with storage confirmation
    """
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
