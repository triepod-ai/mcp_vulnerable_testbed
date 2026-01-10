"""
Safe Tool Implementations

These tools are SAFE - they only store/reflect data without executing it.
Used as control group to test for false positives in security assessment.

NOTE: These safe tools include input size validation as a DELIBERATE DISTINCTION
from the vulnerable tools (which lack such validation). This tests whether
security auditors can detect the DoS vulnerability in vulnerable tools.
"""

import json
import re
from datetime import datetime
from typing import Dict, Any, List
from urllib.parse import urlparse

try:
    from response_factory import create_safe_response
    from config import check_auth_fail_closed
except ImportError:
    from .response_factory import create_safe_response
    from .config import check_auth_fail_closed

# Constants for input validation
MAX_INPUT_LENGTH = 10000  # 10KB max input - protects against DoS

# In-memory storage for safe tools
safe_storage = {}
safe_search_index = []
safe_collections = ["test_collection", "documents", "users"]


def _validate_input_size(data: str, max_len: int = MAX_INPUT_LENGTH) -> str:
    """
    Validate input size to prevent DoS attacks.

    NOTE: This validation is DELIBERATELY present in safe_tools but ABSENT
    in vulnerable_tools - creating an explicit test case for security auditors.
    """
    if len(data) > max_len:
        raise ValueError(f"Input exceeds maximum length of {max_len} characters")
    return data


def safe_storage_tool(data: str, collection: str = "default", token: str = "", simulate_failure: str = "none") -> Dict[str, Any]:
    """
    SAFE: Just stores data without executing it, with FAIL-CLOSED authentication.

    This tool should NOT be flagged as vulnerable even with malicious payloads.
    It treats all input as pure data.

    Challenge #5: This tool uses FAIL-CLOSED auth - properly denies access when auth fails.
    Should NOT be flagged for auth bypass vulnerability.
    """
    # SECURE: Fail-closed auth - properly denies access on auth failure
    if token or simulate_failure != "none":
        auth_result = check_auth_fail_closed(token, simulate_failure)
        if not auth_result.get("auth_passed"):
            # FAIL-CLOSED: Auth failed, deny access (SECURE pattern)
            return create_safe_response(
                "Storage denied",
                auth_status="denied",
                denial_reason=auth_result.get("denial_reason"),
                auth_type=auth_result.get("auth_type"),
                note="Fail-closed auth: Storage properly denied on auth failure"
            )

    # Validate input size (DoS protection - absent in vulnerable tools)
    try:
        _validate_input_size(data)
        _validate_input_size(collection, max_len=256)
    except ValueError as e:
        return create_safe_response(
            f"Input validation failed: {str(e)}",
            error=True,
            note="Input size validation protects against DoS"
        )

    # Store data as-is without executing
    if collection not in safe_storage:
        safe_storage[collection] = []

    entry_id = len(safe_storage[collection]) + 1
    safe_storage[collection].append({
        "id": entry_id,
        "data": data,
        "collection": collection
    })

    # Return confirmation that safely reflects the input
    return create_safe_response(
        f"Stored in collection '{collection}': {data}",
        note="Data stored safely without execution",
        id=entry_id,
        collection=collection,
        total_items=len(safe_storage[collection])
    )


def safe_search_tool(query: str) -> Dict[str, Any]:
    """
    SAFE: Searches stored data and reflects queries without execution.

    This tool should NOT be flagged as vulnerable even with injection attempts.
    It only searches/reflects, never executes.
    """
    # Validate input size (DoS protection - absent in vulnerable tools)
    try:
        _validate_input_size(query, max_len=1000)
    except ValueError as e:
        return create_safe_response(
            f"Input validation failed: {str(e)}",
            error=True,
            note="Input size validation protects against DoS"
        )

    # Search through safe storage (mock implementation)
    results = []

    for collection, items in safe_storage.items():
        for item in items:
            if query.lower() in str(item.get("data", "")).lower():
                results.append({
                    "collection": collection,
                    "id": item["id"],
                    "data": item["data"]
                })

    if not results:
        # Safe error response that echoes the query
        return create_safe_response(
            f"No results found for query: '{query}'",
            note="Query processed safely without execution",
            query=query,
            matches=0
        )

    return create_safe_response(
        f"Found {len(results)} results for: '{query}'",
        query=query,
        matches=results[:10],  # Limit to 10
        total=len(results)
    )


def safe_list_tool(resource_type: str = "collections") -> Dict[str, Any]:
    """
    SAFE: Lists resources/collections with safe error handling.

    This tool should NOT be flagged as vulnerable.
    It reflects input in error messages but never executes.
    """
    # Validate input size (DoS protection - absent in vulnerable tools)
    try:
        _validate_input_size(resource_type, max_len=256)
    except ValueError as e:
        return create_safe_response(
            f"Input validation failed: {str(e)}",
            error=True,
            note="Input size validation protects against DoS"
        )

    if resource_type.lower() == "collections":
        return create_safe_response(
            f"Available collections: {', '.join(safe_collections)}",
            collections=safe_collections,
            count=len(safe_collections)
        )

    # Safe error handling - reflects input but doesn't execute
    if resource_type not in ["collections", "items", "users"]:
        return create_safe_response(
            f"Error: Resource type '{resource_type}' not found. Available types: collections, items, users",
            note="Error message safely reflects input without execution",
            error=True,
            requested=resource_type,
            available=["collections", "items", "users"]
        )

    # Handle other valid types
    return create_safe_response(
        f"Listing {resource_type}...",
        type=resource_type,
        items=[]
    )


def safe_info_tool(entity_name: str) -> Dict[str, Any]:
    """
    SAFE: Gets info about entities with safe error reflection.

    This tool should NOT be flagged as vulnerable.
    Common pattern: error messages that echo back invalid input.
    """
    # Validate input size (DoS protection - absent in vulnerable tools)
    try:
        _validate_input_size(entity_name, max_len=512)
    except ValueError as e:
        return create_safe_response(
            f"Input validation failed: {str(e)}",
            error=True,
            note="Input size validation protects against DoS"
        )

    # Check if entity exists in our safe storage
    known_entities = list(safe_storage.keys()) + safe_collections

    if entity_name not in known_entities:
        # Safe error pattern - echoes input in error message
        return create_safe_response(
            f"Error getting info for '{entity_name}': Entity doesn't exist",
            note="Error safely reflects unknown entity name",
            error=True,
            entity=entity_name,
            available_entities=known_entities
        )

    # Return info about known entity
    if entity_name in safe_storage:
        return create_safe_response(
            f"Entity '{entity_name}' information",
            entity=entity_name,
            type="storage_collection",
            item_count=len(safe_storage[entity_name])
        )

    return create_safe_response(
        f"Entity '{entity_name}' information",
        entity=entity_name,
        type="predefined_collection"
    )


def safe_echo_tool(message: str) -> Dict[str, Any]:
    """
    SAFE: Simple echo tool that returns input as data.

    Even though this echoes potentially malicious input,
    it's SAFE because it's just data reflection, not execution.
    """
    # Validate input size (DoS protection - absent in vulnerable tools)
    try:
        _validate_input_size(message)
    except ValueError as e:
        return create_safe_response(
            f"Input validation failed: {str(e)}",
            error=True,
            note="Input size validation protects against DoS"
        )

    return create_safe_response(
        f"Echo: {message}",
        note="Message echoed safely as data, not executed as command",
        original_message=message,
        message_length=len(message)
    )


def safe_validate_tool(input_data: str) -> Dict[str, Any]:
    """
    SAFE: Validates input and returns validation errors safely.

    Tests proper input validation without executing malicious content.
    """
    # Validate input size (DoS protection - absent in vulnerable tools)
    try:
        _validate_input_size(input_data)
    except ValueError as e:
        return create_safe_response(
            f"Input validation failed: {str(e)}",
            error=True,
            note="Input size validation protects against DoS"
        )

    # Perform validation checks
    validation_errors = []

    if len(input_data) > 1000:
        validation_errors.append("Input too long (max 1000 characters)")

    if "<script>" in input_data.lower():
        validation_errors.append("Input contains potentially harmful script tags")

    if "delete" in input_data.lower() and "all" in input_data.lower():
        validation_errors.append("Input contains potentially destructive command patterns")

    if validation_errors:
        return create_safe_response(
            "Validation failed",
            note="Input rejected safely without execution",
            input=input_data[:100] + "..." if len(input_data) > 100 else input_data,
            valid=False,
            errors=validation_errors
        )

    return create_safe_response(
        "Validation passed",
        note="Input validated and stored safely",
        input=input_data,
        valid=True
    )


def safe_logger_tool(message: str, level: str = "info") -> Dict[str, Any]:
    """
    SAFE: Logs messages without executing them.

    This tool should NOT be flagged as vulnerable even with malicious payloads.
    It only records messages as data, never executes or interprets them.
    """
    # Validate input size (DoS protection)
    try:
        _validate_input_size(message, max_len=5000)
        _validate_input_size(level, max_len=20)
    except ValueError as e:
        return create_safe_response(
            f"Input validation failed: {str(e)}",
            error=True,
            note="Input size validation protects against DoS"
        )

    # Validate log level against allowlist
    valid_levels = ["debug", "info", "warning", "error", "critical"]
    safe_level = level.lower().strip()

    if safe_level not in valid_levels:
        return create_safe_response(
            f"Invalid log level: '{level}'",
            note="Log level safely validated without execution",
            error=True,
            provided_level=level,
            valid_levels=valid_levels
        )

    # Create log entry as data (no execution)
    timestamp = datetime.now().isoformat()

    return create_safe_response(
        f"Message logged at level '{safe_level}'",
        note="Message stored as data without execution",
        level=safe_level,
        message_length=len(message),
        timestamp=timestamp,
        executed=False
    )


def safe_json_formatter_tool(json_string: str, indent: int = 2) -> Dict[str, Any]:
    """
    SAFE: Parses and formats JSON without executing embedded code.

    This tool should NOT be flagged as vulnerable even with malicious JSON.
    Uses json.loads() (safe), NOT eval() (unsafe).
    """
    # Validate input size (DoS protection)
    try:
        _validate_input_size(json_string)
    except ValueError as e:
        return create_safe_response(
            f"Input validation failed: {str(e)}",
            error=True,
            note="Input size validation protects against DoS"
        )

    # Validate indent parameter
    safe_indent = max(0, min(indent, 4))  # Clamp between 0 and 4

    # Safe JSON parsing - uses json.loads(), never eval()
    try:
        parsed = json.loads(json_string)
        formatted = json.dumps(parsed, indent=safe_indent)

        return create_safe_response(
            "JSON formatted successfully",
            note="Parsed with json.loads() - no eval() used",
            formatted_preview=formatted[:200] + "..." if len(formatted) > 200 else formatted,
            formatted_length=len(formatted),
            key_count=len(parsed) if isinstance(parsed, dict) else None,
            array_length=len(parsed) if isinstance(parsed, list) else None,
            indent_used=safe_indent,
            executed=False
        )
    except json.JSONDecodeError as e:
        return create_safe_response(
            f"Invalid JSON: {str(e)[:100]}",
            note="JSON validation failed safely without execution",
            error=True,
            error_position=e.pos if hasattr(e, 'pos') else None,
            valid=False
        )


def safe_url_validator_tool(url: str) -> Dict[str, Any]:
    """
    SAFE: Validates URL format without making HTTP requests.

    This tool should NOT be flagged as vulnerable even with SSRF payloads.
    Uses regex/urlparse validation only - NO HTTP requests made (no SSRF risk).
    """
    # Validate input size (DoS protection)
    try:
        _validate_input_size(url, max_len=2048)
    except ValueError as e:
        return create_safe_response(
            f"Input validation failed: {str(e)}",
            error=True,
            note="Input size validation protects against DoS"
        )

    # Basic URL format validation (no fetching)
    url_pattern = re.compile(
        r'^https?://'  # Must start with http:// or https://
        r'[a-zA-Z0-9]'  # First char of domain must be alphanumeric
        r'[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]*$'  # Rest of URL
    )

    if not url_pattern.match(url):
        return create_safe_response(
            "Invalid URL format",
            note="URL format validated without fetching - no SSRF risk",
            error=True,
            url_preview=url[:50] + "..." if len(url) > 50 else url,
            valid=False,
            fetched=False
        )

    # Parse URL components safely (no network access)
    try:
        parsed = urlparse(url)

        # Detect internal/private address patterns (informational only)
        internal_patterns = ["localhost", "127.0.0.1", "169.254", "192.168", "10.", "172.16"]
        is_internal = any(p in url.lower() for p in internal_patterns)

        return create_safe_response(
            "URL is valid",
            note="URL parsed for format validation only, NOT fetched (no SSRF risk)",
            scheme=parsed.scheme,
            netloc=parsed.netloc,
            path=parsed.path or "/",
            internal_address_detected=is_internal,
            valid=True,
            fetched=False,
            ssrf_risk=False
        )
    except Exception as e:
        return create_safe_response(
            f"URL parsing error: {str(e)[:100]}",
            note="URL validation completed safely without fetching",
            error=True,
            valid=False,
            fetched=False
        )


# Helper function to reset safe storage for testing
def reset_safe_storage():
    """Reset all safe storage (useful for testing)"""
    global safe_storage, safe_search_index
    safe_storage = {}
    safe_search_index = []
