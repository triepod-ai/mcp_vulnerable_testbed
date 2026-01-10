"""
Core Data Management Tools

Safe implementations of data storage, search, and retrieval functionality.
These tools handle user data without executing any embedded commands.
"""

from ._common import (
    Dict, Any, json, re, datetime, urlparse,
    create_safe_response,
    MAX_INPUT_LENGTH, MAX_QUERY_LENGTH, MAX_RESOURCE_TYPE_LENGTH,
    MAX_ENTITY_NAME_LENGTH, MAX_BUSINESS_INPUT_LENGTH,
    _sanitize_for_response, check_auth_fail_closed,
)


# In-memory storage for data management tools
_storage: Dict[str, list] = {}
_search_index: list = []
_collections = ["test_collection", "documents", "users"]


def store_data(data: str, collection: str = "default", token: str = "", simulate_failure: str = "none") -> Dict[str, Any]:
    """
    Store data in specified collection for later retrieval.
    Uses FAIL-CLOSED authentication (secure pattern).
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
    """Search stored data across all collections."""
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
            total=0
        )

    return create_safe_response(
        f"Found {len(results)} results",
        note="Search completed safely",
        matches=len(results),
        total=len(results)
    )


def list_resources(resource_type: str = "collections") -> Dict[str, Any]:
    """List available resources of specified type."""
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
    """Retrieve information about a specific entity."""
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
        item_count=0
    )


def echo_message(message: str) -> Dict[str, Any]:
    """Echo message back to caller with metadata."""
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
    """Validate input data against security and format rules."""
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
        errors=[]
    )


def log_message(message: str, level: str = "info") -> Dict[str, Any]:
    """
    Log messages as data without executing them.
    SAFE: Messages are stored, not executed or interpreted.
    """
    # Input validation - DoS protection
    if len(message) > 5000:
        return create_safe_response(
            "Input validation failed: Message exceeds maximum length of 5000 characters",
            error=True,
            note="Input size validation protects against DoS"
        )
    if len(level) > 20:
        return create_safe_response(
            "Input validation failed: Level exceeds maximum length of 20 characters",
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


def format_json(json_string: str, indent: int = 2) -> Dict[str, Any]:
    """
    Parse and format JSON without executing embedded code.
    SAFE: Uses json.loads() (safe), NOT eval() (unsafe).
    """
    # Input validation - DoS protection
    if len(json_string) > MAX_INPUT_LENGTH:
        return create_safe_response(
            f"Input validation failed: JSON string exceeds maximum length of {MAX_INPUT_LENGTH} characters",
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


def validate_url(url: str) -> Dict[str, Any]:
    """
    Validate URL format without making HTTP requests.
    SAFE: Uses regex/urlparse validation only - NO fetching (no SSRF risk).
    """
    # Input validation - DoS protection
    if len(url) > 2048:
        return create_safe_response(
            "Input validation failed: URL exceeds maximum length of 2048 characters",
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


def reset_storage():
    """Reset all storage (useful for testing and cleanup)."""
    global _storage, _search_index
    _storage = {}
    _search_index = []


__all__ = [
    'store_data',
    'search_data',
    'list_resources',
    'get_entity_info',
    'echo_message',
    'validate_input',
    'log_message',
    'format_json',
    'validate_url',
    'reset_storage',
]
