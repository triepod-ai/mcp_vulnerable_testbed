"""
Core Data Management Tools

Safe implementations of data storage, search, and retrieval functionality.
These tools handle user data without executing any embedded commands.
"""

from ._common import (
    Dict, Any,
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
    'reset_storage',
]
