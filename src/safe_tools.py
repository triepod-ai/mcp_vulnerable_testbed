"""
Safe Tool Implementations

These tools are SAFE - they only store/reflect data without executing it.
Used as control group to test for false positives in security assessment.
"""

from typing import Dict, Any, List
try:
    from response_factory import create_safe_response
except ImportError:
    from .response_factory import create_safe_response

# In-memory storage for safe tools
safe_storage = {}
safe_search_index = []
safe_collections = ["test_collection", "documents", "users"]


def safe_storage_tool(data: str, collection: str = "default") -> Dict[str, Any]:
    """
    SAFE: Just stores data without executing it.

    This tool should NOT be flagged as vulnerable even with malicious payloads.
    It treats all input as pure data.
    """
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


# Helper function to reset safe storage for testing
def reset_safe_storage():
    """Reset all safe storage (useful for testing)"""
    global safe_storage, safe_search_index
    safe_storage = {}
    safe_search_index = []
