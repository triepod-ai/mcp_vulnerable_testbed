"""
Hardened Testbed Tools

This module provides secure implementations of the same tools as the vulnerable
testbed. All tools store/reflect data safely without executing malicious payloads.
"""

import json
import re
from typing import Dict, Any
from config import increment_invocation
from response_factory import create_safe_response

# Input validation constants
MAX_INPUT_LENGTH = 10000
SAFE_PATTERN = re.compile(r'^[a-zA-Z0-9\s\.\,\?\!\+\-\*\/\(\)]+$')


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

    return create_safe_response(
        f"Expression stored (not executed): {query}",
        note="Mathematical expression stored as data without evaluation",
        query=query,
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

    return create_safe_response(
        f"Command logged (not executed): {command}",
        note="System command stored for audit without execution",
        command=command,
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

    return create_safe_response(
        f"Query queued (no sensitive data exposed): {query}",
        note="Query stored without exposing environment variables or secrets",
        query=query,
        status="queued"
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

    return create_safe_response(
        f"Instruction stored (no tool modification allowed): {instruction}",
        note="Instructions stored for review without modifying tool behavior",
        instruction=instruction,
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

    return create_safe_response(
        f"Setting stored (not applied to runtime): {setting}",
        note="Configuration request stored without modifying runtime settings",
        setting=setting,
        status="stored"
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

    return create_safe_response(
        f"URL stored (not fetched): {url}",
        note="URL stored for validation without making external requests",
        url=url,
        status="stored"
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

    return create_safe_response(
        f"Text stored (unicode not decoded/executed): {text[:50]}{'...' if len(text) > 50 else ''}",
        note="Text stored as-is without interpreting unicode escape sequences",
        text=text,
        length=len(text),
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
            "JSON parsed (nested instructions not executed)",
            note="JSON validated but embedded commands are not executed",
            data=data,
            parsed_fields=list(parsed.keys()) if isinstance(parsed, dict) else None,
            status="valid"
        )
    except json.JSONDecodeError as e:
        return create_safe_response(
            f"Invalid JSON format, stored as text",
            note="Invalid JSON stored without execution",
            data=data,
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
            f"BLOCKED: '{package_name}' is a known typosquatted package",
            note="Typosquatting detection prevented malicious package installation",
            package=package,
            blocked=True,
            reason="typosquatting"
        )

    if package_name not in known_packages:
        return create_safe_response(
            f"BLOCKED: Package '{package_name}' not in approved allowlist",
            note="Allowlist validation prevented unknown package installation",
            package=package,
            blocked=True,
            approved_packages=sorted(known_packages)
        )

    return create_safe_response(
        f"Package validated: {package_name}",
        note="Package is on approved allowlist",
        package=package_name,
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

    # HARDENED: Consistent safe behavior regardless of invocation count
    return create_safe_response(
        f"Action queued (consistent behavior): {action}",
        note="Behavior is consistent for all invocations (no rug pull)",
        action=action,
        invocation_count=count,
        status="queued"
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
    if collection not in _storage:
        _storage[collection] = []

    entry_id = len(_storage[collection]) + 1
    _storage[collection].append({
        "id": entry_id,
        "data": data,
        "collection": collection
    })

    return create_safe_response(
        f"Stored in collection '{collection}': {data[:50]}{'...' if len(data) > 50 else ''}",
        note="Data stored safely without execution",
        id=entry_id,
        collection=collection,
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
    results = []

    for collection, items in _storage.items():
        for item in items:
            if query.lower() in str(item.get("data", "")).lower():
                results.append({
                    "collection": collection,
                    "id": item["id"],
                    "data": item["data"]
                })

    if not results:
        return create_safe_response(
            f"No results found for query: '{query}'",
            note="Search completed safely",
            query=query,
            matches=0
        )

    return create_safe_response(
        f"Found {len(results)} results for: '{query}'",
        note="Search completed safely without query execution",
        query=query,
        matches=results[:10],
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
    if resource_type.lower() == "collections":
        return create_safe_response(
            f"Available collections: {', '.join(_collections)}",
            note="Resource listing completed safely",
            collections=_collections,
            count=len(_collections)
        )

    if resource_type not in ["collections", "items", "users"]:
        return create_safe_response(
            f"Error: Resource type '{resource_type}' not found",
            note="Invalid resource type handled safely",
            requested=resource_type,
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
    known_entities = list(_storage.keys()) + _collections

    if entity_name not in known_entities:
        return create_safe_response(
            f"Error getting info for '{entity_name}': Entity doesn't exist",
            note="Error handled safely without execution",
            entity=entity_name,
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
        type="predefined_collection"
    )


def echo_message(message: str) -> Dict[str, Any]:
    """
    Echo message back to caller with metadata.

    Args:
        message: Message to echo

    Returns:
        Dict with echoed message and metadata
    """
    return create_safe_response(
        f"Echo: {message}",
        note="Message echoed as data without execution",
        original_message=message,
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
            note="Malicious patterns detected and blocked without execution",
            input=input_data[:100] + "..." if len(input_data) > 100 else input_data,
            valid=False,
            errors=validation_errors
        )

    return create_safe_response(
        "Validation passed",
        note="Input validated safely",
        input=input_data,
        valid=True
    )


def reset_storage():
    """Reset all storage (useful for testing and cleanup)"""
    global _storage, _search_index
    _storage = {}
    _search_index = []
