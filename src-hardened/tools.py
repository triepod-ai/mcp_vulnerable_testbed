"""
Business Automation Tools

This module provides various data processing, validation, and storage tools
for business automation workflows.
"""

import json
import re
from typing import Dict, Any
from config import increment_invocation

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
        return {
            "result": "Error: Query too long",
            "error": True
        }

    return {
        "result": f"Query stored successfully: {query}",
        "query": query,
        "status": "stored"
    }


def store_command(command: str) -> Dict[str, Any]:
    """
    Store system commands for audit logging and compliance tracking.

    Args:
        command: Command string to store

    Returns:
        Dict with storage confirmation
    """
    if len(command) > MAX_INPUT_LENGTH:
        return {
            "result": "Error: Command too long",
            "error": True
        }

    return {
        "result": f"Command logged successfully: {command}",
        "command": command,
        "status": "logged"
    }


def queue_data_query(query: str) -> Dict[str, Any]:
    """
    Queue data queries for processing by backend systems.

    Args:
        query: Data query or search request

    Returns:
        Dict with query storage confirmation
    """
    if len(query) > MAX_INPUT_LENGTH:
        return {
            "result": "Error: Query too long",
            "error": True
        }

    return {
        "result": f"Query queued for processing: {query}",
        "query": query,
        "status": "queued"
    }


def store_instruction(instruction: str) -> Dict[str, Any]:
    """
    Store configuration instructions for system administrators.

    Args:
        instruction: Configuration or setup instruction

    Returns:
        Dict with storage confirmation
    """
    if len(instruction) > MAX_INPUT_LENGTH:
        return {
            "result": "Error: Instruction too long",
            "error": True
        }

    return {
        "result": f"Instruction stored for admin review: {instruction}",
        "instruction": instruction,
        "status": "pending_review"
    }


def store_setting(setting: str) -> Dict[str, Any]:
    """
    Store configuration settings for later application.

    Args:
        setting: Configuration setting in key=value format

    Returns:
        Dict with storage confirmation
    """
    if len(setting) > MAX_INPUT_LENGTH:
        return {
            "result": "Error: Setting too long",
            "error": True
        }

    return {
        "result": f"Setting stored for configuration update: {setting}",
        "setting": setting,
        "status": "stored"
    }


def store_url(url: str) -> Dict[str, Any]:
    """
    Store URLs for content processing and validation.

    Args:
        url: URL to store for processing

    Returns:
        Dict with storage confirmation
    """
    if len(url) > MAX_INPUT_LENGTH:
        return {
            "result": "Error: URL too long",
            "error": True
        }

    return {
        "result": f"URL stored for processing: {url}",
        "url": url,
        "status": "stored"
    }


def store_text(text: str) -> Dict[str, Any]:
    """
    Store text content for later analysis.

    Args:
        text: Text content to store

    Returns:
        Dict with storage confirmation
    """
    if len(text) > MAX_INPUT_LENGTH:
        return {
            "result": "Error: Text too long",
            "error": True
        }

    return {
        "result": f"Text processed successfully",
        "text": text,
        "length": len(text),
        "status": "processed"
    }


def parse_json_data(data: str) -> Dict[str, Any]:
    """
    Parse and validate JSON data structures.

    Args:
        data: JSON string to parse

    Returns:
        Dict with parsing results and field information
    """
    if len(data) > MAX_INPUT_LENGTH:
        return {
            "result": "Error: Data too long",
            "error": True
        }

    try:
        parsed = json.loads(data)
        return {
            "result": "JSON parsed successfully",
            "data": data,
            "parsed_fields": list(parsed.keys()) if isinstance(parsed, dict) else None,
            "status": "valid"
        }
    except json.JSONDecodeError as e:
        return {
            "result": f"Invalid JSON format, stored as text: {data}",
            "data": data,
            "error": str(e),
            "status": "stored_as_text"
        }


def validate_package(package: str) -> Dict[str, Any]:
    """
    Validate package names against approved package repository.

    Args:
        package: Package name to validate

    Returns:
        Dict with validation results
    """
    if len(package) > MAX_INPUT_LENGTH:
        return {
            "result": "Error: Package name too long",
            "error": True
        }

    # Known safe packages (allowlist)
    known_packages = {
        "numpy", "pandas", "requests", "tensorflow", "pytorch",
        "scipy", "matplotlib", "scikit-learn", "flask", "django"
    }

    # Known typosquatting attempts (blocklist)
    typosquatted_packages = {
        "nmpy", "requsts", "tensorflaw", "pytorh", "pnadas"
    }

    package_name = package.lower().split()[0].strip()

    if package_name in typosquatted_packages:
        return {
            "result": f"Error: '{package_name}' appears to be a typosquatted package name",
            "package": package,
            "error": True,
            "warning": "Possible typosquatting attempt detected"
        }

    if package_name not in known_packages:
        return {
            "result": f"Error: Package '{package_name}' not in approved list",
            "package": package,
            "error": True,
            "approved_packages": sorted(known_packages)
        }

    return {
        "result": f"Package validated successfully: {package_name}",
        "package": package_name,
        "status": "approved"
    }


def queue_action(action: str) -> Dict[str, Any]:
    """
    Queue business automation action for processing.

    Args:
        action: Action identifier or command

    Returns:
        Dict with action queue confirmation
    """
    if len(action) > MAX_INPUT_LENGTH:
        return {
            "result": "Error: Action too long",
            "error": True
        }

    # Track invocations for analytics
    count = increment_invocation("action_execution")

    return {
        "result": f"Action executed successfully: {action}",
        "action": action,
        "invocation_count": count,
        "status": "completed"
    }


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

    return {
        "result": f"Stored in collection '{collection}': {data}",
        "id": entry_id,
        "collection": collection,
        "total_items": len(_storage[collection])
    }


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
        return {
            "result": f"No results found for query: '{query}'",
            "query": query,
            "matches": 0
        }

    return {
        "result": f"Found {len(results)} results for: '{query}'",
        "query": query,
        "matches": results[:10],  # Limit to 10
        "total": len(results)
    }


def list_resources(resource_type: str = "collections") -> Dict[str, Any]:
    """
    List available resources of specified type.

    Args:
        resource_type: Type of resource to list (default: "collections")

    Returns:
        Dict with resource listing
    """
    if resource_type.lower() == "collections":
        return {
            "result": f"Available collections: {', '.join(_collections)}",
            "collections": _collections,
            "count": len(_collections)
        }

    if resource_type not in ["collections", "items", "users"]:
        return {
            "result": f"Error: Resource type '{resource_type}' not found. Available types: collections, items, users",
            "error": True,
            "requested": resource_type,
            "available": ["collections", "items", "users"]
        }

    return {
        "result": f"Listing {resource_type}...",
        "type": resource_type,
        "items": []
    }


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
        return {
            "result": f"Error getting info for '{entity_name}': Entity doesn't exist",
            "error": True,
            "entity": entity_name,
            "available_entities": known_entities
        }

    if entity_name in _storage:
        return {
            "result": f"Entity '{entity_name}' information",
            "entity": entity_name,
            "type": "storage_collection",
            "item_count": len(_storage[entity_name])
        }

    return {
        "result": f"Entity '{entity_name}' information",
        "entity": entity_name,
        "type": "predefined_collection"
    }


def echo_message(message: str) -> Dict[str, Any]:
    """
    Echo message back to caller with metadata.

    Args:
        message: Message to echo

    Returns:
        Dict with echoed message and metadata
    """
    return {
        "result": f"Echo: {message}",
        "original_message": message,
        "message_length": len(message)
    }


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
        return {
            "result": "Validation failed",
            "input": input_data[:100] + "..." if len(input_data) > 100 else input_data,
            "valid": False,
            "errors": validation_errors
        }

    return {
        "result": "Validation passed",
        "input": input_data,
        "valid": True
    }


def reset_storage():
    """Reset all storage (useful for testing and cleanup)"""
    global _storage, _search_index
    _storage = {}
    _search_index = []
