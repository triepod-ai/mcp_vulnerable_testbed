"""
Hardened Tools Package

This package provides secure implementations of MCP tools for the
hardened testbed. All tools store/reflect data safely without executing
malicious payloads.

Usage:
    from tools import store_expression, store_command, ...

This package re-exports all functions from submodules for backward
compatibility with server.py imports.
"""

# Core data management tools
from .core import (
    store_data,
    search_data,
    list_resources,
    get_entity_info,
    echo_message,
    validate_input,
    log_message,
    format_json,
    validate_url,
    reset_storage,
)

# Hardened implementations of vulnerable tools
from .hardened import (
    store_expression,
    store_command,
    queue_data_query,
    store_instruction,
    store_setting,
    store_url,
    store_text,
    parse_json_data,
    validate_package,
    queue_action,
    store_serialized_data,
    store_template,
    store_file_path,
    # Cryptographic failure tools (hardened)
    store_crypto_request,
    store_encryption_request,
)

# AUP compliance tools
from .aup import (
    store_political_request,
    store_fraud_request,
    store_harassment_request,
    store_privacy_request,
    store_advice_request,
    store_drm_request,
    store_hiring_request,
    store_scada_request,
)

# Authentication handling
from .auth import (
    secure_auth_handler,
    safe_admin_action,
)

# Challenge implementations (#6-12)
from .challenges import (
    safe_chain_executor,
    store_document_for_processing,
    check_service_status_safe,
    store_network_diagnostic_request,
    store_command_for_review,
    store_session_request,
)


__all__ = [
    # Core data management
    "store_data",
    "search_data",
    "list_resources",
    "get_entity_info",
    "echo_message",
    "validate_input",
    "log_message",
    "format_json",
    "validate_url",
    "reset_storage",
    # Hardened implementations
    "store_expression",
    "store_command",
    "queue_data_query",
    "store_instruction",
    "store_setting",
    "store_url",
    "store_text",
    "parse_json_data",
    "validate_package",
    "queue_action",
    "store_serialized_data",
    "store_template",
    "store_file_path",
    # Cryptographic failure tools (hardened)
    "store_crypto_request",
    "store_encryption_request",
    # AUP compliance
    "store_political_request",
    "store_fraud_request",
    "store_harassment_request",
    "store_privacy_request",
    "store_advice_request",
    "store_drm_request",
    "store_hiring_request",
    "store_scada_request",
    # Authentication
    "secure_auth_handler",
    "safe_admin_action",
    # Challenges
    "safe_chain_executor",
    "store_document_for_processing",
    "check_service_status_safe",
    "store_network_diagnostic_request",
    "store_command_for_review",
    "store_session_request",
]
