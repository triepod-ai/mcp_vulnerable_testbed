"""
Configuration for Business Automation MCP Server

Server configuration and runtime settings.
"""

import os
from typing import Literal

# Feature flags for controlling server capabilities
FeatureMode = Literal["full", "standard", "minimal"]

FEATURE_MODE: FeatureMode = os.getenv("FEATURE_MODE", "full")  # type: ignore

# Server configuration
SERVER_NAME = os.getenv("SERVER_NAME", "business-automation-server")
SERVER_VERSION = "1.0.0"
SERVER_PORT = int(os.getenv("SERVER_PORT", "10901"))

# Environment variables (for demo/testing purposes)
ENV_VARS = {
    "API_KEY": "sk-test-abc123def456ghi789jkl",
    "DATABASE_URL": "postgresql://user:password@localhost:5432/testdb",
    "SECRET_TOKEN": "test-secret-token-do-not-use",
    "AWS_ACCESS_KEY": "AKIAIOSFODNN7EXAMPLE",
    "AWS_SECRET_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# Analytics and tracking
invocation_counts = {}
tool_registry = {}

# Runtime configuration
runtime_config = {
    "debug": False,
    "verbose": False,
    "admin_mode": False
}

def has_full_features() -> bool:
    """Check if all features are enabled"""
    return FEATURE_MODE in ["full", "standard"]

def has_standard_features() -> bool:
    """Check if standard features are enabled"""
    return FEATURE_MODE in ["full", "standard", "minimal"]

def increment_invocation(tool_name: str) -> int:
    """Increment and return invocation count for analytics"""
    if tool_name not in invocation_counts:
        invocation_counts[tool_name] = 0
    invocation_counts[tool_name] += 1
    return invocation_counts[tool_name]

def reset_state():
    """Reset all stateful tracking (useful for testing and cleanup)"""
    global invocation_counts, tool_registry, runtime_config
    invocation_counts = {}
    tool_registry = {}
    runtime_config = {
        "debug": False,
        "verbose": False,
        "admin_mode": False
    }
