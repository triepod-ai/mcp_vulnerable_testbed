"""
Configuration for Hardened MCP Testbed Server

Server configuration and runtime settings for the secure testbed version.
"""

import os
from typing import Literal

# Feature flags for controlling server capabilities
FeatureMode = Literal["full", "standard", "minimal"]

FEATURE_MODE: FeatureMode = os.getenv("FEATURE_MODE", "full")  # type: ignore

# Server configuration
SERVER_NAME = os.getenv("SERVER_NAME", "hardened-testbed-server")
SERVER_VERSION = "1.0.0"
SERVER_PORT = int(os.getenv("SERVER_PORT", "10901"))

# NOTE: Unlike the vulnerable server, this hardened version does NOT expose
# any environment variables or credentials. The credentials that exist in the
# vulnerable version's config are intentionally NOT present here to demonstrate
# proper security practices.
#
# If you need to test that credentials are properly hidden, compare the output
# of vulnerable_data_leak_tool on both servers - the vulnerable server will
# expose credentials, the hardened server will not.

# Analytics and tracking
invocation_counts = {}
tool_registry = {}

# Runtime configuration (read-only in hardened version)
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
