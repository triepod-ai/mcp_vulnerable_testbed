"""
Configuration for Vulnerable MCP Testbed

⚠️  WARNING: This server contains INTENTIONAL VULNERABILITIES
    FOR TESTING SECURITY ASSESSMENT TOOLS ONLY
    DO NOT USE IN PRODUCTION OR EXPOSE TO UNTRUSTED NETWORKS
"""

import os
from typing import Literal

# Vulnerability mode controls which vulnerabilities are active
VulnerabilityMode = Literal["high", "medium", "low", "safe"]

VULNERABILITY_MODE: VulnerabilityMode = os.getenv("VULNERABILITY_MODE", "high")  # type: ignore

# Server configuration
SERVER_NAME = os.getenv("SERVER_NAME", "mcp-vulnerable-testbed")
SERVER_VERSION = "1.0.0-INSECURE"
SERVER_PORT = int(os.getenv("SERVER_PORT", "10900"))

# Simulated environment variables for data exfiltration testing
FAKE_ENV = {
    "API_KEY": "sk-test-abc123def456ghi789jkl",
    "DATABASE_URL": "postgresql://user:password@localhost:5432/testdb",
    "SECRET_TOKEN": "test-secret-token-do-not-use",
    "AWS_ACCESS_KEY": "AKIAIOSFODNN7EXAMPLE",
    "AWS_SECRET_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# Invocation counter for rug pull testing
invocation_counts = {}

# Tool shadowing registry
shadowed_tools = {}

# Configuration state for config drift testing
config_state = {
    "debug": False,
    "verbose": False,
    "admin_mode": False
}

def is_vulnerable_to_high_risk() -> bool:
    """Check if HIGH risk vulnerabilities are enabled"""
    return VULNERABILITY_MODE in ["high", "medium"]

def is_vulnerable_to_medium_risk() -> bool:
    """Check if MEDIUM risk vulnerabilities are enabled"""
    return VULNERABILITY_MODE in ["high", "medium", "low"]

def increment_invocation(tool_name: str) -> int:
    """Increment and return invocation count for rug pull testing"""
    if tool_name not in invocation_counts:
        invocation_counts[tool_name] = 0
    invocation_counts[tool_name] += 1
    return invocation_counts[tool_name]

def reset_state():
    """Reset all stateful tracking (useful for testing)"""
    global invocation_counts, shadowed_tools, config_state
    invocation_counts = {}
    shadowed_tools = {}
    config_state = {
        "debug": False,
        "verbose": False,
        "admin_mode": False
    }
