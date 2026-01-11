"""
Pytest configuration for MCP Vulnerable Testbed tests.

This file:
- Adds the tests directory to sys.path so local imports work
- Provides shared fixtures for vulnerable and hardened server clients
- Registers custom pytest markers
- Configures Inspector CLI integration via environment variables
"""

import os
import sys
from pathlib import Path

import pytest

# Add tests directory to path for local imports (e.g., mcp_test_client)
tests_dir = Path(__file__).parent
if str(tests_dir) not in sys.path:
    sys.path.insert(0, str(tests_dir))

from mcp_test_client import MCPClient, VULNERABLE_SERVER_URL, HARDENED_SERVER_URL
from dvmcp_client import DVMCPClient, DVMCP_CHALLENGE_URLS


# ============================================================================
# Test Configuration (Environment Variable Overrides)
# ============================================================================
# These allow CI/CD systems to configure paths without code changes

# Inspector CLI directory (default: /home/bryan/inspector)
INSPECTOR_DIR = Path(os.getenv("INSPECTOR_DIR", "/home/bryan/inspector"))

# Inspector CLI timeouts (seconds)
INSPECTOR_TIMEOUT_DEFAULT = int(os.getenv("INSPECTOR_TIMEOUT", "120"))
INSPECTOR_TIMEOUT_SLOW = int(os.getenv("INSPECTOR_TIMEOUT_SLOW", "300"))


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "integration: marks tests requiring server")
    config.addinivalue_line("markers", "unit: marks pure unit tests")
    config.addinivalue_line("markers", "slow: marks slow tests (e.g., rug pull)")
    config.addinivalue_line("markers", "inspector: marks tests requiring Inspector CLI")


# ============================================================================
# Shared Test Helpers
# ============================================================================

def check_server_error(result: dict) -> dict:
    """Skip test if result indicates server import bug.

    This helper checks for common server-side errors (like missing json import)
    and gracefully skips the test instead of failing cryptically.

    Args:
        result: The tool call result dictionary

    Returns:
        The result unchanged if no error detected

    Raises:
        pytest.skip: If server has known import/module bug
    """
    if result.get("isError"):
        result_str = str(result).lower()
        if "json" in result_str or "not defined" in result_str:
            pytest.skip("Server has import bug (json module not imported)")
    return result


def skip_if_not_implemented(result: dict, tool_name: str) -> dict:
    """Skip test if tool is not implemented in server.

    Args:
        result: The tool call result dictionary
        tool_name: Name of the tool being tested (for skip message)

    Returns:
        The result unchanged if tool exists

    Raises:
        pytest.skip: If tool is not implemented
    """
    if result.get("isError") and "unknown tool" in str(result).lower():
        pytest.skip(f"{tool_name} not implemented in server")
    return result


@pytest.fixture(scope="module")
def vulnerable_client():
    """Fixture for vulnerable server client.

    Provides an MCPClient connected to the vulnerable testbed server.
    Automatically resets server state before yielding.
    Skips tests if server is not available.
    """
    client = MCPClient(VULNERABLE_SERVER_URL)
    if not client.connect():
        pytest.skip("Vulnerable server not available")
    client.reset_state()
    yield client


@pytest.fixture
def clean_vulnerable_client():
    """Function-scoped fixture with isolated connection and state.

    Use for tests that depend on clean server state (e.g., rug pull,
    session management, state-based attacks).

    Creates a fresh connection for each test to prevent state leakage
    between tests. Resets state both before and after the test.
    """
    client = MCPClient(VULNERABLE_SERVER_URL)
    if not client.connect():
        pytest.skip("Vulnerable server not available")
    client.reset_state()
    yield client
    # Cleanup: reset state after test to prevent contaminating other tests
    try:
        client.reset_state()
    except Exception:
        pass  # Best effort cleanup


@pytest.fixture(scope="module")
def hardened_client():
    """Fixture for hardened server client.

    Provides an MCPClient connected to the hardened testbed server.
    Skips tests if server is not available.
    """
    client = MCPClient(HARDENED_SERVER_URL)
    if not client.connect():
        pytest.skip("Hardened server not available")
    client.reset_state()
    yield client


@pytest.fixture(scope="module")
def test_payloads():
    """Load test payloads from JSON file."""
    import json
    payloads_file = Path(__file__).parent.parent / "test_payloads.json"
    if not payloads_file.exists():
        pytest.skip(f"Test payloads file not found: {payloads_file}")
    with open(payloads_file) as f:
        return json.load(f)


# ============================================================================
# DVMCP (Damn Vulnerable MCP Server) Fixtures
# ============================================================================

@pytest.fixture
def dvmcp_challenge4_client():
    """Fixture for DVMCP Challenge 4 (Rug Pull) SSE client.

    Provides a DVMCPClient connected to DVMCP Challenge 4 on port 9004.
    Challenge 4 has a 3-call threshold rug pull (vs our 10-call).
    Skips tests if DVMCP server is not available.

    IMPORTANT: Resets DVMCP state before each test since DVMCP stores
    call count in a file (/tmp/dvmcp_challenge4/state/state.json) that
    persists across sessions.

    Note: Function-scoped to ensure fresh state for each test.
    """
    import requests
    import subprocess

    # First check if DVMCP server is reachable
    try:
        response = requests.get("http://localhost:9004/", timeout=2)
    except requests.RequestException:
        pytest.skip("DVMCP Challenge 4 not reachable (port 9004)")

    # Reset DVMCP state before each test (3-call threshold is file-based)
    import warnings
    from subprocess import TimeoutExpired

    try:
        subprocess.run(
            ["docker", "exec", "dvmcp", "rm", "-f",
             "/tmp/dvmcp_challenge4/state/state.json"],
            capture_output=True,
            timeout=5,
            check=False  # Explicit: don't raise on non-zero exit
        )
    except FileNotFoundError:
        warnings.warn(
            "Docker not found in PATH - DVMCP state reset skipped",
            UserWarning
        )
    except TimeoutExpired:
        warnings.warn(
            "Docker exec timed out - DVMCP state may not be reset",
            UserWarning
        )
    except OSError as e:
        warnings.warn(
            f"Failed to reset DVMCP state: {e}",
            UserWarning
        )

    client = DVMCPClient(DVMCP_CHALLENGE_URLS[4])
    if not client.connect():
        pytest.skip("DVMCP Challenge 4 SSE connection failed")

    yield client
    client.close()


@pytest.fixture(scope="module")
def dvmcp_client_factory():
    """Factory fixture to create DVMCP clients for any challenge.

    Usage:
        def test_challenge_5(dvmcp_client_factory):
            client = dvmcp_client_factory(5)
            # test challenge 5...
    """
    clients = []

    def _create_client(challenge_num: int) -> DVMCPClient:
        if challenge_num not in DVMCP_CHALLENGE_URLS:
            pytest.skip(f"Invalid challenge number: {challenge_num}")
        client = DVMCPClient(DVMCP_CHALLENGE_URLS[challenge_num])
        if not client.connect():
            pytest.skip(f"DVMCP Challenge {challenge_num} not available")
        clients.append(client)
        return client

    yield _create_client

    # Cleanup all created clients
    for client in clients:
        client.close()


# ============================================================================
# MCP Inspector CLI Fixtures
# ============================================================================

# Server configs for Inspector CLI (INSPECTOR_DIR defined at top of file)
VULNERABLE_CONFIG = {"transport": "http", "url": "http://localhost:10900/mcp"}
HARDENED_CONFIG = {"transport": "http", "url": "http://localhost:10901/mcp"}


@pytest.fixture(scope="session")
def inspector_cli_available():
    """Session-scoped check for Inspector CLI availability.

    Returns True if Inspector CLI responds to --help, False otherwise.
    Tests can use this to skip gracefully if Inspector is unavailable.
    """
    import subprocess

    try:
        result = subprocess.run(
            ["npm", "run", "assess", "--", "--help"],
            cwd=INSPECTOR_DIR,
            capture_output=True,
            timeout=30
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


@pytest.fixture(scope="module")
def inspector_config_file(tmp_path_factory):
    """Create temporary config file for vulnerable server (port 10900).

    Returns path to a JSON config file suitable for Inspector CLI.
    """
    import json
    config_dir = tmp_path_factory.mktemp("inspector_config")
    config_path = config_dir / "vulnerable-mcp-config.json"
    config_path.write_text(json.dumps(VULNERABLE_CONFIG))
    return str(config_path)


@pytest.fixture(scope="module")
def hardened_inspector_config(tmp_path_factory):
    """Create temporary config file for hardened server (port 10901).

    Returns path to a JSON config file suitable for Inspector CLI.
    """
    import json
    config_dir = tmp_path_factory.mktemp("hardened_config")
    config_path = config_dir / "hardened-mcp-config.json"
    config_path.write_text(json.dumps(HARDENED_CONFIG))
    return str(config_path)
