"""
Pytest configuration for MCP Vulnerable Testbed tests.

This file:
- Adds the tests directory to sys.path so local imports work
- Provides shared fixtures for vulnerable and hardened server clients
- Registers custom pytest markers
"""

import sys
from pathlib import Path

import pytest

# Add tests directory to path for local imports (e.g., mcp_test_client)
tests_dir = Path(__file__).parent
if str(tests_dir) not in sys.path:
    sys.path.insert(0, str(tests_dir))

from mcp_test_client import MCPClient, VULNERABLE_SERVER_URL, HARDENED_SERVER_URL


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "integration: marks tests requiring server")
    config.addinivalue_line("markers", "unit: marks pure unit tests")
    config.addinivalue_line("markers", "slow: marks slow tests (e.g., rug pull)")


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
