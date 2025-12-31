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
from dvmcp_client import DVMCPClient, DVMCP_CHALLENGE_URLS


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


@pytest.fixture
def clean_vulnerable_client(vulnerable_client):
    """Function-scoped fixture that resets state before each test.

    Use for tests that depend on clean server state (e.g., rug pull).
    Reuses the module-scoped connection but ensures fresh state.
    """
    vulnerable_client.reset_state()
    return vulnerable_client


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
    try:
        subprocess.run(
            ["docker", "exec", "dvmcp", "rm", "-f",
             "/tmp/dvmcp_challenge4/state/state.json"],
            capture_output=True,
            timeout=5
        )
    except Exception:
        pass  # Proceed even if reset fails

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
