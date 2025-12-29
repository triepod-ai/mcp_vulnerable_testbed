"""
Pytest configuration for MCP Vulnerable Testbed tests.

This file adds the tests directory to sys.path so local imports work.
"""

import sys
from pathlib import Path

# Add tests directory to path for local imports (e.g., mcp_test_client)
tests_dir = Path(__file__).parent
if str(tests_dir) not in sys.path:
    sys.path.insert(0, str(tests_dir))
