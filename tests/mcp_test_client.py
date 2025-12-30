"""
Shared MCP Client for Testing

Provides a reusable MCP client for pytest fixtures across all test modules.
Extracted to avoid code duplication (DRY principle).
"""

import json
import requests
from typing import Dict, Any, Optional


class MCPClient:
    """Simple MCP client for testing MCP servers."""

    def __init__(self, url: str):
        """Initialize client with server URL.

        Args:
            url: The MCP server HTTP endpoint (e.g., 'http://localhost:10900/mcp')
        """
        self.url = url
        self.session_id: Optional[str] = None

    def connect(self) -> bool:
        """Initialize connection and get session ID.

        Returns:
            True if connection successful, False otherwise.
        """
        try:
            response = requests.post(
                self.url,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream"
                },
                json={
                    "jsonrpc": "2.0",
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "pytest", "version": "1.0"}
                    },
                    "id": 1
                },
                timeout=10
            )
            self.session_id = response.headers.get("mcp-session-id")

            # Send initialized notification (required by MCP protocol)
            if self.session_id:
                requests.post(
                    self.url,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                        "mcp-session-id": self.session_id
                    },
                    json={
                        "jsonrpc": "2.0",
                        "method": "notifications/initialized"
                    },
                    timeout=5
                )
            return self.session_id is not None
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call an MCP tool and return the result.

        Args:
            tool_name: The name of the MCP tool to call
            arguments: Dictionary of arguments to pass to the tool

        Returns:
            The tool's response as a dictionary

        Raises:
            RuntimeError: If not connected (call connect() first)
        """
        if not self.session_id:
            raise RuntimeError("Not connected. Call connect() first.")

        try:
            response = requests.post(
                self.url,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "mcp-session-id": self.session_id
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": tool_name,
                        "arguments": arguments
                    }
                },
                timeout=30
            )
            response.raise_for_status()
        except requests.RequestException as e:
            return {"error": True, "result": f"Request failed: {e}"}

        # Parse SSE response format
        for line in response.text.split("\n"):
            if line.startswith("data: "):
                try:
                    data = json.loads(line[6:])
                except json.JSONDecodeError as e:
                    return {"error": True, "result": f"Invalid JSON response: {e}"}
                result = data.get("result", {})
                # Handle structuredContent wrapper (MCP protocol detail)
                if "structuredContent" in result:
                    return result["structuredContent"].get("result", {})
                return result.get("result", result)

        return {"error": True, "result": "No data in response"}

    def reset_state(self) -> bool:
        """Reset testbed state for clean tests.

        Returns:
            True if reset successful, False otherwise.
        """
        try:
            result = self.call_tool("reset_testbed_state", {})
            return "reset successfully" in result.get("result", "").lower()
        except Exception:
            return False


# Server URL constants for convenience
VULNERABLE_SERVER_URL = "http://localhost:10900/mcp"
HARDENED_SERVER_URL = "http://localhost:10901/mcp"
