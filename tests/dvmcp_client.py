"""
DVMCP SSE Client for Testing

Provides an SSE-based MCP client for testing DVMCP (Damn Vulnerable MCP Server).
DVMCP uses SSE transport on ports 9001-9010, one per challenge.

Key differences from our testbed:
- Transport: SSE vs HTTP
- Rug pull threshold: 3 calls vs 10 calls
- Triggered behavior: Error message vs command execution

DVMCP SSE Protocol (MCP SDK SseServerTransport):
1. Client GETs /sse to establish SSE stream
2. Server sends "endpoint" event with session ID: data: /messages/?session_id=<UUID>
3. Client extracts session ID from endpoint URL
4. Client includes session ID in all POST requests to /messages/?session_id=<UUID>
"""

import json
import re
import requests
import threading
import queue
import time
import warnings
from typing import Dict, Any, Optional


class DVMCPClient:
    """SSE-based MCP client for DVMCP servers with session-based protocol."""

    def __init__(self, url: str):
        """Initialize client with SSE server URL.

        Args:
            url: The DVMCP SSE endpoint (e.g., 'http://localhost:9004/sse')
        """
        self.url = url
        self.base_url = url.replace("/sse", "")
        self.session_id: Optional[str] = None
        self._endpoint_url: Optional[str] = None  # Received from SSE endpoint event
        self._message_id = 0
        self._id_lock = threading.Lock()  # Thread-safe ID generation
        # Bounded queue prevents memory exhaustion from malicious servers (Critical Issue 2)
        self._response_queue: queue.Queue = queue.Queue(maxsize=100)
        self._sse_thread: Optional[threading.Thread] = None
        self._running = False
        # Thread synchronization to detect early failures (Critical Issue 1)
        self._thread_started = threading.Event()
        self._thread_error: Optional[str] = None

    def _next_id(self) -> int:
        """Generate next message ID (thread-safe).

        Uses a lock to ensure unique, incrementing IDs across concurrent
        tool calls. Each JSON-RPC request requires a unique message ID
        for response correlation.

        Returns:
            int: The next unique message ID (1, 2, 3, ...)
        """
        with self._id_lock:
            self._message_id += 1
            return self._message_id

    def _validate_session_id(self, session_id: str) -> bool:
        """Validate session_id is safe UUID format.

        Prevents path traversal and injection attacks from malicious servers.

        Args:
            session_id: The session ID string to validate

        Returns:
            True if valid UUID hex format, False otherwise
        """
        # UUID pattern: 32 hex chars, optionally with dashes (8-4-4-4-12)
        uuid_pattern = r'^[a-f0-9]{8}-?[a-f0-9]{4}-?[a-f0-9]{4}-?[a-f0-9]{4}-?[a-f0-9]{12}$'
        return bool(re.match(uuid_pattern, session_id, re.IGNORECASE))

    def _parse_mcp_result(self, data: Dict[str, Any]) -> Optional[str]:
        """Extract text content from MCP response.

        Args:
            data: JSON-RPC response dictionary

        Returns:
            Extracted text content, error message, or None if unparseable
        """
        if "error" in data:
            return f"Error: {data['error']}"
        if "result" in data:
            result = data["result"]
            if isinstance(result, dict):
                content = result.get("content", [])
                if content and isinstance(content, list):
                    text = content[0].get("text", "")
                    if text:
                        return text
                return str(result)
            return str(result)
        return None

    def _process_sse_event(self, event_type: str, data: str):
        """Process a complete SSE event.

        Args:
            event_type: The event type (endpoint, message, etc.)
            data: The accumulated data lines joined with newlines
        """
        if event_type == "endpoint":
            # Extract session ID from endpoint URL
            # Format: /messages/?session_id=<UUID_HEX>
            self._endpoint_url = data
            if "session_id=" in data:
                sid = data.split("session_id=")[1].split("&")[0]
                if self._validate_session_id(sid):
                    self.session_id = sid
                else:
                    warnings.warn(
                        f"Invalid session_id format rejected: {sid[:20]}...",
                        UserWarning
                    )
        elif event_type == "message":
            try:
                msg = json.loads(data)
                # Non-blocking put with overflow handling (Critical Issue 2)
                try:
                    self._response_queue.put_nowait(msg)
                except queue.Full:
                    # Discard oldest to make room (prevent memory exhaustion)
                    try:
                        self._response_queue.get_nowait()
                        self._response_queue.put_nowait(msg)
                    except (queue.Empty, queue.Full):
                        pass  # Drop if still full
            except json.JSONDecodeError:
                pass

    def _sse_listener(self):
        """Background thread to listen for SSE events.

        Parses two event types:
        - event: endpoint - Contains session ID in data: /messages/?session_id=<UUID>
        - event: message - Contains JSON-RPC response data

        Per SSE spec, multiple data: lines are joined with newlines,
        and events are terminated by empty lines.
        """
        try:
            response = requests.get(
                f"{self.base_url}/sse",
                headers={"Accept": "text/event-stream"},
                stream=True,
                timeout=60
            )
            # Signal that thread has started successfully (Critical Issue 1)
            self._thread_started.set()
            current_event = None
            current_data_lines = []  # Accumulate multiline data per SSE spec

            for line in response.iter_lines(decode_unicode=True):
                if not self._running:
                    break

                # Empty line = end of event (per SSE spec)
                if not line:
                    if current_event and current_data_lines:
                        data = "\n".join(current_data_lines)
                        self._process_sse_event(current_event, data)
                    current_event = None
                    current_data_lines = []
                    continue

                if line.startswith("event: "):
                    current_event = line[7:].strip()
                elif line.startswith("data: "):
                    current_data_lines.append(line[6:])
        except Exception as e:
            # Store error and signal for connect() to detect (Critical Issue 1)
            self._thread_error = str(e)
            self._thread_started.set()
            print(f"SSE listener error: {e}")

    def connect(self) -> bool:
        """Initialize SSE connection and get session.

        Returns:
            True if connection successful with valid session ID, False otherwise.
        """
        try:
            # Start SSE listener in background
            self._running = True
            self._thread_started.clear()
            self._thread_error = None
            self._sse_thread = threading.Thread(target=self._sse_listener, daemon=True)
            self._sse_thread.start()

            # Wait for thread to establish connection or fail (Critical Issue 1)
            if not self._thread_started.wait(timeout=5):
                print("SSE thread failed to start within timeout")
                return False

            if self._thread_error:
                print(f"SSE connection failed: {self._thread_error}")
                return False

            # Wait for session ID from endpoint event (reduced since thread is running)
            for _ in range(30):  # 30 * 0.1 = 3 seconds
                if self.session_id:
                    break
                time.sleep(0.1)

            if not self.session_id:
                print("Failed to get session ID from SSE endpoint event")
                return False

            # Send initialize via POST with session ID in query param
            response = requests.post(
                f"{self.base_url}/messages/?session_id={self.session_id}",
                headers={"Content-Type": "application/json"},
                json={
                    "jsonrpc": "2.0",
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "pytest-dvmcp", "version": "1.0"}
                    },
                    "id": self._next_id()
                },
                timeout=10
            )

            if not response.ok:
                print(f"Initialize request failed: HTTP {response.status_code}")
                return False

            # Wait for SSE response
            try:
                data = self._response_queue.get(timeout=5)
                if "result" in data:
                    # Send initialized notification
                    requests.post(
                        f"{self.base_url}/messages/?session_id={self.session_id}",
                        headers={"Content-Type": "application/json"},
                        json={
                            "jsonrpc": "2.0",
                            "method": "notifications/initialized"
                        },
                        timeout=5
                    )
                    return True
            except queue.Empty:
                print("No response received for initialize request")

            return False

        except Exception as e:
            print(f"DVMCP connection failed: {e}")
            return False

    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """Call a DVMCP tool and return the result as string.

        Args:
            tool_name: The name of the MCP tool to call
            arguments: Dictionary of arguments to pass to the tool

        Returns:
            The tool's response as a string (for easy assertion checking)

        Raises:
            RuntimeError: If not connected (call connect() first)
        """
        if not self.session_id:
            raise RuntimeError("Not connected. Call connect() first.")

        msg_id = self._next_id()
        try:
            response = requests.post(
                f"{self.base_url}/messages/?session_id={self.session_id}",
                headers={"Content-Type": "application/json"},
                json={
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "method": "tools/call",
                    "params": {
                        "name": tool_name,
                        "arguments": arguments
                    }
                },
                timeout=30
            )

            if not response.ok:
                return f"Error: HTTP {response.status_code}"

            # Try to get response from SSE queue
            try:
                data = self._response_queue.get(timeout=5)
                parsed = self._parse_mcp_result(data)
                if parsed:
                    return parsed
            except queue.Empty:
                pass

            # Fallback: Check direct response body
            if response.text:
                try:
                    data = response.json()
                    parsed = self._parse_mcp_result(data)
                    if parsed:
                        return parsed
                except json.JSONDecodeError:
                    pass

            return "Error: No response received"
        except Exception as e:
            return f"Error: {e}"

    def close(self):
        """Clean up client resources and terminate background threads.

        Performs cleanup in this order:
        1. Signals SSE listener thread to stop via _running flag
        2. Clears session state (session_id, endpoint_url)
        3. Waits up to 5 seconds for SSE thread to terminate
        4. Issues ResourceWarning if thread doesn't terminate (daemon will be abandoned)
        5. Drains response queue to release any blocked producers

        Note:
            If the SSE thread doesn't terminate within timeout, a ResourceWarning
            is issued but the thread is left as a daemon (will be cleaned up on
            process exit).
        """
        import warnings

        self._running = False
        self.session_id = None
        self._endpoint_url = None
        if self._sse_thread:
            self._sse_thread.join(timeout=5)  # Increased from 1s
            if self._sse_thread.is_alive():
                warnings.warn(
                    "SSE thread did not terminate - daemon will be abandoned",
                    ResourceWarning
                )
        # Clear queue to release any blocked producers
        while not self._response_queue.empty():
            try:
                self._response_queue.get_nowait()
            except queue.Empty:
                break
        self._sse_thread = None


# DVMCP Challenge URLs
DVMCP_CHALLENGE_URLS = {
    1: "http://localhost:9001/sse",
    2: "http://localhost:9002/sse",
    3: "http://localhost:9003/sse",
    4: "http://localhost:9004/sse",  # Rug Pull challenge
    5: "http://localhost:9005/sse",
    6: "http://localhost:9006/sse",
    7: "http://localhost:9007/sse",
    8: "http://localhost:9008/sse",
    9: "http://localhost:9009/sse",
    10: "http://localhost:9010/sse",
}
