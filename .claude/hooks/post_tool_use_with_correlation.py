#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

"""
PostToolUse hook wrapper that retrieves correlation_id for event data.
This script reads the tool result, retrieves the stored correlation_id,
and forwards the data with correlation_id to send_event_async.py.
"""

import json
import sys
import os
from pathlib import Path

# Add session helpers
sys.path.append(os.path.join(os.path.dirname(__file__), 'utils'))
from session_helpers import get_stored_correlation_id, get_project_name, get_stored_session_id


def main():
    """Retrieve correlation_id and forward to send_event_async.py."""
    try:
        # Read hook input from stdin
        hook_input = sys.stdin.read().strip()
        if not hook_input:
            sys.exit(0)

        # Parse the tool result data
        tool_data = json.loads(hook_input)
        tool_name = tool_data.get('tool', 'unknown')

        # Get project name and retrieve correlation_id
        project_name = get_project_name()
        correlation_id = get_stored_correlation_id(project_name, tool_name)

        # Get the actual session_id
        session_id = get_stored_session_id(project_name)

        # Create event data with correlation_id (if found)
        event_data = {
            "tool_name": tool_name,
            "tool_input": tool_data.get('input', {}),
            "tool_output": tool_data.get('output', ''),
            "success": not tool_data.get('error'),
            "session_id": session_id,
            "cwd": os.getcwd(),
            "payload": tool_data
        }

        # Include correlation_id if we found a matching one
        if correlation_id:
            event_data["correlation_id"] = correlation_id

        # Forward to send_event_async.py
        print(json.dumps(event_data))

    except Exception as e:
        # Don't fail the tool execution
        print(f"Error in post_tool_use_with_correlation: {e}", file=sys.stderr)
        # Still output basic data
        print(json.dumps({"tool_name": "unknown", "error": str(e)}))


if __name__ == '__main__':
    main()