#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

"""
PreToolUse hook wrapper that adds correlation_id to event data.
This script reads the tool input, generates a correlation_id, stores it,
and forwards the data with correlation_id to send_event_async.py.
"""

import json
import sys
import os
from pathlib import Path

# Add session helpers
sys.path.append(os.path.join(os.path.dirname(__file__), 'utils'))
from session_helpers import generate_correlation_id, store_correlation_id, get_project_name, get_stored_session_id


def main():
    """Generate correlation_id and forward to send_event_async.py."""
    try:
        # Read hook input from stdin
        hook_input = sys.stdin.read().strip()
        if not hook_input:
            sys.exit(0)

        # Parse the tool data
        tool_data = json.loads(hook_input)
        tool_name = tool_data.get('tool', 'unknown')

        # Generate correlation_id and store it
        correlation_id = generate_correlation_id()
        project_name = get_project_name()

        # Store correlation_id for PostToolUse to retrieve
        store_correlation_id(correlation_id, project_name, tool_name)

        # Get the actual session_id
        session_id = get_stored_session_id(project_name)

        # Create event data with correlation_id
        event_data = {
            "tool_name": tool_name,
            "tool_input": tool_data.get('parameters', {}),
            "session_id": session_id,
            "correlation_id": correlation_id,
            "cwd": os.getcwd(),
            "payload": tool_data
        }

        # Forward to send_event_async.py with correlation_id
        print(json.dumps(event_data))

    except Exception as e:
        # Don't fail the tool execution
        print(f"Error in pre_tool_use_with_correlation: {e}", file=sys.stderr)
        # Still output basic data
        print(json.dumps({"tool_name": "unknown", "error": str(e)}))


if __name__ == '__main__':
    main()