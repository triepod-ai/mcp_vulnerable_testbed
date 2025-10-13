#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# ///

"""
STUB FILE - This hook is not supported by Claude Code.

SubagentStart is not a valid Claude Code hook event. This stub exists
temporarily for backward compatibility during the current session.

Agent tracking is properly handled by SubagentStop hook.
See .claude/hooks/archive/README.md for details.
"""

import sys
import json

# Read and discard stdin to prevent blocking
try:
    json.load(sys.stdin)
except:
    pass

# Exit successfully without doing anything
sys.exit(0)
