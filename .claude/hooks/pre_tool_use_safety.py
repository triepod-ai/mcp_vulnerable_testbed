#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///

"""
PreToolUse Safety Hook - Blocks dangerous commands before execution.
This hook validates Bash commands and blocks patterns that could cause data loss.
"""

import json
import sys
import re
import os


# Dangerous command patterns that should be blocked
DANGEROUS_PATTERNS = [
    # Dangerous rm patterns - hidden files
    (r'rm\s+.*\.\*', 'Deleting files with .* pattern (all hidden files)'),
    (r'rm\s+.*\s+\.\s*$', 'Deleting current directory (.)'),
    (r'rm\s+.*\s+\.\.\s*$', 'Deleting parent directory (..)'),
    (r'rm\s+.*~/\.\*', 'Deleting all hidden files in home directory'),

    # Dangerous rm patterns - root and system paths
    (r'rm\s+.*\s+/\s*$', 'Deleting root directory'),
    (r'rm\s+.*\s+/etc\b', 'Deleting system configuration'),
    (r'rm\s+.*\s+/usr\b', 'Deleting system binaries'),
    (r'rm\s+.*\s+/var\b', 'Deleting system data'),
    (r'rm\s+.*\s+/boot\b', 'Deleting boot files'),

    # Dangerous find + rm combinations
    (r'find\s+.*\|\s*xargs\s+rm', 'Dangerous find + rm combination'),
    (r'find\s+.*-exec\s+rm', 'Dangerous find -exec rm'),

    # Dangerous wildcards in dangerous locations
    (r'rm\s+.*\*\s*$', 'Deleting all files with wildcard (*)'),
    (r'rm\s+.*~/', 'Deleting from home directory root'),

    # Dangerous file operations
    (r'>\s*/dev/sd[a-z]', 'Writing directly to disk device'),
    (r'dd\s+.*of=/dev/', 'Dangerous disk write operation'),
]

# File extensions and paths that are safe to delete
SAFE_PATTERNS = [
    r'\.log$',
    r'/tmp/',
    r'\.tmp$',
    r'\.cache/',
    r'node_modules/',
    r'\.pyc$',
    r'__pycache__/',
]


def is_safe_path(command: str) -> bool:
    """Check if the command operates on safe paths."""
    for pattern in SAFE_PATTERNS:
        if re.search(pattern, command):
            return True
    return False


def check_dangerous_command(command: str) -> tuple[bool, str]:
    """
    Check if a command matches dangerous patterns.
    Returns (is_dangerous, reason).
    """
    # Skip if command operates on safe paths
    if is_safe_path(command):
        return False, ""

    # Check against dangerous patterns
    for pattern, reason in DANGEROUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return True, reason

    return False, ""


def main():
    """Validate tool use and block dangerous commands."""
    try:
        # Read hook input from stdin
        hook_input = sys.stdin.read().strip()
        if not hook_input:
            sys.exit(0)

        # Parse the tool data
        tool_data = json.loads(hook_input)
        tool_name = tool_data.get('tool', 'unknown')

        # Only validate Bash commands
        if tool_name.lower() == 'bash':
            parameters = tool_data.get('parameters', {})
            command = parameters.get('command', '')

            if command:
                is_dangerous, reason = check_dangerous_command(command)

                if is_dangerous:
                    # Block the command by exiting with error
                    error_message = f"""
🚨 BLOCKED: Dangerous command detected!

Command: {command}

Reason: {reason}

This command has been blocked to prevent potential data loss.
If you need to run this command, please:
1. Review the command carefully
2. Consider safer alternatives
3. Run it manually outside of Claude Code if absolutely necessary

Pattern matched: This appears to be a potentially destructive operation.
"""
                    print(error_message, file=sys.stderr)

                    # Log the blocked command
                    blocked_log = f"/tmp/claude_blocked_commands_{os.getpid()}.log"
                    with open(blocked_log, 'a') as f:
                        f.write(f"{command} | {reason}\n")

                    # Exit with error to block execution
                    sys.exit(1)

        # If we get here, command is safe - allow execution
        sys.exit(0)

    except Exception as e:
        # Don't fail the tool execution on hook errors
        print(f"Warning: Safety hook error: {e}", file=sys.stderr)
        sys.exit(0)


if __name__ == '__main__':
    main()
