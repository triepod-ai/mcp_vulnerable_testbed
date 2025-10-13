#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "redis>=4.0.0",
#     "python-dotenv",
# ]
# ///
"""
Session End Hook

SINGLE PURPOSE: Export session context and update PROJECT_STATUS.md on session end.

- Captures final session state (git status, work completed)
- Creates handoff document for next session
- Updates PROJECT_STATUS.md with session summary
- Stores to Redis for session_context_loader.py to retrieve
"""

import sys
import json
import os
import subprocess
from pathlib import Path
from datetime import datetime

# Add utils to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'utils'))

from session_helpers import get_project_name, get_git_status, format_git_summary


def create_session_handoff(project_name: str, input_data: dict) -> str:
    """Create handoff document with session summary."""

    # Get git information
    git_info = get_git_status()
    git_summary = format_git_summary(git_info)

    # Get working directory
    working_dir = os.getcwd()

    # Build session summary
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    session_id_formatted = datetime.now().strftime('%Y%m%d_%H%M%S')

    # Collect git status details
    git_status_lines = "\n".join([f" {line}" for line in git_info["status_lines"][:10]])

    handoff_content = f"""EXPORT: {project_name} - {timestamp}

## Session Summary
Session ended at {timestamp}

## Context
- Project: {project_name}
- Timestamp: {timestamp}
- Working Directory: {working_dir}
- Git Branch: {git_info.get('branch', 'unknown')}
- Modified Files: {git_info['modified_count']}

## Session Work Completed
Session activity tracked via observability system

## Recent Changes"""

    # Add recent commits
    if git_info["recent_commits"]:
        handoff_content += "\n"
        for commit in git_info["recent_commits"][:3]:
            handoff_content += f"\n- {commit}"

    # Add modified files
    if git_info["modified_count"] > 0:
        handoff_content += f"""

## Modified Files
{git_status_lines}"""

    handoff_content += """

---
Created by: SessionEnd hook
Retention: 30 days
"""

    return handoff_content


def save_handoff_to_redis(project_name: str, handoff_content: str) -> bool:
    """Save handoff to Redis with timestamp-based key."""
    try:
        from utils.fallback_storage import get_fallback_storage
        fallback = get_fallback_storage()

        # Save using fallback storage (handles Redis + local)
        result = fallback.save_session_handoff(
            project_name=project_name,
            handoff_content=handoff_content,
            session_id=datetime.now().strftime('%Y%m%d_%H%M%S')
        )

        return result
    except Exception as e:
        print(f"Warning: Could not save handoff to Redis: {e}", file=sys.stderr)
        return False


def update_project_status(project_name: str, git_info: dict) -> bool:
    """Update PROJECT_STATUS.md with session export entry."""
    try:
        status_file = Path("PROJECT_STATUS.md")

        if not status_file.exists():
            print("PROJECT_STATUS.md not found, skipping update", file=sys.stderr)
            return False

        # Read existing content
        with open(status_file, 'r') as f:
            content = f.read()

        # Create backup
        backup_file = Path("PROJECT_STATUS.md.bak")
        with open(backup_file, 'w') as f:
            f.write(content)

        # Build session export entry
        session_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        export_date = datetime.now().strftime('%a %b %d %Y')
        git_summary = format_git_summary(git_info)

        export_entry = f"""### Session Export - {session_id}
- **Date**: {export_date}
- **Git**: {git_summary}
- **Description**: Session ended - work tracked via observability system

"""

        # Find where to insert (after "## Recent Session Exports" header)
        lines = content.split('\n')
        insert_index = -1

        for i, line in enumerate(lines):
            if line.strip() == "## Recent Session Exports":
                # Skip the header and blank line
                insert_index = i + 2
                break

        if insert_index > 0:
            # Insert the new entry
            lines.insert(insert_index, export_entry)
            updated_content = '\n'.join(lines)

            # Write updated content
            with open(status_file, 'w') as f:
                f.write(updated_content)

            print(f"Updated PROJECT_STATUS.md with session {session_id}", file=sys.stderr)
            return True
        else:
            print("Could not find 'Recent Session Exports' section in PROJECT_STATUS.md", file=sys.stderr)
            return False

    except Exception as e:
        print(f"Error updating PROJECT_STATUS.md: {e}", file=sys.stderr)
        return False


def main():
    """Main session end execution."""
    try:
        # Read input data from stdin
        input_data = json.loads(sys.stdin.read())

        # Get project information
        project_name = get_project_name()
        git_info = get_git_status()

        # Create handoff document
        handoff_content = create_session_handoff(project_name, input_data)

        # Save to Redis (and local fallback)
        redis_success = save_handoff_to_redis(project_name, handoff_content)

        # Update PROJECT_STATUS.md
        status_success = update_project_status(project_name, git_info)

        # Report results
        if redis_success:
            print(f"✅ Session handoff saved to Redis for {project_name}", file=sys.stderr)
        else:
            print(f"⚠️  Could not save to Redis, using local fallback", file=sys.stderr)

        if status_success:
            print(f"✅ PROJECT_STATUS.md updated", file=sys.stderr)

        print(f"Session end processed for {project_name}", file=sys.stderr)

    except Exception as e:
        print(f"Session end error: {e}", file=sys.stderr)
        # Don't exit with error - session end failure shouldn't break Claude


if __name__ == "__main__":
    main()
