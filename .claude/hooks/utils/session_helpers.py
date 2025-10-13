#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""
Session Helper Utilities

Shared utilities for focused session hooks following KISS principle.
Each function has a single, clear responsibility.
"""

import subprocess
import tempfile
import os
import uuid
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime, timedelta


def get_project_name() -> str:
    """Get project name from git root directory, regardless of current working directory."""
    import os
    current_dir = os.getcwd()
    
    # Walk up the directory tree to find git root
    while current_dir != "/":
        if os.path.exists(os.path.join(current_dir, ".git")):
            # Found git root, return its basename
            return os.path.basename(current_dir)
        current_dir = os.path.dirname(current_dir)
    
    # Fallback: if no git root found, use current directory
    return Path.cwd().name


def get_project_status() -> Optional[str]:
    """Load PROJECT_STATUS.md content if it exists."""
    status_file = Path("PROJECT_STATUS.md")
    if not status_file.exists():
        return None
    
    content = status_file.read_text()
    # Truncate if too long for context injection
    if len(content) > 500:
        return content[:500] + "..."
    return content


def get_git_status() -> Dict[str, Any]:
    """Get git repository status information."""
    result = {
        "status_lines": [],
        "recent_commits": [],
        "branch": "main",
        "modified_count": 0
    }
    
    if not Path(".git").exists():
        return result
    
    try:
        # Get git status
        git_status = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True, text=True, timeout=5
        )
        if git_status.returncode == 0:
            status_lines = [line for line in git_status.stdout.strip().split('\n') if line.strip()]
            result["status_lines"] = status_lines
            result["modified_count"] = len(status_lines)
        
        # Get recent commits
        git_log = subprocess.run(
            ["git", "log", "--oneline", "-5"],
            capture_output=True, text=True, timeout=5
        )
        if git_log.returncode == 0:
            result["recent_commits"] = git_log.stdout.strip().split('\n')
        
        # Get current branch
        git_branch = subprocess.run(
            ["git", "branch", "--show-current"],
            capture_output=True, text=True, timeout=5
        )
        if git_branch.returncode == 0:
            result["branch"] = git_branch.stdout.strip() or "main"
            
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    return result


def create_rate_limit_file(session_type: str) -> Path:
    """Create rate limiting file path for session type."""
    return Path(f"/tmp/claude_session_{session_type}_last.txt")


def is_rate_limited(session_type: str, cooldown_seconds: int = 30) -> bool:
    """Check if session type is rate limited."""
    rate_file = create_rate_limit_file(session_type)
    
    if not rate_file.exists():
        return False
    
    try:
        last_time = float(rate_file.read_text().strip())
        return (datetime.now().timestamp() - last_time) < cooldown_seconds
    except (ValueError, FileNotFoundError):
        return False


def update_rate_limit(session_type: str) -> None:
    """Update rate limit timestamp for session type."""
    rate_file = create_rate_limit_file(session_type)
    rate_file.write_text(str(datetime.now().timestamp()))


def format_git_summary(git_info: Dict[str, Any]) -> str:
    """Format git information for display."""
    modified_count = git_info["modified_count"]
    recent_count = len(git_info["recent_commits"])
    branch = git_info["branch"]

    parts = [f"Branch: {branch}"]
    if modified_count > 0:
        parts.append(f"{modified_count} modified files")
    if recent_count > 0:
        parts.append(f"{recent_count} recent commits")

    return " | ".join(parts)


# ============================================
# Phase 1: Core Session Storage Functions
# ============================================

def store_session_id(session_id: str, project_name: str) -> bool:
    """
    Atomically store session_id for project using temp file approach.

    Args:
        session_id: Claude session ID to store
        project_name: Project name for scoping

    Returns:
        bool: True if stored successfully, False on error
    """
    try:
        session_file = Path(f"/tmp/claude_session_{project_name}")

        # Create temporary file in same directory for atomic operation
        with tempfile.NamedTemporaryFile(
            mode='w',
            dir='/tmp',
            prefix=f'claude_session_{project_name}_',
            suffix='.tmp',
            delete=False
        ) as tmp_file:
            # Write session_id and timestamp
            timestamp = datetime.now().isoformat()
            tmp_file.write(f"{session_id}\n{timestamp}\n")
            tmp_file.flush()
            os.fsync(tmp_file.fileno())  # Force write to disk
            tmp_path = tmp_file.name

        # Set proper permissions (600 - owner read/write only)
        os.chmod(tmp_path, 0o600)

        # Atomic move to final location
        os.rename(tmp_path, session_file)

        return True

    except Exception as e:
        # Clean up temp file if it exists
        try:
            if 'tmp_path' in locals():
                Path(tmp_path).unlink(missing_ok=True)
        except:
            pass
        print(f"Error storing session_id: {e}")
        return False


def get_stored_session_id(project_name: str) -> str:
    """
    Retrieve session_id with staleness check (24-hour TTL).

    Args:
        project_name: Project name for scoping

    Returns:
        str: session_id if found and fresh, "unknown" otherwise
    """
    try:
        session_file = Path(f"/tmp/claude_session_{project_name}")

        if not session_file.exists():
            return "unknown"

        content = session_file.read_text().strip()
        lines = content.split('\n')

        if len(lines) < 2:
            return "unknown"

        session_id = lines[0]
        timestamp_str = lines[1]

        # Check staleness (24-hour TTL)
        try:
            stored_time = datetime.fromisoformat(timestamp_str)
            current_time = datetime.now()

            if current_time - stored_time > timedelta(hours=24):
                # Stale session, clean up file
                session_file.unlink(missing_ok=True)
                return "unknown"

            return session_id

        except ValueError:
            # Invalid timestamp format
            return "unknown"

    except Exception as e:
        print(f"Error retrieving session_id: {e}")
        return "unknown"


def cleanup_stale_sessions() -> int:
    """
    Clean up session files older than 24 hours.

    Returns:
        int: Number of stale sessions cleaned up
    """
    cleanup_count = 0

    try:
        tmp_dir = Path("/tmp")
        current_time = datetime.now()

        # Find all claude_session_* files
        for session_file in tmp_dir.glob("claude_session_*"):
            try:
                # Skip if not a regular file
                if not session_file.is_file():
                    continue

                # Skip temporary files (they have .tmp suffix)
                if session_file.suffix == '.tmp':
                    continue

                content = session_file.read_text().strip()
                lines = content.split('\n')

                if len(lines) < 2:
                    # Invalid format, clean up
                    session_file.unlink(missing_ok=True)
                    cleanup_count += 1
                    continue

                timestamp_str = lines[1]

                try:
                    stored_time = datetime.fromisoformat(timestamp_str)

                    if current_time - stored_time > timedelta(hours=24):
                        session_file.unlink(missing_ok=True)
                        cleanup_count += 1

                except ValueError:
                    # Invalid timestamp, clean up
                    session_file.unlink(missing_ok=True)
                    cleanup_count += 1

            except Exception as e:
                print(f"Error processing {session_file}: {e}")
                continue

    except Exception as e:
        print(f"Error during cleanup: {e}")

    return cleanup_count


def generate_correlation_id() -> str:
    """
    Generate a unique correlation ID for pairing pre/post tool events.

    Returns:
        str: A UUID4 string
    """
    return str(uuid.uuid4())


def store_correlation_id(correlation_id: str, project_name: str, tool_name: str) -> bool:
    """
    Store correlation ID for a tool execution to temporary file.

    Args:
        correlation_id: UUID for correlating pre/post events
        project_name: Project name for scoping
        tool_name: Tool name for scoping

    Returns:
        bool: True if stored successfully, False otherwise
    """
    try:
        # Create unique file per project/tool combination
        correlation_file = Path(f"/tmp/claude_correlation_{project_name}_{tool_name}")

        # Store correlation_id with timestamp
        content = f"{correlation_id}\n{datetime.now().isoformat()}"

        # Atomic write using temporary file
        temp_file = Path(f"{correlation_file}.tmp")
        temp_file.write_text(content)
        temp_file.rename(correlation_file)

        # Set appropriate permissions (readable only by user)
        correlation_file.chmod(0o600)

        return True

    except Exception as e:
        print(f"Error storing correlation_id: {e}")
        return False


def get_stored_correlation_id(project_name: str, tool_name: str) -> Optional[str]:
    """
    Retrieve stored correlation ID for a tool execution.

    Args:
        project_name: Project name for scoping
        tool_name: Tool name for scoping

    Returns:
        str: The correlation ID if found and valid, None otherwise
    """
    try:
        correlation_file = Path(f"/tmp/claude_correlation_{project_name}_{tool_name}")

        if not correlation_file.exists():
            return None

        content = correlation_file.read_text().strip()
        lines = content.split('\n')

        if len(lines) < 2:
            return None

        correlation_id = lines[0]
        timestamp_str = lines[1]

        # Check staleness (10-minute TTL for correlation)
        try:
            stored_time = datetime.fromisoformat(timestamp_str)
            current_time = datetime.now()

            if current_time - stored_time > timedelta(minutes=10):
                # Stale correlation, clean up file
                correlation_file.unlink(missing_ok=True)
                return None

            # After successful retrieval, clean up the file (one-time use)
            correlation_file.unlink(missing_ok=True)

            return correlation_id

        except ValueError:
            # Invalid timestamp format
            return None

    except Exception as e:
        print(f"Error retrieving correlation_id: {e}")
        return None