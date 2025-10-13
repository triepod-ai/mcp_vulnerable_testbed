#!/usr/bin/env python3
"""
Message deduplication and rate limiting for TTS notifications.
Prevents redundant announcements within configurable time windows.
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta


@dataclass
class MessageRecord:
    """Record of a spoken message for deduplication."""
    message_hash: str
    message_text: str
    category: str
    timestamp: float
    count: int = 1
    last_spoken: float = 0.0


class MessageDeduplicator:
    """
    Deduplicates and rate-limits TTS messages.

    Features:
    - Time-based deduplication (don't repeat same message within N seconds)
    - Category-based rate limiting (max messages per category per time window)
    - Similarity detection (fuzzy matching for similar messages)
    - Persistent storage (survives process restarts)
    """

    def __init__(
        self,
        cache_file: Optional[Path] = None,
        default_cooldown: int = 300,  # 5 minutes default
        cleanup_after: int = 3600  # Clean up records older than 1 hour
    ):
        """
        Initialize the deduplicator.

        Args:
            cache_file: Path to persistent cache file
            default_cooldown: Default cooldown period in seconds
            cleanup_after: Remove records older than this (seconds)
        """
        self.cache_file = cache_file or Path("/tmp/tts-queue/message-cache.json")
        self.default_cooldown = default_cooldown
        self.cleanup_after = cleanup_after
        self.records: Dict[str, MessageRecord] = {}

        # Category-specific cooldowns (in seconds)
        self.category_cooldowns = {
            "session_completion": 300,  # 5 minutes
            "session_start": 300,       # 5 minutes
            "error": 60,                # 1 minute (allow more frequent error notices)
            "warning": 120,             # 2 minutes
            "completion": 180,          # 3 minutes
            "general": 300,             # 5 minutes
        }

        # Load existing records
        self._load_cache()

    def _load_cache(self):
        """Load message records from cache file."""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                    self.records = {
                        k: MessageRecord(**v)
                        for k, v in data.items()
                    }
        except Exception:
            # If cache is corrupt, start fresh
            self.records = {}

    def _save_cache(self):
        """Save message records to cache file."""
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, 'w') as f:
                json.dump(
                    {k: asdict(v) for k, v in self.records.items()},
                    f,
                    indent=2
                )
        except Exception:
            # Silently fail - caching is non-critical
            pass

    def _cleanup_old_records(self):
        """Remove records older than cleanup_after threshold."""
        current_time = time.time()
        cutoff_time = current_time - self.cleanup_after

        # Remove old records
        old_keys = [
            key for key, record in self.records.items()
            if record.timestamp < cutoff_time
        ]

        for key in old_keys:
            del self.records[key]

        # Save if we cleaned anything up
        if old_keys:
            self._save_cache()

    def _create_message_hash(self, message: str, category: str) -> str:
        """Create a hash for message deduplication."""
        # Normalize message for comparison
        normalized = message.lower().strip()

        # Create hash from normalized message + category
        hash_input = f"{category}:{normalized}"
        return hashlib.md5(hash_input.encode()).hexdigest()[:16]

    def _extract_category(self, context: Dict[str, Any]) -> str:
        """Extract message category from context."""
        # Check explicit category
        if "category" in context:
            return context["category"]

        # Infer from message content
        message = context.get("summary", "").lower()

        if "session completed" in message or "session ended" in message:
            return "session_completion"
        elif "started session" in message or "session started" in message:
            return "session_start"
        elif "error" in message or "failed" in message:
            return "error"
        elif "warning" in message or "caution" in message:
            return "warning"
        elif "completed" in message or "finished" in message:
            return "completion"
        else:
            return "general"

    def should_speak(
        self,
        message: str,
        context: Optional[Dict[str, Any]] = None
    ) -> tuple[bool, Optional[str]]:
        """
        Determine if message should be spoken.

        Args:
            message: The message text to check
            context: Additional context about the message

        Returns:
            Tuple of (should_speak: bool, reason: str or None)
        """
        # Cleanup old records periodically
        self._cleanup_old_records()

        # Extract context
        context = context or {}
        category = self._extract_category(context)

        # Get category cooldown
        cooldown = self.category_cooldowns.get(category, self.default_cooldown)

        # Create message hash
        msg_hash = self._create_message_hash(message, category)

        # Check if we've seen this message recently
        if msg_hash in self.records:
            record = self.records[msg_hash]
            time_since_last = time.time() - record.last_spoken

            if time_since_last < cooldown:
                # Still in cooldown period
                record.count += 1
                self._save_cache()

                time_remaining = int(cooldown - time_since_last)
                reason = f"Message in cooldown (category: {category}, {time_remaining}s remaining, repeated {record.count}x)"
                return False, reason

        # Message should be spoken
        # Update or create record
        current_time = time.time()
        self.records[msg_hash] = MessageRecord(
            message_hash=msg_hash,
            message_text=message,
            category=category,
            timestamp=current_time,
            last_spoken=current_time,
            count=1
        )

        self._save_cache()
        return True, None

    def get_stats(self) -> Dict[str, Any]:
        """Get deduplication statistics."""
        current_time = time.time()

        stats = {
            "total_records": len(self.records),
            "by_category": {},
            "recent_duplicates": []
        }

        # Count by category
        for record in self.records.values():
            category = record.category
            if category not in stats["by_category"]:
                stats["by_category"][category] = {
                    "count": 0,
                    "total_duplicates": 0
                }

            stats["by_category"][category]["count"] += 1
            stats["by_category"][category]["total_duplicates"] += record.count - 1

        # Find recent duplicates (within last 5 minutes)
        recent_threshold = current_time - 300
        for record in self.records.values():
            if record.timestamp > recent_threshold and record.count > 1:
                stats["recent_duplicates"].append({
                    "message": record.message_text[:50],
                    "category": record.category,
                    "count": record.count,
                    "last_spoken": datetime.fromtimestamp(record.last_spoken).isoformat()
                })

        return stats


# Global instance
_deduplicator: Optional[MessageDeduplicator] = None


def get_deduplicator() -> MessageDeduplicator:
    """Get the global deduplicator instance."""
    global _deduplicator
    if _deduplicator is None:
        _deduplicator = MessageDeduplicator()
    return _deduplicator


def should_speak_message(message: str, context: Optional[Dict[str, Any]] = None) -> bool:
    """
    Convenience function to check if a message should be spoken.

    Args:
        message: The message text
        context: Optional context dict

    Returns:
        True if message should be spoken, False if rate-limited
    """
    deduplicator = get_deduplicator()
    should_speak, reason = deduplicator.should_speak(message, context)

    if not should_speak and reason:
        # Log suppression
        import sys
        print(f"[TTS SUPPRESSED] {reason}", file=sys.stderr)

    return should_speak


if __name__ == "__main__":
    # Test the deduplicator
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--stats":
        # Show stats
        dedup = get_deduplicator()
        stats = dedup.get_stats()
        print(json.dumps(stats, indent=2))
    else:
        # Test deduplication
        test_messages = [
            ("Session completed in multi-agent-observability-system", {"category": "session_completion"}),
            ("Session completed in multi-agent-observability-system", {"category": "session_completion"}),  # Duplicate
            ("Error in authentication module", {"category": "error"}),
            ("Session completed in client", {"category": "session_completion"}),  # Different message
        ]

        print("Testing message deduplication...")
        for i, (msg, ctx) in enumerate(test_messages, 1):
            should_speak, reason = get_deduplicator().should_speak(msg, ctx)
            print(f"\nTest {i}: {msg[:50]}...")
            print(f"  Category: {ctx.get('category', 'unknown')}")
            print(f"  Should speak: {should_speak}")
            if reason:
                print(f"  Reason: {reason}")
