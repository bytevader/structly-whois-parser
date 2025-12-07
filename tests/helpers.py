from __future__ import annotations

from datetime import datetime, timezone


def iso_to_datetime(value: str) -> datetime:
    """Simple helper used by CLI tests to ensure date parser wiring works."""
    sanitized = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(sanitized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
