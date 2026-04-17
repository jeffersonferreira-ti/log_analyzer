"""Basic model definitions for log records."""

from dataclasses import dataclass
from typing import Any


@dataclass
class LogRecord:
    """Minimal structured representation of a log entry."""

    raw: str
    metadata: dict[str, Any] | None = None
