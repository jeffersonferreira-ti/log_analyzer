"""Data models used during log ingestion and parsing."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True)
class RawLogFile:
    """Represents a raw log file loaded from disk."""

    file_name: str
    file_path: str
    raw_content: str


@dataclass(slots=True)
class ParsedLogEntry:
    """Represents a parsed log entry ready for later analysis."""

    source_file: str
    raw_line: str
    timestamp: datetime | None
    level: str
    message: str
    ip_address: str | None
