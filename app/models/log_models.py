"""Data models used during log ingestion."""

from dataclasses import dataclass


@dataclass(slots=True)
class RawLogFile:
    """Represents a raw log file loaded from disk."""

    file_name: str
    file_path: str
    raw_content: str
