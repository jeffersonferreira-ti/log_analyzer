"""Data models used during ingestion, parsing, and analysis."""

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


@dataclass(slots=True)
class AnalysisFinding:
    """Represents a triggered heuristic finding."""

    rule_name: str
    description: str
    severity: str
    score: int
    evidence: list[str]


@dataclass(slots=True)
class AnalysisResult:
    """Represents the aggregate analysis output for one run."""

    total_score: int
    classification: str
    summary: str
    findings: list[AnalysisFinding]
