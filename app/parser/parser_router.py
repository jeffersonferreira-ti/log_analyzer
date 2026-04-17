"""Parser router that chooses the most likely parser per file."""

from __future__ import annotations

from app.models.log_models import ParsedLogEntry, RawLogFile
from app.parser.apache_log_parser import ApacheLogParser
from app.parser.auth_log_parser import AuthLogParser
from app.parser.log_parser import LogParser
from app.parser.windows_log_parser import WindowsLogParser


class ParserRouter:
    """Route each input file through the best matching parser."""

    _SPECIALIZED_THRESHOLD = 5

    def __init__(self) -> None:
        self.fallback_parser = LogParser()
        self.specialized_parsers = [
            AuthLogParser(),
            ApacheLogParser(),
            WindowsLogParser(),
        ]

    def parse_files(self, raw_logs: list[RawLogFile]) -> list[ParsedLogEntry]:
        """Parse multiple files with automatic parser selection."""
        entries: list[ParsedLogEntry] = []

        for raw_log in raw_logs:
            entries.extend(self.parse_file(raw_log))

        return entries

    def parse_file(self, raw_log: RawLogFile) -> list[ParsedLogEntry]:
        """Parse one file through the detected parser."""
        parser = self.select_parser(raw_log)
        return parser.parse_file(raw_log)

    def select_parser(self, raw_log: RawLogFile) -> LogParser:
        """Return the most likely parser, or the generic fallback."""
        best_score = self._SPECIALIZED_THRESHOLD
        best_parser = self.fallback_parser

        for parser in self.specialized_parsers:
            score = parser.can_parse_file(raw_log)
            if score > best_score:
                best_score = score
                best_parser = parser

        return best_parser
