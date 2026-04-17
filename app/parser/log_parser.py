"""Utilities for parsing raw log files into structured entries."""

from __future__ import annotations

import re
from datetime import datetime

from app.models.log_models import ParsedLogEntry, RawLogFile


class LogParser:
    """Parse raw log files line by line into structured log entries."""

    _ISO_LEVEL_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
        r"(?P<level>[A-Z]+)\s+"
        r"(?P<message>.*)$"
    )
    _BRACKET_LEVEL_PATTERN = re.compile(
        r"^\[(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+"
        r"(?P<level>[A-Z]+)\s+"
        r"(?P<message>.*)$"
    )
    _SYSLOG_PATTERN = re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+"
        r"(?P<message>.*)$"
    )
    _LEVEL_PATTERN = re.compile(
        r"\b(DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL|NOTICE|ALERT|EMERGENCY)\b"
    )
    _IP_PATTERN = re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    )

    def parse_files(self, raw_logs: list[RawLogFile]) -> list[ParsedLogEntry]:
        """Parse multiple raw log files into structured entries."""
        entries: list[ParsedLogEntry] = []

        for raw_log in raw_logs:
            entries.extend(self.parse_file(raw_log))

        return entries

    def parse_file(self, raw_log: RawLogFile) -> list[ParsedLogEntry]:
        """Parse one raw log file into structured entries."""
        entries: list[ParsedLogEntry] = []

        for line in raw_log.raw_content.splitlines():
            if not line.strip():
                continue

            entries.append(self.parse_line(raw_log.file_name, line))

        return entries

    def parse_line(self, source_file: str, raw_line: str) -> ParsedLogEntry:
        """Parse one log line without raising on malformed input."""
        timestamp: datetime | None = None
        level = "UNKNOWN"
        message = raw_line.strip()

        try:
            timestamp, detected_level, detected_message = self._extract_parts(raw_line)
            if detected_level:
                level = detected_level
            if detected_message:
                message = detected_message
        except Exception:
            message = raw_line.strip()

        ip_address = self._extract_ip(raw_line)

        return ParsedLogEntry(
            source_file=source_file,
            raw_line=raw_line,
            timestamp=timestamp,
            level=level,
            message=message,
            ip_address=ip_address,
        )

    def _extract_parts(self, raw_line: str) -> tuple[datetime | None, str | None, str]:
        """Extract timestamp, level, and message from a raw log line."""
        stripped_line = raw_line.strip()

        iso_match = self._ISO_LEVEL_PATTERN.match(stripped_line)
        if iso_match:
            return (
                self._parse_datetime(iso_match.group("timestamp"), "%Y-%m-%d %H:%M:%S"),
                self._normalize_level(iso_match.group("level")),
                iso_match.group("message").strip(),
            )

        bracket_match = self._BRACKET_LEVEL_PATTERN.match(stripped_line)
        if bracket_match:
            return (
                self._parse_datetime(bracket_match.group("timestamp"), "%Y-%m-%d %H:%M:%S"),
                self._normalize_level(bracket_match.group("level")),
                bracket_match.group("message").strip(),
            )

        syslog_match = self._SYSLOG_PATTERN.match(stripped_line)
        if syslog_match:
            message = syslog_match.group("message").strip()
            return (
                self._parse_syslog_timestamp(syslog_match.group("timestamp")),
                self._detect_level(message),
                self._extract_syslog_message(message),
            )

        return None, self._detect_level(stripped_line), stripped_line

    def _parse_datetime(self, value: str, fmt: str) -> datetime | None:
        """Parse a datetime value and return None on failure."""
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            return None

    def _parse_syslog_timestamp(self, value: str) -> datetime | None:
        """Parse syslog timestamps that do not include a year."""
        current_year = datetime.now().year
        try:
            parsed = datetime.strptime(value, "%b %d %H:%M:%S")
            return parsed.replace(year=current_year)
        except ValueError:
            return None

    def _detect_level(self, text: str) -> str | None:
        """Detect a known log level from the provided text."""
        match = self._LEVEL_PATTERN.search(text)
        if not match:
            return None

        return self._normalize_level(match.group(1))

    def _normalize_level(self, value: str) -> str:
        """Normalize log level labels to a compact common set."""
        normalized = value.upper()
        if normalized == "WARN":
            return "WARNING"
        return normalized

    def _extract_syslog_message(self, message: str) -> str:
        """Reduce common syslog prefixes to the message body."""
        if ": " in message:
            return message.split(": ", maxsplit=1)[1].strip()
        return message

    def _extract_ip(self, raw_line: str) -> str | None:
        """Return the first detected IPv4 address from the line."""
        match = self._IP_PATTERN.search(raw_line)
        if not match:
            return None
        return match.group(0)
