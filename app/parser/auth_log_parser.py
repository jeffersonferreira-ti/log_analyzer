"""Parser for Linux authentication log families."""

from __future__ import annotations

import re

from app.models.log_models import ParsedLogEntry, RawLogFile
from app.parser.base import BaseLogParser


class AuthLogParser(BaseLogParser):
    """Parse Linux auth logs such as auth.log and secure."""

    parser_name = "linux_auth"
    _AUTH_PATTERN = re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+"
        r"(?P<process>[A-Za-z0-9_.-]+)(?:\[\d+\])?:\s*"
        r"(?P<message>.*)$"
    )
    _AUTH_HINT_PATTERN = re.compile(
        r"\b(sshd|sudo|failed password|accepted password|authentication failure|session opened|session closed)\b",
        re.IGNORECASE,
    )

    def can_parse_file(self, raw_log: RawLogFile) -> int:
        """Score whether the file looks like a Linux auth log."""
        score = 0
        file_name = raw_log.file_name.lower()
        if file_name in {"auth.log", "secure"} or "auth" in file_name or "secure" in file_name:
            score += 6

        for line in raw_log.raw_content.splitlines()[:20]:
            if self._AUTH_PATTERN.match(line) and self._AUTH_HINT_PATTERN.search(line):
                score += 3

        return min(score, 18)

    def parse_line(self, source_file: str, raw_line: str) -> ParsedLogEntry:
        """Parse an auth log line into a structured entry."""
        match = self._AUTH_PATTERN.match(raw_line.strip())
        if not match:
            return super().parse_line(source_file, raw_line)

        message = match.group("message").strip()
        process_name = match.group("process")
        return self._build_entry(
            source_file=source_file,
            raw_line=raw_line,
            timestamp=self._parse_syslog_timestamp(match.group("timestamp")),
            level=self._detect_auth_level(message, process_name),
            message=message,
            event_source=process_name,
        )

    def _detect_auth_level(self, message: str, process_name: str) -> str:
        """Infer a practical auth level from common security actions."""
        lowered = message.lower()
        if "failed password" in lowered or "authentication failure" in lowered:
            return "WARNING"
        if "accepted password" in lowered or "session opened" in lowered:
            return "INFO"
        if process_name == "sudo":
            return "NOTICE"

        detected = self._detect_level(message)
        if detected:
            return detected

        if process_name == "sshd":
            return "INFO"

        return "UNKNOWN"
