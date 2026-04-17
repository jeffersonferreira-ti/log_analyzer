"""Parser for Apache and Nginx access and error logs."""

from __future__ import annotations

import re

from app.models.log_models import ParsedLogEntry, RawLogFile
from app.parser.base import BaseLogParser


class ApacheLogParser(BaseLogParser):
    """Parse common Apache and Nginx web server log formats."""

    parser_name = "apache_nginx"
    _ACCESS_PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>[A-Z]+)\s+(?P<path>[^"\s]+)(?:\s+[^"]+)?"\s+'
        r'(?P<status>\d{3})\s+(?P<size>\S+)'
    )
    _APACHE_ERROR_PATTERN = re.compile(
        r"^\[(?P<timestamp>[^\]]+)\]\s+"
        r"\[(?P<level>[A-Za-z]+)(?::[^\]]+)?\]\s+"
        r"(?:\[pid [^\]]+\]\s+)?"
        r"(?:\[client (?P<client>\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?\]\s+)?"
        r"(?P<message>.*)$"
    )
    _NGINX_ERROR_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+"
        r"\[(?P<level>[^\]]+)\]\s+"
        r"(?P<message>.*)$"
    )
    _CLIENT_IP_PATTERN = re.compile(r"\bclient:\s*(?P<client>\d{1,3}(?:\.\d{1,3}){3})\b")

    def can_parse_file(self, raw_log: RawLogFile) -> int:
        """Score whether the file looks like a web server log."""
        score = 0
        file_name = raw_log.file_name.lower()
        if any(token in file_name for token in ("access", "error", "apache", "nginx")):
            score += 5

        for line in raw_log.raw_content.splitlines()[:20]:
            stripped = line.strip()
            if (
                self._ACCESS_PATTERN.match(stripped)
                or self._APACHE_ERROR_PATTERN.match(stripped)
                or self._NGINX_ERROR_PATTERN.match(stripped)
            ):
                score += 3

        return min(score, 20)

    def parse_line(self, source_file: str, raw_line: str) -> ParsedLogEntry:
        """Parse access and error log formats without raising on malformed data."""
        stripped = raw_line.strip()

        access_match = self._ACCESS_PATTERN.match(stripped)
        if access_match:
            status_code = int(access_match.group("status"))
            method = access_match.group("method")
            path = access_match.group("path")
            return self._build_entry(
                source_file=source_file,
                raw_line=raw_line,
                timestamp=self._parse_datetime(
                    access_match.group("timestamp"),
                    "%d/%b/%Y:%H:%M:%S %z",
                ),
                level=self._level_from_status_code(status_code),
                message=f'{method} {path} -> {status_code}',
                ip_address=access_match.group("ip"),
                http_method=method,
                http_path=path,
                status_code=status_code,
            )

        apache_error_match = self._APACHE_ERROR_PATTERN.match(stripped)
        if apache_error_match:
            return self._build_entry(
                source_file=source_file,
                raw_line=raw_line,
                timestamp=self._parse_datetime(
                    apache_error_match.group("timestamp"),
                    "%a %b %d %H:%M:%S.%f %Y",
                    "%a %b %d %H:%M:%S %Y",
                ),
                level=apache_error_match.group("level"),
                message=apache_error_match.group("message").strip(),
                ip_address=apache_error_match.group("client"),
                event_source="apache_error",
            )

        nginx_error_match = self._NGINX_ERROR_PATTERN.match(stripped)
        if nginx_error_match:
            client_match = self._CLIENT_IP_PATTERN.search(nginx_error_match.group("message"))
            return self._build_entry(
                source_file=source_file,
                raw_line=raw_line,
                timestamp=self._parse_datetime(
                    nginx_error_match.group("timestamp"),
                    "%Y/%m/%d %H:%M:%S",
                ),
                level=nginx_error_match.group("level"),
                message=nginx_error_match.group("message").strip(),
                ip_address=client_match.group("client") if client_match else None,
                event_source="nginx_error",
            )

        return super().parse_line(source_file, raw_line)
