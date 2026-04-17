"""Parser for practical Windows event text exports."""

from __future__ import annotations

import re

from app.models.log_models import ParsedLogEntry, RawLogFile
from app.parser.base import BaseLogParser


class WindowsLogParser(BaseLogParser):
    """Parse simple Windows event text blocks and copied exports."""

    parser_name = "windows_event"
    _KEY_VALUE_PATTERN = re.compile(r"^(?P<key>[A-Za-z ][A-Za-z0-9 /_-]*):\s*(?P<value>.*)$")
    _EVENT_START_PATTERN = re.compile(r"(?im)^(Date|Time Created)\s*:")
    _FIELD_HINT_PATTERN = re.compile(
        r"^(Date|Time Created|Source|Provider Name|Level|Entry Type|Event ID|Instance ID|Description|Message)\s*:",
        re.IGNORECASE,
    )

    def can_parse_file(self, raw_log: RawLogFile) -> int:
        """Score whether the file looks like exported Windows events."""
        score = 0
        file_name = raw_log.file_name.lower()
        if any(token in file_name for token in ("system", "application", "security", "event")):
            score += 2

        for line in raw_log.raw_content.splitlines()[:30]:
            if self._FIELD_HINT_PATTERN.match(line.strip()):
                score += 2

        return min(score, 20)

    def parse_file(self, raw_log: RawLogFile) -> list[ParsedLogEntry]:
        """Parse Windows event text blocks while keeping a safe fallback."""
        blocks = self._split_blocks(raw_log.raw_content)
        if not blocks:
            return super().parse_file(raw_log)

        entries: list[ParsedLogEntry] = []
        for block in blocks:
            entry = self._parse_block(raw_log.file_name, block)
            if entry is None:
                for line in block.splitlines():
                    if line.strip():
                        entries.append(super().parse_line(raw_log.file_name, line))
                continue
            entries.append(entry)

        return entries

    def _split_blocks(self, raw_content: str) -> list[str]:
        """Split event exports into likely event blocks."""
        stripped = raw_content.strip()
        if not stripped:
            return []

        if len(self._EVENT_START_PATTERN.findall(stripped)) >= 2:
            return [
                block.strip()
                for block in re.split(r"(?im)(?=^(?:Date|Time Created)\s*:)", stripped)
                if block.strip()
            ]

        blank_split_blocks = [
            block.strip()
            for block in re.split(r"(?:\r?\n){2,}", stripped)
            if block.strip()
        ]
        return blank_split_blocks or [stripped]

    def _parse_block(self, source_file: str, block: str) -> ParsedLogEntry | None:
        """Parse a key-value Windows event block."""
        fields: dict[str, str] = {}
        current_key: str | None = None

        for line in block.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            match = self._KEY_VALUE_PATTERN.match(stripped)
            if match:
                current_key = self._normalize_key(match.group("key"))
                fields[current_key] = match.group("value").strip()
                continue

            if current_key is not None:
                existing = fields.get(current_key, "")
                fields[current_key] = f"{existing} {stripped}".strip()

        if not fields:
            return None

        timestamp = self._extract_windows_timestamp(fields)
        event_source = fields.get("source") or fields.get("provider_name") or fields.get("log_name")
        level = fields.get("level") or fields.get("entry_type") or self._detect_level(block)
        message = fields.get("description") or fields.get("message") or block.replace("\n", " ").strip()
        event_id = self._parse_event_id(fields.get("event_id") or fields.get("instance_id"))

        if timestamp is None and event_source is None and event_id is None and level is None:
            return None

        return self._build_entry(
            source_file=source_file,
            raw_line=block,
            timestamp=timestamp,
            level=level or "UNKNOWN",
            message=message,
            event_source=event_source,
            event_id=event_id,
        )

    def _normalize_key(self, key: str) -> str:
        """Normalize field names for simpler lookup."""
        return key.strip().lower().replace(" ", "_").replace("/", "_")

    def _extract_windows_timestamp(self, fields: dict[str, str]):
        """Parse common Windows event export timestamps."""
        timestamp_value = fields.get("time_created") or fields.get("date")
        if timestamp_value is None and fields.get("date") and fields.get("time"):
            timestamp_value = f"{fields['date']} {fields['time']}"
        if timestamp_value is None:
            return None

        return self._parse_datetime(
            timestamp_value,
            "%m/%d/%Y %I:%M:%S %p",
            "%m/%d/%Y %H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
        )

    def _parse_event_id(self, value: str | None) -> int | None:
        """Extract an integer event id when available."""
        if not value:
            return None

        match = re.search(r"\d+", value)
        if not match:
            return None

        return int(match.group(0))
