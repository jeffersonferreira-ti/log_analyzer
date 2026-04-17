"""JSON report generation for analyzed log data."""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from app.models.log_models import AnalysisResult, ParsedLogEntry


class ReportGenerator:
    """Generate and persist a JSON report for one analysis run."""

    _LEVEL_ORDER = ("INFO", "WARNING", "ERROR", "CRITICAL", "UNKNOWN", "NOTICE")
    _TOP_ITEMS_LIMIT = 5
    _TIMELINE_LIMIT = 8
    _TIMELINE_GROUP_GAP_SECONDS = 60

    def generate_json_report(
        self,
        total_files_loaded: int,
        total_entries_parsed: int,
        parsed_entries: list[ParsedLogEntry],
        level_counts: Counter[str],
        analysis_result: AnalysisResult,
        output_path: str | Path,
    ) -> Path:
        """Write the JSON report to disk and return its path."""
        report_path = Path(output_path)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_data = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_files_loaded": total_files_loaded,
            "total_entries_parsed": total_entries_parsed,
            "level_counts": dict(sorted(level_counts.items())),
            "analysis_summary": {
                "total_score": analysis_result.total_score,
                "classification": analysis_result.classification,
                "summary": analysis_result.summary,
            },
            "top_ips": self._build_top_ips(parsed_entries),
            "top_errors": self._build_top_errors(parsed_entries),
            "files_summary": self._build_files_summary(parsed_entries),
            "timeline_highlights": self._build_timeline_highlights(parsed_entries),
            "triggered_findings": [
                {
                    "rule_name": finding.rule_name,
                    "description": finding.description,
                    "severity": finding.severity,
                    "score": finding.score,
                    "evidence": finding.evidence,
                }
                for finding in analysis_result.findings
            ],
        }

        report_path.write_text(
            json.dumps(report_data, indent=2),
            encoding="utf-8",
        )
        return report_path

    def _build_top_ips(self, parsed_entries: list[ParsedLogEntry]) -> list[dict[str, int | str]]:
        """Return the most frequent IP addresses found in parsed entries."""
        ip_counts = Counter(
            entry.ip_address.strip()
            for entry in parsed_entries
            if entry.ip_address and entry.ip_address.strip()
        )
        return [
            {"ip": ip_address, "count": count}
            for ip_address, count in ip_counts.most_common(self._TOP_ITEMS_LIMIT)
        ]

    def _build_top_errors(
        self,
        parsed_entries: list[ParsedLogEntry],
    ) -> list[dict[str, int | str]]:
        """Return the most repeated error messages from ERROR and CRITICAL entries."""
        error_groups: Counter[str] = Counter()
        canonical_messages: dict[str, str] = {}

        for entry in parsed_entries:
            if entry.level not in {"ERROR", "CRITICAL"}:
                continue

            normalized_message = self._normalize_error_message(entry.message)
            if not normalized_message:
                continue

            error_groups[normalized_message] += 1
            canonical_messages.setdefault(normalized_message, entry.message.strip())

        return [
            {"message": canonical_messages[normalized], "count": count}
            for normalized, count in error_groups.most_common(self._TOP_ITEMS_LIMIT)
        ]

    def _build_files_summary(
        self,
        parsed_entries: list[ParsedLogEntry],
    ) -> list[dict[str, int | dict[str, int] | str]]:
        """Return parsed-entry counts and levels grouped by source file."""
        files_summary: dict[str, dict[str, int | Counter[str]]] = {}

        for entry in parsed_entries:
            file_summary = files_summary.setdefault(
                entry.source_file,
                {"entries": 0, "levels": Counter()},
            )
            file_summary["entries"] += 1
            file_summary["levels"][entry.level] += 1

        summary_rows: list[dict[str, int | dict[str, int] | str]] = []
        for file_name in sorted(files_summary):
            file_summary = files_summary[file_name]
            levels_counter: Counter[str] = file_summary["levels"]
            levels = {
                level: levels_counter.get(level, 0)
                for level in self._LEVEL_ORDER
            }
            for level in sorted(levels_counter):
                if level not in levels:
                    levels[level] = levels_counter[level]

            summary_rows.append(
                {
                    "file_name": file_name,
                    "entries": file_summary["entries"],
                    "levels": levels,
                }
            )

        return summary_rows

    def _build_timeline_highlights(self, parsed_entries: list[ParsedLogEntry]) -> list[str]:
        """Return the most relevant parsed events in chronological order."""
        suspicious_ips = {
            ip_address
            for ip_address, count in Counter(
                entry.ip_address.strip()
                for entry in parsed_entries
                if entry.ip_address and entry.ip_address.strip()
            ).items()
            if count > 1
        }

        ranked_entries: list[tuple[int, datetime, int, ParsedLogEntry]] = []
        for index, entry in enumerate(parsed_entries):
            if entry.timestamp is None:
                continue

            relevance = self._score_timeline_entry(entry, suspicious_ips)
            if relevance <= 0:
                continue

            ranked_entries.append((relevance, entry.timestamp, index, entry))

        ranked_entries.sort(key=lambda item: (item[1], item[2]))
        grouped_entries = self._group_timeline_entries(ranked_entries)
        grouped_entries.sort(key=lambda item: (-item["score"], item["start"], item["index"]))
        selected_groups = grouped_entries[: self._TIMELINE_LIMIT]
        selected_groups.sort(key=lambda item: (item["start"], item["index"]))

        return [self._format_timeline_group(group) for group in selected_groups]

    def _group_timeline_entries(
        self,
        ranked_entries: list[tuple[int, datetime, int, ParsedLogEntry]],
    ) -> list[dict[str, int | datetime | str | ParsedLogEntry]]:
        """Group repeated nearby timeline events into compact summaries."""
        grouped_entries: list[dict[str, int | datetime | str | ParsedLogEntry]] = []
        failed_login_groups: dict[str, dict[str, int | datetime | str | ParsedLogEntry]] = {}

        for score, timestamp, index, entry in ranked_entries:
            group_key = self._build_timeline_group_key(entry)
            group_label = self._build_timeline_group_label(entry)

            if self._is_failed_login_entry(entry):
                existing_group = failed_login_groups.get(group_key)
                within_gap = False
                if existing_group is not None:
                    existing_end = existing_group["end"]
                    within_gap = (
                        isinstance(existing_end, datetime)
                        and (timestamp - existing_end).total_seconds()
                        <= self._TIMELINE_GROUP_GAP_SECONDS
                    )

                if existing_group is not None and within_gap:
                    existing_group["count"] += 1
                    existing_group["end"] = timestamp
                    existing_group["score"] = max(existing_group["score"], score)
                    continue

                new_group = {
                    "key": group_key,
                    "label": group_label,
                    "count": 1,
                    "score": score,
                    "start": timestamp,
                    "end": timestamp,
                    "index": index,
                    "entry": entry,
                }
                grouped_entries.append(new_group)
                failed_login_groups[group_key] = new_group
                continue

            if grouped_entries:
                previous_group = grouped_entries[-1]
                previous_end = previous_group["end"]
                within_gap = (
                    isinstance(previous_end, datetime)
                    and (timestamp - previous_end).total_seconds() <= self._TIMELINE_GROUP_GAP_SECONDS
                )
                if previous_group["key"] == group_key and within_gap:
                    previous_group["count"] += 1
                    previous_group["end"] = timestamp
                    previous_group["score"] = max(previous_group["score"], score)
                    continue

            grouped_entries.append(
                {
                    "key": group_key,
                    "label": group_label,
                    "count": 1,
                    "score": score,
                    "start": timestamp,
                    "end": timestamp,
                    "index": index,
                    "entry": entry,
                }
            )

        return grouped_entries

    def _is_failed_login_entry(self, entry: ParsedLogEntry) -> bool:
        """Return whether an entry represents a failed login event."""
        lowered_message = entry.message.lower()
        return (
            "failed password" in lowered_message
            or "authentication failure" in lowered_message
        )

    def _score_timeline_entry(
        self,
        entry: ParsedLogEntry,
        suspicious_ips: set[str],
    ) -> int:
        """Score whether an entry should appear in the incident timeline."""
        lowered_message = entry.message.lower()
        score = 0

        if entry.level == "CRITICAL":
            score += 100
        elif entry.level == "ERROR":
            score += 80
        elif entry.level == "WARNING":
            score += 35

        if "failed password" in lowered_message or "authentication failure" in lowered_message:
            score += 70
        if "accepted password" in lowered_message or "session opened" in lowered_message:
            score += 40

        if entry.ip_address and entry.ip_address in suspicious_ips:
            score += 20

        return score

    def _format_timeline_entry(self, entry: ParsedLogEntry) -> str:
        """Render one timeline highlight as a compact human-readable string."""
        timestamp_text = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        lowered_message = entry.message.lower()

        if "failed password" in lowered_message or "authentication failure" in lowered_message:
            ip_suffix = f" from {entry.ip_address}" if entry.ip_address else ""
            return f"{timestamp_text} Failed login{ip_suffix}"

        if "accepted password" in lowered_message:
            ip_suffix = f" from {entry.ip_address}" if entry.ip_address else ""
            return f"{timestamp_text} Accepted login{ip_suffix}"

        return f"{timestamp_text} {entry.level} {entry.message}"

    def _format_timeline_group(
        self,
        group: dict[str, int | datetime | str | ParsedLogEntry],
    ) -> str:
        """Render a grouped timeline item as either a single event or a compact summary."""
        count = group["count"]
        if isinstance(count, int) and count >= 2:
            start = group["start"]
            end = group["end"]
            if isinstance(start, datetime) and isinstance(end, datetime):
                start_text, end_text = self._format_timeline_range(start, end)
                return f"{count}x {group['label']} between {start_text} and {end_text}"

        entry = group["entry"]
        if isinstance(entry, ParsedLogEntry):
            return self._format_timeline_entry(entry)

        return str(group["label"])

    def _build_timeline_group_key(self, entry: ParsedLogEntry) -> str:
        """Build a stable grouping key for repeated timeline events."""
        lowered_message = entry.message.lower()

        if "failed password" in lowered_message or "authentication failure" in lowered_message:
            ip_suffix = entry.ip_address or "unknown-ip"
            return f"failed-login:{ip_suffix}"

        if "accepted password" in lowered_message:
            ip_suffix = entry.ip_address or "unknown-ip"
            return f"accepted-login:{ip_suffix}"

        return f"{entry.level}:{self._normalize_error_message(entry.message)}"

    def _build_timeline_group_label(self, entry: ParsedLogEntry) -> str:
        """Build a readable label for grouped timeline events."""
        lowered_message = entry.message.lower()

        if "failed password" in lowered_message or "authentication failure" in lowered_message:
            ip_suffix = f" from {entry.ip_address}" if entry.ip_address else ""
            return f"Failed login{ip_suffix}"

        if "accepted password" in lowered_message:
            ip_suffix = f" from {entry.ip_address}" if entry.ip_address else ""
            return f"Accepted login{ip_suffix}"

        return entry.message

    def _format_timeline_range(self, start: datetime, end: datetime) -> tuple[str, str]:
        """Format a compact time range for a grouped timeline item."""
        if start.date() == end.date():
            return start.strftime("%H:%M:%S"), end.strftime("%H:%M:%S")

        return start.strftime("%Y-%m-%d %H:%M:%S"), end.strftime("%Y-%m-%d %H:%M:%S")

    def _normalize_error_message(self, message: str) -> str:
        """Normalize an error message conservatively for repeat grouping."""
        normalized = message.strip().lower()
        normalized = re.sub(r"\b\d+\b", "<num>", normalized)
        normalized = re.sub(r"\s+", " ", normalized)
        return normalized
