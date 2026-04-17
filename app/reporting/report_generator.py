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

    def _normalize_error_message(self, message: str) -> str:
        """Normalize an error message conservatively for repeat grouping."""
        normalized = message.strip().lower()
        normalized = re.sub(r"\b\d+\b", "<num>", normalized)
        normalized = re.sub(r"\s+", " ", normalized)
        return normalized
