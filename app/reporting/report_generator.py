"""JSON report generation for analyzed log data."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from app.models.log_models import AnalysisResult, ParsedLogEntry


class ReportGenerator:
    """Generate and persist a JSON report for one analysis run."""

    _LEVEL_ORDER = ("INFO", "WARNING", "ERROR", "CRITICAL", "UNKNOWN", "NOTICE")
    _CORRELATIONS_LIMIT = 5
    _CORRELATION_WINDOW_SECONDS = 300
    _TOP_ITEMS_LIMIT = 5
    _RISK_DRIVERS_LIMIT = 5
    _TIMELINE_LIMIT = 8
    _TIMELINE_GROUP_GAP_SECONDS = 60
    _RISK_DRIVER_MESSAGES = {
        "repeated_failed_logins": (
            "Repeated SSH authentication failures from a single IP suggest possible "
            "brute-force activity."
        ),
        "suspicious_ip_activity": (
            "A single IP showed repeated suspicious behavior across multiple log entries."
        ),
        "repeated_errors": (
            "Recurring application errors indicate persistent service instability."
        ),
        "critical_events_present": (
            "A critical system event significantly increased the overall risk level."
        ),
        "excessive_warning_or_error_volume": (
            "A high concentration of warning and error events suggests broader "
            "operational instability."
        ),
    }

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
            "correlations": self._build_correlations(parsed_entries),
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
            "risk_drivers": self._build_risk_drivers(analysis_result),
        }

        report_path.write_text(
            json.dumps(report_data, indent=2),
            encoding="utf-8",
        )
        return report_path

    def _build_correlations(self, parsed_entries: list[ParsedLogEntry]) -> list[dict[str, str]]:
        """Build concise cross-event relationships for the report."""
        correlations: list[dict[str, str]] = []
        seen_descriptions: set[str] = set()

        for correlation in (
            self._build_ip_correlations(parsed_entries)
            + self._build_cross_file_correlations(parsed_entries)
            + self._build_temporal_correlations(parsed_entries)
        ):
            normalized_description = correlation["description"].casefold()
            if normalized_description in seen_descriptions:
                continue

            seen_descriptions.add(normalized_description)
            correlations.append(correlation)

            if len(correlations) >= self._CORRELATIONS_LIMIT:
                break

        return correlations

    def _build_ip_correlations(self, parsed_entries: list[ParsedLogEntry]) -> list[dict[str, str]]:
        """Highlight repeated suspicious IP activity."""
        ip_entries: dict[str, list[ParsedLogEntry]] = defaultdict(list)

        for entry in parsed_entries:
            if not entry.ip_address or not self._is_relevant_correlation_entry(entry):
                continue
            ip_entries[entry.ip_address].append(entry)

        correlations: list[dict[str, str]] = []
        ranked_ip_entries = sorted(
            ip_entries.items(),
            key=lambda item: len(item[1]),
            reverse=True,
        )
        for ip_address, entries in ranked_ip_entries:
            if len(entries) < 2:
                continue

            files = sorted({entry.source_file for entry in entries})
            failed_logins = sum(1 for entry in entries if self._is_failed_login_entry(entry))
            critical_events = sum(1 for entry in entries if self._is_critical_correlation_entry(entry))

            if failed_logins >= 2:
                description = (
                    f"IP {ip_address} appears repeatedly in authentication failures and is "
                    "a likely source of suspicious activity."
                )
            elif len(files) >= 2:
                description = (
                    f"IP {ip_address} appears across {files[0]} and {files[1]}, linking "
                    "related suspicious events in multiple files."
                )
            elif critical_events >= 1:
                description = (
                    f"IP {ip_address} appears in repeated high-severity events and may be "
                    "associated with broader suspicious activity."
                )
            else:
                description = (
                    f"IP {ip_address} appears repeatedly across relevant log events and "
                    "may indicate persistent suspicious activity."
                )

            correlations.append(
                {
                    "type": "ip_activity",
                    "description": description,
                }
            )

            if len(correlations) >= 2:
                break

        return correlations

    def _build_cross_file_correlations(
        self,
        parsed_entries: list[ParsedLogEntry],
    ) -> list[dict[str, str]]:
        """Highlight likely related events observed across different files."""
        correlations: list[dict[str, str]] = []
        failed_logins = [
            entry
            for entry in parsed_entries
            if entry.timestamp is not None and self._is_failed_login_entry(entry)
        ]
        critical_events = [
            entry
            for entry in parsed_entries
            if entry.timestamp is not None and self._is_critical_correlation_entry(entry)
        ]

        if failed_logins and critical_events:
            closest_pair = self._find_closest_entry_pair(
                failed_logins,
                critical_events,
                require_different_files=True,
            )
            if closest_pair is not None:
                login_entry, critical_entry = closest_pair
                correlations.append(
                    {
                        "type": self._build_cross_file_correlation_type(
                            login_entry.source_file,
                            critical_entry.source_file,
                        ),
                        "description": (
                            f"Authentication failures in {login_entry.source_file} occurred "
                            f"close to a critical system event in {critical_entry.source_file}."
                        ),
                    }
                )

        repeated_error_group = self._find_repeated_error_group(parsed_entries)
        if repeated_error_group is not None:
            error_label, error_entries = repeated_error_group
            issue_entries = [
                entry
                for entry in parsed_entries
                if entry.timestamp is not None
                and entry.source_file != error_entries[0].source_file
                and self._is_system_issue_entry(entry)
            ]
            closest_pair = self._find_closest_entry_pair(
                error_entries,
                issue_entries,
                require_different_files=True,
            )
            if closest_pair is not None:
                error_entry, issue_entry = closest_pair
                correlations.append(
                    {
                        "type": self._build_cross_file_correlation_type(
                            error_entry.source_file,
                            issue_entry.source_file,
                        ),
                        "description": (
                            f"Repeated {error_label} in {error_entry.source_file} occurred "
                            f"close to a system issue in {issue_entry.source_file}."
                        ),
                    }
                )

        return correlations

    def _build_temporal_correlations(
        self,
        parsed_entries: list[ParsedLogEntry],
    ) -> list[dict[str, str]]:
        """Highlight important events that occurred close together in time."""
        critical_events = [
            entry
            for entry in parsed_entries
            if entry.timestamp is not None and self._is_critical_correlation_entry(entry)
        ]
        if not critical_events:
            return []

        repeated_error_group = self._find_repeated_error_group(parsed_entries)
        failed_logins = [
            entry
            for entry in parsed_entries
            if entry.timestamp is not None and self._is_failed_login_entry(entry)
        ]

        for critical_entry in sorted(critical_events, key=lambda entry: entry.timestamp):
            preceding_labels: list[str] = []

            if repeated_error_group is not None:
                error_label, error_entries = repeated_error_group
                if any(self._is_close_in_time(error_entry, critical_entry) for error_entry in error_entries):
                    preceding_labels.append(f"repeated {error_label}")

            if any(self._is_close_in_time(login_entry, critical_entry) for login_entry in failed_logins):
                preceding_labels.append("failed logins")

            if len(preceding_labels) >= 2:
                description = (
                    f"{preceding_labels[0].capitalize()} and {preceding_labels[1]} occurred "
                    "shortly before a critical system event."
                )
                return [
                    {
                        "type": "temporal_sequence",
                        "description": description,
                    }
                ]

            if len(preceding_labels) == 1:
                description = (
                    f"{preceding_labels[0].capitalize()} occurred shortly before a critical "
                    "system event."
                )
                return [
                    {
                        "type": "temporal_sequence",
                        "description": description,
                    }
                ]

        return []

    def _build_risk_drivers(self, analysis_result: AnalysisResult) -> list[str]:
        """Return concise human-readable drivers for the triggered findings."""
        drivers: list[str] = []
        seen_messages: set[str] = set()

        sorted_findings = sorted(
            analysis_result.findings,
            key=lambda finding: finding.score,
            reverse=True,
        )
        for finding in sorted_findings:
            driver = self._build_risk_driver_message(finding)
            if not driver:
                continue

            normalized_driver = driver.casefold()
            if normalized_driver in seen_messages:
                continue

            seen_messages.add(normalized_driver)
            drivers.append(driver)

            if len(drivers) >= self._RISK_DRIVERS_LIMIT:
                break

        return drivers

    def _build_risk_driver_message(self, finding) -> str:
        """Map one finding to a human-readable risk driver."""
        return self._RISK_DRIVER_MESSAGES.get(
            finding.rule_name,
            finding.description.strip(),
        )

    def _find_repeated_error_group(
        self,
        parsed_entries: list[ParsedLogEntry],
    ) -> tuple[str, list[ParsedLogEntry]] | None:
        """Return the strongest repeated error cluster, if one exists."""
        grouped_entries: dict[tuple[str, str], list[ParsedLogEntry]] = defaultdict(list)
        canonical_messages: dict[tuple[str, str], str] = {}

        for entry in parsed_entries:
            if entry.level != "ERROR" or entry.timestamp is None:
                continue

            normalized_message = self._normalize_error_message(entry.message)
            group_key = (entry.source_file, normalized_message)
            grouped_entries[group_key].append(entry)
            canonical_messages.setdefault(group_key, entry.message.strip())

        if not grouped_entries:
            return None

        best_group_key, best_group_entries = max(
            grouped_entries.items(),
            key=lambda item: len(item[1]),
        )
        if len(best_group_entries) < 2:
            return None

        message = canonical_messages[best_group_key]
        return self._summarize_error_message(message), best_group_entries

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

    def _summarize_error_message(self, message: str) -> str:
        """Convert a repeated error message into a short readable label."""
        lowered_message = message.strip().lower()
        if "database" in lowered_message:
            return "database errors"
        if "timeout" in lowered_message:
            return "timeout errors"
        return f"errors matching '{message.strip()}'"

    def _is_relevant_correlation_entry(self, entry: ParsedLogEntry) -> bool:
        """Return whether an entry is relevant for a correlation summary."""
        return self._is_failed_login_entry(entry) or entry.level in {"WARNING", "ERROR", "CRITICAL"}

    def _is_critical_correlation_entry(self, entry: ParsedLogEntry) -> bool:
        """Return whether an entry represents a critical event for correlation."""
        lowered_message = entry.message.lower()
        return (
            entry.level == "CRITICAL"
            or "reboot" in lowered_message
            or "fatal" in lowered_message
            or "panic" in lowered_message
        )

    def _is_system_issue_entry(self, entry: ParsedLogEntry) -> bool:
        """Return whether an entry looks like a broader system issue."""
        lowered_message = entry.message.lower()
        return (
            self._is_critical_correlation_entry(entry)
            or "timeout" in lowered_message
        )

    def _build_cross_file_correlation_type(
        self,
        left_source_file: str,
        right_source_file: str,
    ) -> str:
        """Return a more descriptive type for cross-file correlations."""
        combined_sources = f"{left_source_file} {right_source_file}".lower()

        if "auth" in combined_sources and "system" in combined_sources:
            return "auth_system_correlation"

        if (
            any(keyword in combined_sources for keyword in ("webapp", "app", "database"))
            and "system" in combined_sources
        ):
            return "app_system_correlation"

        return "cross_file_pattern"

    def _find_closest_entry_pair(
        self,
        left_entries: list[ParsedLogEntry],
        right_entries: list[ParsedLogEntry],
        require_different_files: bool = False,
    ) -> tuple[ParsedLogEntry, ParsedLogEntry] | None:
        """Return the closest pair of entries within the correlation window."""
        closest_pair: tuple[ParsedLogEntry, ParsedLogEntry] | None = None
        closest_seconds: float | None = None

        for left_entry in left_entries:
            if left_entry.timestamp is None:
                continue

            for right_entry in right_entries:
                if right_entry.timestamp is None:
                    continue
                if require_different_files and left_entry.source_file == right_entry.source_file:
                    continue

                delta_seconds = abs(
                    (left_entry.timestamp - right_entry.timestamp).total_seconds()
                )
                if delta_seconds > self._CORRELATION_WINDOW_SECONDS:
                    continue

                if closest_seconds is None or delta_seconds < closest_seconds:
                    closest_pair = (left_entry, right_entry)
                    closest_seconds = delta_seconds

        return closest_pair

    def _is_close_in_time(self, first_entry: ParsedLogEntry, second_entry: ParsedLogEntry) -> bool:
        """Return whether two parsed entries occurred within the correlation window."""
        if first_entry.timestamp is None or second_entry.timestamp is None:
            return False

        delta_seconds = (second_entry.timestamp - first_entry.timestamp).total_seconds()
        return 0 <= delta_seconds <= self._CORRELATION_WINDOW_SECONDS
