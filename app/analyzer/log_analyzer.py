"""Heuristic analysis for parsed log entries."""

from __future__ import annotations

from collections import Counter, defaultdict
from difflib import SequenceMatcher

from app.models.log_models import AnalysisResult, AnalysisFinding, ParsedLogEntry


class LogAnalyzer:
    """Inspect parsed log entries and generate practical heuristic findings."""

    def analyze(self, entries: list[ParsedLogEntry]) -> AnalysisResult:
        """Run all heuristic rules and return an aggregate result."""
        findings: list[AnalysisFinding] = []

        for rule in (
            self._repeated_failed_logins,
            self._repeated_errors,
            self._suspicious_ip_activity,
            self._critical_events_present,
            self._excessive_warning_or_error_volume,
        ):
            finding = rule(entries)
            if finding is not None:
                findings.append(finding)

        total_score = sum(finding.score for finding in findings)
        classification = self._classify(total_score)
        summary = self._build_summary(classification, findings)

        return AnalysisResult(
            total_score=total_score,
            classification=classification,
            summary=summary,
            findings=findings,
        )

    def _repeated_failed_logins(
        self, entries: list[ParsedLogEntry]
    ) -> AnalysisFinding | None:
        failed_entries = [
            entry for entry in entries if "failed password" in entry.raw_line.lower()
        ]
        if len(failed_entries) < 2:
            return None

        ip_counts = Counter(entry.ip_address for entry in failed_entries if entry.ip_address)
        repeated_ip, repeated_count = ("unknown", 0)
        if ip_counts:
            repeated_ip, repeated_count = ip_counts.most_common(1)[0]

        score = min(26, 16 + len(failed_entries) + min(repeated_count, 4))
        description = f"Detected {len(failed_entries)} failed login attempts."
        evidence = [entry.raw_line for entry in failed_entries[:3]]
        if repeated_count >= 2:
            description += f" Most attempts originated from {repeated_ip}."
            evidence.append(f"Repeated source IP: {repeated_ip} ({repeated_count} attempts)")

        return AnalysisFinding(
            rule_name="repeated_failed_logins",
            description=description,
            severity="HIGH",
            score=score,
            evidence=evidence,
        )

    def _repeated_errors(self, entries: list[ParsedLogEntry]) -> AnalysisFinding | None:
        error_entries = [entry for entry in entries if entry.level == "ERROR"]
        if len(error_entries) < 2:
            return None

        grouped_messages: list[list[ParsedLogEntry]] = []

        for entry in error_entries:
            normalized_message = self._normalize_message(entry.message)
            matched_group = None

            for group in grouped_messages:
                group_message = self._normalize_message(group[0].message)
                similarity = SequenceMatcher(None, normalized_message, group_message).ratio()
                if similarity >= 0.88:
                    matched_group = group
                    break

            if matched_group is None:
                grouped_messages.append([entry])
            else:
                matched_group.append(entry)

        repeated_group = max(grouped_messages, key=len)
        if len(repeated_group) < 2:
            return None

        repeated_message = repeated_group[0].message
        score = min(18, 8 + (len(repeated_group) * 2))
        description = (
            f"Repeated error pattern detected {len(repeated_group)} times: "
            f"{repeated_message}"
        )
        evidence = [entry.raw_line for entry in repeated_group[:3]]

        return AnalysisFinding(
            rule_name="repeated_errors",
            description=description,
            severity="MEDIUM",
            score=score,
            evidence=evidence,
        )

    def _suspicious_ip_activity(
        self, entries: list[ParsedLogEntry]
    ) -> AnalysisFinding | None:
        problematic_entries = [
            entry
            for entry in entries
            if entry.ip_address
            and (
                "failed password" in entry.raw_line.lower()
                or entry.level in {"WARNING", "ERROR", "CRITICAL"}
            )
        ]
        if len(problematic_entries) < 2:
            return None

        ip_events: dict[str, list[ParsedLogEntry]] = defaultdict(list)
        for entry in problematic_entries:
            if entry.ip_address:
                ip_events[entry.ip_address].append(entry)

        repeated_activity = max(ip_events.items(), key=lambda item: len(item[1]), default=None)
        if repeated_activity is None:
            return None

        ip_address, ip_entries = repeated_activity
        if len(ip_entries) < 2:
            return None

        score = min(22, 12 + (len(ip_entries) * 2))
        description = (
            f"Repeated problematic activity detected from IP {ip_address} "
            f"across {len(ip_entries)} log entries."
        )
        evidence = [entry.raw_line for entry in ip_entries[:3]]

        return AnalysisFinding(
            rule_name="suspicious_ip_activity",
            description=description,
            severity="HIGH",
            score=score,
            evidence=evidence,
        )

    def _critical_events_present(
        self, entries: list[ParsedLogEntry]
    ) -> AnalysisFinding | None:
        critical_keywords = ("reboot", "fatal", "panic")
        critical_entries = [
            entry
            for entry in entries
            if entry.level == "CRITICAL"
            or any(keyword in entry.raw_line.lower() for keyword in critical_keywords)
        ]
        if not critical_entries:
            return None

        score = min(35, 24 + (len(critical_entries) * 4))
        description = (
            f"Detected {len(critical_entries)} critical event(s) or critical keywords."
        )
        evidence = [entry.raw_line for entry in critical_entries[:3]]

        return AnalysisFinding(
            rule_name="critical_events_present",
            description=description,
            severity="HIGH",
            score=score,
            evidence=evidence,
        )

    def _excessive_warning_or_error_volume(
        self, entries: list[ParsedLogEntry]
    ) -> AnalysisFinding | None:
        high_signal_entries = [
            entry for entry in entries if entry.level in {"WARNING", "ERROR"}
        ]
        if len(high_signal_entries) < 5:
            return None

        score = min(12, 6 + min(len(high_signal_entries) - 4, 6))
        description = (
            f"High volume of warning and error events detected: "
            f"{len(high_signal_entries)} entries."
        )
        evidence = [entry.raw_line for entry in high_signal_entries[:3]]

        return AnalysisFinding(
            rule_name="excessive_warning_or_error_volume",
            description=description,
            severity="MEDIUM",
            score=score,
            evidence=evidence,
        )

    def _normalize_message(self, message: str) -> str:
        """Normalize messages enough to group similar repeated errors."""
        return " ".join(message.lower().split())

    def _classify(self, total_score: int) -> str:
        """Map the accumulated score to a simple risk classification."""
        if total_score >= 80:
            return "CRITICAL"
        if total_score >= 50:
            return "SUSPICIOUS"
        if total_score >= 20:
            return "ATTENTION"
        return "NORMAL"

    def _build_summary(
        self, classification: str, findings: list[AnalysisFinding]
    ) -> str:
        """Create a short run summary from triggered findings."""
        if not findings:
            return "No significant suspicious or operational patterns were detected."

        return (
            f"{classification} based on {len(findings)} triggered finding(s) "
            "across authentication, error, and event severity heuristics."
        )
