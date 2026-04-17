"""JSON report generation for analyzed log data."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from app.models.log_models import AnalysisResult


class ReportGenerator:
    """Generate and persist a JSON report for one analysis run."""

    def generate_json_report(
        self,
        total_files_loaded: int,
        total_entries_parsed: int,
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
