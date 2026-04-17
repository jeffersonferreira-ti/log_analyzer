"""Application entry point for Log Analyzer."""

import argparse
from collections import Counter
from pathlib import Path

from app.analyzer.log_analyzer import LogAnalyzer
from app.ingestor.log_ingestor import LogIngestor
from app.parser.log_parser import LogParser
from app.reporting.report_generator import ReportGenerator
from config import settings


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for the log analyzer."""
    default_output = settings.output_dir / "log_analysis_report.json"

    parser = argparse.ArgumentParser(description="Analyze operational and security logs.")
    parser.add_argument(
        "--source",
        default=str(settings.samples_dir),
        help="Input directory containing .log and .txt files.",
    )
    parser.add_argument(
        "--output",
        default=str(default_output),
        help="Output path for the JSON report.",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Print only the high-level analysis summary.",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Skip JSON report generation.",
    )
    return parser.parse_args()


def print_default_output(
    log_files_count: int,
    failed_files: int,
    parsed_entries_count: int,
    level_counts: Counter[str],
    total_score: int,
    classification: str,
    summary: str,
    findings: list[tuple[str, int]],
    report_path: Path | None,
) -> None:
    """Print the default detailed terminal output."""
    print(f"{settings.app_name} is ready.")
    print(f"Loaded {log_files_count} log files ({failed_files} failed)")
    print(f"Parsed {parsed_entries_count} log entries")

    print()
    print("Levels:")
    for level, count in sorted(level_counts.items()):
        print(f"{level}: {count}")

    print()
    print("## Analysis Summary")
    print()
    print(f"Total Score: {total_score}")
    print(f"Classification: {classification}")
    print(f"Summary: {summary}")
    print()
    print("Triggered Findings:")
    if not findings:
        print("* none")
    else:
        for finding_name, finding_score in findings:
            print(f"* {finding_name} [score={finding_score}]")

    if report_path is not None:
        print()
        print(f"Report path: {report_path}")


def print_summary_only_output(
    log_files_count: int,
    failed_files: int,
    parsed_entries_count: int,
    total_score: int,
    classification: str,
    finding_names: list[str],
    report_path: Path | None,
) -> None:
    """Print the condensed terminal output."""
    print(f"Loaded {log_files_count} log files ({failed_files} failed)")
    print(f"Parsed {parsed_entries_count} log entries")
    print(f"Total Score: {total_score}")
    print(f"Classification: {classification}")
    print("Triggered Findings:")
    if not finding_names:
        print("* none")
    else:
        for finding_name in finding_names:
            print(f"* {finding_name}")

    if report_path is not None:
        print(f"Report path: {report_path}")


def main() -> None:
    """Load, parse, analyze, and optionally report on log files."""
    args = parse_args()
    ingestor = LogIngestor()
    parser = LogParser()
    analyzer = LogAnalyzer()
    report_generator = ReportGenerator()

    source_dir = Path(args.source)
    if not source_dir.exists() or not source_dir.is_dir():
        print(f"Invalid source directory: {source_dir}")
        return

    log_files, failed_files = ingestor.load_from_directory(source_dir)
    parsed_entries = parser.parse_files(log_files)
    level_counts = Counter(entry.level for entry in parsed_entries)
    analysis_result = analyzer.analyze(parsed_entries)
    finding_names = [finding.rule_name for finding in analysis_result.findings]
    findings_with_scores = [
        (finding.rule_name, finding.score) for finding in analysis_result.findings
    ]

    report_path: Path | None = None
    if not args.no_report:
        try:
            report_path = report_generator.generate_json_report(
                total_files_loaded=len(log_files),
                total_entries_parsed=len(parsed_entries),
                level_counts=level_counts,
                analysis_result=analysis_result,
                output_path=args.output,
            )
        except OSError as exc:
            print(f"Report generation failed: {exc}")

    if args.summary_only:
        print_summary_only_output(
            log_files_count=len(log_files),
            failed_files=failed_files,
            parsed_entries_count=len(parsed_entries),
            total_score=analysis_result.total_score,
            classification=analysis_result.classification,
            finding_names=finding_names,
            report_path=report_path,
        )
        return

    print_default_output(
        log_files_count=len(log_files),
        failed_files=failed_files,
        parsed_entries_count=len(parsed_entries),
        level_counts=level_counts,
        total_score=analysis_result.total_score,
        classification=analysis_result.classification,
        summary=analysis_result.summary,
        findings=findings_with_scores,
        report_path=report_path,
    )


if __name__ == "__main__":
    main()
