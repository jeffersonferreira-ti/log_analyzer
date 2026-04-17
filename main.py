"""Application entry point for Log Analyzer."""

from collections import Counter

from app.analyzer.log_analyzer import LogAnalyzer
from app.ingestor.log_ingestor import LogIngestor
from app.parser.log_parser import LogParser
from app.reporting.report_generator import ReportGenerator
from config import settings


def main() -> None:
    """Load, parse, and analyze log files from the local sample directory."""
    ingestor = LogIngestor()
    parser = LogParser()
    analyzer = LogAnalyzer()
    report_generator = ReportGenerator()

    log_files, failed_files = ingestor.load_from_directory(settings.samples_dir)
    parsed_entries = parser.parse_files(log_files)
    level_counts = Counter(entry.level for entry in parsed_entries)
    analysis_result = analyzer.analyze(parsed_entries)
    report_path = report_generator.generate_json_report(
        total_files_loaded=len(log_files),
        total_entries_parsed=len(parsed_entries),
        level_counts=level_counts,
        analysis_result=analysis_result,
        output_dir=settings.output_dir,
    )

    print(f"{settings.app_name} is ready.")
    print(f"Loaded {len(log_files)} log files ({failed_files} failed)")
    print(f"Parsed {len(parsed_entries)} log entries")

    print()
    print("Levels:")
    for level, count in sorted(level_counts.items()):
        print(f"{level}: {count}")

    print()
    print("## Analysis Summary")
    print()
    print(f"Total Score: {analysis_result.total_score}")
    print(f"Classification: {analysis_result.classification}")
    print(f"Summary: {analysis_result.summary}")
    print()
    print("Triggered Findings:")
    if not analysis_result.findings:
        print("* none")
    else:
        for finding in analysis_result.findings:
            print(f"* {finding.rule_name} [score={finding.score}]")

    print()
    print(f"Report path: {report_path}")


if __name__ == "__main__":
    main()
