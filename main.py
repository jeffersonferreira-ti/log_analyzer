"""Application entry point for Log Analyzer."""

from collections import Counter

from app.analyzer.log_analyzer import LogAnalyzer
from app.ingestor.log_ingestor import LogIngestor
from app.parser.log_parser import LogParser
from config import settings


def main() -> None:
    """Load, parse, and analyze log files from the local sample directory."""
    ingestor = LogIngestor()
    parser = LogParser()
    analyzer = LogAnalyzer()

    log_files, failed_files = ingestor.load_from_directory(settings.samples_dir)
    parsed_entries = parser.parse_files(log_files)
    level_counts = Counter(entry.level for entry in parsed_entries)
    analysis_result = analyzer.analyze(parsed_entries)

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


if __name__ == "__main__":
    main()
