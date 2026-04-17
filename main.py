"""Application entry point for Log Analyzer."""

from collections import Counter

from app.ingestor.log_ingestor import LogIngestor
from app.parser.log_parser import LogParser
from config import settings


def main() -> None:
    """Load and parse raw log files from the local sample directory."""
    ingestor = LogIngestor()
    parser = LogParser()

    log_files, failed_files = ingestor.load_from_directory(settings.samples_dir)
    parsed_entries = parser.parse_files(log_files)
    level_counts = Counter(entry.level for entry in parsed_entries)

    print(f"{settings.app_name} is ready.")
    print(f"Loaded {len(log_files)} log files ({failed_files} failed)")
    print(f"Parsed {len(parsed_entries)} log entries")

    print()
    print("Levels:")
    for level, count in sorted(level_counts.items()):
        print(f"{level}: {count}")


if __name__ == "__main__":
    main()
